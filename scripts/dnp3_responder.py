#!/usr/bin/env python3
"""DNP3 software responder for testing icsFuzzer without hardware.

Writes a sidecar JSONL (one record per DLL frame processed) so every responder
decision can be correlated against fuzzer crash indicators.

Response logic:
  DLL FC=4 (unconfirmed user data): parse TL + AL, respond based on AL FC
  DLL FC=3 (confirmed user data):   send DLL ACK, then parse and respond
  DLL FC=0,1,2,9 (link-layer):      send appropriate DLL response or ignore
  AL FC=READ:       respond with FC=0x81 RESPONSE, IIN=0x0000, no objects
  AL FC=WRITE:      respond with FC=0x81 RESPONSE, IIN=0x0000
  AL FC=DIRECT_OP:  respond with FC=0x81 RESPONSE, echo objects, IIN=0x0000
  AL FC=COLD/WARM_RESTART: respond with FC=0x81, IIN=0x0000
  Unknown AL FC:    respond with FC=0x81, IIN2.FUNC_NOT_SUPP=1
  Unknown G/V in READ: respond with FC=0x81, IIN2.OBJ_UNKNOWN=1
  Close on: bad start bytes, LEN<5, bad header CRC, bad block CRC, truncated

Sidecar action vocabulary (stable — these are join keys for analysis):
  response_empty         READ response: FC=0x81, IIN=0x0000, no objects
  response_echo          DIRECT_OPERATE echo response
  response_exception_fnc FC=0x81 with IIN2.FUNC_NOT_SUPP=1
  response_exception_obj FC=0x81 with IIN2.OBJ_UNKNOWN=1
  response_dll_ack       DLL ACK (FC=0) sent for confirmed user data
  response_link_status   LINK_STATUS response (FC=11) for REQUEST_LINK_STATUS
  close_bad_start_byte   start bytes ≠ 0x05 0x64
  close_bad_length       DLL LEN < 5
  close_bad_header_crc   header CRC check failed
  close_bad_block_crc    data block CRC check failed
  close_truncated        received fewer bytes than LEN implies
  close_timeout          5 s idle timeout
  close_client_reset     unexpected client close / RST

Usage:
  python3 scripts/dnp3_responder.py [--host 127.0.0.1] [--port 20001]

  Then run the fuzzer against it:
  python3 icsfuzzer.py --protocol dnp3 --target 127.0.0.1:20001 --yes
"""

import argparse
import collections
import json
import socket
import struct
import threading
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# DLL constants (mirrors protocols/dnp3/fuzzer.py — keep in sync)
# ---------------------------------------------------------------------------
_START = b'\x05\x64'

# DLL function codes
_DLL_FC_RESET_LINK    = 0x00
_DLL_FC_RESET_PROCESS = 0x01
_DLL_FC_TEST_LINK     = 0x02
_DLL_FC_USER_DATA_CON = 0x03
_DLL_FC_USER_DATA_UNC = 0x04
_DLL_FC_REQUEST_LINK  = 0x09

# AL function codes
_FC_READ              = 0x01
_FC_WRITE             = 0x02
_FC_SELECT            = 0x03
_FC_OPERATE           = 0x04
_FC_DIRECT_OPERATE    = 0x05
_FC_DIRECT_OPERATE_NR = 0x06
_FC_IMMED_FREEZE      = 0x07
_FC_FREEZE_CLEAR      = 0x09
_FC_COLD_RESTART      = 0x0D
_FC_WARM_RESTART      = 0x0E
_FC_ENABLE_UNSOL      = 0x14
_FC_DISABLE_UNSOL     = 0x15
_FC_AUTH_REQ          = 0x20
_FC_RESPONSE          = 0x81
_FC_UNSOL_RESPONSE    = 0x82
_FC_AUTH_CHALLENGE    = 0x83

_FC_NO_RESP = frozenset([_FC_DIRECT_OPERATE_NR, _FC_IMMED_FREEZE, _FC_FREEZE_CLEAR])

# IIN2 bits
_IIN2_FUNC_NOT_SUPP = 0x01
_IIN2_OBJ_UNKNOWN   = 0x02

# CTRL bytes
_CTRL_SEC_ACK       = 0x00   # secondary ACK: DIR=0, PRM=0, FC=0
_CTRL_SEC_LINK_STAT = 0x0B   # secondary LINK_STATUS: DIR=0, PRM=0, FC=11
_CTRL_SEC_USER_DATA = 0x0E   # secondary unconfirmed user data: DIR=0, PRM=0, FC=14

# Sidecar action vocabulary
ACTION_RESP_EMPTY      = "response_empty"
ACTION_RESP_ECHO       = "response_echo"
ACTION_RESP_EXC_FNC    = "response_exception_fnc"
ACTION_RESP_EXC_OBJ    = "response_exception_obj"
ACTION_RESP_DLL_ACK    = "response_dll_ack"
ACTION_RESP_LINK_STAT  = "response_link_status"
ACTION_CLOSE_BAD_START = "close_bad_start_byte"
ACTION_CLOSE_BAD_LEN   = "close_bad_length"
ACTION_CLOSE_BAD_HCRC  = "close_bad_header_crc"
ACTION_CLOSE_BAD_BCRC  = "close_bad_block_crc"
ACTION_CLOSE_TRUNCATED = "close_truncated"
ACTION_CLOSE_TIMEOUT   = "close_timeout"
ACTION_CLOSE_RESET     = "close_client_reset"


# ---------------------------------------------------------------------------
# CRC-16/DNP (must match fuzzer.py)
# ---------------------------------------------------------------------------

def _crc16(data: bytes) -> bytes:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", (crc ^ 0xFFFF) & 0xFFFF)


def _crc16_int(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (crc ^ 0xFFFF) & 0xFFFF


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _dll_frame(user_data: bytes, ctrl: int = _CTRL_SEC_USER_DATA,
               dst: int = 3, src: int = 1) -> bytes:
    length = 5 + len(user_data)
    hdr_body = bytes([length & 0xFF, ctrl,
                      dst & 0xFF, (dst >> 8) & 0xFF,
                      src & 0xFF, (src >> 8) & 0xFF])
    header = _START + hdr_body + _crc16(_START + hdr_body)
    blocks = b""
    for i in range(0, len(user_data), 16):
        chunk = user_data[i:i + 16]
        blocks += chunk + _crc16(chunk)
    return header + blocks


def _dll_ack(dst: int = 3, src: int = 1) -> bytes:
    return _dll_frame(b"", ctrl=_CTRL_SEC_ACK, dst=dst, src=src)


def _dll_link_status(dst: int = 3, src: int = 1) -> bytes:
    return _dll_frame(b"", ctrl=_CTRL_SEC_LINK_STAT, dst=dst, src=src)


def _tl_byte() -> bytes:
    return bytes([0xC0])   # FIR=1, FIN=1, SEQ=0


def _al_response(al_fc: int, iin1: int, iin2: int, objects: bytes = b"", seq: int = 0) -> bytes:
    ac = 0xC0 | (seq & 0x0F)
    return bytes([ac, al_fc, iin1, iin2]) + objects


def _response_frame(iin1: int, iin2: int, objects: bytes = b"",
                    dst: int = 3, src: int = 1, al_seq: int = 0) -> bytes:
    al = _al_response(_FC_RESPONSE, iin1, iin2, objects, seq=al_seq)
    return _dll_frame(_tl_byte() + al, dst=dst, src=src)


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def _extract_user_data(body: bytes, user_data_len: int) -> bytes:
    data, offset, remaining = b"", 0, user_data_len
    while remaining > 0 and offset < len(body):
        n = min(remaining, 16)
        data += body[offset:offset + n]
        offset += n + 2
        remaining -= n
    return data


# ---------------------------------------------------------------------------
# Sidecar logger
# ---------------------------------------------------------------------------

class SidecarLogger:
    def __init__(self, output_dir: str):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.path = out / f"dnp3-responder-{ts}.jsonl"
        self._file   = open(self.path, "w", encoding="utf-8")
        self._lock   = threading.Lock()
        self._counts: collections.Counter = collections.Counter()
        print(f"[responder] sidecar  → {self.path}")

    def log(self, session_id: str, seq: int, client: tuple,
            dll_fc: int | None, al_fc: int | None,
            action: str, reason: str, rx_hex: str, tx_hex: str | None):
        record = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "seq":        seq,
            "client":     f"{client[0]}:{client[1]}",
            "dll_fc":     dll_fc,
            "al_fc":      f"0x{al_fc:02X}" if al_fc is not None else None,
            "action":     action,
            "reason":     reason,
            "rx_hex":     rx_hex,
            "tx_hex":     tx_hex,
        }
        with self._lock:
            self._file.write(json.dumps(record) + "\n")
            self._file.flush()
            self._counts[action] += 1

    def summary(self):
        total = sum(self._counts.values())
        print(f"\n[responder] sidecar summary — {total} frames processed")
        for action, count in sorted(self._counts.items(), key=lambda x: -x[1]):
            print(f"  {action:<48} {count}")
        print(f"[responder] sidecar  → {self.path}")

    def close(self):
        with self._lock:
            if not self._file.closed:
                self._file.close()


# ---------------------------------------------------------------------------
# Per-connection handler
# ---------------------------------------------------------------------------

_session_counter = 0
_session_lock    = threading.Lock()


def _next_session_id() -> str:
    global _session_counter
    with _session_lock:
        _session_counter += 1
        return f"S{_session_counter:04d}"


def handle_client(conn: socket.socket, addr: tuple,
                  sidecar: SidecarLogger, verbose: bool = True) -> None:
    session_id = _next_session_id()
    seq        = 0
    al_seq     = 0   # application layer response sequence counter

    if verbose:
        print(f"[responder] + {addr[0]}:{addr[1]}  ({session_id})")
    conn.settimeout(5.0)

    def log(dll_fc, al_fc, action, reason, rx, tx):
        sidecar.log(session_id, seq, addr,
                    dll_fc, al_fc,
                    action, reason,
                    rx.hex() if rx else "",
                    tx.hex() if tx else None)

    try:
        while True:
            seq += 1

            # --- Read start bytes ---
            start = _recv_exact(conn, 2)
            if len(start) == 0:
                return  # clean close
            if len(start) < 2:
                log(None, None, ACTION_CLOSE_TRUNCATED, "received <2 bytes", start, None)
                return

            if start != _START:
                extra = _recv_exact(conn, 8)  # read a bit more for context
                log(None, None, ACTION_CLOSE_BAD_START,
                    f"start bytes 0x{start.hex()} ≠ 0x0564",
                    start + extra, None)
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  bad start bytes — closing")
                return

            # --- Read LEN byte ---
            len_byte = _recv_exact(conn, 1)
            if not len_byte:
                log(None, None, ACTION_CLOSE_TRUNCATED, "no LEN byte", start, None)
                return
            length = len_byte[0]

            if length < 5:
                rest = _recv_exact(conn, min(8, length))
                rx = start + len_byte + rest
                log(None, None, ACTION_CLOSE_BAD_LEN,
                    f"DLL LEN={length} < 5 minimum", rx, None)
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  LEN={length} too small — closing")
                return

            # --- Read remaining header (CTRL, DST, SRC, HDR_CRC) = 7 bytes ---
            hdr_rest = _recv_exact(conn, 7)
            if len(hdr_rest) < 7:
                rx = start + len_byte + hdr_rest
                log(None, None, ACTION_CLOSE_TRUNCATED,
                    f"truncated header: got {len(hdr_rest)}/7 bytes", rx, None)
                return

            hdr_body_bytes = len_byte + hdr_rest[:5]   # LEN + CTRL + DST(2) + SRC(2)
            hdr_crc_recv   = hdr_rest[5:7]
            hdr_crc_calc   = _crc16(start + hdr_body_bytes)  # includes start bytes per opendnp3

            ctrl   = hdr_rest[0]
            dst    = hdr_rest[1] | (hdr_rest[2] << 8)
            src    = hdr_rest[3] | (hdr_rest[4] << 8)
            hdr_rx = start + hdr_body_bytes + hdr_crc_recv

            if hdr_crc_recv != hdr_crc_calc:
                log(None, None, ACTION_CLOSE_BAD_HCRC,
                    f"header CRC 0x{hdr_crc_recv.hex()} ≠ expected 0x{hdr_crc_calc.hex()}",
                    hdr_rx, None)
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  bad header CRC — closing")
                return

            # --- Read user data blocks ---
            user_data_len = length - 5
            block_data    = b""
            block_rx      = b""
            remaining     = user_data_len
            bad_block_crc = False

            while remaining > 0:
                n = min(remaining, 16)
                chunk = _recv_exact(conn, n + 2)   # data + CRC
                if len(chunk) < n + 2:
                    rx = hdr_rx + block_rx + chunk
                    log(None, None, ACTION_CLOSE_TRUNCATED,
                        f"truncated block: got {len(chunk)}/{n+2}", rx, None)
                    return
                block_rx += chunk
                data_part = chunk[:n]
                crc_part  = chunk[n:n+2]
                if crc_part != _crc16(data_part):
                    bad_block_crc = True
                block_data += data_part
                remaining  -= n

            full_rx = hdr_rx + block_rx

            if bad_block_crc:
                log(None, None, ACTION_CLOSE_BAD_BCRC,
                    "data block CRC check failed", full_rx, None)
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  bad block CRC — closing")
                return

            # --- Parse CTRL ---
            dll_fc  = ctrl & 0x0F
            is_prim = bool(ctrl & 0x40)

            # --- Handle DLL-only frames (no user data, link-layer control) ---
            if user_data_len == 0 or not is_prim:
                if dll_fc == _DLL_FC_REQUEST_LINK:
                    resp = _dll_link_status(dst=src, src=dst)
                    conn.sendall(resp)
                    log(dll_fc, None, ACTION_RESP_LINK_STAT,
                        f"REQUEST_LINK_STATUS → LINK_STATUS", full_rx, resp)
                elif dll_fc in (_DLL_FC_RESET_LINK, _DLL_FC_RESET_PROCESS,
                                _DLL_FC_TEST_LINK):
                    resp = _dll_ack(dst=src, src=dst)
                    conn.sendall(resp)
                    log(dll_fc, None, ACTION_RESP_DLL_ACK,
                        f"link-layer FC={dll_fc} → DLL ACK", full_rx, resp)
                else:
                    # DLL-only frame, secondary FC, or no-response needed
                    log(dll_fc, None, ACTION_RESP_DLL_ACK,
                        f"DLL FC={dll_fc} (no AL, ignoring)", full_rx, None)
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  DLL FC={dll_fc} (link-layer)")
                continue

            # --- Send DLL ACK for confirmed user data (FC=3) ---
            if dll_fc == _DLL_FC_USER_DATA_CON:
                ack = _dll_ack(dst=src, src=dst)
                conn.sendall(ack)
                log(dll_fc, None, ACTION_RESP_DLL_ACK,
                    "FC=3 confirmed user data → DLL ACK sent", full_rx, ack)

            # --- Parse TL + AL ---
            if len(block_data) < 2:
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  user data too short for TL+AL")
                continue

            # block_data[0] = TL, block_data[1] = AC, block_data[2] = AL FC
            al_fc = block_data[2] if len(block_data) >= 3 else None
            al_req_seq = (block_data[1] & 0x0F) if len(block_data) >= 2 else 0

            if al_fc is None:
                log(dll_fc, None, ACTION_RESP_EXC_FNC,
                    "user data too short for AL FC", full_rx, None)
                continue

            if verbose:
                print(f"[responder]   {session_id}/{seq}  DLL FC={dll_fc}  AL FC=0x{al_fc:02X}")

            # --- Build AL response ---
            if al_fc in (_FC_READ, _FC_WRITE, _FC_SELECT,
                         _FC_COLD_RESTART, _FC_WARM_RESTART,
                         _FC_ENABLE_UNSOL, _FC_DISABLE_UNSOL,
                         _FC_IMMED_FREEZE, _FC_FREEZE_CLEAR):
                resp = _response_frame(0x00, 0x00, dst=src, src=dst, al_seq=al_req_seq)
                conn.sendall(resp)
                log(dll_fc, al_fc, ACTION_RESP_EMPTY,
                    f"AL FC=0x{al_fc:02X} → empty RESPONSE (IIN=0x0000)", full_rx, resp)

            elif al_fc in (_FC_DIRECT_OPERATE, _FC_OPERATE):
                # Echo the objects back (skip TL + AC + FC bytes)
                obj_echo = block_data[3:] if len(block_data) > 3 else b""
                resp = _response_frame(0x00, 0x00, objects=obj_echo,
                                       dst=src, src=dst, al_seq=al_req_seq)
                conn.sendall(resp)
                log(dll_fc, al_fc, ACTION_RESP_ECHO,
                    f"DIRECT_OPERATE → echo RESPONSE", full_rx, resp)

            elif al_fc == _FC_DIRECT_OPERATE_NR:
                # No response for direct operate no-return
                log(dll_fc, al_fc, ACTION_RESP_EMPTY,
                    "DIRECT_OPERATE_NR → no response (by spec)", full_rx, None)

            elif al_fc == _FC_AUTH_REQ:
                # SAv5 AUTH_REQ: respond with function not supported
                resp = _response_frame(0x00, _IIN2_FUNC_NOT_SUPP,
                                       dst=src, src=dst, al_seq=al_req_seq)
                conn.sendall(resp)
                log(dll_fc, al_fc, ACTION_RESP_EXC_FNC,
                    "AUTH_REQ (FC=0x20) → IIN2.FUNC_NOT_SUPP (SAv5 not implemented)", full_rx, resp)

            elif al_fc in (_FC_RESPONSE, _FC_UNSOL_RESPONSE, _FC_AUTH_CHALLENGE):
                # Master sent a response/challenge — wrong direction
                resp = _response_frame(0x00, _IIN2_FUNC_NOT_SUPP,
                                       dst=src, src=dst, al_seq=al_req_seq)
                conn.sendall(resp)
                log(dll_fc, al_fc, ACTION_RESP_EXC_FNC,
                    f"Master sent AL FC=0x{al_fc:02X} (outstation FC) → IIN2.FUNC_NOT_SUPP",
                    full_rx, resp)
            else:
                # Unknown / unsupported FC
                resp = _response_frame(0x00, _IIN2_FUNC_NOT_SUPP,
                                       dst=src, src=dst, al_seq=al_req_seq)
                conn.sendall(resp)
                log(dll_fc, al_fc, ACTION_RESP_EXC_FNC,
                    f"Unknown AL FC=0x{al_fc:02X} → IIN2.FUNC_NOT_SUPP", full_rx, resp)

            al_seq = (al_seq + 1) & 0x0F

    except socket.timeout:
        sidecar.log(session_id, seq, addr,
                    None, None,
                    ACTION_CLOSE_TIMEOUT, "5 s idle timeout", "", None)
    except (ConnectionResetError, BrokenPipeError, OSError):
        sidecar.log(session_id, seq, addr,
                    None, None,
                    ACTION_CLOSE_RESET, "client reset or closed unexpectedly", "", None)
    finally:
        conn.close()
        if verbose:
            print(f"[responder] - {addr[0]}:{addr[1]}  ({session_id})")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DNP3 software responder — icsFuzzer calibration target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--port",   type=int, default=20001,
                        help="Bind port (default: 20001; real DNP3 uses 20000)")
    parser.add_argument("--output", default="output", metavar="DIR")
    parser.add_argument("--quiet",  action="store_true")
    args = parser.parse_args()

    sidecar = SidecarLogger(args.output)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(10)
    print(f"[responder] listening on {args.host}:{args.port}  (Ctrl-C to stop)")

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(
                target=handle_client,
                args=(conn, addr, sidecar, not args.quiet),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\n[responder] stopping ...")
    finally:
        srv.close()
        sidecar.summary()
        sidecar.close()


if __name__ == "__main__":
    main()
