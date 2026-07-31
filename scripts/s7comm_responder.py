#!/usr/bin/env python3
"""Siemens S7comm software responder for icsFuzzer calibration.

TCP server on port 10200 (102 * 100 to avoid root).
Implements TPKT + COTP CR/CC + S7 Setup Communication + stub request handlers.

Sidecar action vocabulary:
  cotp_ok            COTP CC sent (connection established)
  cotp_bad           Malformed COTP CR; connection closed
  cotp_malformed     TPKT/COTP too short; connection closed
  setup_comm_ok      S7 Setup Communication → Ack_Data sent
  setup_comm_bad     Setup Comm with bad function code
  read_ok            Read Variable request returned stub data
  read_bad_area      Read with unknown or unsupported area code
  read_bad_db        Read DB with DB number not found (DB 0 or >1000)
  read_bad_address   Read with address > 0x7FFF
  write_ok           Write Variable accepted
  write_reject       Write to read-only area (Inputs)
  szl_ok             SZL read returned stub data
  szl_unknown_id     SZL ID not in known list
  cpu_control_reject PI service or PLC Stop rejected
  pdu_unknown_func   Unknown S7 function code
  pdu_malformed      S7 PDU too short or magic wrong
  disconnect         Client disconnected cleanly
"""

import argparse
import json
import socket
import struct
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants (mirrors protocols/s7comm/fuzzer.py)
# ---------------------------------------------------------------------------

_COTP_CR = 0xE0
_COTP_CC = 0xD0
_COTP_DT = 0xF0

_ROSCTR_JOB      = 0x01
_ROSCTR_ACK      = 0x02
_ROSCTR_ACK_DATA = 0x03
_ROSCTR_USERDATA = 0x07

_FC_SETUP_COMM = 0xF0
_FC_READ_VAR   = 0x04
_FC_WRITE_VAR  = 0x05
_FC_PI_SERVICE = 0x28
_FC_PLC_STOP   = 0x29

AREA_INPUTS  = 0x81   # read-only
AREA_OUTPUTS = 0x82
AREA_FLAGS   = 0x83
AREA_DB      = 0x84
AREA_LOCAL   = 0x1C

_KNOWN_AREAS = frozenset([AREA_INPUTS, AREA_OUTPUTS, AREA_FLAGS, AREA_DB, AREA_LOCAL])
_READONLY_AREAS = frozenset([AREA_INPUTS])

_KNOWN_SZL_IDS = frozenset([
    0x0011, 0x001C, 0x0111, 0x0112, 0x0113, 0x0114, 0x0115, 0x0222, 0x0424,
])

_NEGOTIATE_PDU_LEN = 480

# Pre-built COTP CC response (mirrors COTP CR structure)
_COTP_CC_PKT = struct.pack('!BBH', 0x03, 0x00, 22) + bytes([
    0x11, _COTP_CC,            # LI=17, CC
    0x00, 0x01,                # DST-REF = mirrors client SRC-REF = 1
    0x00, 0x01,                # SRC-REF = server's own
    0x00,                      # class 0
    0xC0, 0x01, 0x0A,          # TPDU-size = 1024
    0xC1, 0x02, 0x01, 0x00,    # calling TSAP = 0x0100
    0xC2, 0x02, 0x02, 0x00,    # called TSAP = 0x0200
])

# ---------------------------------------------------------------------------
# Sidecar logger
# ---------------------------------------------------------------------------

class SidecarLogger:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._f    = open(path, 'w', encoding='utf-8')
        self._lock = threading.Lock()
        self._counts: dict = {}

    def log(self, action: str, **kwargs):
        self._counts[action] = self._counts.get(action, 0) + 1
        rec = {"ts": datetime.now(timezone.utc).isoformat(), "action": action, **kwargs}
        with self._lock:
            self._f.write(json.dumps(rec) + "\n")
            self._f.flush()

    def summary(self):
        print("[s7comm_responder] summary:")
        for action, count in sorted(self._counts.items()):
            print(f"  {action:<30} {count}")

    def close(self):
        with self._lock:
            self._f.close()

# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _recv_fixed(conn: socket.socket, n: int) -> Optional[bytes]:
    buf = b''
    try:
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return buf if buf else None
            buf += chunk
    except socket.timeout:
        return None
    return buf


def _recv_tpkt(conn: socket.socket) -> Optional[bytes]:
    """Read one complete TPKT-framed PDU."""
    hdr = _recv_fixed(conn, 4)
    if not hdr or len(hdr) < 4:
        return hdr
    total_len = struct.unpack('!H', hdr[2:4])[0]
    if total_len <= 4:
        return hdr
    rest = _recv_fixed(conn, total_len - 4)
    if rest is None:
        return hdr
    return hdr + rest


def _tpkt(payload: bytes) -> bytes:
    return struct.pack('!BBH', 0x03, 0x00, 4 + len(payload)) + payload


def _cotp_dt(payload: bytes) -> bytes:
    return bytes([0x02, _COTP_DT, 0x80]) + payload


def _s7_pkt(s7_payload: bytes) -> bytes:
    return _tpkt(_cotp_dt(s7_payload))


def _s7_resp_header(pdu_ref: int, param_len: int, data_len: int,
                    error_class: int = 0, error_code: int = 0) -> bytes:
    """Build 12-byte S7 Ack_Data response header."""
    return bytes([0x32, _ROSCTR_ACK_DATA, 0x00, 0x00]) + \
           struct.pack('!HHH', pdu_ref, param_len, data_len) + \
           bytes([error_class, error_code])


def _s7_error_resp(pdu_ref: int, error_class: int = 0x81,
                   error_code: int = 0x04) -> bytes:
    """S7 Ack_Data error response (no parameter, no data)."""
    hdr = _s7_resp_header(pdu_ref, 0, 0, error_class, error_code)
    return _s7_pkt(hdr)

# ---------------------------------------------------------------------------
# S7 request handlers
# ---------------------------------------------------------------------------

def _handle_setup_comm(pdu_ref: int, param: bytes, sidecar) -> bytes:
    if len(param) < 8 or param[0] != _FC_SETUP_COMM:
        sidecar.log("setup_comm_bad", pdu_ref=pdu_ref)
        return _s7_error_resp(pdu_ref, error_class=0x81, error_code=0x04)
    # Echo back negotiated params (cap PDU length at our max)
    max_amq_c, max_amq_s, pdu_len = struct.unpack_from('!HHH', param, 2)
    pdu_len = min(pdu_len, _NEGOTIATE_PDU_LEN) if pdu_len else _NEGOTIATE_PDU_LEN
    resp_param = bytes([_FC_SETUP_COMM, 0x00]) + struct.pack('!HHH', max_amq_c, max_amq_s, pdu_len)
    hdr = _s7_resp_header(pdu_ref, len(resp_param), 0)
    sidecar.log("setup_comm_ok", pdu_ref=pdu_ref, pdu_len=pdu_len)
    return _s7_pkt(hdr + resp_param)


def _handle_read_var(pdu_ref: int, param: bytes, sidecar) -> bytes:
    if len(param) < 14:  # FC + num_items + at least 1 item (12B)
        sidecar.log("pdu_malformed", reason="read_param_too_short", pdu_ref=pdu_ref)
        return _s7_error_resp(pdu_ref, 0x81, 0x05)

    num_items = param[1]
    # Parse first item only (simplified)
    item_offset = 2
    if len(param) < item_offset + 12:
        sidecar.log("pdu_malformed", reason="read_item_truncated", pdu_ref=pdu_ref)
        return _s7_error_resp(pdu_ref, 0x81, 0x05)

    item      = param[item_offset:item_offset + 12]
    transport = item[3]
    count     = struct.unpack_from('!H', item, 4)[0]
    db_num    = struct.unpack_from('!H', item, 6)[0]
    area      = item[8]
    address   = struct.unpack_from('!I', bytes([0]) + item[9:12])[0] >> 3  # bit→byte

    if area not in _KNOWN_AREAS:
        sidecar.log("read_bad_area", area=f"0x{area:02X}", pdu_ref=pdu_ref)
        # Return item with error code 0x05 (address out of range)
        resp_param = bytes([_FC_READ_VAR])
        resp_data  = bytes([0x0A, 0x00])  # return_code=0x0A (object not supported)
        hdr = _s7_resp_header(pdu_ref, len(resp_param), len(resp_data))
        return _s7_pkt(hdr + resp_param + resp_data)

    if area == AREA_DB and (db_num == 0 or db_num > 1000):
        sidecar.log("read_bad_db", db=db_num, pdu_ref=pdu_ref)
        resp_param = bytes([_FC_READ_VAR])
        resp_data  = bytes([0x0A, 0x00])
        hdr = _s7_resp_header(pdu_ref, len(resp_param), len(resp_data))
        return _s7_pkt(hdr + resp_param + resp_data)

    if address > 0x7FFF:
        sidecar.log("read_bad_address", address=address, pdu_ref=pdu_ref)
        resp_param = bytes([_FC_READ_VAR])
        resp_data  = bytes([0x05, 0x00])  # 0x05 = address out of range
        hdr = _s7_resp_header(pdu_ref, len(resp_param), len(resp_data))
        return _s7_pkt(hdr + resp_param + resp_data)

    # Return stub data: count words of zeros
    safe_count = min(count, 120)
    data_bytes = b'\x00' * (safe_count * 2)
    data_len_bits = len(data_bytes) * 8
    resp_param = bytes([_FC_READ_VAR])
    resp_data  = bytes([0xFF, 0x04]) + struct.pack('!H', data_len_bits) + data_bytes
    hdr = _s7_resp_header(pdu_ref, len(resp_param), len(resp_data))
    sidecar.log("read_ok", area=f"0x{area:02X}", db=db_num, addr=address,
                count=count, pdu_ref=pdu_ref)
    return _s7_pkt(hdr + resp_param + resp_data)


def _handle_write_var(pdu_ref: int, param: bytes, sidecar) -> bytes:
    if len(param) < 14:
        sidecar.log("pdu_malformed", reason="write_param_too_short", pdu_ref=pdu_ref)
        return _s7_error_resp(pdu_ref, 0x81, 0x05)

    item   = param[2:14]
    area   = item[8]
    db_num = struct.unpack_from('!H', item, 6)[0]

    if area in _READONLY_AREAS:
        sidecar.log("write_reject", area=f"0x{area:02X}", pdu_ref=pdu_ref)
        resp_param = bytes([_FC_WRITE_VAR])
        resp_data  = bytes([0x03])  # return_code = write protected
        hdr = _s7_resp_header(pdu_ref, len(resp_param), len(resp_data))
        return _s7_pkt(hdr + resp_param + resp_data)

    sidecar.log("write_ok", area=f"0x{area:02X}", db=db_num, pdu_ref=pdu_ref)
    resp_param = bytes([_FC_WRITE_VAR])
    resp_data  = bytes([0xFF])  # return_code = success
    hdr = _s7_resp_header(pdu_ref, len(resp_param), len(resp_data))
    return _s7_pkt(hdr + resp_param + resp_data)


def _handle_szl_read(pdu_ref: int, param: bytes, data: bytes, sidecar) -> bytes:
    if len(data) < 8:
        sidecar.log("pdu_malformed", reason="szl_data_too_short", pdu_ref=pdu_ref)
        return _s7_error_resp(pdu_ref, 0x81, 0x05)

    szl_id    = struct.unpack_from('!H', data, 4)[0]
    szl_index = struct.unpack_from('!H', data, 6)[0]

    if szl_id not in _KNOWN_SZL_IDS:
        sidecar.log("szl_unknown_id", szl_id=f"0x{szl_id:04X}", pdu_ref=pdu_ref)
        # UserData error response
        resp_param = bytes([0x00, 0x01, 0x12, 0x04, 0x12, 0x44, 0x01, 0x0A])  # error
        resp_data  = bytes([0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        hdr = _s7_resp_header(pdu_ref, len(resp_param), len(resp_data),
                              error_class=0x82, error_code=0x04)
        return _s7_pkt(hdr + resp_param + resp_data)

    # Return stub SZL data (8 bytes: szl_id + szl_index + length_header + empty entries)
    stub = struct.pack('!HH', szl_id, szl_index) + b'\x00' * 4
    resp_param = bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x00])  # response
    resp_data  = bytes([0xFF, 0x09]) + struct.pack('!H', len(stub)) + stub
    hdr = _s7_resp_header(pdu_ref, len(resp_param), len(resp_data))
    sidecar.log("szl_ok", szl_id=f"0x{szl_id:04X}", szl_index=szl_index, pdu_ref=pdu_ref)
    return _s7_pkt(hdr + resp_param + resp_data)


def _handle_cpu_control(pdu_ref: int, fc: int, sidecar) -> bytes:
    sidecar.log("cpu_control_reject", fc=f"0x{fc:02X}", pdu_ref=pdu_ref)
    return _s7_error_resp(pdu_ref, error_class=0x8A, error_code=0x02)


# ---------------------------------------------------------------------------
# Main client handler (importable for integration tests)
# ---------------------------------------------------------------------------

def handle_client(conn: socket.socket, addr, sidecar, verbose: bool = True) -> None:
    """Handle one TCP client connection: COTP handshake + S7 request loop."""
    peer = f"{addr[0]}:{addr[1]}"
    try:
        # --- Step 1: COTP CR ---
        cr_pkt = _recv_tpkt(conn)
        if not cr_pkt or len(cr_pkt) < 6:
            sidecar.log("cotp_malformed", peer=peer, length=len(cr_pkt) if cr_pkt else 0)
            return

        cotp_ptype = cr_pkt[5]
        if cotp_ptype != _COTP_CR:
            sidecar.log("cotp_bad", peer=peer, got=f"0x{cotp_ptype:02X}")
            return

        conn.sendall(_COTP_CC_PKT)
        sidecar.log("cotp_ok", peer=peer)
        if verbose:
            print(f"[s7comm_responder] {peer}  COTP OK", flush=True)

        # --- Step 2: Request loop ---
        while True:
            pkt = _recv_tpkt(conn)
            if not pkt:
                sidecar.log("disconnect", peer=peer)
                break

            # Minimum: TPKT(4) + COTP-DT(3) + S7-magic(1) + ROSCTR(1) = 9
            # Full S7 Job header needs 17B (TPKT(4)+COTP(3)+S7hdr(10))
            if len(pkt) < 9 or pkt[7] != 0x32:
                sidecar.log("pdu_malformed", peer=peer, length=len(pkt))
                # Don't close — let fuzzer keep sending
                continue

            if len(pkt) < 17:
                sidecar.log("pdu_malformed", peer=peer, length=len(pkt),
                            reason="s7_header_truncated")
                continue

            rosctr    = pkt[8]
            pdu_ref   = struct.unpack_from('!H', pkt, 11)[0]
            param_len = struct.unpack_from('!H', pkt, 13)[0]
            data_len  = struct.unpack_from('!H', pkt, 15)[0]

            # For ROSCTR=0x01 (Job), S7 header is 10B; for 0x03/0x07 responses it's 12B
            s7_body_offset = 7 + 10  # TPKT(4) + COTP-DT(3) = 7; S7 header(10) = 17
            param = pkt[s7_body_offset: s7_body_offset + param_len]
            data  = pkt[s7_body_offset + param_len: s7_body_offset + param_len + data_len]

            if rosctr != _ROSCTR_JOB and rosctr != _ROSCTR_USERDATA:
                # Client sending response-type ROSCTR; echo with error
                sidecar.log("pdu_malformed", peer=peer,
                            rosctr=f"0x{rosctr:02X}", reason="wrong_rosctr")
                conn.sendall(_s7_error_resp(pdu_ref, 0x80, 0x01))
                continue

            if not param:
                sidecar.log("pdu_malformed", peer=peer, reason="empty_param")
                conn.sendall(_s7_error_resp(pdu_ref, 0x80, 0x01))
                continue

            fc = param[0]

            if verbose:
                print(f"[s7comm_responder]   ROSCTR=0x{rosctr:02X}  FC=0x{fc:02X}  "
                      f"pdu_ref={pdu_ref}",
                      flush=True)

            if fc == _FC_SETUP_COMM:
                resp = _handle_setup_comm(pdu_ref, param, sidecar)
            elif fc == _FC_READ_VAR:
                resp = _handle_read_var(pdu_ref, param, sidecar)
            elif fc == _FC_WRITE_VAR:
                resp = _handle_write_var(pdu_ref, param, sidecar)
            elif fc == _FC_PI_SERVICE or fc == _FC_PLC_STOP:
                resp = _handle_cpu_control(pdu_ref, fc, sidecar)
            elif rosctr == _ROSCTR_USERDATA and len(param) >= 8 and param[4] == 0x11:
                resp = _handle_szl_read(pdu_ref, param, data, sidecar)
            else:
                sidecar.log("pdu_unknown_func", fc=f"0x{fc:02X}", peer=peer)
                resp = _s7_error_resp(pdu_ref, 0x81, 0x04)

            try:
                conn.sendall(resp)
            except OSError:
                break

    except (ConnectionResetError, BrokenPipeError, OSError):
        sidecar.log("disconnect", peer=peer, reason="reset")
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# TCP server loop (importable for integration tests)
# ---------------------------------------------------------------------------

def _server_loop(host: str, port: int, sidecar, stop: threading.Event,
                 verbose: bool = True) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(50)
    srv.settimeout(0.5)
    if verbose:
        print(f"[s7comm_responder] Listening TCP {host}:{port}")
    while not stop.is_set():
        try:
            conn, addr = srv.accept()
            conn.settimeout(3.0)
            t = threading.Thread(target=handle_client,
                                 args=(conn, addr, sidecar, verbose), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception:
            continue
    srv.close()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="S7comm software responder")
    parser.add_argument("--host",   default="0.0.0.0")
    parser.add_argument("--port",   type=int, default=10200)
    parser.add_argument("--output", default="output/")
    parser.add_argument("--quiet",  action="store_true")
    args = parser.parse_args()

    ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = f"{args.output}/s7comm-responder-{ts}.jsonl"
    import os; os.makedirs(args.output, exist_ok=True)
    sidecar = SidecarLogger(path)
    stop    = threading.Event()
    try:
        _server_loop(args.host, args.port, sidecar, stop, verbose=not args.quiet)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        sidecar.summary()
        sidecar.close()


if __name__ == "__main__":
    main()
