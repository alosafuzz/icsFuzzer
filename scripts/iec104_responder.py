#!/usr/bin/env python3
"""IEC 60870-5-104 software responder for testing icsFuzzer without hardware.

Writes a sidecar JSONL (one record per APDU processed) so every responder
decision can be correlated against fuzzer crash indicators to distinguish
expected protocol-level behaviour from genuine anomaly candidates.

Session state machine:
  WAIT_STARTDT → DATA_TRANSFER → STOPPED

Response logic:
  STARTDT_ACT  → STARTDT_CON, transition to DATA_TRANSFER
  TESTFR_ACT   → TESTFR_CON (any session state)
  STOPDT_ACT   → STOPDT_CON, transition to STOPPED
  S-frame      → no response (pure acknowledgment)
  I-frame (DATA_TRANSFER):
    TypeID recognised as a command (45-51, 100-103): return exception COT=44 (unknown type — we
    implement no process image) or COT=45 (unknown COT) as appropriate
    Anything else: return exception COT=44 (unknown TypeID)
  I-frame (WAIT_STARTDT): close (frame received before session established)

Sidecar action vocabulary (stable — these are join keys for analysis):
  response_u_startdt_con     STARTDT_CON sent
  response_u_stopdt_con      STOPDT_CON sent
  response_u_testfr_con      TESTFR_CON sent
  response_i_exception       I-frame exception ASDU sent (COT=44 or 45)
  response_s_ignored         S-frame received, no response needed
  close_bad_start_byte       APDU start byte ≠ 0x68
  close_bad_length           length=0,1,2,3 (too short for CF fields)
  close_length_overflow      length > 253 (exceeds APDU max)
  close_truncated            received fewer body bytes than declared
  close_i_before_startdt     I-frame received before STARTDT handshake
  close_invalid_cf1          CF1 does not match any defined frame type
  close_timeout              5 s idle timeout
  close_client_reset         unexpected client close / RST

Usage:
  python3 scripts/iec104_responder.py [--host 127.0.0.1] [--port 2405]

  Then run the fuzzer against it:
  python3 icsfuzzer.py --protocol iec104 --target 127.0.0.1:2405 --yes
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
# Frame type constants (mirrors protocols/iec104/fuzzer.py — keep in sync)
# ---------------------------------------------------------------------------
_CF1_STARTDT_ACT = 0x07
_CF1_STARTDT_CON = 0x0B
_CF1_STOPDT_ACT  = 0x13
_CF1_STOPDT_CON  = 0x23
_CF1_TESTFR_ACT  = 0x43
_CF1_TESTFR_CON  = 0x83

COT_UNKNOWN_TI = 44
COT_UNKNOWN_COT = 45

# Session states
_ST_WAIT    = "WAIT_STARTDT"
_ST_DATA    = "DATA_TRANSFER"
_ST_STOPPED = "STOPPED"

# Sidecar action vocabulary
ACTION_RESP_STARTDT_CON     = "response_u_startdt_con"
ACTION_RESP_STOPDT_CON      = "response_u_stopdt_con"
ACTION_RESP_TESTFR_CON      = "response_u_testfr_con"
ACTION_RESP_I_EXCEPTION     = "response_i_exception"
ACTION_RESP_S_IGNORED       = "response_s_ignored"
ACTION_CLOSE_BAD_START      = "close_bad_start_byte"
ACTION_CLOSE_BAD_LENGTH     = "close_bad_length"
ACTION_CLOSE_LENGTH_OVER    = "close_length_overflow"
ACTION_CLOSE_TRUNCATED      = "close_truncated"
ACTION_CLOSE_I_BEFORE_STTDT = "close_i_before_startdt"
ACTION_CLOSE_INVALID_CF1    = "close_invalid_cf1"
ACTION_CLOSE_TIMEOUT        = "close_timeout"
ACTION_CLOSE_CLIENT_RESET   = "close_client_reset"


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _u_frame(cf1: int) -> bytes:
    return bytes([0x68, 4, cf1, 0x00, 0x00, 0x00])


def _exception_asdu(type_id: int, cot: int, ca: int) -> bytes:
    """Minimal exception ASDU: 1 object, IOA=0, no data."""
    return bytes([type_id, 0x01, cot & 0x3F, 0x00]) + struct.pack("<H", ca) + b"\x00\x00\x00"


def _exception_i_frame(type_id: int, cot: int, ca: int,
                        resp_ssn: int = 0, rsn: int = 0) -> bytes:
    asdu = _exception_asdu(type_id, cot, ca)
    return (bytes([0x68, 4 + len(asdu)])
            + struct.pack("<H", (resp_ssn & 0x7FFF) << 1)
            + struct.pack("<H", (rsn & 0x7FFF) << 1)
            + asdu)


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Sidecar logger
# ---------------------------------------------------------------------------

class SidecarLogger:
    def __init__(self, output_dir: str):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.path = out / f"iec104-responder-{ts}.jsonl"
        self._file  = open(self.path, "w", encoding="utf-8")
        self._lock  = threading.Lock()
        self._counts: collections.Counter = collections.Counter()
        print(f"[responder] sidecar  → {self.path}")

    def log(self, session_id, seq, client, state,
            cf1, type_id, cot, ca,
            action, reason, rx_hex, tx_hex):
        record = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "seq":        seq,
            "client":     f"{client[0]}:{client[1]}",
            "state":      state,
            "cf1":        f"0x{cf1:02X}" if cf1 is not None else None,
            "type_id":    type_id,
            "cot":        cot,
            "ca":         ca,
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
        print(f"\n[responder] sidecar summary — {total} APDUs processed")
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
    state      = _ST_WAIT
    resp_ssn   = 0   # our send sequence number

    if verbose:
        print(f"[responder] + {addr[0]}:{addr[1]}  ({session_id})")
    conn.settimeout(5.0)

    def log(cf1, type_id, cot, ca, action, reason, rx, tx):
        sidecar.log(session_id, seq, addr, state,
                    cf1, type_id, cot, ca,
                    action, reason,
                    rx.hex() if rx else "",
                    tx.hex() if tx else None)

    try:
        while True:
            seq += 1

            # Read start byte + length byte
            hdr2 = _recv_exact(conn, 2)
            if len(hdr2) == 0:
                return  # clean close, no log entry needed
            if len(hdr2) < 2:
                log(None, None, None, None,
                    ACTION_CLOSE_TRUNCATED,
                    "received <2 bytes for APDU header",
                    hdr2, None)
                return

            start_byte, length = hdr2[0], hdr2[1]

            if start_byte != 0x68:
                # Read a few more bytes for rx_hex context
                extra = _recv_exact(conn, min(16, length))
                log(None, None, None, None,
                    ACTION_CLOSE_BAD_START,
                    f"start byte 0x{start_byte:02X} ≠ 0x68",
                    hdr2 + extra, None)
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  bad start byte 0x{start_byte:02X} — closing")
                return

            if length < 4:
                log(None, None, None, None,
                    ACTION_CLOSE_BAD_LENGTH,
                    f"APCI length={length} < 4 (cannot contain CF fields)",
                    hdr2, None)
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  length={length} too short — closing")
                return

            if length > 253:
                log(None, None, None, None,
                    ACTION_CLOSE_LENGTH_OVER,
                    f"APCI length={length} > 253 (max APDU body)",
                    hdr2, None)
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  length={length} overflow — closing")
                return

            body = _recv_exact(conn, length)
            rx   = hdr2 + body

            if len(body) < length:
                log(None, None, None, None,
                    ACTION_CLOSE_TRUNCATED,
                    f"received {len(body)}/{length} body bytes",
                    rx, None)
                return

            cf1  = body[0]
            asdu = body[4:]  # body = CF1 CF2 CF3 CF4 [ASDU...]

            # Determine frame type
            if cf1 & 0x03 == 0x03:  # U-frame
                if cf1 not in (_CF1_STARTDT_ACT, _CF1_STOPDT_ACT,
                                _CF1_TESTFR_ACT, _CF1_STARTDT_CON,
                                _CF1_STOPDT_CON, _CF1_TESTFR_CON):
                    log(cf1, None, None, None,
                        ACTION_CLOSE_INVALID_CF1,
                        f"U-frame CF1=0x{cf1:02X} not a defined U-frame function",
                        rx, None)
                    if verbose:
                        print(f"[responder]   {session_id}/{seq}  invalid U-frame CF1=0x{cf1:02X} — closing")
                    return

                if cf1 == _CF1_STARTDT_ACT:
                    resp = _u_frame(_CF1_STARTDT_CON)
                    conn.sendall(resp)
                    state = _ST_DATA
                    log(cf1, None, None, None,
                        ACTION_RESP_STARTDT_CON,
                        "STARTDT_ACT received — STARTDT_CON sent, state → DATA_TRANSFER",
                        rx, resp)

                elif cf1 == _CF1_STOPDT_ACT:
                    resp = _u_frame(_CF1_STOPDT_CON)
                    conn.sendall(resp)
                    state = _ST_STOPPED
                    log(cf1, None, None, None,
                        ACTION_RESP_STOPDT_CON,
                        "STOPDT_ACT received — STOPDT_CON sent, state → STOPPED",
                        rx, resp)

                elif cf1 == _CF1_TESTFR_ACT:
                    resp = _u_frame(_CF1_TESTFR_CON)
                    conn.sendall(resp)
                    log(cf1, None, None, None,
                        ACTION_RESP_TESTFR_CON,
                        "TESTFR_ACT — TESTFR_CON sent",
                        rx, resp)

                else:
                    # CON-direction U-frame sent by client — close
                    log(cf1, None, None, None,
                        ACTION_CLOSE_INVALID_CF1,
                        f"client sent server-direction U-frame CF1=0x{cf1:02X}",
                        rx, None)
                    return

                if verbose:
                    print(f"[responder]   {session_id}/{seq}  U-frame CF1=0x{cf1:02X}  state={state}")

            elif cf1 & 0x03 == 0x01:  # S-frame
                log(cf1, None, None, None,
                    ACTION_RESP_S_IGNORED,
                    "S-frame received — pure ACK, no response required",
                    rx, None)
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  S-frame (ignored)")

            else:  # I-frame (CF1 bit 0 == 0)
                if state != _ST_DATA:
                    log(cf1, None, None, None,
                        ACTION_CLOSE_I_BEFORE_STTDT,
                        f"I-frame received in state {state} — STARTDT not yet sent",
                        rx, None)
                    if verbose:
                        print(f"[responder]   {session_id}/{seq}  I-frame before STARTDT — closing")
                    return

                # Parse ASDU
                type_id = asdu[0] if len(asdu) >= 1 else None
                cot     = (asdu[2] & 0x3F) if len(asdu) >= 3 else None
                ca      = struct.unpack("<H", asdu[4:6])[0] if len(asdu) >= 6 else None

                # Respond with exception COT=44 (unknown TypeID)
                resp_cot = COT_UNKNOWN_TI if type_id is not None else COT_UNKNOWN_COT
                resp = _exception_i_frame(
                    type_id if type_id is not None else 0,
                    resp_cot,
                    ca if ca is not None else 1,
                    resp_ssn=resp_ssn,
                )
                resp_ssn = (resp_ssn + 1) & 0x7FFF
                conn.sendall(resp)

                log(cf1, type_id, cot, ca,
                    ACTION_RESP_I_EXCEPTION,
                    f"I-frame TypeID={type_id} → exception COT={resp_cot}",
                    rx, resp)
                if verbose:
                    print(f"[responder]   {session_id}/{seq}  I-frame TypeID=0x{type_id:02X if type_id else 0:02X}  COT={cot}  CA={ca} → exception COT={resp_cot}")

    except socket.timeout:
        sidecar.log(session_id, seq, addr, state,
                    None, None, None, None,
                    ACTION_CLOSE_TIMEOUT,
                    "5 s idle timeout", "", None)
    except (ConnectionResetError, BrokenPipeError, OSError):
        sidecar.log(session_id, seq, addr, state,
                    None, None, None, None,
                    ACTION_CLOSE_CLIENT_RESET,
                    "client reset or closed unexpectedly", "", None)
    finally:
        conn.close()
        if verbose:
            print(f"[responder] - {addr[0]}:{addr[1]}  ({session_id})")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="IEC 104 software responder — icsFuzzer calibration target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--port",   type=int, default=2405,
                        help="Bind port (default: 2405; real IEC 104 uses 2404)")
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
