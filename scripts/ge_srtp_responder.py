#!/usr/bin/env python3
"""GE SRTP software responder for icsFuzzer calibration.

TCP server on port 18246 (18245 + 1 to avoid root).
Simulates a GE Series 90-30 PLC with limited read-only capability.

Sidecar action vocabulary:
  handshake_ok      INIT received; INIT_ACK sent
  handshake_bad     INIT malformed; connection closed
  status_ok         PLC_SHORT_STATUS returned
  get_info_ok       GET_INFO returned
  get_time_ok       GET_TIME returned
  get_fault_ok      GET_FAULT returned (empty)
  read_ok           READ_SYS_MEM/TASK_MEM/PROG_MEM returned data
  read_error        READ with unsupported seg or out-of-range index
  write_reject      WRITE service rejected (read-only responder)
  run_reject        SET_PLC_RUN rejected
  svc_unknown       Unknown service code; SHORT_ERR returned
  bad_pkt_type      Not REQ (0x0002); connection closed
  malformed         Packet < 56 bytes; connection closed
  disconnect        Client disconnected
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PKT_INIT      = 0x0000
_PKT_INIT_ACK  = 0x0001
_PKT_REQ       = 0x0002
_PKT_REQ_ACK   = 0x0003

_MSG_SHORT     = 0xC0
_MSG_SHORT_ACK = 0xD4
_MSG_SHORT_ERR = 0xD1

SVC_STATUS         = 0x00
SVC_GET_PROGNAME   = 0x03
SVC_READ_SYS_MEM   = 0x04
SVC_READ_TASK_MEM  = 0x05
SVC_READ_PROG_MEM  = 0x06
SVC_WRITE_SYS_MEM  = 0x07
SVC_WRITE_TASK_MEM = 0x08
SVC_WRITE_PROG_MEM = 0x09
SVC_PROG_LOGON     = 0x20
SVC_CHANGE_PRIV    = 0x21
SVC_SET_CPU_ID     = 0x22
SVC_SET_PLC_RUN    = 0x23
SVC_SET_PLC_TIME   = 0x24
SVC_GET_TIME       = 0x25
SVC_GET_FAULT      = 0x38
SVC_CLR_FAULT      = 0x39
SVC_GET_INFO       = 0x43

# Documented memory types we'll pretend to support
_VALID_SEGS = {0x08, 0x0A, 0x0C, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E, 0x38}

# ---------------------------------------------------------------------------
# Sidecar logger
# ---------------------------------------------------------------------------

class SidecarLogger:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._f    = open(path, 'w', encoding='utf-8')
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}

    def log(self, action: str, **kwargs):
        self._counts[action] = self._counts.get(action, 0) + 1
        rec = {"ts": datetime.now(timezone.utc).isoformat(),
               "action": action, **kwargs}
        with self._lock:
            self._f.write(json.dumps(rec) + "\n")
            self._f.flush()

    def summary(self):
        print("[responder] sidecar summary:")
        for action, count in sorted(self._counts.items()):
            print(f"  {action:<30} {count}")

    def close(self):
        with self._lock:
            self._f.close()

# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

_MBOX_SRC_SERVER = 0x000E1000
_MBOX_DST_CLIENT = 0x00010000

def _build_response(msg_type: int, invoke_seq: int, invoke_mbox_src: int,
                    svc_req_code: int, payload: bytes = b'') -> bytes:
    """Build a 56-byte REQ_ACK response header (+ optional trailing payload bytes)."""
    hdr  = struct.pack('<H', _PKT_REQ_ACK)     # 0-1
    hdr += struct.pack('<H', invoke_seq & 0xFFFF)  # 2-3 (mirror client index)
    hdr += struct.pack('<H', len(payload))     # 4-5  payload length
    hdr += b'\x00' * 20                        # 6-25
    hdr += bytes([0x00, 0x00, 0x00])           # 26-28 timestamp
    hdr += bytes([invoke_seq & 0xFF])          # 29 msg_seq
    hdr += bytes([msg_type])                   # 30
    hdr += bytes([0x00])                       # 31
    hdr += struct.pack('<I', _MBOX_SRC_SERVER) # 32-35
    hdr += struct.pack('<I', invoke_mbox_src)  # 36-39
    hdr += bytes([0x01, 0x01])                 # 40-41 pkt_num=1, total=1
    hdr += bytes([svc_req_code])               # 42
    hdr += bytes([0x00])                       # 43
    hdr += b'\x00' * 4                         # 44-47
    hdr += b'\x00' * 6                         # 48-53
    hdr += b'\x00\x00'                         # 54-55
    assert len(hdr) == 56
    return hdr + payload


def _ack(req_index: int, mbox_src: int, svc: int, data: bytes = b'') -> bytes:
    return _build_response(_MSG_SHORT_ACK, req_index, mbox_src, svc, data)


def _err(req_index: int, mbox_src: int, svc: int) -> bytes:
    return _build_response(_MSG_SHORT_ERR, req_index, mbox_src, svc, b'')


def _init_ack() -> bytes:
    """56-byte INIT_ACK."""
    hdr  = struct.pack('<H', _PKT_INIT_ACK)
    hdr += b'\x00' * 54
    return hdr

# ---------------------------------------------------------------------------
# Request handlers
# ---------------------------------------------------------------------------

def _handle_req(data: bytes, sidecar) -> Optional[bytes]:
    """Parse a 56-byte REQ and return the response bytes."""
    if len(data) < 56:
        sidecar.log("malformed", length=len(data))
        return None   # caller will close

    pkt_type = struct.unpack_from('<H', data, 0)[0]
    if pkt_type != _PKT_REQ:
        sidecar.log("bad_pkt_type", got=f"0x{pkt_type:04X}")
        return None   # caller will close

    req_index  = struct.unpack_from('<H', data, 2)[0]
    mbox_src   = struct.unpack_from('<I', data, 32)[0]
    svc        = data[42]
    seg        = data[43]
    target_idx = struct.unpack_from('<H', data, 44)[0]
    count      = struct.unpack_from('<H', data, 46)[0]

    if svc == SVC_STATUS:
        sidecar.log("status_ok")
        # Return 4 status bytes: run_mode=0x01, faults=0x00, ...
        return _ack(req_index, mbox_src, svc, bytes([0x01, 0x00, 0x00, 0x00]))

    if svc == SVC_GET_INFO:
        sidecar.log("get_info_ok")
        info = b'icsfuzzer-sw\x00' + b'\x00' * 20
        return _ack(req_index, mbox_src, svc, info[:32])

    if svc == SVC_GET_TIME:
        sidecar.log("get_time_ok")
        t = datetime.now(timezone.utc)
        time_bytes = bytes([t.hour, t.minute, t.second])
        return _ack(req_index, mbox_src, svc, time_bytes)

    if svc == SVC_GET_FAULT:
        sidecar.log("get_fault_ok")
        return _ack(req_index, mbox_src, svc, b'\x00' * 4)

    if svc == SVC_GET_PROGNAME:
        sidecar.log("read_ok", svc=f"0x{svc:02X}")
        return _ack(req_index, mbox_src, svc, b'ICSFUZZ\x00')

    if svc in (SVC_READ_SYS_MEM, SVC_READ_TASK_MEM, SVC_READ_PROG_MEM):
        if seg not in _VALID_SEGS:
            sidecar.log("read_error", reason="unknown_seg", seg=f"0x{seg:02X}")
            return _err(req_index, mbox_src, svc)
        # Return count * 2 zero bytes (word-sized registers)
        safe_count = min(count, 128)
        sidecar.log("read_ok", svc=f"0x{svc:02X}", seg=f"0x{seg:02X}",
                    idx=target_idx, count=count)
        return _ack(req_index, mbox_src, svc, b'\x00' * (safe_count * 2))

    if svc in (SVC_WRITE_SYS_MEM, SVC_WRITE_TASK_MEM, SVC_WRITE_PROG_MEM):
        sidecar.log("write_reject", svc=f"0x{svc:02X}")
        return _err(req_index, mbox_src, svc)

    if svc == SVC_SET_PLC_RUN:
        sidecar.log("run_reject")
        return _err(req_index, mbox_src, svc)

    if svc in (SVC_PROG_LOGON, SVC_CHANGE_PRIV, SVC_SET_CPU_ID, SVC_SET_PLC_TIME, SVC_CLR_FAULT):
        sidecar.log("write_reject", svc=f"0x{svc:02X}")
        return _err(req_index, mbox_src, svc)

    # Unknown service code
    sidecar.log("svc_unknown", svc=f"0x{svc:02X}")
    return _err(req_index, mbox_src, svc)


# ---------------------------------------------------------------------------
# Client handler (called from test fixture or main loop)
# ---------------------------------------------------------------------------

def handle_client(conn: socket.socket, addr, sidecar, verbose: bool = True):
    """Handle one TCP client connection through its full session lifecycle."""
    try:
        # Step 1: Read INIT (56 bytes)
        init = _recv_fixed(conn, 56)
        if not init or len(init) < 2:
            sidecar.log("disconnect", addr=addr[0], reason="no_init")
            return

        pkt_type = struct.unpack_from('<H', init, 0)[0]
        if pkt_type != _PKT_INIT:
            sidecar.log("handshake_bad", got=f"0x{pkt_type:04X}", addr=addr[0])
            return

        # Respond with INIT_ACK
        conn.sendall(_init_ack())
        sidecar.log("handshake_ok", addr=addr[0])
        if verbose:
            print(f"[responder] {addr[0]}:{addr[1]}  INIT OK")

        # Step 2: Process REQ/REQ_ACK pairs until disconnect
        while True:
            hdr = _recv_fixed(conn, 56)
            if not hdr:
                sidecar.log("disconnect", addr=addr[0])
                break

            if verbose:
                svc = hdr[42] if len(hdr) > 42 else 0xFF
                print(f"[responder]   REQ svc=0x{svc:02X}  idx={struct.unpack_from('<H', hdr, 44)[0] if len(hdr)>=46 else '?'}",
                      flush=True)

            resp = _handle_req(hdr, sidecar)
            if resp is None:
                break   # close connection on malformed/bad_pkt_type
            conn.sendall(resp)

    except (ConnectionResetError, BrokenPipeError, OSError):
        sidecar.log("disconnect", addr=addr[0], reason="reset")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _recv_fixed(conn: socket.socket, n: int) -> Optional[bytes]:
    """Receive exactly n bytes; return None on timeout/EOF."""
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


# ---------------------------------------------------------------------------
# Standalone server entry point
# ---------------------------------------------------------------------------

def _serve(port: int, output_dir: str, verbose: bool):
    ts      = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    sc_path = os.path.join(output_dir, f"ge-srtp-responder-{ts}.jsonl")
    os.makedirs(output_dir, exist_ok=True)
    sidecar = SidecarLogger(sc_path)
    print(f"[responder] sidecar  → {sc_path}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(10)
    srv.settimeout(1.0)
    print(f"[responder] listening on 127.0.0.1:{port}  (Ctrl-C to stop)")

    n_conns = 0
    try:
        while True:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            n_conns += 1
            conn.settimeout(3.0)
            if verbose:
                print(f"[responder] conn #{n_conns} from {addr[0]}:{addr[1]}")
            t = threading.Thread(target=handle_client,
                                 args=(conn, addr, sidecar, verbose), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print(f"\n[responder] {n_conns} connections handled.")
        sidecar.summary()
    finally:
        srv.close()
        sidecar.close()


def main():
    parser = argparse.ArgumentParser(description="GE SRTP software responder")
    parser.add_argument("--port",   type=int, default=18246,
                        help="TCP port to listen on (default: 18246)")
    parser.add_argument("--output", default="output/",
                        help="Sidecar JSONL output directory (default: output/)")
    parser.add_argument("--quiet",  action="store_true")
    args = parser.parse_args()
    _serve(args.port, args.output, verbose=not args.quiet)


if __name__ == "__main__":
    main()
