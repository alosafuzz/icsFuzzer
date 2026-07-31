#!/usr/bin/env python3
"""OMRON FINS software responder for icsFuzzer calibration.

UDP server on port 9610 (9600 + 10).
Implements the FINS command/response protocol for common commands.

Sidecar action vocabulary:
  read_ok            Memory area read successful
  read_bad_area      Unknown or unsupported memory area code
  read_bad_address   Address out of valid range for area
  read_bad_count     Item count too large or zero
  write_ok           Memory area write successful
  write_bad_area     Unknown area for write
  write_reject       Write to read-only area (Timer PV, Counter PV, CIO bit)
  fill_ok            Memory fill successful
  fill_bad_area      Fill to unknown area
  run_reject         CPU Run rejected (safety)
  stop_reject        CPU Stop rejected (safety)
  reset_reject       CPU Reset rejected (safety)
  clock_ok           Clock read responded
  status_ok          Controller status returned
  ctrl_data_ok       Controller data returned
  cmd_unknown        Unknown MRC/SRC pair
  cmd_malformed      Packet too short to parse header
"""

import argparse
import json
import socket
import struct
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants (mirrors protocols/fins/fuzzer.py)
# ---------------------------------------------------------------------------

_ICF_COMMAND  = 0x80
_ICF_RESPONSE = 0xC0

_MRC_MEMORY_READ  = 0x01; _SRC_MEMORY_READ  = 0x01
_MRC_MEMORY_WRITE = 0x01; _SRC_MEMORY_WRITE = 0x02
_MRC_MEMORY_FILL  = 0x01; _SRC_MEMORY_FILL  = 0x03
_MRC_CPU_RUN      = 0x04; _SRC_CPU_RUN      = 0x01
_MRC_CPU_STOP     = 0x04; _SRC_CPU_STOP     = 0x02
_MRC_CPU_RESET    = 0x04; _SRC_CPU_RESET    = 0x03
_MRC_CLOCK_READ   = 0x07; _SRC_CLOCK_READ   = 0x01
_MRC_CTRL_DATA    = 0x05; _SRC_CTRL_DATA    = 0x01
_MRC_CTRL_STATUS  = 0x06; _SRC_CTRL_STATUS  = 0x01

AREA_CIO_WORD    = 0x82
AREA_CIO_BIT     = 0x80
AREA_DM_WORD     = 0x02
AREA_DM_BIT      = 0x30
AREA_EM0_WORD    = 0x0A
AREA_HR_WORD     = 0x52
AREA_TIMER_PV    = 0xB0
AREA_COUNTER_PV  = 0xB1

_READABLE_AREAS = frozenset([
    AREA_CIO_WORD, AREA_CIO_BIT, AREA_DM_WORD, AREA_DM_BIT,
    AREA_EM0_WORD, AREA_HR_WORD, AREA_TIMER_PV, AREA_COUNTER_PV,
])
_WRITABLE_AREAS = frozenset([
    AREA_CIO_WORD, AREA_DM_WORD, AREA_EM0_WORD, AREA_HR_WORD,
    AREA_DM_BIT,
])

_END_CODE_OK             = b'\x00\x00'
_END_CODE_NOT_SUPPORTED  = b'\x04\x01'
_END_CODE_AREA_MISSING   = b'\x01\x02'
_END_CODE_ADDR_RANGE     = b'\x02\x01'
_END_CODE_WRITE_PROTECT  = b'\x04\x02'
_END_CODE_UNIT_ERROR     = b'\x04\x04'

_MAX_READ_WORDS = 500   # cap stub data


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
        print("[fins_responder] summary:")
        for action, count in sorted(self._counts.items()):
            print(f"  {action:<30} {count}")

    def close(self):
        with self._lock:
            self._f.close()


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _fins_resp_header(request: bytes) -> bytes:
    """Build 12-byte response header from request: swap DA/SA, set ICF=0xC0."""
    if len(request) < 12:
        return b'\xC0\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    # Swap routing: response DA ← request SA, SA ← request DA
    return bytes([
        _ICF_RESPONSE,   # [0] ICF response
        0x00,            # [1] RSV
        request[2],      # [2] GCT (carry through)
        request[6],      # [3] DNA ← SNA
        request[7],      # [4] DA1 ← SA1
        request[8],      # [5] DA2 ← SA2
        request[3],      # [6] SNA ← DNA
        request[4],      # [7] SA1 ← DA1
        request[5],      # [8] SA2 ← DA2
        request[9],      # [9] SID (echoed)
        request[10],     # [10] MRC (echoed)
        request[11],     # [11] SRC (echoed)
    ])


def _build_response(request: bytes, end_code: bytes, data: bytes = b'') -> bytes:
    hdr = _fins_resp_header(request)
    return hdr + end_code + data


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _handle_memory_read(request: bytes, sidecar) -> bytes:
    # Data: [area 1B] [address 2B BE] [bit 1B] [count 2B BE]
    if len(request) < 18:  # 12 header + 6 data
        sidecar.log("cmd_malformed", reason="read_too_short", length=len(request))
        return _build_response(request, _END_CODE_NOT_SUPPORTED)

    area    = request[12]
    address = struct.unpack_from('!H', request, 13)[0]
    bit     = request[15]
    count   = struct.unpack_from('!H', request, 16)[0]

    if area not in _READABLE_AREAS:
        sidecar.log("read_bad_area", area=f"0x{area:02X}")
        return _build_response(request, _END_CODE_AREA_MISSING)

    if address > 0x7FFF:
        sidecar.log("read_bad_address", area=f"0x{area:02X}", address=address)
        return _build_response(request, _END_CODE_ADDR_RANGE)

    if count == 0:
        sidecar.log("read_bad_count", count=0)
        return _build_response(request, _END_CODE_NOT_SUPPORTED)

    safe_count = min(count, _MAX_READ_WORDS)
    stub = b'\x00\x00' * safe_count
    sidecar.log("read_ok", area=f"0x{area:02X}", address=address, count=count)
    return _build_response(request, _END_CODE_OK, stub)


def _handle_memory_write(request: bytes, sidecar) -> bytes:
    # Data: [area 1B] [address 2B BE] [bit 1B] [count 2B BE] [data...]
    if len(request) < 18:
        sidecar.log("cmd_malformed", reason="write_too_short", length=len(request))
        return _build_response(request, _END_CODE_NOT_SUPPORTED)

    area    = request[12]
    address = struct.unpack_from('!H', request, 13)[0]
    count   = struct.unpack_from('!H', request, 16)[0]
    wdata   = request[18:]

    if area not in _WRITABLE_AREAS:
        if area in _READABLE_AREAS:
            sidecar.log("write_reject", area=f"0x{area:02X}")
            return _build_response(request, _END_CODE_WRITE_PROTECT)
        sidecar.log("write_bad_area", area=f"0x{area:02X}")
        return _build_response(request, _END_CODE_AREA_MISSING)

    sidecar.log("write_ok", area=f"0x{area:02X}", address=address,
                count=count, data_len=len(wdata))
    return _build_response(request, _END_CODE_OK)


def _handle_memory_fill(request: bytes, sidecar) -> bytes:
    if len(request) < 19:
        sidecar.log("cmd_malformed", reason="fill_too_short", length=len(request))
        return _build_response(request, _END_CODE_NOT_SUPPORTED)

    area  = request[12]
    count = struct.unpack_from('!H', request, 16)[0]

    if area not in _WRITABLE_AREAS:
        sidecar.log("fill_bad_area", area=f"0x{area:02X}")
        return _build_response(request, _END_CODE_AREA_MISSING)

    sidecar.log("fill_ok", area=f"0x{area:02X}", count=count)
    return _build_response(request, _END_CODE_OK)


def _handle_cpu_run(request: bytes, sidecar) -> bytes:
    sidecar.log("run_reject")
    return _build_response(request, _END_CODE_NOT_SUPPORTED)


def _handle_cpu_stop(request: bytes, sidecar) -> bytes:
    sidecar.log("stop_reject")
    return _build_response(request, _END_CODE_NOT_SUPPORTED)


def _handle_cpu_reset(request: bytes, sidecar) -> bytes:
    sidecar.log("reset_reject")
    return _build_response(request, _END_CODE_NOT_SUPPORTED)


def _handle_clock_read(request: bytes, sidecar) -> bytes:
    # Stub clock: 2000-01-01 00:00:00, day=6 (Saturday)
    clock_data = bytes([0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x06])
    sidecar.log("clock_ok")
    return _build_response(request, _END_CODE_OK, clock_data)


def _handle_status(request: bytes, sidecar) -> bytes:
    # Status: [operating_mode 1B] [operating_status 1B]
    # mode=0x80=RUN, status=0x00=normal
    status_data = bytes([0x80, 0x00])
    sidecar.log("status_ok")
    return _build_response(request, _END_CODE_OK, status_data)


def _handle_ctrl_data(request: bytes, sidecar) -> bytes:
    # Stub controller data (model name etc.)
    ctrl_data = b'STUB_CPU_UNIT\x00\x00\x00\x00\x00\x00'
    sidecar.log("ctrl_data_ok")
    return _build_response(request, _END_CODE_OK, ctrl_data)


# ---------------------------------------------------------------------------
# Main responder loop (importable for integration tests)
# ---------------------------------------------------------------------------

def _responder_loop(host: str, port: int, sidecar, stop: threading.Event,
                    verbose: bool = True) -> None:
    """UDP receive-dispatch loop. Runs in its own thread."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    if verbose:
        print(f"[fins_responder] Listening UDP {host}:{port}")

    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except Exception:
            continue

        if len(data) < 12:
            sidecar.log("cmd_malformed", reason="too_short",
                        length=len(data), peer=f"{addr[0]}:{addr[1]}")
            continue

        mrc = data[10]
        src = data[11]

        if verbose:
            print(f"[fins_responder]   {addr[0]}:{addr[1]}  "
                  f"MRC=0x{mrc:02X}  SRC=0x{src:02X}",
                  flush=True)

        try:
            if   mrc == _MRC_MEMORY_READ  and src == _SRC_MEMORY_READ:
                resp = _handle_memory_read(data, sidecar)
            elif mrc == _MRC_MEMORY_WRITE and src == _SRC_MEMORY_WRITE:
                resp = _handle_memory_write(data, sidecar)
            elif mrc == _MRC_MEMORY_FILL  and src == _SRC_MEMORY_FILL:
                resp = _handle_memory_fill(data, sidecar)
            elif mrc == _MRC_CPU_RUN      and src == _SRC_CPU_RUN:
                resp = _handle_cpu_run(data, sidecar)
            elif mrc == _MRC_CPU_STOP     and src == _SRC_CPU_STOP:
                resp = _handle_cpu_stop(data, sidecar)
            elif mrc == _MRC_CPU_RESET    and src == _SRC_CPU_RESET:
                resp = _handle_cpu_reset(data, sidecar)
            elif mrc == _MRC_CLOCK_READ   and src == _SRC_CLOCK_READ:
                resp = _handle_clock_read(data, sidecar)
            elif mrc == _MRC_CTRL_STATUS  and src == _SRC_CTRL_STATUS:
                resp = _handle_status(data, sidecar)
            elif mrc == _MRC_CTRL_DATA    and src == _SRC_CTRL_DATA:
                resp = _handle_ctrl_data(data, sidecar)
            else:
                sidecar.log("cmd_unknown", mrc=f"0x{mrc:02X}", src=f"0x{src:02X}",
                            peer=f"{addr[0]}:{addr[1]}")
                resp = _build_response(data, _END_CODE_NOT_SUPPORTED)

            sock.sendto(resp, addr)

        except Exception as e:
            sidecar.log("cmd_malformed", reason=str(e),
                        mrc=f"0x{mrc:02X}", src=f"0x{src:02X}")

    sock.close()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="FINS software responder")
    parser.add_argument("--host",   default="0.0.0.0")
    parser.add_argument("--port",   type=int, default=9610)
    parser.add_argument("--output", default="output/")
    parser.add_argument("--quiet",  action="store_true")
    args = parser.parse_args()

    import os
    os.makedirs(args.output, exist_ok=True)
    ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = f"{args.output}/fins-responder-{ts}.jsonl"
    sidecar = SidecarLogger(path)
    stop    = threading.Event()
    try:
        _responder_loop(args.host, args.port, sidecar, stop, verbose=not args.quiet)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        sidecar.summary()
        sidecar.close()


if __name__ == "__main__":
    main()
