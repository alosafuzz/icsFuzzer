#!/usr/bin/env python3
"""PROFINET PNIO-CM software responder for icsFuzzer calibration.

UDP server on port 34965 (34964 + 1 to avoid privileged port).
Implements DCE/RPC Bind/BindACK + stub PNIO-CM operation handlers.

Sidecar action vocabulary:
  bind_ok              Bind with correct PNIO-CM UUID → BindACK (context accepted)
  bind_bad_uuid        Bind with wrong interface UUID → BindACK (context rejected)
  bind_malformed       Bind PDU < 72 bytes or truncated → dropped
  connect_ok           Connect Op parsed → ConnectResponse sent
  connect_bad_ar       Connect with unknown AR type → RPC Fault
  connect_malformed    Connect payload missing/truncated → RPC Fault
  read_ok              Record Read index recognised → stub ReadResponse
  read_bad_index       Record Read unknown index → RPC Fault (0x0B)
  write_ok             Record Write accepted → WriteResponse
  write_reject         Record Write to read-only index → RPC Fault
  release_ok           Release → empty Reply
  control_ok           Control → empty Reply
  rpc_unknown_op       Unknown op_num → RPC Fault
  rpc_malformed        Request PDU too short → dropped
  pdu_unknown          Unknown PTYPE → dropped
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
# Constants (mirrors protocols/profinet/fuzzer.py)
# ---------------------------------------------------------------------------

_PTYPE_REQUEST  = 0x0B
_PTYPE_RESPONSE = 0x0C
_PTYPE_BIND     = 0x0F
_PTYPE_BIND_ACK = 0x10
_PTYPE_FAULT    = 0x13
_PFC_FLAGS      = 0x03

_PNIO_CM_UUID = bytes([
    0xD0, 0x01, 0xC4, 0xDE, 0x1B, 0xA9, 0xD0, 0x11,
    0x96, 0xE1, 0x00, 0xA0, 0x24, 0x51, 0x7A, 0x00,
])
_NDR_UUID = bytes([
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
])

_OP_CONNECT = 0x0000
_OP_RELEASE = 0x0001
_OP_READ    = 0x0002
_OP_WRITE   = 0x0003
_OP_CONTROL = 0x0004

# Record indices treated as read-only
_READ_ONLY_INDICES = frozenset([0xF000])

# Record indices we pretend to know about
_KNOWN_READ_INDICES = frozenset([
    0xF000, 0xF001, 0xF002, 0xF003, 0xF004, 0xF020, 0xF040,
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
        rec = {"ts": datetime.now(timezone.utc).isoformat(),
               "action": action, **kwargs}
        with self._lock:
            self._f.write(json.dumps(rec) + "\n")
            self._f.flush()

    def summary(self):
        print("\n--- PROFINET responder summary ---")
        for action, count in sorted(self._counts.items()):
            print(f"  {action:30s} {count}")

    def close(self):
        self._f.close()


# ---------------------------------------------------------------------------
# DCE/RPC frame builders
# ---------------------------------------------------------------------------

def _rpc_header(ptype: int, call_id: int, frag_len: int) -> bytes:
    h  = bytes([0x04, 0x00, ptype & 0xFF, _PFC_FLAGS])
    h += bytes([0x10, 0x00, 0x00, 0x00])
    h += struct.pack('<HHI', frag_len & 0xFFFF, 0, call_id & 0xFFFFFFFF)
    return h


def _bind_ack(call_id: int, context_result: int = 0) -> bytes:
    """Build BindACK PDU. context_result=0 = accept, 2 = reject."""
    body  = struct.pack('<HH', 5840, 5840)    # max_xmit_frag, max_recv_frag
    body += struct.pack('<I', 0)               # assoc_group_id
    # secondary address (port hint string): empty
    body += struct.pack('<H', 0)               # sec_addr length=0
    body += bytes([0, 0])                      # alignment
    # p_results[0]
    body += struct.pack('<H', 1)               # num_results
    body += struct.pack('<H', context_result)  # 0=accept, 2=provider_rejection
    body += struct.pack('<H', 0)               # reason
    if context_result == 0:
        body += _NDR_UUID                      # accepted transfer syntax
        body += struct.pack('<HH', 2, 0)       # version
    else:
        body += bytes(20)                      # zeros for rejected context
    return _rpc_header(_PTYPE_BIND_ACK, call_id, 16 + len(body)) + body


def _rpc_fault(call_id: int, status: int = 0x00000006) -> bytes:
    """Build RPC Fault PDU (PTYPE=0x13)."""
    body = struct.pack('<HHHHI', 0, 0, 0, 0, status)
    return _rpc_header(_PTYPE_FAULT, call_id, 16 + len(body)) + body


def _rpc_reply(call_id: int, ctx_id: int, payload: bytes) -> bytes:
    """Build RPC Response PDU (PTYPE=0x0C)."""
    body  = struct.pack('<I', len(payload))  # alloc_hint
    body += struct.pack('<HH', ctx_id, 0)   # p_cont_def_result, cancel_count
    body += payload
    return _rpc_header(_PTYPE_RESPONSE, call_id, 16 + len(body)) + body


# ---------------------------------------------------------------------------
# PNIO-CM stub response builders
# ---------------------------------------------------------------------------

def _stub_connect_response(call_id: int) -> bytes:
    """Return minimal PNIO Connect positive response."""
    # Just an empty reply — real Connect response has blocks
    return _rpc_reply(call_id, 0, b'\x00' * 4)


def _stub_read_response(call_id: int, index: int) -> bytes:
    """Return minimal RecordRead response with dummy data."""
    data = bytes(16)    # stub 16-byte record
    payload = struct.pack('!HH', 0x0025, len(data) + 4)  # BlockType=RecordReadRes
    payload += bytes([0x01, 0x00])                         # version
    payload += data
    return _rpc_reply(call_id, 0, payload)


def _stub_write_response(call_id: int) -> bytes:
    """Return minimal RecordWrite positive response."""
    return _rpc_reply(call_id, 0, b'\x00\x00\x00\x00')


# ---------------------------------------------------------------------------
# Per-datagram handler (stateless)
# ---------------------------------------------------------------------------

def handle_datagram(data: bytes, addr: tuple,
                    sidecar: SidecarLogger,
                    verbose: bool = True) -> Optional[bytes]:
    """Process one incoming UDP datagram.

    Returns the response bytes to send, or None to drop.
    """
    peer = f"{addr[0]}:{addr[1]}"

    if len(data) < 16:
        sidecar.log("rpc_malformed", peer=peer, length=len(data))
        return None

    ptype   = data[2]
    call_id = struct.unpack_from('<I', data, 12)[0]

    # --- Bind ---
    if ptype == _PTYPE_BIND:
        if len(data) < 72:
            sidecar.log("bind_malformed", peer=peer, length=len(data))
            return None
        # Interface UUID is at offset 32 in the bind body (offset 16+16=32)
        if_uuid = data[32:48]
        if if_uuid == _PNIO_CM_UUID:
            sidecar.log("bind_ok", peer=peer, call_id=call_id)
            return _bind_ack(call_id, context_result=0)
        else:
            sidecar.log("bind_bad_uuid",
                        peer=peer, got=if_uuid.hex(), call_id=call_id)
            return _bind_ack(call_id, context_result=2)

    # --- Request ---
    if ptype == _PTYPE_REQUEST:
        if len(data) < 24:
            sidecar.log("rpc_malformed", peer=peer, length=len(data),
                        ptype=hex(ptype))
            return _rpc_fault(call_id)

        ctx_id  = struct.unpack_from('<H', data, 20)[0]
        op_num  = struct.unpack_from('<H', data, 22)[0]
        payload = data[24:]

        if op_num == _OP_CONNECT:
            # Minimal AR block check: needs at least 6 bytes (BlockType 2B + BlockLength 2B + Version 2B)
            if len(payload) < 6:
                sidecar.log("connect_malformed", peer=peer,
                            payload_len=len(payload))
                return _rpc_fault(call_id)
            ar_type = struct.unpack_from('!H', payload, 6)[0] if len(payload) >= 8 else 0xFFFF
            if ar_type not in (0x0001, 0x0002, 0x0004, 0x0006):
                sidecar.log("connect_bad_ar", peer=peer,
                            ar_type=f"0x{ar_type:04X}")
                return _rpc_fault(call_id, 0x0000001C)  # nca_s_fault_invalid_tag
            sidecar.log("connect_ok", peer=peer, ar_type=f"0x{ar_type:04X}")
            return _stub_connect_response(call_id)

        elif op_num == _OP_RELEASE:
            sidecar.log("release_ok", peer=peer)
            return _rpc_reply(call_id, ctx_id, b'')

        elif op_num == _OP_READ:
            # RecordRead block layout (big-endian):
            #   0: BlockType(2) + BlockLength(2) + Version(2) + SeqNum(2) = 8B
            #   8: ARUUID(16B) = 24B
            #  24: API(4B) + Slot(2B) + Subslot(2B) + Pad(2B) + Index(2B) = 34B
            if len(payload) < 36:
                sidecar.log("rpc_malformed", peer=peer,
                            reason="record_read_too_short")
                return _rpc_fault(call_id)
            index = struct.unpack_from('!H', payload, 34)[0]
            if index in _KNOWN_READ_INDICES:
                sidecar.log("read_ok", peer=peer, index=f"0x{index:04X}")
                return _stub_read_response(call_id, index)
            else:
                sidecar.log("read_bad_index", peer=peer,
                            index=f"0x{index:04X}")
                return _rpc_fault(call_id, 0x0000000B)  # nca_s_fault_ill_inst

        elif op_num == _OP_WRITE:
            # RecordWrite block layout matches RecordRead: Index is at offset 34
            if len(payload) < 36:
                sidecar.log("rpc_malformed", peer=peer,
                            reason="record_write_too_short")
                return _rpc_fault(call_id)
            index = struct.unpack_from('!H', payload, 34)[0]
            if index in _READ_ONLY_INDICES:
                sidecar.log("write_reject", peer=peer,
                            index=f"0x{index:04X}")
                return _rpc_fault(call_id, 0x0000000B)
            sidecar.log("write_ok", peer=peer, index=f"0x{index:04X}")
            return _stub_write_response(call_id)

        elif op_num == _OP_CONTROL:
            sidecar.log("control_ok", peer=peer)
            return _rpc_reply(call_id, ctx_id, b'')

        else:
            sidecar.log("rpc_unknown_op", peer=peer,
                        op=f"0x{op_num:04X}")
            return _rpc_fault(call_id)

    # Unknown PTYPE
    sidecar.log("pdu_unknown", peer=peer, ptype=f"0x{ptype:02X}")
    return None


# ---------------------------------------------------------------------------
# Main UDP loop (importable for tests)
# ---------------------------------------------------------------------------

def _responder_loop(host: str, port: int,
                    sidecar: SidecarLogger,
                    stop: threading.Event,
                    verbose: bool = True) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    if verbose:
        print(f"[profinet_responder] Listening UDP {host}:{port}")
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception as exc:
            if verbose:
                print(f"[profinet_responder] recvfrom error: {exc}")
            break
        resp = handle_datagram(data, addr, sidecar, verbose)
        if resp is not None:
            try:
                sock.sendto(resp, addr)
            except Exception:
                pass
    sock.close()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="PROFINET PNIO-CM software responder for icsFuzzer")
    parser.add_argument("--host",   default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port",   type=int, default=34965,
                        help="UDP port (default: 34965)")
    parser.add_argument("--output", default="output/profinet-sidecar",
                        help="Sidecar JSONL output directory")
    parser.add_argument("--quiet",  action="store_true")
    args = parser.parse_args()

    sidecar_path = f"{args.output}/sidecar.jsonl"
    sidecar = SidecarLogger(sidecar_path)
    stop    = threading.Event()

    try:
        _responder_loop(args.host, args.port, sidecar, stop,
                        verbose=not args.quiet)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        sidecar.summary()
        sidecar.close()


if __name__ == "__main__":
    main()
