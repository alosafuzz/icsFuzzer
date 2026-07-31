#!/usr/bin/env python3
"""BACnet/IP software responder for icsFuzzer calibration.

UDP server on port 47809 (47808 + 1 to avoid root).
Writes a sidecar JSONL so every responder decision can be
correlated against fuzzer crash indicators.

Simulated device:
  Device Object:    instance=1234, vendor_id=0x1234, name="icsfuzzer-sw"
  Analog-Input 0:   Present_Value = 42.0
  Analog-Value 0:   Present_Value = 0.0  (writable)
  Binary-Value 0:   Present_Value = false (writable)

Sidecar action vocabulary (stable — join keys for analysis):
  who_is_received     Who-Is received; I-Am sent
  who_has_received    Who-Has received; I-Have sent (or ignored)
  i_am_received       I-Am received (ignored)
  read_ok             ReadProperty returned value
  read_error          ReadProperty returned BACnet-Error
  write_ok            WriteProperty returned Simple-ACK
  write_error         WriteProperty returned BACnet-Error
  subscribe_ok        SubscribeCOV returned Simple-ACK
  subscribe_cancel    SubscribeCOV cancel (lifetime=0)
  cov_notif_received  UnconfirmedCOVNotification received (ignored)
  dcc_error           DeviceCommunicationControl returned Error (auth)
  reinit_error        ReinitializeDevice returned Error (auth)
  register_fd         Register-Foreign-Device: BVLC-Result success
  read_bdt            Read-BDT: BDT-Ack sent
  read_fdt            Read-FDT: FDT-Ack sent
  write_bdt_rejected  Write-BDT: BVLC-Result error
  forwarded_npdu      Forwarded-NPDU received; inner APDU dispatched
  distrib_bcast       Distribute-Broadcast received; inner APDU dispatched
  unknown_service     Confirmed service unknown; Reject sent
  unknown_bvll        Unknown BVLL function; no response
  drop_short          Packet too short to parse; dropped
  drop_bad_type       BVLL type ≠ 0x81; dropped
  drop_len_mismatch   BVLL declared length ≠ actual length; dropped
  drop_bad_npdu       NPDU version ≠ 0x01 or truncated; dropped
  drop_empty_apdu     APDU zero bytes; dropped
  ack_only            PDU type needs no response (abort/reject/ack from fuzzer)
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

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
            print(f"  {action:<35} {count}")

    def close(self):
        with self._lock:
            self._f.close()


# ---------------------------------------------------------------------------
# Simulated device state (module-level, shared across datagrams)
# ---------------------------------------------------------------------------

_DEVICE_INSTANCE = 1234
_DEVICE_NAME     = "icsfuzzer-sw"
_VENDOR_ID       = 0x1234
_VENDOR_NAME     = "icsFuzzer"
_MODEL_NAME      = "SoftwareTestbed"

_objects = {
    (8,  1234): {"present_value": None,  "name": _DEVICE_NAME},
    (0,  0):    {"present_value": 42.0,  "name": "icsfuzzer-ai0"},
    (2,  0):    {"present_value": 0.0,   "name": "icsfuzzer-av0"},
    (5,  0):    {"present_value": False, "name": "icsfuzzer-bv0"},
}
_state_lock = threading.Lock()

# Property ID → Object_Identifier
_PROP_OBJECT_IDENTIFIER = 75
_PROP_OBJECT_NAME       = 77
_PROP_OBJECT_TYPE       = 79
_PROP_PRESENT_VALUE     = 85
_PROP_VENDOR_ID         = 117
_PROP_VENDOR_NAME       = 121
_PROP_MODEL_NAME        = 70
_PROP_SYSTEM_STATUS     = 112
_PROP_MAX_APDU          = 126

# Error class / code constants
_ERR_CLASS_OBJECT    = 1
_ERR_CLASS_PROPERTY  = 2
_ERR_CLASS_SECURITY  = 4
_ERR_CLASS_SERVICES  = 5
_ERR_CODE_UNKNOWN_OBJ  = 31
_ERR_CODE_UNKNOWN_PROP = 32
_ERR_CODE_NO_WRITE     = 23
_ERR_CODE_AUTH_FAIL    = 1

# Service codes
_SVC_SUBSCRIBE_COV   = 0x05
_SVC_READ_PROPERTY   = 0x0C
_SVC_WRITE_PROPERTY  = 0x0F
_SVC_DCC             = 0x11
_SVC_REINITIALIZE    = 0x14
_USVC_I_AM           = 0x00
_USVC_I_HAVE         = 0x01
_USVC_COV_NOTIF      = 0x02
_USVC_WHO_HAS        = 0x06
_USVC_WHO_IS         = 0x08

# BVLL function codes
_BVLL_RESULT       = 0x00
_BVLL_WRITE_BDT    = 0x01
_BVLL_READ_BDT     = 0x02
_BVLL_READ_BDT_ACK = 0x03
_BVLL_FWD_NPDU     = 0x04
_BVLL_REG_FD       = 0x05
_BVLL_READ_FDT     = 0x06
_BVLL_READ_FDT_ACK = 0x07
_BVLL_DEL_FDT      = 0x08
_BVLL_DISTRIB      = 0x09
_BVLL_UNICAST      = 0x0A
_BVLL_BROADCAST    = 0x0B

# ---------------------------------------------------------------------------
# Tag helpers
# ---------------------------------------------------------------------------

def _bvll(func: int, data: bytes) -> bytes:
    return bytes([0x81, func]) + struct.pack('>H', 4 + len(data)) + data


def _npdu_hdr(ctrl: int = 0x00) -> bytes:
    return bytes([0x01, ctrl])


def _app_obj_id(obj_type: int, instance: int) -> bytes:
    return bytes([0xC4]) + struct.pack('>I', (obj_type << 22) | (instance & 0x3FFFFF))


def _app_unsigned(n: int) -> bytes:
    if n <= 0xFF:   return bytes([0x21, n])
    if n <= 0xFFFF: return bytes([0x22]) + struct.pack('>H', n)
    return bytes([0x24]) + struct.pack('>I', n)


def _app_real(f: float) -> bytes:
    return bytes([0x44]) + struct.pack('>f', f)


def _app_bool(b: bool) -> bytes:
    return bytes([0x11, 0x01 if b else 0x00])


def _app_enum(n: int) -> bytes:
    return bytes([0x91, n & 0xFF])


def _app_char_string(s: str) -> bytes:
    enc = s.encode('utf-8')
    return bytes([0x75, 1 + len(enc), 0x00]) + enc


def _ctx_open(ctx: int) -> bytes:
    return bytes([(ctx << 4) | 0x08 | 6])


def _ctx_close(ctx: int) -> bytes:
    return bytes([(ctx << 4) | 0x08 | 7])


def _ctx_tag(ctx: int, data: bytes) -> bytes:
    n = len(data)
    if n > 4:
        return bytes([(ctx << 4) | 0x08 | 5, n]) + data
    return bytes([(ctx << 4) | 0x08 | n]) + data

# ---------------------------------------------------------------------------
# APDU builders
# ---------------------------------------------------------------------------

def _simple_ack(invoke_id: int, service: int) -> bytes:
    apdu = bytes([0x20, invoke_id & 0xFF, service & 0xFF])
    return _bvll(_BVLL_UNICAST, _npdu_hdr() + apdu)


def _complex_ack(invoke_id: int, service: int, data: bytes) -> bytes:
    apdu = bytes([0x30, invoke_id & 0xFF, service & 0xFF]) + data
    return _bvll(_BVLL_UNICAST, _npdu_hdr() + apdu)


def _error_apdu(invoke_id: int, service: int,
                err_class: int, err_code: int) -> bytes:
    apdu = bytes([0x50, invoke_id & 0xFF, service & 0xFF,
                  0x91, err_class & 0xFF, 0x91, err_code & 0xFF])
    return _bvll(_BVLL_UNICAST, _npdu_hdr() + apdu)


def _reject_apdu(invoke_id: int, reason: int) -> bytes:
    apdu = bytes([0x60, invoke_id & 0xFF, reason & 0xFF])
    return _bvll(_BVLL_UNICAST, _npdu_hdr() + apdu)


def _i_am_pkt() -> bytes:
    body  = _app_obj_id(8, _DEVICE_INSTANCE)
    body += _app_unsigned(1476)
    body += _app_enum(3)   # segmentation=none
    body += bytes([0x22]) + struct.pack('>H', _VENDOR_ID)
    apdu  = bytes([0x10, _USVC_I_AM]) + body
    return _bvll(_BVLL_UNICAST, _npdu_hdr() + apdu)


def _bvlc_result(code: int) -> bytes:
    return _bvll(_BVLL_RESULT, struct.pack('>H', code & 0xFFFF))

# ---------------------------------------------------------------------------
# Property value encoder
# ---------------------------------------------------------------------------

def _encode_property(obj_type: int, instance: int, prop_id: int) -> Optional[bytes]:
    """Return application-tagged property value, or None if not found."""
    if obj_type == 8 and instance == _DEVICE_INSTANCE:
        if prop_id == _PROP_OBJECT_IDENTIFIER:
            return _app_obj_id(8, _DEVICE_INSTANCE)
        if prop_id == _PROP_OBJECT_NAME:
            return _app_char_string(_DEVICE_NAME)
        if prop_id == _PROP_OBJECT_TYPE:
            return _app_enum(8)
        if prop_id == _PROP_VENDOR_ID:
            return _app_unsigned(_VENDOR_ID)
        if prop_id == _PROP_VENDOR_NAME:
            return _app_char_string(_VENDOR_NAME)
        if prop_id == _PROP_MODEL_NAME:
            return _app_char_string(_MODEL_NAME)
        if prop_id == _PROP_SYSTEM_STATUS:
            return _app_enum(0)    # operational
        if prop_id == _PROP_MAX_APDU:
            return _app_unsigned(1476)
        return None

    key = (obj_type, instance)
    if key not in _objects:
        return None

    obj = _objects[key]
    if prop_id == _PROP_OBJECT_IDENTIFIER:
        return _app_obj_id(obj_type, instance)
    if prop_id == _PROP_OBJECT_NAME:
        return _app_char_string(obj["name"])
    if prop_id == _PROP_OBJECT_TYPE:
        return _app_enum(obj_type)
    if prop_id == _PROP_PRESENT_VALUE:
        val = obj["present_value"]
        if isinstance(val, bool):
            return _app_enum(1 if val else 0)
        if isinstance(val, float):
            return _app_real(val)
        if isinstance(val, int):
            return _app_unsigned(val)
    return None

# ---------------------------------------------------------------------------
# Request parsers
# ---------------------------------------------------------------------------

def _parse_obj_id(data: bytes, offset: int):
    """Parse context-tag 0 object-identifier (0x0C prefix)."""
    if data[offset] != 0x0C:
        return None, offset
    obj_word = struct.unpack_from('>I', data, offset + 1)[0]
    return ((obj_word >> 22) & 0x3FF, obj_word & 0x3FFFFF), offset + 5


def _parse_prop_id(data: bytes, offset: int):
    """Parse context-tag 1 property-identifier (0x19 or 0x1A or 0x1C)."""
    tag = data[offset]
    if (tag >> 4) != 1 or not (tag & 0x08):
        return None, offset
    plen = tag & 0x07
    if plen == 1:
        return data[offset + 1], offset + 2
    if plen == 2:
        return struct.unpack_from('>H', data, offset + 1)[0], offset + 3
    if plen == 4:
        return struct.unpack_from('>I', data, offset + 1)[0], offset + 5
    return None, offset


def _skip_npdu_bytes(data: bytes, offset: int) -> int:
    ctrl = data[offset + 1]
    pos  = offset + 2
    if ctrl & 0x04:   # DEST specifier (bit 2 per ASHRAE 135 Table 6-1)
        dlen = data[pos + 2]
        pos += 3 + dlen + 1
    if ctrl & 0x02:   # SRC specifier (bit 1 per ASHRAE 135 Table 6-1)
        slen = data[pos + 2]
        pos += 3 + slen
    return pos

# ---------------------------------------------------------------------------
# Service handlers
# ---------------------------------------------------------------------------

def _handle_read_property(apdu_body: bytes, invoke_id: int, sidecar) -> bytes:
    try:
        (obj_type, instance), pos = _parse_obj_id(apdu_body, 0)
        prop_id, _                = _parse_prop_id(apdu_body, pos)
        if prop_id is None:
            sidecar.log("read_error", reason="bad_property_tag")
            return _error_apdu(invoke_id, _SVC_READ_PROPERTY,
                               _ERR_CLASS_PROPERTY, _ERR_CODE_UNKNOWN_PROP)
    except (IndexError, TypeError, struct.error):
        sidecar.log("read_error", reason="parse_failure")
        return _reject_apdu(invoke_id, 0x05)  # missing-required-parameter

    encoded = _encode_property(obj_type, instance, prop_id)
    if encoded is None:
        if (obj_type, instance) not in _objects and not (obj_type == 8 and instance == _DEVICE_INSTANCE):
            sidecar.log("read_error", obj_type=obj_type, instance=instance,
                        reason="unknown_object")
            return _error_apdu(invoke_id, _SVC_READ_PROPERTY,
                               _ERR_CLASS_OBJECT, _ERR_CODE_UNKNOWN_OBJ)
        sidecar.log("read_error", prop_id=prop_id, reason="unknown_property")
        return _error_apdu(invoke_id, _SVC_READ_PROPERTY,
                           _ERR_CLASS_PROPERTY, _ERR_CODE_UNKNOWN_PROP)

    # Complex-ACK body: context[0] obj-id, context[1] prop-id, context[3] value
    ack_body  = bytes([0x0C]) + struct.pack('>I', (obj_type << 22) | instance)
    ack_body += bytes([0x19, prop_id & 0xFF]) if prop_id <= 0xFF else bytes([0x1A]) + struct.pack('>H', prop_id)
    ack_body += bytes([0x3E]) + encoded + bytes([0x3F])
    sidecar.log("read_ok", obj_type=obj_type, instance=instance, prop_id=prop_id)
    return _complex_ack(invoke_id, _SVC_READ_PROPERTY, ack_body)


def _handle_write_property(apdu_body: bytes, invoke_id: int, sidecar) -> bytes:
    try:
        (obj_type, instance), pos = _parse_obj_id(apdu_body, 0)
        prop_id, pos              = _parse_prop_id(apdu_body, pos)
        if prop_id is None:
            sidecar.log("write_error", reason="bad_property_tag")
            return _error_apdu(invoke_id, _SVC_WRITE_PROPERTY,
                               _ERR_CLASS_PROPERTY, _ERR_CODE_UNKNOWN_PROP)
    except (IndexError, TypeError, struct.error):
        sidecar.log("write_error", reason="parse_failure")
        return _reject_apdu(invoke_id, 0x05)

    # Device object properties are read-only
    if obj_type == 8:
        if prop_id != _PROP_PRESENT_VALUE:
            sidecar.log("write_error", prop_id=prop_id, reason="read_only")
            return _error_apdu(invoke_id, _SVC_WRITE_PROPERTY,
                               _ERR_CLASS_PROPERTY, _ERR_CODE_NO_WRITE)

    key = (obj_type, instance)
    if key not in _objects:
        sidecar.log("write_error", obj_type=obj_type, instance=instance,
                    reason="unknown_object")
        return _error_apdu(invoke_id, _SVC_WRITE_PROPERTY,
                           _ERR_CLASS_OBJECT, _ERR_CODE_UNKNOWN_OBJ)

    if prop_id != _PROP_PRESENT_VALUE and prop_id != _PROP_OBJECT_NAME:
        sidecar.log("write_error", prop_id=prop_id, reason="read_only")
        return _error_apdu(invoke_id, _SVC_WRITE_PROPERTY,
                           _ERR_CLASS_PROPERTY, _ERR_CODE_NO_WRITE)

    sidecar.log("write_ok", obj_type=obj_type, instance=instance, prop_id=prop_id)
    return _simple_ack(invoke_id, _SVC_WRITE_PROPERTY)


def _handle_subscribe_cov(apdu_body: bytes, invoke_id: int, sidecar) -> bytes:
    try:
        # Context[0]: proc-id, Context[1]: obj-id
        # Very minimal: just parse enough to log and respond
        if len(apdu_body) < 2:
            return _reject_apdu(invoke_id, 0x05)
        # Check if lifetime present — if context[3] is missing, treat as cancel
        has_lifetime = b'\x3C' in apdu_body or b'\x3D' in apdu_body or (len(apdu_body) > 6)
        if has_lifetime:
            sidecar.log("subscribe_ok")
        else:
            sidecar.log("subscribe_cancel")
        return _simple_ack(invoke_id, _SVC_SUBSCRIBE_COV)
    except Exception:
        return _reject_apdu(invoke_id, 0x05)


def _handle_confirmed(apdu: bytes, sidecar) -> Optional[bytes]:
    if len(apdu) < 4:
        return None
    invoke_id = apdu[2]
    service   = apdu[3]
    body      = apdu[4:]

    if service == _SVC_READ_PROPERTY:
        return _handle_read_property(body, invoke_id, sidecar)
    if service == _SVC_WRITE_PROPERTY:
        return _handle_write_property(body, invoke_id, sidecar)
    if service == _SVC_SUBSCRIBE_COV:
        return _handle_subscribe_cov(body, invoke_id, sidecar)
    if service == _SVC_DCC:
        sidecar.log("dcc_error")
        return _error_apdu(invoke_id, _SVC_DCC, _ERR_CLASS_SECURITY, _ERR_CODE_AUTH_FAIL)
    if service == _SVC_REINITIALIZE:
        sidecar.log("reinit_error")
        return _error_apdu(invoke_id, _SVC_REINITIALIZE,
                           _ERR_CLASS_SECURITY, _ERR_CODE_AUTH_FAIL)

    sidecar.log("unknown_service", service=f"0x{service:02X}")
    return _reject_apdu(invoke_id, 0x09)  # unrecognized-service


def _handle_unconfirmed(apdu: bytes, sidecar) -> Optional[bytes]:
    if len(apdu) < 2:
        return None
    service = apdu[1]

    if service == _USVC_WHO_IS:
        sidecar.log("who_is_received")
        return _i_am_pkt()

    if service == _USVC_WHO_HAS:
        sidecar.log("who_has_received")
        return None   # I-Have not implemented; just log and drop

    if service == _USVC_I_AM:
        sidecar.log("i_am_received")
        return None   # ignore; fuzzer announced itself

    if service == _USVC_COV_NOTIF:
        sidecar.log("cov_notif_received")
        return None   # unconfirmed COV; no response

    sidecar.log("unknown_service", service=f"0x{service:02X}")
    return None

# ---------------------------------------------------------------------------
# Main datagram handler (importable by tests)
# ---------------------------------------------------------------------------

def handle_datagram(data: bytes, addr,
                    sidecar, verbose: bool = True) -> Optional[bytes]:
    """Parse one BACnet/IP UDP datagram and return the response bytes (or None)."""

    if len(data) < 4:
        sidecar.log("drop_short", addr=addr[0], length=len(data))
        return None

    if data[0] != 0x81:
        sidecar.log("drop_bad_type", addr=addr[0], got=f"0x{data[0]:02X}")
        return None

    func     = data[1]
    declared = struct.unpack_from('>H', data, 2)[0]
    if declared != len(data):
        sidecar.log("drop_len_mismatch", addr=addr[0],
                    declared=declared, actual=len(data))
        return None

    if verbose:
        print(f"[responder]   func=0x{func:02X}  len={len(data)}", flush=True)

    # BBMD-only functions (no NPDU/APDU)
    if func == _BVLL_REG_FD:
        sidecar.log("register_fd", addr=addr[0])
        return _bvlc_result(0x0000)

    if func == _BVLL_READ_BDT:
        sidecar.log("read_bdt", addr=addr[0])
        return _bvll(_BVLL_READ_BDT_ACK, b'')   # empty BDT

    if func == _BVLL_READ_FDT:
        sidecar.log("read_fdt", addr=addr[0])
        return _bvll(_BVLL_READ_FDT_ACK, b'')   # empty FDT

    if func == _BVLL_WRITE_BDT:
        sidecar.log("write_bdt_rejected", addr=addr[0])
        return _bvlc_result(0x0010)   # Write-BDT-Failed

    if func == _BVLL_DEL_FDT:
        sidecar.log("delete_fdt", addr=addr[0])
        return _bvlc_result(0x0050)   # Delete-FDT-Entry-Failed

    if func == _BVLL_RESULT:
        # BVLC-Result injected by fuzzer; we just drop it
        sidecar.log("bvlc_result_received", addr=addr[0])
        return None

    # Functions carrying NPDU+APDU
    if func not in (_BVLL_UNICAST, _BVLL_BROADCAST, _BVLL_FWD_NPDU, _BVLL_DISTRIB):
        sidecar.log("unknown_bvll", addr=addr[0], func=f"0x{func:02X}")
        return None

    # Determine NPDU start
    npdu_start = 4
    if func == _BVLL_FWD_NPDU:
        npdu_start = 10   # skip 6-byte originator
        sidecar.log("forwarded_npdu", addr=addr[0])
    elif func == _BVLL_DISTRIB:
        sidecar.log("distrib_bcast", addr=addr[0])

    if len(data) < npdu_start + 2:
        sidecar.log("drop_short", addr=addr[0])
        return None

    if data[npdu_start] != 0x01:
        sidecar.log("drop_bad_npdu", addr=addr[0],
                    npdu_ver=f"0x{data[npdu_start]:02X}")
        return None

    try:
        apdu_start = _skip_npdu_bytes(data, npdu_start)
    except IndexError:
        sidecar.log("drop_bad_npdu", addr=addr[0], reason="truncated")
        return None

    apdu = data[apdu_start:]
    if not apdu:
        sidecar.log("drop_empty_apdu", addr=addr[0])
        return None

    pdu_type = apdu[0] & 0xF0

    if pdu_type == 0x00:   # Confirmed-Request
        return _handle_confirmed(apdu, sidecar)
    if pdu_type == 0x10:   # Unconfirmed-Request
        return _handle_unconfirmed(apdu, sidecar)

    # ACK/Error/Reject/Abort sent by fuzzer — nothing to respond to
    sidecar.log("ack_only", addr=addr[0], pdu_type=f"0x{pdu_type:02X}")
    return None

# ---------------------------------------------------------------------------
# Standalone server entry point
# ---------------------------------------------------------------------------

def _serve(port: int, output_dir: str, verbose: bool):
    ts      = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    sc_path = os.path.join(output_dir, f"bacnet-responder-{ts}.jsonl")
    os.makedirs(output_dir, exist_ok=True)

    sidecar = SidecarLogger(sc_path)
    print(f"[responder] sidecar  → {sc_path}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(1.0)
    print(f"[responder] listening on 127.0.0.1:{port}  (Ctrl-C to stop)")

    n_datagrams = 0
    try:
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            n_datagrams += 1
            if verbose:
                print(f"[responder] dgram #{n_datagrams} from {addr[0]}:{addr[1]}  len={len(data)}")
            resp = handle_datagram(data, addr, sidecar=sidecar, verbose=verbose)
            if resp:
                sock.sendto(resp, addr)
    except KeyboardInterrupt:
        print(f"\n[responder] {n_datagrams} datagrams processed.")
        sidecar.summary()
    finally:
        sock.close()
        sidecar.close()


def main():
    parser = argparse.ArgumentParser(description="BACnet/IP software responder")
    parser.add_argument("--port",    type=int, default=47809,
                        help="UDP port to listen on (default: 47809)")
    parser.add_argument("--output",  default="output/",
                        help="Sidecar JSONL output directory (default: output/)")
    parser.add_argument("--quiet",   action="store_true",
                        help="Suppress per-datagram output")
    args = parser.parse_args()
    _serve(args.port, args.output, verbose=not args.quiet)


if __name__ == "__main__":
    main()
