#!/usr/bin/env python3
"""OPC-UA software responder for icsFuzzer calibration.

TCP server on port 4841 (4840+1, no root needed).
Implements the minimum OPC-UA UA Binary session handshake and a small set of
services to let the fuzzer complete connect() without a real server.

Sidecar action vocabulary:
  hel_ok            HEL received; ACK sent
  hel_bad           Malformed HEL; closed
  opn_ok            OPN received; OPN response sent (channel_id=1, token_id=1)
  session_create    CreateSession (i=461) responded (auth_token ns=0 id=42)
  session_activate  ActivateSession (i=467) responded Good
  read_ok           Read (i=631) responded with Good DataValue
  browse_ok         Browse (i=527) responded with empty BrowseResult
  write_reject      Write (i=673) responded BadNotWritable
  sub_create        CreateSubscription (i=787) responded (sub_id=1)
  svc_unknown       Unknown service; ServiceFault BadServiceUnsupported
  svc_fault         Known service with structurally bad body; ServiceFault
  clo_ok            CLO received; connection closed
  err_ok            ERR received; connection closed
  bad_frame         Unrecognised frame type; ERR sent + closed
  disconnect        Client disconnected normally
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
# Encoding helpers (duplicated from fuzzer.py to avoid imports from protocols/)
# ---------------------------------------------------------------------------

def _ua_string(s) -> bytes:
    if s is None:
        return struct.pack('<i', -1)
    b = s.encode('utf-8') if isinstance(s, str) else bytes(s)
    return struct.pack('<i', len(b)) + b

def _ua_bytestring(b) -> bytes:
    if b is None:
        return struct.pack('<i', -1)
    return struct.pack('<i', len(b)) + bytes(b)

def _ua_nodeid_null() -> bytes:
    return b'\x00\x00'

def _ua_nodeid_fourbyte(ns: int, id_: int) -> bytes:
    return struct.pack('<BBH', 0x01, ns & 0xFF, id_ & 0xFFFF)

def _ua_msg_header(msg_type: bytes, chunk_type: bytes, body_len: int) -> bytes:
    return msg_type[:3] + chunk_type[:1] + struct.pack('<I', 8 + body_len)

_POLICY_NONE = b"http://opcfoundation.org/UA/SecurityPolicy#None"

def _ua_datetime_now() -> bytes:
    import time
    ticks = int(time.time() * 1e7) + 116444736000000000
    return struct.pack('<q', ticks)

def _response_header(req_handle: int = 1, status: int = 0) -> bytes:
    h  = _ua_datetime_now()
    h += struct.pack('<I', req_handle)
    h += struct.pack('<I', status)
    h += struct.pack('<B', 0)       # DiagnosticInfo: no info
    h += struct.pack('<I', 0)       # StringTable: empty
    h += b'\x00\x00\x00'          # AdditionalHeader: null ExtensionObject
    return h

# ---------------------------------------------------------------------------
# Message builders
# ---------------------------------------------------------------------------

def _build_ack() -> bytes:
    body  = struct.pack('<I', 0)      # ProtocolVersion
    body += struct.pack('<I', 65536)  # ReceiveBufferSize
    body += struct.pack('<I', 65536)  # SendBufferSize
    body += struct.pack('<I', 0)      # MaxMessageSize
    body += struct.pack('<I', 0)      # MaxChunkCount
    return _ua_msg_header(b'ACK', b'F', len(body)) + body

def _build_opn_response(req_id: int = 1) -> bytes:
    sec_hdr  = struct.pack('<I', 1)            # SecureChannelId=1
    sec_hdr += _ua_bytestring(_POLICY_NONE)
    sec_hdr += _ua_bytestring(None)
    sec_hdr += _ua_bytestring(None)
    seq_hdr  = struct.pack('<I', 1)
    seq_hdr += struct.pack('<I', req_id)
    body  = _ua_nodeid_fourbyte(0, 449)        # TypeId: OpenSecureChannelResponse
    body += _response_header(req_handle=req_id)
    body += struct.pack('<I', 0)               # ServerProtocolVersion
    # SecurityToken
    body += struct.pack('<I', 1)               # ChannelId
    body += struct.pack('<I', 1)               # TokenId
    body += _ua_datetime_now()                 # CreatedAt
    body += struct.pack('<I', 3600000)         # RevisedLifetime
    body += _ua_bytestring(None)               # ServerNonce
    inner = sec_hdr + seq_hdr + body
    return _ua_msg_header(b'OPN', b'F', len(inner)) + inner

def _build_msg(svc_id: int, svc_body: bytes, req_id: int = 1) -> bytes:
    sym  = struct.pack('<I', 1) + struct.pack('<I', 1)   # channel_id=1, token_id=1
    seq  = struct.pack('<I', 2) + struct.pack('<I', req_id)
    body = _ua_nodeid_fourbyte(0, svc_id) + svc_body
    inner = sym + seq + body
    return _ua_msg_header(b'MSG', b'F', len(inner)) + inner

def _build_create_session_response(req_id: int) -> bytes:
    body  = _response_header(req_handle=req_id)
    body += _ua_nodeid_fourbyte(0, 1)         # SessionId ns=0 id=1
    body += _ua_nodeid_fourbyte(0, 42)        # AuthenticationToken ns=0 id=42
    body += struct.pack('<d', 3600000.0)       # RevisedSessionTimeout
    body += _ua_bytestring(None)               # ServerNonce
    body += _ua_bytestring(None)               # ServerCertificate
    body += struct.pack('<I', 0)               # ServerEndpoints (empty)
    body += struct.pack('<I', 0)               # ServerSoftwareCertificates (empty)
    body += _ua_string(None)                   # ServerSignature.Algorithm
    body += _ua_bytestring(None)               # ServerSignature.Signature
    body += struct.pack('<I', 0)               # MaxRequestMessageSize
    return _build_msg(464, body, req_id)

def _build_activate_session_response(req_id: int) -> bytes:
    body  = _response_header(req_handle=req_id)
    body += _ua_bytestring(None)               # ServerNonce
    body += struct.pack('<I', 0)               # Results (empty)
    body += struct.pack('<I', 0)               # DiagnosticInfos (empty)
    return _build_msg(470, body, req_id)

def _build_read_response(req_id: int) -> bytes:
    # Single DataValue: Good, UInt32 value=0
    dv  = struct.pack('<B', 0x01)              # EncodingMask: value present
    dv += struct.pack('<B', 0x07)              # VariantType: UInt32
    dv += struct.pack('<I', 0)                 # value
    body  = _response_header(req_handle=req_id)
    body += struct.pack('<I', 1)               # Results count
    body += dv
    body += struct.pack('<I', 0)               # DiagnosticInfos (empty)
    return _build_msg(634, body, req_id)

def _build_browse_response(req_id: int) -> bytes:
    # Single BrowseResult: Good, no continuation, no references
    br  = struct.pack('<I', 0)                 # StatusCode=Good
    br += _ua_bytestring(None)                 # ContinuationPoint
    br += struct.pack('<I', 0)                 # References (empty)
    body  = _response_header(req_handle=req_id)
    body += struct.pack('<I', 1)               # Results count
    body += br
    body += struct.pack('<I', 0)               # DiagnosticInfos (empty)
    return _build_msg(530, body, req_id)

def _build_write_response(req_id: int) -> bytes:
    body  = _response_header(req_handle=req_id)
    body += struct.pack('<I', 1)               # Results count
    body += struct.pack('<I', 0x803B0000)      # BadNotWritable
    body += struct.pack('<I', 0)               # DiagnosticInfos (empty)
    return _build_msg(676, body, req_id)

def _build_create_subscription_response(req_id: int) -> bytes:
    body  = _response_header(req_handle=req_id)
    body += struct.pack('<I', 1)               # SubscriptionId=1
    body += struct.pack('<d', 500.0)           # RevisedPublishingInterval
    body += struct.pack('<I', 10)              # RevisedLifetimeCount
    body += struct.pack('<I', 3)               # RevisedMaxKeepAliveCount
    return _build_msg(790, body, req_id)

def _build_service_fault(req_id: int, status: int = 0x80550000) -> bytes:
    # 0x80550000 = BadServiceUnsupported
    body  = _response_header(req_handle=req_id, status=status)
    return _build_msg(397, body, req_id)

def _build_err(status: int = 0x80820000, reason: str = "protocol error") -> bytes:
    body  = struct.pack('<I', status)
    body += _ua_string(reason)
    return _ua_msg_header(b'ERR', b'F', len(body)) + body

# ---------------------------------------------------------------------------
# Frame receiver
# ---------------------------------------------------------------------------

def _recv_msg(conn: socket.socket) -> Optional[bytes]:
    buf = b''
    try:
        while len(buf) < 8:
            chunk = conn.recv(8 - len(buf))
            if not chunk:
                return None
            buf += chunk
        total = struct.unpack_from('<I', buf, 4)[0]
        if total < 8 or total > 1 << 20:   # reject > 1 MB
            return buf
        remaining = total - 8
        while remaining > 0:
            chunk = conn.recv(min(remaining, 4096))
            if not chunk:
                return buf
            buf += chunk
            remaining -= len(chunk)
    except Exception:
        return None
    return buf

# ---------------------------------------------------------------------------
# Service ID extraction
# ---------------------------------------------------------------------------

def _extract_service_id(data: bytes) -> Optional[int]:
    """Extract service NodeId integer from MSG frame, or None."""
    if len(data) < 28:
        return None
    # After 8B msg hdr + 8B sym hdr + 8B seq hdr = offset 24
    enc = data[24]
    try:
        if enc == 0x00:
            return data[25]
        elif enc == 0x01:
            return struct.unpack_from('<H', data, 26)[0]
        elif enc == 0x02:
            return struct.unpack_from('<I', data, 28)[0]
    except Exception:
        pass
    return None

def _extract_req_id(data: bytes) -> int:
    """Extract RequestId from MSG (offset 20) or 1 on failure."""
    if len(data) < 24:
        return 1
    try:
        return struct.unpack_from('<I', data, 20)[0]
    except Exception:
        return 1

# ---------------------------------------------------------------------------
# Client handler
# ---------------------------------------------------------------------------

def handle_client(conn: socket.socket, addr, sidecar, verbose: bool = False):
    def log(action, **kw):
        sidecar.log(action, addr=str(addr), **kw)

    try:
        while True:
            msg = _recv_msg(conn)
            if not msg:
                log("disconnect")
                break

            msg_type = msg[:3] if len(msg) >= 3 else b''

            if msg_type == b'HEL':
                if len(msg) < 28:
                    log("hel_bad")
                    break
                conn.sendall(_build_ack())
                log("hel_ok")

            elif msg_type == b'OPN':
                req_id = _extract_req_id(msg) if len(msg) >= 24 else 1
                conn.sendall(_build_opn_response(req_id))
                log("opn_ok")

            elif msg_type == b'MSG':
                req_id = _extract_req_id(msg)
                svc_id = _extract_service_id(msg)

                if svc_id == 461:    # CreateSession
                    conn.sendall(_build_create_session_response(req_id))
                    log("session_create")
                elif svc_id == 467:  # ActivateSession
                    conn.sendall(_build_activate_session_response(req_id))
                    log("session_activate")
                elif svc_id == 473:  # CloseSession
                    conn.sendall(_build_service_fault(req_id, 0x00000000))
                    log("session_close")
                elif svc_id == 631:  # Read
                    conn.sendall(_build_read_response(req_id))
                    log("read_ok")
                elif svc_id == 527:  # Browse
                    conn.sendall(_build_browse_response(req_id))
                    log("browse_ok")
                elif svc_id == 673:  # Write
                    conn.sendall(_build_write_response(req_id))
                    log("write_reject")
                elif svc_id == 787:  # CreateSubscription
                    conn.sendall(_build_create_subscription_response(req_id))
                    log("sub_create")
                elif svc_id == 426:  # GetEndpoints
                    # Minimal: empty endpoint array
                    body  = _response_header(req_handle=req_id)
                    body += struct.pack('<I', 0)
                    conn.sendall(_build_msg(429, body, req_id))
                    log("svc_unknown", svc_id=svc_id)
                else:
                    conn.sendall(_build_service_fault(req_id))
                    log("svc_unknown", svc_id=svc_id)

            elif msg_type == b'CLO':
                log("clo_ok")
                break

            elif msg_type == b'ERR':
                log("err_ok")
                break

            else:
                conn.sendall(_build_err(0x80820000, "unexpected frame type"))
                log("bad_frame", msg_type=msg_type.hex())
                break

    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

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
        with self._lock:
            self._counts[action] = self._counts.get(action, 0) + 1
            rec = {"ts": datetime.now(timezone.utc).isoformat(),
                   "action": action, **kwargs}
            self._f.write(json.dumps(rec) + '\n')
            self._f.flush()

    def summary(self):
        with self._lock:
            return dict(self._counts)

    def close(self):
        try:
            self._f.close()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="OPC-UA software responder")
    ap.add_argument('--port',    type=int, default=4841)
    ap.add_argument('--host',    default='0.0.0.0')
    ap.add_argument('--sidecar', default='output/opcua_responder_sidecar.jsonl')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    sidecar = SidecarLogger(args.sidecar)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(50)
    print(f"[opcua_responder] listening on {args.host}:{args.port}", flush=True)

    try:
        while True:
            conn, addr = srv.accept()
            conn.settimeout(5.0)
            t = threading.Thread(
                target=handle_client, args=(conn, addr, sidecar, args.verbose),
                daemon=True)
            t.start()
    except KeyboardInterrupt:
        print(f"\n[opcua_responder] summary: {sidecar.summary()}", flush=True)
    finally:
        sidecar.close()
        srv.close()

if __name__ == '__main__':
    main()
