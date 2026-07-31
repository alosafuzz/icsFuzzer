"""EtherNet/IP software responder — port 44819 (offset from standard 44818).

Implements a minimal EtherNet/IP/CIP stack for fuzzer calibration:
  - Register/Unregister Session
  - List Identity, List Services, List Interfaces, NOP
  - Send RR Data: Get_Attribute_All/Single, Forward_Open/Close,
    Large_Forward_Open, Unconnected_Send, Multiple_Service_Packet
  - Returns CIP error responses for unknown services/classes

Run standalone: python3 scripts/ethernetip_responder.py [--port 44819] [--output output/]

Import handle_client for integration tests:
  from scripts.ethernetip_responder import handle_client
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Sidecar logger (same pattern as modbus/iec104/dnp3 responders)
# ---------------------------------------------------------------------------

class SidecarLogger:
    def __init__(self, output_dir: str = "output"):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        ts    = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        fname = Path(output_dir) / f"ethernetip-responder-{ts}.jsonl"
        self._f = open(fname, "a", buffering=1)
        print(f"[responder] sidecar  → {fname}", flush=True)

    def log(self, **fields):
        self._f.write(json.dumps(fields) + "\n")

    def summary(self):
        pass

    def close(self):
        self._f.close()


# ---------------------------------------------------------------------------
# ENIP / CIP constants
# ---------------------------------------------------------------------------

_CMD_NOP              = 0x0001
_CMD_LIST_SERVICES    = 0x0004
_CMD_LIST_IDENTITY    = 0x0063
_CMD_LIST_INTERFACES  = 0x0064
_CMD_REGISTER_SESSION = 0x0065
_CMD_UNREGISTER_SES   = 0x0066
_CMD_SEND_RR_DATA     = 0x006F
_CMD_SEND_UNIT_DATA   = 0x0070

_STATUS_SUCCESS    = 0x0000
_STATUS_UNSUP      = 0x0001
_STATUS_BAD_DATA   = 0x0003
_STATUS_BAD_SESSION= 0x0004
_STATUS_BAD_LEN    = 0x0005

_CPF_NULL_ADDR   = 0x0000
_CPF_CONN_ADDR   = 0x00A1
_CPF_CONN_DATA   = 0x00B1
_CPF_UNCONN_DATA = 0x00B2

_SVC_GET_ATTR_ALL    = 0x01
_SVC_SET_ATTR_ALL    = 0x02
_SVC_GET_ATTR_LIST   = 0x03
_SVC_RESET           = 0x05
_SVC_MULTI_SERVICE   = 0x0A
_SVC_GET_ATTR_SINGLE = 0x0E
_SVC_SET_ATTR_SINGLE = 0x10
_SVC_FWD_CLOSE       = 0x4E
_SVC_UNCONN_SEND     = 0x52
_SVC_FWD_OPEN        = 0x54
_SVC_LARGE_FWD_OPEN  = 0x5E

# Sidecar action labels
ACTION_LIST_IDENTITY   = "response_list_identity"
ACTION_LIST_SERVICES   = "response_list_services"
ACTION_LIST_INTERFACES = "response_list_interfaces"
ACTION_REGISTER        = "response_register_session"
ACTION_UNREGISTER      = "response_unregister_session"
ACTION_NOP             = "response_nop"
ACTION_CIP_SUCCESS     = "response_cip_success"
ACTION_CIP_ERROR       = "response_cip_error"
ACTION_FWD_OPEN_OK     = "response_fwd_open_success"
ACTION_FWD_CLOSE_OK    = "response_fwd_close_success"
ACTION_LFO_OK          = "response_large_fwd_open_success"
ACTION_ENIP_ERROR      = "response_enip_error"
ACTION_CLOSE_SHORT_HDR = "close_short_header"
ACTION_CLOSE_BAD_LEN   = "close_bad_length"
ACTION_CLOSE_TRUNCATED = "close_truncated"
ACTION_CLOSE_TIMEOUT   = "close_timeout"
ACTION_CLOSE_RESET     = "close_client_reset"
ACTION_CLOSE_UNREGISTER= "close_unregister_session"


# ---------------------------------------------------------------------------
# Wire builders
# ---------------------------------------------------------------------------

def _enip_packet(cmd: int, data: bytes, session: int = 0, status: int = 0,
                 context: bytes = b'\x00' * 8) -> bytes:
    hdr = struct.pack('<HHII8sI', cmd, len(data), session, status, context, 0)
    return hdr + data


def _enip_error(cmd: int, status: int, context: bytes) -> bytes:
    return _enip_packet(cmd, b'', session=0, status=status, context=context)


def _cpf_items(*items) -> bytes:
    out = struct.pack('<H', len(items))
    for type_id, item_data in items:
        out += struct.pack('<HH', type_id, len(item_data)) + item_data
    return out


def _send_rr_response(cpf: bytes, session: int, context: bytes) -> bytes:
    data = struct.pack('<IH', 0, 0) + cpf
    return _enip_packet(_CMD_SEND_RR_DATA, data, session=session, context=context)


def _cip_response(service: int, gen_status: int = 0, data: bytes = b'') -> bytes:
    return bytes([service | 0x80, 0x00, gen_status, 0x00]) + data


def _cip_in_cpf(cip: bytes) -> bytes:
    return _cpf_items(
        (_CPF_NULL_ADDR, b''),
        (_CPF_UNCONN_DATA, cip),
    )


# ---------------------------------------------------------------------------
# Identity Object attributes (fabricated)
# ---------------------------------------------------------------------------

_VENDOR_ID    = struct.pack('<H', 0x0001)   # Rockwell Automation (fake)
_DEVICE_TYPE  = struct.pack('<H', 0x000C)   # Communications Adapter
_PRODUCT_CODE = struct.pack('<H', 0x0065)
_REVISION     = bytes([1, 3])               # major=1, minor=3
_STATUS_WORD  = struct.pack('<H', 0x0030)
_SERIAL_NUM   = struct.pack('<I', 0xDEADC0DE)
_PRODUCT_NAME = b'\x0Dicsfuzzer-sw'         # length-prefixed short string

_IDENTITY_ATTRS = {
    1: _VENDOR_ID,
    2: _DEVICE_TYPE,
    3: _PRODUCT_CODE,
    4: _REVISION,
    5: _STATUS_WORD,
    6: _SERIAL_NUM,
    7: _PRODUCT_NAME,
}
_IDENTITY_ALL = (_VENDOR_ID + _DEVICE_TYPE + _PRODUCT_CODE + _REVISION
                 + _STATUS_WORD + _SERIAL_NUM + _PRODUCT_NAME)


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

_session_counter_lock = threading.Lock()
_session_counter      = 0


def _next_session_handle() -> int:
    """Thread-safe monotonically increasing session handle."""
    global _session_counter
    with _session_counter_lock:
        _session_counter += 1
        return 0x45455000 + _session_counter


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Connection state
# ---------------------------------------------------------------------------

class _ConnectionState:
    def __init__(self, session_handle: int):
        self.session_handle = session_handle
        self.connections: dict = {}   # conn_serial → (ot_cid, to_cid)


# ---------------------------------------------------------------------------
# CIP handler
# ---------------------------------------------------------------------------

def _handle_cip(cip: bytes, state: _ConnectionState) -> bytes:
    """Parse a CIP request and return a CIP response."""
    if len(cip) < 2:
        return _cip_response(0x00, 0x13)  # not enough data

    service  = cip[0] & 0x7F
    path_sz  = cip[1]           # in WORDs
    path_len = path_sz * 2
    path_end = 2 + path_len
    if len(cip) < path_end:
        return _cip_response(service, 0x04)  # path segment error

    path = cip[2:path_end]
    data = cip[path_end:]

    # Parse class and instance from path
    cls  = 0
    inst = 1
    attr = None
    i = 0
    while i + 2 <= len(path):
        seg = path[i]
        if (seg & 0xE0) == 0x20:    # logical class
            cls  = path[i + 1] if i + 1 < len(path) else 0
        elif (seg & 0xE0) == 0x20 and (seg & 0x1F) == 0x04:
            attr = path[i + 1] if i + 1 < len(path) else 0
        elif (seg & 0xE0) == 0x20:
            pass
        elif seg == 0x24:            # instance
            inst = path[i + 1] if i + 1 < len(path) else 1
        elif seg == 0x30:            # attribute
            attr = path[i + 1] if i + 1 < len(path) else 0
        i += 2

    # --- Service dispatch ---

    if service == _SVC_GET_ATTR_ALL:
        if cls == 0x01:   # Identity
            return _cip_response(service, 0x00, _IDENTITY_ALL)
        elif cls in (0x02, 0x06):
            return _cip_response(service, 0x00, b'\x00' * 4)
        else:
            return _cip_response(service, 0x08)  # service not supported for this class

    elif service == _SVC_GET_ATTR_SINGLE:
        if cls == 0x01 and attr is not None and attr in _IDENTITY_ATTRS:
            return _cip_response(service, 0x00, _IDENTITY_ATTRS[attr])
        elif cls == 0x01 and attr is not None:
            return _cip_response(service, 0x14)  # attribute not supported
        else:
            return _cip_response(service, 0x08)

    elif service in (_SVC_SET_ATTR_ALL, _SVC_SET_ATTR_SINGLE):
        return _cip_response(service, 0x0E)  # attribute not settable (read-only)

    elif service == _SVC_RESET:
        if cls == 0x01:
            return _cip_response(service, 0x00, b'')
        return _cip_response(service, 0x08)

    elif service == _SVC_FWD_OPEN:
        return _handle_forward_open(data, state, service)

    elif service == _SVC_LARGE_FWD_OPEN:
        return _handle_large_forward_open(data, state, service)

    elif service == _SVC_FWD_CLOSE:
        return _handle_forward_close(data, state, service)

    elif service == _SVC_MULTI_SERVICE:
        return _handle_multi_service(data, service, state)

    elif service == _SVC_UNCONN_SEND:
        return _handle_unconnected_send(data, state, service)

    elif service == _SVC_GET_ATTR_LIST:
        return _cip_response(service, 0x00, b'\x00' * 4)

    else:
        return _cip_response(service, 0x08)  # service not supported


def _handle_forward_open(data: bytes, state: _ConnectionState,
                          service: int) -> bytes:
    if len(data) < 30:
        return _cip_response(service, 0x13)  # not enough data
    try:
        conn_serial = struct.unpack_from('<H', data, 8)[0]
        vendor_id   = struct.unpack_from('<H', data, 10)[0]
        orig_serial = struct.unpack_from('<I', data, 12)[0]
        ot_cid      = struct.unpack_from('<I', data, 0)[0]

        to_cid = 0x4545BEEF   # assigned T→O CID
        state.connections[conn_serial] = (ot_cid, to_cid)

        resp_data = (
            struct.pack('<I', ot_cid)          # O→T actual CID
            + struct.pack('<I', to_cid)        # T→O actual CID
            + struct.pack('<HHI', conn_serial, vendor_id, orig_serial)
            + struct.pack('<II', 10000, 10000) # O→T, T→O actual RPI
            + bytes([0x00, 0x00])              # app reply size, reserved
        )
        return _cip_response(service, 0x00, resp_data)
    except Exception:
        return _cip_response(service, 0x01)  # connection failure


def _handle_large_forward_open(data: bytes, state: _ConnectionState,
                                 service: int) -> bytes:
    if len(data) < 34:
        return _cip_response(service, 0x13)
    try:
        conn_serial = struct.unpack_from('<H', data, 8)[0]
        vendor_id   = struct.unpack_from('<H', data, 10)[0]
        orig_serial = struct.unpack_from('<I', data, 12)[0]
        ot_cid      = struct.unpack_from('<I', data, 0)[0]

        to_cid = 0x4C464F00   # Large Forward Open assigned CID
        state.connections[conn_serial] = (ot_cid, to_cid)

        resp_data = (
            struct.pack('<I', ot_cid)
            + struct.pack('<I', to_cid)
            + struct.pack('<HHI', conn_serial, vendor_id, orig_serial)
            + struct.pack('<II', 10000, 10000)
            + bytes([0x00, 0x00])
        )
        return _cip_response(service, 0x00, resp_data)
    except Exception:
        return _cip_response(service, 0x01)


def _handle_forward_close(data: bytes, state: _ConnectionState,
                           service: int) -> bytes:
    if len(data) < 10:
        return _cip_response(service, 0x13)
    try:
        conn_serial = struct.unpack_from('<H', data, 2)[0]
        vendor_id   = struct.unpack_from('<H', data, 4)[0]
        orig_serial = struct.unpack_from('<I', data, 6)[0]

        if conn_serial in state.connections:
            del state.connections[conn_serial]
            resp = struct.pack('<HHI', conn_serial, vendor_id, orig_serial) + bytes([0x00, 0x00])
            return _cip_response(service, 0x00, resp)
        else:
            # Unknown connection serial — return error
            return _cip_response(service, 0x08)
    except Exception:
        return _cip_response(service, 0x01)


def _handle_multi_service(data: bytes, service: int,
                           state: _ConnectionState) -> bytes:
    """Parse Multiple_Service_Packet, dispatch each, return combined response."""
    if len(data) < 2:
        return _cip_response(service, 0x13)
    try:
        n = struct.unpack_from('<H', data, 0)[0]
        if n == 0 or n > 20 or len(data) < 2 + n * 2:
            return _cip_response(service, 0x13)

        results_cip = []
        for i in range(n):
            offset = struct.unpack_from('<H', data, 2 + i * 2)[0]
            end    = struct.unpack_from('<H', data, 2 + (i + 1) * 2)[0] if i + 1 < n else len(data)
            sub_cip = data[offset:end]
            results_cip.append(_handle_cip(sub_cip, state))

        # Build response: count + offsets + data
        offsets = []
        combined = b''
        base_off = 2 + n * 2
        for r in results_cip:
            offsets.append(base_off + len(combined))
            combined += r
        off_bytes = struct.pack('<H', n)
        for o in offsets:
            off_bytes += struct.pack('<H', o)

        return _cip_response(service, 0x00, off_bytes + combined)
    except Exception:
        return _cip_response(service, 0xFF)


def _handle_unconnected_send(data: bytes, state: _ConnectionState,
                              service: int) -> bytes:
    """Route nested CIP request inside Unconnected_Send."""
    if len(data) < 4:
        return _cip_response(service, 0x13)
    try:
        msg_size = struct.unpack_from('<H', data, 2)[0]
        nested   = data[4:4 + msg_size]
        return _handle_cip(nested, state)
    except Exception:
        return _cip_response(service, 0x1E)   # embedded service error


# ---------------------------------------------------------------------------
# List Identity response body
# ---------------------------------------------------------------------------

def _list_identity_response() -> bytes:
    """Build a List Identity item list (type=0x000C, one identity item)."""
    item_data = (
        struct.pack('<H', 1)           # protocol version
        + struct.pack('<HH', 0xAF12, 44818)   # socket addr family, port
        + bytes([127, 0, 0, 1])        # IP address (127.0.0.1)
        + bytes([0] * 8)               # padding
        + _VENDOR_ID + _DEVICE_TYPE + _PRODUCT_CODE
        + _REVISION + _STATUS_WORD + _SERIAL_NUM + _PRODUCT_NAME
        + bytes([0x00])                # state
    )
    item = struct.pack('<HH', 0x000C, len(item_data)) + item_data
    return struct.pack('<H', 1) + item   # item count=1


def _list_services_response() -> bytes:
    """Build a List Services response."""
    name = b'Communications\x00\x00'  # 16 bytes padded
    svc  = struct.pack('<HH', 1, 0x0014) + name   # version=1, capabilities=TCP|UDP(0x14)
    item = struct.pack('<HH', 0x0100, len(svc)) + svc  # type=0x0100 (CIP identity service)
    return struct.pack('<H', 1) + item


# ---------------------------------------------------------------------------
# Main handle_client
# ---------------------------------------------------------------------------

def handle_client(conn: socket.socket, addr, sidecar, verbose: bool = True) -> None:
    """Handle one EtherNet/IP TCP client connection."""
    state: Optional[_ConnectionState] = None
    frame_seq = 0

    def log(action: str, **kw):
        sidecar.log(session=getattr(state, 'session_handle', 0),
                    seq=frame_seq, action=action, **kw)

    try:
        conn.settimeout(10.0)
        while True:
            frame_seq += 1

            # Read 24-byte ENIP header
            hdr = _recv_exact(conn, 24)
            if len(hdr) == 0:
                return  # clean close
            if len(hdr) < 24:
                log(ACTION_CLOSE_SHORT_HDR, rx_hex=hdr.hex())
                if verbose:
                    print(f"[responder]   short header ({len(hdr)} bytes) — closing", flush=True)
                return

            cmd     = struct.unpack_from('<H', hdr, 0)[0]
            length  = struct.unpack_from('<H', hdr, 2)[0]
            sess_rx = struct.unpack_from('<I', hdr, 4)[0]
            context = hdr[12:20]

            if verbose:
                print(f"[responder]   frame {frame_seq}  cmd=0x{cmd:04X}  len={length}",
                      flush=True)

            # Validate length
            if length > 65535:
                log(ACTION_CLOSE_BAD_LEN, cmd=cmd, length=length)
                return

            # Read body
            body = _recv_exact(conn, length)
            if len(body) < length:
                log(ACTION_CLOSE_TRUNCATED, cmd=cmd, expected=length, got=len(body))
                if verbose:
                    print(f"[responder]   truncated body — closing", flush=True)
                return

            rx_hex = (hdr + body).hex()

            # --- Command dispatch ---

            if cmd == _CMD_NOP:
                # NOP: echo back
                resp = _enip_packet(_CMD_NOP, b'', context=context)
                conn.sendall(resp)
                log(ACTION_NOP, rx_hex=rx_hex, tx_hex=resp.hex())
                continue

            if cmd == _CMD_LIST_IDENTITY:
                resp = _enip_packet(_CMD_LIST_IDENTITY, _list_identity_response(),
                                    context=context)
                conn.sendall(resp)
                log(ACTION_LIST_IDENTITY, rx_hex=rx_hex, tx_hex=resp.hex())
                continue

            if cmd == _CMD_LIST_SERVICES:
                resp = _enip_packet(_CMD_LIST_SERVICES, _list_services_response(),
                                    context=context)
                conn.sendall(resp)
                log(ACTION_LIST_SERVICES, rx_hex=rx_hex, tx_hex=resp.hex())
                continue

            if cmd == _CMD_LIST_INTERFACES:
                # Empty list
                resp = _enip_packet(_CMD_LIST_INTERFACES, struct.pack('<H', 0),
                                    context=context)
                conn.sendall(resp)
                log(ACTION_LIST_INTERFACES, rx_hex=rx_hex, tx_hex=resp.hex())
                continue

            if cmd == _CMD_REGISTER_SESSION:
                # Accept any Register Session (ignore protocol version)
                sess = _next_session_handle()
                state = _ConnectionState(sess)
                resp_data = struct.pack('<HH', 1, 0)   # version=1, options=0
                resp = _enip_packet(_CMD_REGISTER_SESSION, resp_data,
                                    session=sess, context=context)
                conn.sendall(resp)
                log(ACTION_REGISTER, rx_hex=rx_hex, tx_hex=resp.hex(),
                    session_handle=sess)
                if verbose:
                    print(f"[responder]   → Register Session  handle=0x{sess:08X}", flush=True)
                continue

            if cmd == _CMD_UNREGISTER_SES:
                log(ACTION_UNREGISTER, rx_hex=rx_hex)
                if verbose:
                    print(f"[responder]   → Unregister Session — closing", flush=True)
                return

            if cmd == _CMD_SEND_RR_DATA:
                # Validate session (require valid session)
                if state is None or sess_rx != state.session_handle:
                    resp = _enip_error(cmd, _STATUS_BAD_SESSION, context)
                    conn.sendall(resp)
                    log(ACTION_ENIP_ERROR, status=_STATUS_BAD_SESSION, rx_hex=rx_hex)
                    continue

                if len(body) < 6:
                    resp = _enip_error(cmd, _STATUS_BAD_DATA, context)
                    conn.sendall(resp)
                    log(ACTION_ENIP_ERROR, status=_STATUS_BAD_DATA)
                    continue

                # Parse CPF: skip InterfaceHandle(4) + Timeout(2)
                cpf     = body[6:]
                cip_req = None
                cpf_ok  = False

                if len(cpf) >= 2:
                    item_count = struct.unpack_from('<H', cpf, 0)[0]
                    offset = 2
                    for _ in range(item_count):
                        if offset + 4 > len(cpf):
                            break
                        itype  = struct.unpack_from('<H', cpf, offset)[0]
                        ilen   = struct.unpack_from('<H', cpf, offset + 2)[0]
                        idata  = cpf[offset + 4: offset + 4 + ilen]
                        if itype == _CPF_UNCONN_DATA:
                            cip_req = idata
                            cpf_ok  = True
                        offset += 4 + ilen

                if cip_req is None:
                    # No CIP payload — return error CPF with empty unconnected data
                    cpf_resp = _cpf_items(
                        (_CPF_NULL_ADDR, b''),
                        (_CPF_UNCONN_DATA, _cip_response(0x00, 0x13)),
                    )
                    resp = _send_rr_response(cpf_resp, state.session_handle, context)
                    conn.sendall(resp)
                    log(ACTION_CIP_ERROR, status=0x13, rx_hex=rx_hex)
                    continue

                cip_resp = _handle_cip(cip_req, state)
                gen_status = cip_resp[2] if len(cip_resp) >= 3 else 0xFF
                cpf_resp = _cpf_items(
                    (_CPF_NULL_ADDR, b''),
                    (_CPF_UNCONN_DATA, cip_resp),
                )
                resp = _send_rr_response(cpf_resp, state.session_handle, context)
                conn.sendall(resp)
                action = ACTION_CIP_SUCCESS if gen_status == 0 else ACTION_CIP_ERROR
                log(action, svc=cip_req[0] if cip_req else 0,
                    gen_status=gen_status, rx_hex=rx_hex, tx_hex=resp.hex())
                continue

            if cmd == _CMD_SEND_UNIT_DATA:
                # Connected messaging — not fully implemented, return error
                resp = _enip_error(cmd, _STATUS_BAD_SESSION, context)
                conn.sendall(resp)
                log(ACTION_ENIP_ERROR, status=_STATUS_BAD_SESSION, rx_hex=rx_hex)
                continue

            # Unknown command
            resp = _enip_error(cmd, _STATUS_UNSUP, context)
            conn.sendall(resp)
            log(ACTION_ENIP_ERROR, status=_STATUS_UNSUP, cmd=cmd, rx_hex=rx_hex)
            if verbose:
                print(f"[responder]   unknown cmd 0x{cmd:04X} → ENIP error", flush=True)

    except socket.timeout:
        log(ACTION_CLOSE_TIMEOUT)
    except (ConnectionResetError, BrokenPipeError, OSError):
        log(ACTION_CLOSE_RESET)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Server entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="EtherNet/IP software responder")
    parser.add_argument("--port",   type=int, default=44819)
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--output", default="output")
    parser.add_argument("--verbose", action="store_true", default=True)
    args = parser.parse_args()

    sidecar = SidecarLogger(args.output)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(32)
    print(f"[responder] listening on {args.host}:{args.port}  (Ctrl-C to stop)",
          flush=True)

    conn_counter = [0]

    try:
        while True:
            conn, addr = srv.accept()
            conn_counter[0] += 1
            cid = conn_counter[0]
            print(f"[responder] + {addr[0]}:{addr[1]}  (C{cid:04d})", flush=True)

            def _serve(c=conn, a=addr, n=cid):
                handle_client(c, a, sidecar, verbose=args.verbose)
                print(f"[responder] - {a[0]}:{a[1]}  (C{n:04d})", flush=True)

            threading.Thread(target=_serve, daemon=True).start()
    except KeyboardInterrupt:
        print("\n[responder] shutting down", flush=True)
    finally:
        sidecar.close()
        srv.close()


if __name__ == "__main__":
    main()
