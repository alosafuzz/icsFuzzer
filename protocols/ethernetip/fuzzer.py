"""EtherNet/IP (CIP) fuzzer module — ODVA EtherNet/IP Specification, CIP Vol. 1 & 2.

ENIP Encapsulation (24-byte header, LE) → Common Packet Format (CPF) → CIP

No application-level CRC. Session established via Register Session before CIP traffic.
Session Handle (bytes 4:8) is patched at send time for most categories.
"""

import socket
import struct
import time
from typing import Optional

from core.base_module import (
    ANOMALY_CONNECTION_RESET,
    ANOMALY_EXCEPTION,
    ANOMALY_MALFORMED_RESPONSE,
    ANOMALY_NO_RESPONSE,
    ANOMALY_TIMEOUT,
    ANOMALY_UNEXPECTED_DATA,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
    FuzzModule,
    FuzzResult,
)

# ---------------------------------------------------------------------------
# Protocol-specific category names
# ---------------------------------------------------------------------------
CATEGORY_FWD_OPEN_CLOSE  = "forward_open_close"
CATEGORY_CIP_PATH        = "cip_path_segments"
CATEGORY_UNCONN_SEND     = "unconnected_send"
CATEGORY_LARGE_FWD_OPEN  = "large_forward_open"
CATEGORY_LOGIX_TAG       = "logix_tag"
CATEGORY_PCCC            = "pccc"

# Categories where session handle is NOT patched (testing wrong session / no session)
_SKIP_SESSION_PATCH = {CATEGORY_BINARY_CORRUPTION, CATEGORY_STATE_MACHINE}

# ENIP commands that have no response (fuzzer skips recv wait)
_CMD_NO_RESPONSE = {0x0001}   # NOP

# ---------------------------------------------------------------------------
# ENIP Command codes
# ---------------------------------------------------------------------------
_CMD_NOP              = 0x0001
_CMD_LIST_SERVICES    = 0x0004
_CMD_LIST_IDENTITY    = 0x0063
_CMD_LIST_INTERFACES  = 0x0064
_CMD_REGISTER_SESSION = 0x0065
_CMD_UNREGISTER_SES   = 0x0066
_CMD_SEND_RR_DATA     = 0x006F
_CMD_SEND_UNIT_DATA   = 0x0070

# ENIP Status codes (in response header bytes 8:12)
_ENIP_STATUS_SUCCESS      = 0x0000
_ENIP_STATUS_UNSUPPORTED  = 0x0001
_ENIP_STATUS_NO_MEMORY    = 0x0002
_ENIP_STATUS_BAD_DATA     = 0x0003
_ENIP_STATUS_BAD_SESSION  = 0x0004
_ENIP_STATUS_BAD_LENGTH   = 0x0005
_ENIP_STATUS_BAD_VERSION  = 0x0006
_ENIP_STATUS_BAD_SESSION2 = 0x0065  # some vendors

# CPF item type IDs
_CPF_NULL_ADDR    = 0x0000
_CPF_CONN_ADDR    = 0x00A1
_CPF_CONN_DATA    = 0x00B1
_CPF_UNCONN_DATA  = 0x00B2

# CIP service codes
_SVC_GET_ATTR_ALL    = 0x01
_SVC_SET_ATTR_ALL    = 0x02
_SVC_GET_ATTR_LIST   = 0x03
_SVC_RESET           = 0x05
_SVC_MULTI_SERVICE   = 0x0A
_SVC_GET_ATTR_SINGLE = 0x0E
_SVC_SET_ATTR_SINGLE = 0x10
_SVC_EXEC_PCCC       = 0x4B
_SVC_READ_TAG        = 0x4C
_SVC_WRITE_TAG       = 0x4D
_SVC_FWD_CLOSE       = 0x4E
_SVC_READ_TAG_FRAG   = 0x4E   # same as FWD_CLOSE by ODVA numbering; Logix-specific
_SVC_WRITE_TAG_FRAG  = 0x4F
_SVC_UNCONN_SEND     = 0x52
_SVC_FWD_OPEN        = 0x54
_SVC_LARGE_FWD_OPEN  = 0x5E

# CIP atomic data type codes (Logix)
_CIP_TYPE_BOOL  = 0xC1
_CIP_TYPE_SINT  = 0xC2
_CIP_TYPE_INT   = 0xC3
_CIP_TYPE_DINT  = 0xC4
_CIP_TYPE_REAL  = 0xCA

# CIP General Status codes that map to ANOMALY_EXCEPTION (not crash)
_CIP_EXCEPTION_STATUSES = {
    0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0xFF,
}

# Our fuzzer's originator parameters (fixed for repeatability)
_ORIG_VENDOR_ID   = 0x1337   # vendor ID to use in Forward_Open
_ORIG_SERIAL      = 0xDEADC0DE
_ORIG_OT_CID      = 0xA1B2C3D4   # O→T connection ID we pick


# ---------------------------------------------------------------------------
# ENIP wire builders
# ---------------------------------------------------------------------------

def _enip_packet(cmd: int, data: bytes, session: int = 0, status: int = 0,
                 context: bytes = b'\x00' * 8) -> bytes:
    """Build a complete 24-byte ENIP header + data."""
    hdr = struct.pack('<HHII8sI',
                      cmd,
                      len(data),
                      session,
                      status,
                      context,
                      0)  # options = 0
    return hdr + data


def _register_session_packet() -> bytes:
    data = struct.pack('<HH', 1, 0)   # protocol version=1, options=0
    return _enip_packet(_CMD_REGISTER_SESSION, data, session=0)


def _unregister_session_packet(session: int) -> bytes:
    return _enip_packet(_CMD_UNREGISTER_SES, b'', session=session)


def _list_identity_packet() -> bytes:
    return _enip_packet(_CMD_LIST_IDENTITY, b'')


def _list_services_packet() -> bytes:
    return _enip_packet(_CMD_LIST_SERVICES, b'')


def _nop_packet(data: bytes = b'') -> bytes:
    return _enip_packet(_CMD_NOP, data)


# ---------------------------------------------------------------------------
# CPF builders
# ---------------------------------------------------------------------------

def _cpf_items(*items) -> bytes:
    """Build CPF item list. Each item is (type_id: int, data: bytes)."""
    out = struct.pack('<H', len(items))
    for type_id, item_data in items:
        out += struct.pack('<HH', type_id, len(item_data)) + item_data
    return out


def _send_rr_data(cpf: bytes, session: int, timeout: int = 10) -> bytes:
    data = struct.pack('<IH', 0, timeout) + cpf   # InterfaceHandle=0, Timeout, CPF
    return _enip_packet(_CMD_SEND_RR_DATA, data, session=session)


def _unconnected_msg(cip_bytes: bytes, session: int) -> bytes:
    """Build a Send RR Data frame containing a single unconnected CIP request."""
    cpf = _cpf_items(
        (_CPF_NULL_ADDR, b''),
        (_CPF_UNCONN_DATA, cip_bytes),
    )
    return _send_rr_data(cpf, session)


def _cip_service_from_send_rr(payload: bytes) -> 'int | None':
    """Return the CIP service byte from a SendRRData payload by parsing CPF, or None."""
    if len(payload) < 2:
        return None
    cmd = struct.unpack_from('<H', payload, 0)[0]
    if cmd != _CMD_SEND_RR_DATA:
        return None
    # ENIP header (24) + InterfaceHandle (4) + Timeout (2) + ItemCount (2) = 32
    if len(payload) < 32:
        return None
    offset = 32
    item_count = struct.unpack_from('<H', payload, 30)[0]
    for _ in range(item_count):
        if offset + 4 > len(payload):
            return None
        type_id = struct.unpack_from('<H', payload, offset)[0]
        length  = struct.unpack_from('<H', payload, offset + 2)[0]
        data_start = offset + 4
        if type_id in (_CPF_UNCONN_DATA, _CPF_CONN_DATA):
            if length >= 1 and data_start < len(payload):
                return payload[data_start]
        offset += 4 + length
    return None


# ---------------------------------------------------------------------------
# CIP builders
# ---------------------------------------------------------------------------

def _cip_path(*segments: tuple) -> bytes:
    """Build a CIP logical path from (segment_type, value) tuples.
    Supported segment types: 'class', 'instance', 'attribute', 'connpoint'.
    """
    seg_map = {'class': 0x20, 'instance': 0x24, 'attribute': 0x30, 'connpoint': 0x2C}
    out = b''
    for seg_type, val in segments:
        prefix = seg_map.get(seg_type, seg_type)   # allow raw int too
        out += bytes([prefix, val & 0xFF])
    return out


def _cip_path_raw(*path_bytes: int) -> bytes:
    return bytes(path_bytes)


def _cip_request(service: int, path: bytes, data: bytes = b'') -> bytes:
    """Build a CIP request: service, path_size (in WORDs), path, data."""
    path_words = len(path) // 2
    return bytes([service, path_words]) + path + data


def _get_attr_all(cls: int, instance: int = 1) -> bytes:
    path = _cip_path(('class', cls), ('instance', instance))
    return _cip_request(_SVC_GET_ATTR_ALL, path)


def _get_attr_single(cls: int, instance: int, attr: int) -> bytes:
    path = (_cip_path(('class', cls), ('instance', instance))
            + bytes([0x30, attr]))
    return _cip_request(_SVC_GET_ATTR_SINGLE, path)


def _set_attr_single(cls: int, instance: int, attr: int, data: bytes) -> bytes:
    path = (_cip_path(('class', cls), ('instance', instance))
            + bytes([0x30, attr]))
    return _cip_request(_SVC_SET_ATTR_SINGLE, path, data)


def _forward_open(ot_cid: int = _ORIG_OT_CID, to_cid: int = 0,
                  conn_serial: int = 0x1234, ot_size: int = 128,
                  to_size: int = 128, rpi: int = 10000,
                  transport: int = 0xA3, path: bytes = b'') -> bytes:
    """Build CIP Forward_Open request body."""
    if not path:
        # Default: connection manager (class 6, instance 1)
        path = _cip_path(('class', 0x06), ('instance', 0x01))
    ot_params = 0x8200 | (ot_size & 0x01FF)   # P2P=1, size in bits 0-8
    to_params = 0x8200 | (to_size & 0x01FF)
    body = (
        bytes([0x0A, 0xFF])                            # priority, timeout_ticks
        + struct.pack('<II', ot_cid, to_cid)          # O→T CID, T→O CID
        + struct.pack('<HHI', conn_serial,
                      _ORIG_VENDOR_ID, _ORIG_SERIAL)   # serial, vendor, orig serial
        + bytes([0x00, 0x00, 0x00, 0x00])             # multiplier + 3 reserved
        + struct.pack('<I', rpi)                        # O→T RPI
        + struct.pack('<H', ot_params)                  # O→T params
        + struct.pack('<I', rpi)                        # T→O RPI
        + struct.pack('<H', to_params)                  # T→O params
        + bytes([transport, len(path) // 2])           # transport, path size
        + path                                          # connection path
    )
    return _cip_request(_SVC_FWD_OPEN,
                        _cip_path(('class', 0x06), ('instance', 0x01)),
                        body)


def _large_forward_open(ot_cid: int = _ORIG_OT_CID, to_cid: int = 0,
                        conn_serial: int = 0x5678, ot_size: int = 4000,
                        to_size: int = 4000, rpi: int = 10000,
                        transport: int = 0xA3, path: bytes = b'') -> bytes:
    """Build CIP Large Forward_Open (service 0x5E) — 4-byte net params."""
    if not path:
        path = _cip_path(('class', 0x06), ('instance', 0x01))
    # 4-byte net params: P2P=1 (bit31), size in bits 0-15
    ot_params = 0x82000000 | (ot_size & 0xFFFF)
    to_params = 0x82000000 | (to_size & 0xFFFF)
    body = (
        bytes([0x0A, 0xFF])
        + struct.pack('<II', ot_cid, to_cid)
        + struct.pack('<HHI', conn_serial, _ORIG_VENDOR_ID, _ORIG_SERIAL)
        + bytes([0x00, 0x00, 0x00, 0x00])
        + struct.pack('<I', rpi)
        + struct.pack('<I', ot_params)
        + struct.pack('<I', rpi)
        + struct.pack('<I', to_params)
        + bytes([transport, len(path) // 2])
        + path
    )
    return _cip_request(_SVC_LARGE_FWD_OPEN,
                        _cip_path(('class', 0x06), ('instance', 0x01)),
                        body)


def _forward_close(conn_serial: int = 0x1234, path: bytes = b'') -> bytes:
    """Build CIP Forward_Close request body."""
    if not path:
        path = _cip_path(('class', 0x06), ('instance', 0x01))
    body = (
        bytes([0x0A, 0xFF])
        + struct.pack('<HHI', conn_serial, _ORIG_VENDOR_ID, _ORIG_SERIAL)
        + bytes([0x00, 0x00])   # reserved
        + bytes([len(path) // 2, 0x00])  # path size, reserved
        + path
    )
    return _cip_request(_SVC_FWD_CLOSE,
                        _cip_path(('class', 0x06), ('instance', 0x01)),
                        body)


def _multi_service_packet(*cip_requests: bytes) -> bytes:
    """Build a Multiple Service Packet (service 0x0A) containing multiple CIP requests."""
    n = len(cip_requests)
    offsets = []
    data = b''
    base = 2 + n * 2   # offset list header: count(2) + n offsets(2 each)
    for req in cip_requests:
        offsets.append(base + len(data))
        data += req
    offset_bytes = struct.pack('<H', n)
    for off in offsets:
        offset_bytes += struct.pack('<H', off)
    body = offset_bytes + data
    # Path to Message Router (class 2, instance 1)
    path = _cip_path(('class', 0x02), ('instance', 0x01))
    return _cip_request(_SVC_MULTI_SERVICE, path, body)


def _unconnected_send_cip(nested_cip: bytes, route_path: bytes = b'') -> bytes:
    """Build CIP Unconnected_Send (service 0x52) with nested CIP request."""
    if not route_path:
        # Default route: port 1, link 0
        route_path = bytes([0x01, 0x00])   # port segment
    timeout = bytes([0x0A, 0xFF])   # priority, timeout_ticks
    msg_request_size = struct.pack('<H', len(nested_cip))
    # Pad to word boundary
    pad = b'\x00' if len(nested_cip) % 2 else b''
    route_path_size = bytes([len(route_path) // 2, 0x00])  # path size, reserved
    body = timeout + msg_request_size + nested_cip + pad + route_path_size + route_path
    path = _cip_path(('class', 0x06), ('instance', 0x01))
    return _cip_request(_SVC_UNCONN_SEND, path, body)


def _logix_sym_path(name: bytes) -> bytes:
    """Build CIP symbolic segment for a Logix tag name (extended symbol, type 0x91)."""
    name_len = len(name)
    pad = b'\x00' if name_len % 2 else b''
    return bytes([0x91, name_len]) + name + pad


# ---------------------------------------------------------------------------
# EthernetIpFuzzer
# ---------------------------------------------------------------------------

class EthernetIpFuzzer(FuzzModule):
    """EtherNet/IP / CIP fuzzer — ODVA EtherNet/IP Specification."""

    PROTOCOL_NAME = "ethernetip"
    DEFAULT_PORT = 44818
    FUZZ_CATEGORIES = [
        CATEGORY_BOUNDARY,
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_SEQUENCE,
        CATEGORY_STATE_MACHINE,
        CATEGORY_FWD_OPEN_CLOSE,
        CATEGORY_CIP_PATH,
        CATEGORY_UNCONN_SEND,
        CATEGORY_LARGE_FWD_OPEN,
        CATEGORY_LOGIX_TAG,
        CATEGORY_PCCC,
    ]

    def __init__(self, target: Device, logger, delay: float = 0.0, seeds: list = None):
        super().__init__(target, logger, delay, seeds)
        self._sock: Optional[socket.socket] = None
        self._session: int = 0

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self, target: Device) -> None:
        self.target = target
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(5.0)
        self._sock.connect((target.ip, target.port))
        self._session = 0
        self._register_session()

    def _register_session(self) -> None:
        """Send Register Session; store returned session handle."""
        self._sock.sendall(_register_session_packet())
        resp = self._recv_enip()
        if resp and len(resp) >= 8:
            self._session = struct.unpack_from('<I', resp, 4)[0]

    def _reconnect(self) -> None:
        self.close()
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(5.0)
            self._sock.connect((self.target.ip, self.target.port))
            self._session = 0
            self._register_session()
        except Exception:
            self.close()

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._session = 0

    def discover(self, interface: str, timeout: int = 30) -> list:
        raise NotImplementedError("EtherNet/IP discovery not yet implemented.")

    def fingerprint(self, active: bool = True) -> "FingerprintResult":
        """EtherNet/IP fingerprint.

        Passive: OUI lookup from ARP cache (zero packets).
        Active:  send CIP List Identity (command 0x0063) on an ephemeral TCP
                 connection — mandatory per ODVA spec, returns vendor ID, product
                 name, firmware revision, and serial number.
        """
        from core.fingerprint import FingerprintResult, fingerprint_from_oui, parse_enip_list_identity

        oui_result = fingerprint_from_oui(self.target.ip)
        if not active:
            return oui_result

        # Active: open a short-lived TCP connection and send List Identity
        raw = b""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(3.0)
            s.connect((self.target.ip, self.target.port))
            s.sendall(_list_identity_packet())
            try:
                chunk = s.recv(256)
                if chunk:
                    raw = chunk
            except socket.timeout:
                pass
        except OSError:
            return oui_result
        finally:
            s.close()

        result = parse_enip_list_identity(raw)
        if result is None:
            return oui_result

        # Merge OUI MAC into extra if available
        if oui_result.extra.get("mac"):
            result.extra["mac"] = oui_result.extra["mac"]
        # If OUI vendor matches, bump confidence; if conflict, keep active result
        if oui_result.is_known():
            result.extra["oui_vendor"] = oui_result.vendor
        return result

    def replay_payload(self, payload: bytes) -> Optional[bytes]:
        if self._sock is None:
            raise RuntimeError(
                "Not connected — call connect() before replay_payload()."
            )
        self._sock.sendall(payload)
        return self._recv_enip()

    # ------------------------------------------------------------------
    # Generate cases
    # ------------------------------------------------------------------

    def generate_cases(self, categories: Optional[list] = None) -> list:
        cats = self._resolve_categories(categories)
        self._case_counter = 0
        gen_map = {
            CATEGORY_BOUNDARY:         self._gen_boundary,
            CATEGORY_BINARY_CORRUPTION: self._gen_binary_corruption,
            CATEGORY_SEQUENCE:         self._gen_sequence,
            CATEGORY_STATE_MACHINE:    self._gen_state_machine,
            CATEGORY_FWD_OPEN_CLOSE:   self._gen_forward_open_close,
            CATEGORY_CIP_PATH:         self._gen_cip_path,
            CATEGORY_UNCONN_SEND:      self._gen_unconnected_send,
            CATEGORY_LARGE_FWD_OPEN:   self._gen_large_forward_open,
            CATEGORY_LOGIX_TAG:        self._gen_logix_tag,
            CATEGORY_PCCC:             self._gen_pccc,
        }
        cases = []
        for cat in cats:
            if cat in gen_map:
                cases.extend(gen_map[cat]())
        return cases

    # ------------------------------------------------------------------
    # Fuzz loop
    # ------------------------------------------------------------------

    def fuzz(self, categories: Optional[list] = None) -> list:
        if self._sock is None:
            raise RuntimeError(
                "Not connected — call connect() before fuzz(). "
                "Use generate_cases() to build payloads without a live target."
            )
        cats  = self._resolve_categories(categories)
        cases = self.generate_cases(cats)
        results = []
        total = len(cases)
        for i, (case_id, category, description, payload) in enumerate(cases, 1):
            if i % 50 == 0:
                print(f"[fuzz] {i}/{total}  {case_id}", flush=True)
            results.append(self._send_case(case_id, category, description, payload))
        print(f"\n[fuzz] Completed {total} cases for "
              f"{self.target.ip}:{self.target.port}", flush=True)
        return results

    # ------------------------------------------------------------------
    # Send + classify
    # ------------------------------------------------------------------

    def _send_case(self, case_id: str, category: str,
                   description: str, payload: bytes) -> FuzzResult:
        if self._sock is None:
            raise RuntimeError(
                "Not connected — call connect() before fuzz(). "
                "Use generate_cases() to build payloads without a live target."
            )
        start  = time.monotonic()
        result = FuzzResult(
            case_id=case_id,
            protocol=self.PROTOCOL_NAME,
            target=f"{self.target.ip}:{self.target.port}",
            category=category,
            description=description,
            payload=payload,
        )
        try:
            send_payload = self._prepare_payload(payload, category)
            self._sock.sendall(send_payload)

            # Detect if command expects no response (NOP)
            cmd = struct.unpack_from('<H', send_payload, 0)[0] if len(send_payload) >= 2 else 0
            if cmd in _CMD_NO_RESPONSE:
                result.anomaly = None
                result.crash_indicator = False
            else:
                response = self._recv_enip()
                result.response = response

                if not response:
                    result.anomaly = ANOMALY_NO_RESPONSE
                    result.crash_indicator = True
                    self._reconnect()
                elif len(response) < 24:
                    result.anomaly = ANOMALY_MALFORMED_RESPONSE
                    result.crash_indicator = True
                    self._reconnect()
                else:
                    req_svc = _cip_service_from_send_rr(send_payload)
                    self._classify_response(response, result, req_svc)

        except socket.timeout:
            result.anomaly = ANOMALY_TIMEOUT
            result.crash_indicator = True
            self._reconnect()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
            result.anomaly = ANOMALY_CONNECTION_RESET
            result.crash_indicator = True
            self._reconnect()
        finally:
            result.duration_ms = (time.monotonic() - start) * 1000

        if self.logger:
            self.logger.log(result)
        if self.delay:
            time.sleep(self.delay)
        return result

    def _prepare_payload(self, payload: bytes, category: str) -> bytes:
        """Patch session handle (bytes 4:8) for non-corruption/state-machine categories."""
        if category in _SKIP_SESSION_PATCH:
            return payload
        if len(payload) < 8 or self._session == 0:
            return payload
        # Don't patch Register Session / List commands (session=0 by spec)
        cmd = struct.unpack_from('<H', payload, 0)[0]
        if cmd in (_CMD_REGISTER_SESSION, _CMD_LIST_IDENTITY, _CMD_LIST_SERVICES,
                   _CMD_LIST_INTERFACES, _CMD_NOP):
            return payload
        return payload[:4] + struct.pack('<I', self._session) + payload[8:]

    def _recv_enip(self) -> bytes:
        """Read one complete ENIP packet (24-byte header + Length bytes)."""
        hdr = self._recv_exact(24)
        if len(hdr) < 24:
            return hdr
        length = struct.unpack_from('<H', hdr, 2)[0]
        if length == 0:
            return hdr
        body = self._recv_exact(length)
        return hdr + body

    def _recv_exact(self, n: int) -> bytes:
        buf = b''
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                return buf
            buf += chunk
        return buf

    def _classify_response(self, response: bytes, result: FuzzResult,
                           request_cip_service: 'int | None' = None) -> None:
        """Parse ENIP response and set anomaly/crash_indicator on result."""
        if len(response) < 24:
            result.anomaly = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        resp_cmd    = struct.unpack_from('<H', response, 0)[0]
        resp_length = struct.unpack_from('<H', response, 2)[0]
        enip_status = struct.unpack_from('<I', response, 8)[0]

        # ENIP-level errors
        if enip_status != _ENIP_STATUS_SUCCESS:
            # 0x0003 (malformed) or 0x0001 (unsupported+close) → crash
            if enip_status in (_ENIP_STATUS_UNSUPPORTED, _ENIP_STATUS_BAD_DATA):
                result.anomaly = ANOMALY_EXCEPTION
                result.crash_indicator = True
            else:
                result.anomaly = ANOMALY_EXCEPTION
                result.crash_indicator = False
            result.response_decoded = f"ENIP status=0x{enip_status:04X}"
            return

        # For Send RR Data response: parse CPF → CIP
        if resp_cmd == _CMD_SEND_RR_DATA and len(response) >= 32:
            data = response[24:]   # everything after header
            # data: InterfaceHandle(4) + Timeout(2) + CPF
            if len(data) < 6:
                return
            cpf_start = 6
            self._classify_cpf(data[cpf_start:], result, request_cip_service)
            return

    def _classify_cpf(self, cpf: bytes, result: FuzzResult,
                      request_cip_service: 'int | None' = None) -> None:
        """Parse CPF and check CIP response status."""
        if len(cpf) < 2:
            return
        item_count = struct.unpack_from('<H', cpf, 0)[0]
        offset = 2
        for _ in range(item_count):
            if offset + 4 > len(cpf):
                return
            type_id = struct.unpack_from('<H', cpf, offset)[0]
            length  = struct.unpack_from('<H', cpf, offset + 2)[0]
            data    = cpf[offset + 4: offset + 4 + length]
            if type_id == _CPF_UNCONN_DATA and len(data) >= 4:
                self._classify_cip_response(data, result, request_cip_service)
                return
            if type_id == _CPF_CONN_DATA and len(data) >= 2:
                self._classify_cip_response(data, result, request_cip_service)
                return
            offset += 4 + length

    def _classify_cip_response(self, cip: bytes, result: FuzzResult,
                               request_cip_service: 'int | None' = None) -> None:
        """Parse CIP response: check service response bit, service echo, and general status."""
        if len(cip) < 4:
            result.anomaly = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return
        service = cip[0]
        if not (service & 0x80):
            # Not a response — unexpected
            result.anomaly = ANOMALY_UNEXPECTED_DATA
            result.crash_indicator = True
            return
        # Service byte in a CIP response must echo (request_service | 0x80)
        if request_cip_service is not None and service != (request_cip_service | 0x80):
            result.anomaly = ANOMALY_UNEXPECTED_DATA
            result.crash_indicator = False
            result.response_decoded = (
                f"CIP service mismatch: expected=0x{request_cip_service | 0x80:02X} "
                f"got=0x{service:02X}"
            )
            return
        gen_status = cip[2]
        if gen_status != 0x00:
            result.anomaly = ANOMALY_EXCEPTION
            result.crash_indicator = False
            result.response_decoded = f"CIP general status=0x{gen_status:02X}"

    # ------------------------------------------------------------------
    # Category generators
    # ------------------------------------------------------------------

    def _gen_boundary(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_BOUNDARY, desc, payload))

        session = 0   # will be patched at send time

        # --- Discovery commands (no session required) ---
        add("List Identity (standard discovery)",     _list_identity_packet())
        add("List Services (standard discovery)",     _list_services_packet())
        add("List Interfaces",
            _enip_packet(_CMD_LIST_INTERFACES, b''))

        # --- NOP variants ---
        add("NOP empty data",                         _nop_packet(b''))
        add("NOP with 4 bytes of zeros",              _nop_packet(b'\x00' * 4))
        add("NOP with max-length ASCII data (250B)",  _nop_packet(b'A' * 250))

        # --- Register Session variants ---
        add("Register Session protocol version=1 (standard)",
            _register_session_packet())
        add("Register Session protocol version=0",
            _enip_packet(_CMD_REGISTER_SESSION, struct.pack('<HH', 0, 0)))
        add("Register Session protocol version=0xFFFF",
            _enip_packet(_CMD_REGISTER_SESSION, struct.pack('<HH', 0xFFFF, 0)))
        add("Register Session with extra data (6 bytes)",
            _enip_packet(_CMD_REGISTER_SESSION,
                         struct.pack('<HH', 1, 0) + b'\x00\x00'))

        # --- Basic CIP reads (via Send RR Data with patched session) ---
        # Identity Object
        add("Get_Attributes_All Identity (class=0x01, inst=1)",
            _unconnected_msg(_get_attr_all(0x01, 1), session))
        add("Get_Attribute_Single Identity Vendor ID (attr=1)",
            _unconnected_msg(_get_attr_single(0x01, 1, 1), session))
        add("Get_Attribute_Single Identity Device Type (attr=2)",
            _unconnected_msg(_get_attr_single(0x01, 1, 2), session))
        add("Get_Attribute_Single Identity Product Code (attr=3)",
            _unconnected_msg(_get_attr_single(0x01, 1, 3), session))
        add("Get_Attribute_Single Identity Revision (attr=4)",
            _unconnected_msg(_get_attr_single(0x01, 1, 4), session))
        add("Get_Attribute_Single Identity Status (attr=5)",
            _unconnected_msg(_get_attr_single(0x01, 1, 5), session))
        add("Get_Attribute_Single Identity Serial Number (attr=6)",
            _unconnected_msg(_get_attr_single(0x01, 1, 6), session))
        add("Get_Attribute_Single Identity Product Name (attr=7)",
            _unconnected_msg(_get_attr_single(0x01, 1, 7), session))

        # Message Router
        add("Get_Attributes_All Message Router (class=0x02, inst=1)",
            _unconnected_msg(_get_attr_all(0x02, 1), session))

        # Connection Manager
        add("Get_Attributes_All Connection Manager (class=0x06, inst=1)",
            _unconnected_msg(_get_attr_all(0x06, 1), session))

        # Reset object
        add("Reset Identity Object (class=0x01, inst=1, service=0x05)",
            _unconnected_msg(_cip_request(_SVC_RESET,
                                          _cip_path(('class', 0x01), ('instance', 1))),
                             session))

        # Set read-only attribute
        add("Set_Attribute_Single Identity Vendor ID (should fail, attr=1 is RO)",
            _unconnected_msg(_set_attr_single(0x01, 1, 1, struct.pack('<H', 0xBEEF)),
                             session))

        # Instance 0 (class-level)
        add("Get_Attributes_All Identity class-level (inst=0)",
            _unconnected_msg(_get_attr_all(0x01, 0), session))

        # All standard ENIP commands probed with empty data
        for cmd_val, label in [
            (0x0001, "NOP"), (0x0004, "List Services"), (0x0063, "List Identity"),
            (0x0064, "List Interfaces"), (0x0065, "Register Session"),
            (0x0066, "Unregister Session"), (0x006F, "Send RR Data empty"),
        ]:
            if cmd_val not in (_CMD_LIST_IDENTITY, _CMD_LIST_SERVICES,
                               _CMD_LIST_INTERFACES, _CMD_NOP):
                add(f"ENIP command 0x{cmd_val:04X} ({label}) empty payload",
                    _enip_packet(cmd_val, b'', session=session))

        # Max and min data payloads for Send RR Data
        add("Send RR Data with CPF item count=0 (empty CPF)",
            _enip_packet(_CMD_SEND_RR_DATA,
                         struct.pack('<IHH', 0, 10, 0),   # IntHandle+Timeout+Count=0
                         session=session))

        add("Send RR Data CPF with only Null Address Item (no data item)",
            _send_rr_data(_cpf_items((_CPF_NULL_ADDR, b'')), session))

        # Multiple CIP classes
        for cls in [0x03, 0x04, 0x05, 0x08]:
            add(f"Get_Attributes_All class=0x{cls:02X} instance=1",
                _unconnected_msg(_get_attr_all(cls, 1), session))

        return cases

    def _gen_binary_corruption(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_BINARY_CORRUPTION, desc, payload))

        # Wrong command codes
        for cmd_val, label in [
            (0x0000, "command 0x0000 (reserved)"),
            (0x0002, "command 0x0002 (reserved)"),
            (0x0003, "command 0x0003 (reserved)"),
            (0x0005, "command 0x0005 (reserved)"),
            (0x0100, "command 0x0100 (out-of-range)"),
            (0xFFFF, "command 0xFFFF (all-ones)"),
        ]:
            add(f"Wrong ENIP {label}",
                _enip_packet(cmd_val, b'\x00' * 4))

        # Malformed length field
        valid_cmd = b'\x6F\x00'    # Send RR Data in LE
        for length_val, label in [
            (0x0000, "length=0 (no data for Send RR)"),
            (0x0001, "length=1 (odd/too short)"),
            (0xFFFF, "length=0xFFFF (claims 65535 bytes)"),
            (0x0100, "length=256 (reasonable but no data)"),
        ]:
            hdr = struct.pack('<HHII8sI',
                              _CMD_SEND_RR_DATA, length_val, 0, 0, b'\x00'*8, 0)
            add(f"Send RR Data with {label}", hdr)

        # Truncated at each byte of 24-byte header
        ref = _list_identity_packet()
        for i in range(1, 24):
            add(f"Truncated at byte {i} (of 24-byte header)", ref[:i])

        # All-zero / all-FF
        add("All-zero 24 bytes", b'\x00' * 24)
        add("All-0xFF 24 bytes", b'\xFF' * 24)
        add("Empty payload (0 bytes)", b'')

        # Bad session handle in header (non-zero session for session-less commands)
        for sess, label in [
            (0xFFFFFFFF, "0xFFFFFFFF"),
            (0xDEADBEEF, "0xDEADBEEF"),
            (0x00000001, "0x00000001"),
            (0x12345678, "0x12345678"),
        ]:
            add(f"List Identity with session handle={label} (should be 0)",
                _enip_packet(_CMD_LIST_IDENTITY, b'', session=sess))
            add(f"Send RR Data with wrong session={label}",
                _unconnected_msg(_get_attr_all(0x01, 1), sess))

        # Bad ENIP status from initiator (spec says must be 0)
        for status_val in [0x00000001, 0xFFFFFFFF, 0x00000008]:
            hdr = struct.pack('<HHII8sI',
                              _CMD_SEND_RR_DATA, 0, 0, status_val, b'\x00'*8, 0)
            add(f"Send RR Data with initiator status=0x{status_val:08X}", hdr)

        # Bad options field (must be 0)
        hdr = struct.pack('<HHIIII',
                          _CMD_LIST_IDENTITY, 0, 0, 0, 0, 0xDEADBEEF)
        add("List Identity with options=0xDEADBEEF (spec says must be 0)", hdr)

        # Corrupt CPF item type
        cpf = struct.pack('<H', 1) + struct.pack('<HH', 0xDEAD, 4) + b'\x00' * 4
        add("CPF with unknown item type=0xDEAD",
            _send_rr_data(cpf, 0))

        # CPF item count overflow
        cpf = struct.pack('<H', 0xFFFF)   # claims 65535 items, no data
        add("CPF item count=0xFFFF (overflow)", _send_rr_data(cpf, 0))

        # CPF item length mismatch
        cpf = (_cpf_items((_CPF_NULL_ADDR, b''))
               + struct.pack('<HH', _CPF_UNCONN_DATA, 0x0100))  # claims 256 bytes, no data
        add("CPF item length=256 but no data follows", _send_rr_data(cpf, 0))

        # Valid start, random remainder (various widths)
        import os
        for i in range(8):
            rand_body = os.urandom(20)
            add(f"Valid ENIP command + random body variant {i+1}",
                _enip_packet(_CMD_SEND_RR_DATA, rand_body))

        # Single bit-flips in specific positions
        for pos, label in [(0, "cmd_lo"), (1, "cmd_hi"), (2, "len_lo"), (8, "status_lo")]:
            ref = list(_list_identity_packet())
            ref[pos] ^= 0xFF
            add(f"Bit-flip at byte {pos} ({label})", bytes(ref))

        return cases

    def _gen_sequence(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_SEQUENCE, desc, payload))

        session = 0  # patched at send time

        # Sender context variants (echoed in response, shouldn't affect behavior)
        for ctx_val, label in [
            (b'\xFF' * 8, "all-0xFF sender context"),
            (b'\x00' * 8, "all-zero sender context"),
            (b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE', "0xDEADBEEFCAFEBABE"),
            (bytes(range(8)),                        "0x0001020304050607"),
        ]:
            add(f"Get_Attr_All with {label}",
                _enip_packet(_CMD_SEND_RR_DATA,
                             struct.pack('<IH', 0, 10)
                             + _cpf_items((_CPF_NULL_ADDR, b''),
                                          (_CPF_UNCONN_DATA, _get_attr_all(0x01, 1))),
                             session=session, context=ctx_val))

        # Wrong session handles (state exploration)
        for sess, label in [
            (0x00000000, "session=0 (unregistered)"),
            (0xFFFFFFFF, "session=0xFFFFFFFF"),
            (0x00000001, "session=1 (guessed)"),
            (0xDEADBEEF, "session=0xDEADBEEF"),
        ]:
            add(f"Send RR Data with {label}",
                _unconnected_msg(_get_attr_all(0x01, 1), sess))

        # Large interface handle (must be 0)
        for iface, label in [
            (0x00000001, "InterfaceHandle=1"),
            (0xFFFFFFFF, "InterfaceHandle=0xFFFFFFFF"),
            (0x00000100, "InterfaceHandle=256"),
        ]:
            data = struct.pack('<IH', iface, 10) + _cpf_items(
                (_CPF_NULL_ADDR, b''),
                (_CPF_UNCONN_DATA, _get_attr_all(0x01, 1)),
            )
            add(f"Send RR Data with {label}",
                _enip_packet(_CMD_SEND_RR_DATA, data, session=session))

        # Timeout field variants
        for tout, label in [
            (0x0000, "Timeout=0 (no timeout)"),
            (0xFFFF, "Timeout=0xFFFF (max)"),
            (0x0001, "Timeout=1 (very short)"),
        ]:
            data = struct.pack('<IH', 0, tout) + _cpf_items(
                (_CPF_NULL_ADDR, b''),
                (_CPF_UNCONN_DATA, _get_attr_all(0x01, 1)),
            )
            add(f"Send RR Data with {label}",
                _enip_packet(_CMD_SEND_RR_DATA, data, session=session))

        # Double-register attempt
        add("Second Register Session (re-registration attempt)",
            _register_session_packet())

        # Unregister then re-register
        add("Unregister Session (force close + reconnect scenario)",
            _enip_packet(_CMD_UNREGISTER_SES, b'', session=session))

        return cases

    def _gen_state_machine(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_STATE_MACHINE, desc, payload))

        # Before session: CIP traffic with session=0
        add("Send RR Data before Register Session (session=0)",
            _unconnected_msg(_get_attr_all(0x01, 1), 0))

        # Wrong / expired session handles
        add("Forward_Open with session=0 (no session)",
            _unconnected_msg(_forward_open(), 0))

        add("Send Unit Data before any connected session",
            _enip_packet(_CMD_SEND_UNIT_DATA,
                         struct.pack('<IH', 0, 0)
                         + _cpf_items(
                             (_CPF_CONN_ADDR, struct.pack('<I', 0xDEADBEEF)),
                             (_CPF_CONN_DATA, b'\x00\x00' + _get_attr_all(0x01, 1)),
                         )))

        # All ENIP command codes we haven't tested yet
        for cmd_val in range(0x0007, 0x0063):
            if cmd_val in (0x0001, 0x0004, 0x0063, 0x0064, 0x0065, 0x0066, 0x006F, 0x0070):
                continue
            # Sample ~8 values spread across the space
            if cmd_val in (0x0010, 0x0020, 0x0030, 0x0040, 0x0050, 0x0060, 0x0061, 0x0062):
                add(f"Undocumented ENIP command 0x{cmd_val:04X}",
                    _enip_packet(cmd_val, b'\x00' * 4))

        # Forward_Close without prior Forward_Open
        add("Forward_Close without prior Forward_Open (wrong serial)",
            _unconnected_msg(_forward_close(conn_serial=0xDEAD), 0))

        # Send Unit Data with zero connection ID
        add("Send Unit Data with connected CID=0",
            _enip_packet(_CMD_SEND_UNIT_DATA,
                         struct.pack('<IH', 0, 0)
                         + _cpf_items(
                             (_CPF_CONN_ADDR, struct.pack('<I', 0)),
                             (_CPF_CONN_DATA, b'\x00\x00\xAA\xBB'),
                         )))

        # Unregister with wrong session
        add("Unregister Session with wrong session handle",
            _enip_packet(_CMD_UNREGISTER_SES, b'', session=0xBADDCAFE))

        # Send_RR_Data after Unregister
        add("Send RR Data immediately after Unregister (stale session)",
            _unconnected_msg(_get_attr_all(0x01, 1), 0xDEAD1234))

        # Initiator sends response-like ENIP command
        add("Initiator sends ENIP Status=0x0001 (error status in request)",
            struct.pack('<HHII8sI',
                        _CMD_SEND_RR_DATA, 0, 0, 0x0001, b'\x00'*8, 0))

        # Empty CPF for Send RR Data
        add("Send RR Data with no CPF items (item count=0)",
            _enip_packet(_CMD_SEND_RR_DATA,
                         struct.pack('<IHH', 0, 0, 0),
                         session=0))

        # CPF with only Connected Data (missing Connected Address)
        add("CPF with only Unconnected Data, no Null Address (malformed)",
            _send_rr_data(_cpf_items((_CPF_UNCONN_DATA, _get_attr_all(0x01, 1))), 0))

        return cases

    def _gen_forward_open_close(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_FWD_OPEN_CLOSE, desc, payload))

        session = 0  # patched at send time

        # Standard Forward_Open (benchmark case)
        add("Forward_Open standard (class3, 128-byte, 10ms RPI)",
            _unconnected_msg(_forward_open(), session))

        # RPI variants
        for rpi, label in [
            (0, "RPI=0 (invalid)"),
            (1, "RPI=1µs (too fast)"),
            (500, "RPI=500µs (very fast)"),
            (1000, "RPI=1ms"),
            (100000, "RPI=100ms"),
            (0xFFFFFFFF, "RPI=0xFFFFFFFF (max)"),
        ]:
            add(f"Forward_Open {label}",
                _unconnected_msg(_forward_open(rpi=rpi), session))

        # Priority_Time_Tick variants
        for ptick, label in [
            (0x00, "priority=0 timeout_ticks=0"),
            (0xFF, "priority=0xFF timeout_ticks=0xFF (extreme)"),
            (0xAA, "priority=0xAA (alternating bits)"),
        ]:
            body = (bytes([ptick >> 8 & 0xFF if False else 0x0A, ptick & 0xFF])
                    + b'\x00' * 28
                    + bytes([2, 0x20, 0x06, 0x24, 0x01]))
            add(f"Forward_Open with {label}",
                _unconnected_msg(
                    _cip_request(_SVC_FWD_OPEN,
                                 _cip_path(('class', 0x06), ('instance', 1)),
                                 bytes([0x0A, ptick & 0xFF]) + b'\x00' * 28
                                 + bytes([2]) + _cip_path(('class', 0x06), ('instance', 1))),
                    session))

        # Connection size edge cases
        for ot_size, to_size, label in [
            (0, 0, "size=0 both directions"),
            (1, 1, "size=1 byte"),
            (500, 500, "size=500 (max for standard FwdOpen)"),
            (501, 501, "size=501 (exceeds standard FwdOpen max)"),
            (0x01FF, 0x01FF, "size=0x01FF (9 bits, max for 2-byte param)"),
        ]:
            add(f"Forward_Open connection {label}",
                _unconnected_msg(_forward_open(ot_size=ot_size, to_size=to_size), session))

        # Transport class variants
        for transport, label in [
            (0x00, "transport=0x00 (class 0 client)"),
            (0x01, "transport=0x01 (class 1 client)"),
            (0x02, "transport=0x02 (class 2 client)"),
            (0x03, "transport=0x03 (class 3 client)"),
            (0xA3, "transport=0xA3 (class 3 server, standard)"),
            (0xA0, "transport=0xA0 (class 0 server)"),
            (0xFF, "transport=0xFF (all bits set)"),
        ]:
            add(f"Forward_Open {label}",
                _unconnected_msg(_forward_open(transport=transport), session))

        # Connection serial variants
        for serial, label in [
            (0x0000, "conn_serial=0"),
            (0xFFFF, "conn_serial=0xFFFF (max)"),
            (0xAAAA, "conn_serial=0xAAAA (alternating)"),
        ]:
            add(f"Forward_Open {label}",
                _unconnected_msg(_forward_open(conn_serial=serial), session))

        # Connection path to wrong classes
        for cls, inst, label in [
            (0x01, 0x01, "path to Identity (class 1)"),
            (0x02, 0x01, "path to Message Router (class 2)"),
            (0xFF, 0x01, "path to class 0xFF (nonexistent)"),
            (0x00, 0x00, "path class=0 instance=0"),
        ]:
            path = _cip_path(('class', cls), ('instance', inst))
            add(f"Forward_Open {label}",
                _unconnected_msg(_forward_open(path=path), session))

        # OT/TO CID values
        add("Forward_Open with OT CID=0",
            _unconnected_msg(_forward_open(ot_cid=0), session))
        add("Forward_Open with OT CID=0xFFFFFFFF",
            _unconnected_msg(_forward_open(ot_cid=0xFFFFFFFF), session))

        # Standard Forward_Close (after a Forward_Open)
        add("Forward_Close standard (conn_serial=0x1234)",
            _unconnected_msg(_forward_close(conn_serial=0x1234), session))

        # Forward_Close with wrong params
        add("Forward_Close wrong connection serial",
            _unconnected_msg(_forward_close(conn_serial=0xDEAD), session))

        add("Forward_Close wrong vendor ID (mangled)",
            # Build manually with wrong vendor
            _unconnected_msg(
                _cip_request(_SVC_FWD_CLOSE,
                             _cip_path(('class', 0x06), ('instance', 0x01)),
                             (bytes([0x0A, 0xFF])
                              + struct.pack('<HHI', 0x1234, 0xBEEF, _ORIG_SERIAL)
                              + bytes([0x00, 0x00, 0x02, 0x00])
                              + _cip_path(('class', 0x06), ('instance', 0x01)))),
                session))

        add("Forward_Close to class 0xFF (nonexistent)",
            _unconnected_msg(_forward_close(path=_cip_path(('class', 0xFF), ('instance', 1))),
                             session))

        # Empty path in Forward_Open
        add("Forward_Open with empty connection path (size=0)",
            _unconnected_msg(_forward_open(path=b''), session))

        return cases

    def _gen_cip_path(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_CIP_PATH, desc, payload))

        session = 0  # patched

        def req_with_path(path, service=_SVC_GET_ATTR_ALL):
            return _unconnected_msg(_cip_request(service, path), session)

        # Standard logical segment types (1-byte)
        for seg, val, label in [
            (0x20, 0x01, "Class=0x01 (Identity)"),
            (0x24, 0x01, "Instance=0x01"),
            (0x30, 0x01, "Attribute=0x01"),
            (0x2C, 0x01, "ConnectionPoint=0x01"),
            (0x28, 0x00, "MemberID=0x00"),
        ]:
            path = bytes([seg, val, 0x24, 0x01])   # segment + instance
            add(f"Logical segment {label}",
                req_with_path(path))

        # 2-byte (extended) logical segments
        for seg_ext, cls_val, label in [
            (0x21, 0x0100, "Class 0x0100 (extended, 2-byte)"),
            (0x21, 0x0200, "Class 0x0200 (extended, 2-byte)"),
            (0x21, 0xFFFF, "Class 0xFFFF (extended, max)"),
            (0x25, 0x0100, "Instance 0x0100 (extended)"),
        ]:
            path = bytes([seg_ext, 0x00]) + struct.pack('<H', cls_val) + bytes([0x24, 0x01])
            add(f"Extended logical segment {label}",
                req_with_path(path))

        # All common class IDs
        for cls in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x0E, 0x0F, 0x10, 0x2C, 0x42, 0xAC, 0xF0, 0xFF]:
            path = _cip_path(('class', cls), ('instance', 1))
            add(f"Get_Attr_All class=0x{cls:02X}",
                req_with_path(path))

        # Port segments
        add("Port segment port=1 (backplane)",
            req_with_path(bytes([0x01, 0x01, 0x20, 0x01, 0x24, 0x01])))
        add("Port segment port=0 (unspecified)",
            req_with_path(bytes([0x01, 0x00, 0x20, 0x01, 0x24, 0x01])))
        add("Port segment with extended link address (2-byte port)",
            req_with_path(bytes([0x1F, 0x01, 0x01, 0x00, 0x20, 0x01, 0x24, 0x01])))

        # Data segments
        add("ANSI Extended Symbol data segment (empty)",
            req_with_path(bytes([0x91, 0x00, 0x20, 0x01, 0x24, 0x01])))
        add("ANSI Extended Symbol 'Program:MainRoutine'",
            _unconnected_msg(
                _cip_request(_SVC_GET_ATTR_ALL,
                             bytes([0x91, 12]) + b'Program:Main'),
                session))

        # Malformed paths
        add("Path size=0 (empty path)",
            _unconnected_msg(bytes([_SVC_GET_ATTR_ALL, 0]), session))
        add("Path size claims 4 WORDs but only 2 present (underrun)",
            _unconnected_msg(bytes([_SVC_GET_ATTR_ALL, 4, 0x20, 0x01]), session))
        add("Path size claims 1 WORD but 4 bytes present (overrun)",
            _unconnected_msg(bytes([_SVC_GET_ATTR_ALL, 1, 0x20, 0x01, 0x24, 0x01]), session))

        # Truncated path (odd number of bytes when path size is even)
        add("Path with odd number of bytes (misaligned)",
            req_with_path(bytes([0x20, 0x01, 0x24])))

        # Deeply nested path (max 7 WORDs / 14 bytes typically)
        deep_path = (bytes([0x20, 0x01]) * 4 + bytes([0x24, 0x01]))
        add("Deeply nested path (4× class segment + instance)",
            req_with_path(deep_path))

        # All zeros path
        add("Path all zeros (4 bytes)",
            req_with_path(b'\x00' * 4))

        # All 0xFF path
        add("Path all 0xFF (4 bytes)",
            req_with_path(b'\xFF' * 4))

        return cases

    def _gen_unconnected_send(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_UNCONN_SEND, desc, payload))

        session = 0  # patched

        # Multiple_Service_Packet with 2 requests
        get_id   = _get_attr_single(0x01, 1, 1)   # Vendor ID
        get_type = _get_attr_single(0x01, 1, 2)   # Device Type
        add("Multiple_Service_Packet: 2× Get_Attribute_Single",
            _unconnected_msg(_multi_service_packet(get_id, get_type), session))

        # Multiple_Service_Packet with 3 requests
        get_pc   = _get_attr_single(0x01, 1, 3)
        add("Multiple_Service_Packet: 3× Get_Attribute_Single",
            _unconnected_msg(_multi_service_packet(get_id, get_type, get_pc), session))

        # Unconnected_Send (nested)
        inner = _get_attr_all(0x01, 1)
        add("Unconnected_Send nested (route via class 6)",
            _unconnected_msg(_unconnected_send_cip(inner), session))

        # All known CIP service codes against Identity Object
        identity_path = _cip_path(('class', 0x01), ('instance', 1))
        for svc in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]:
            add(f"Service 0x{svc:02X} on Identity Object",
                _unconnected_msg(_cip_request(svc, identity_path), session))

        # Empty CIP data (only service + path, no data)
        add("Get_Attribute_Single with no attribute data",
            _unconnected_msg(_cip_request(_SVC_GET_ATTR_SINGLE,
                                          _cip_path(('class', 0x01), ('instance', 1))),
                             session))

        # Oversized CIP request
        big_data = b'\x00' * 240
        add("Set_Attribute_All Identity with 240 bytes of zeros",
            _unconnected_msg(_cip_request(_SVC_SET_ATTR_ALL,
                                          _cip_path(('class', 0x01), ('instance', 1)),
                                          big_data),
                             session))

        # Get_Attributes_All on all common objects
        for cls in [0x01, 0x02, 0x03, 0x06, 0x42, 0xAC]:
            add(f"Unconnected_Send Get_Attr_All class=0x{cls:02X}",
                _unconnected_msg(_get_attr_all(cls, 1), session))

        # Service 0xFF (undefined, high)
        add("Service 0xFF (undefined) on Identity",
            _unconnected_msg(_cip_request(0xFF, identity_path), session))

        # CIP request with zero path
        add("CIP request service=0x01, path size=0 (no path)",
            _unconnected_msg(bytes([0x01, 0x00]), session))

        return cases

    def _gen_large_forward_open(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_LARGE_FWD_OPEN, desc, payload))

        session = 0  # patched

        # Standard Large_Forward_Open
        add("Large_Forward_Open standard (4000-byte, 10ms RPI)",
            _unconnected_msg(_large_forward_open(), session))

        # O→T size edge cases (4-byte params allow 0..65535)
        for ot_size, label in [
            (0, "OT_size=0"),
            (1, "OT_size=1"),
            (500, "OT_size=500 (standard FwdOpen max)"),
            (4000, "OT_size=4000 (typical LFO)"),
            (65535, "OT_size=65535 (max)"),
        ]:
            add(f"Large_Forward_Open {label}",
                _unconnected_msg(_large_forward_open(ot_size=ot_size), session))

        # T→O size edge cases
        for to_size, label in [
            (0, "TO_size=0"),
            (65535, "TO_size=65535 (max)"),
            (4001, "TO_size=4001"),
        ]:
            add(f"Large_Forward_Open TO {label}",
                _unconnected_msg(_large_forward_open(to_size=to_size), session))

        # Transport class variants
        for transport, label in [
            (0x03, "transport=0x03 (class 3 client)"),
            (0xA3, "transport=0xA3 (class 3 server, standard)"),
            (0xFF, "transport=0xFF (all bits)"),
        ]:
            add(f"Large_Forward_Open {label}",
                _unconnected_msg(_large_forward_open(transport=transport), session))

        # Wrong path
        add("Large_Forward_Open path to class 0xFF",
            _unconnected_msg(_large_forward_open(path=_cip_path(('class', 0xFF), ('instance', 1))),
                             session))
        add("Large_Forward_Open empty path",
            _unconnected_msg(_large_forward_open(path=b''), session))

        # RPI extremes
        add("Large_Forward_Open RPI=0",
            _unconnected_msg(_large_forward_open(rpi=0), session))
        add("Large_Forward_Open RPI=0xFFFFFFFF",
            _unconnected_msg(_large_forward_open(rpi=0xFFFFFFFF), session))

        # Large_Forward_Open combined with wrong connection serial
        add("Large_Forward_Open conn_serial=0xFFFF",
            _unconnected_msg(_large_forward_open(conn_serial=0xFFFF), session))

        return cases

    def _gen_logix_tag(self):
        cases = []
        session = 0  # patched at send time

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_LOGIX_TAG, desc, payload))

        def read_tag(name: bytes, count: int = 1) -> bytes:
            path = _logix_sym_path(name)
            cip = bytes([_SVC_READ_TAG, len(path) // 2]) + path + struct.pack('<H', count)
            return _unconnected_msg(cip, session)

        def write_tag(name: bytes, data_type: int, data: bytes, count: int = 1) -> bytes:
            path = _logix_sym_path(name)
            cip = (bytes([_SVC_WRITE_TAG, len(path) // 2]) + path
                   + struct.pack('<HH', data_type, count) + data)
            return _unconnected_msg(cip, session)

        # Standard reads
        add("Read Tag 'TestTag' element_count=1 (standard)", read_tag(b'TestTag'))
        add("Read Tag 'TestTag' element_count=10",           read_tag(b'TestTag', count=10))

        # Name edge cases
        path0 = bytes([0x91, 0x00])
        cip0 = bytes([_SVC_READ_TAG, len(path0) // 2]) + path0 + struct.pack('<H', 1)
        add("Read Tag empty name (len=0)", _unconnected_msg(cip0, session))

        add("Read Tag max-length name (82 chars)",       read_tag(b'A' * 82))
        add("Read Tag odd-length name b'Tag' (3 chars)", read_tag(b'Tag'))
        add("Read Tag even-length name b'TagX' (4 chars)", read_tag(b'TagX'))
        add("Read Tag name with embedded null b'Tag\\x00Bad'", read_tag(b'Tag\x00Bad'))
        add("Read Tag name with format chars b'%s%n'",   read_tag(b'%s%n'))
        add("Read Tag name with spaces b'My Tag'",       read_tag(b'My Tag'))
        add("Read Tag dot notation b'Program:Main.LocalTag'",
            read_tag(b'Program:Main.LocalTag'))
        add("Read Tag array subscript b'Tag[0]'",        read_tag(b'Tag[0]'))
        add("Read Tag non-ASCII high bytes b'\\xFE\\xFF'", read_tag(b'\xFE\xFF'))

        # element_count extremes
        add("Read Tag element_count=0",      read_tag(b'TestTag', count=0))
        add("Read Tag element_count=0xFFFF", read_tag(b'TestTag', count=0xFFFF))

        # Write Tag variants
        add("Write Tag 'TestTag' BOOL (0xC1)",
            write_tag(b'TestTag', _CIP_TYPE_BOOL, b'\x01'))
        add("Write Tag 'TestTag' DINT (0xC4)",
            write_tag(b'TestTag', _CIP_TYPE_DINT, struct.pack('<i', 12345678)))
        add("Write Tag 'TestTag' REAL (0xCA)",
            write_tag(b'TestTag', _CIP_TYPE_REAL, struct.pack('<f', 3.14159)))
        add("Write Tag 'TestTag' element_count=0",
            write_tag(b'TestTag', _CIP_TYPE_INT, b'', count=0))
        add("Write Tag 'TestTag' 240 zero bytes (overflow data)",
            write_tag(b'TestTag', _CIP_TYPE_SINT, b'\x00' * 240, count=240))

        # Fragmented tag services
        frag_path = _logix_sym_path(b'TestTag')
        frag_words = len(frag_path) // 2
        add("Read Tag Fragmented (0x4E) offset=0",
            _unconnected_msg(
                bytes([_SVC_READ_TAG_FRAG, frag_words]) + frag_path
                + struct.pack('<HI', 1, 0), session))
        add("Write Tag Fragmented (0x4F) offset=0",
            _unconnected_msg(
                bytes([_SVC_WRITE_TAG_FRAG, frag_words]) + frag_path
                + struct.pack('<HHI', _CIP_TYPE_DINT, 1, 0) + struct.pack('<i', 0),
                session))

        # Wrong / missing path
        add("Read Tag path_size=0 (no symbolic path)",
            _unconnected_msg(bytes([_SVC_READ_TAG, 0x00]) + struct.pack('<H', 1), session))

        wrong_path = _cip_path(('class', 0x01), ('instance', 1))
        add("Read Tag with logical class/instance path (not symbolic)",
            _unconnected_msg(
                bytes([_SVC_READ_TAG, len(wrong_path) // 2]) + wrong_path
                + struct.pack('<H', 1), session))

        return cases

    def _gen_pccc(self):
        cases = []
        session = 0  # patched at send time

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_PCCC, desc, payload))

        pccc_path = _cip_path(('class', 0x67), ('instance', 0x01))
        default_req_id = b'\x07\x00\x00\x00\x00\x00'  # 6-byte requestor ID

        def exec_pccc(pccc_cmd: bytes, req_id: bytes = default_req_id) -> bytes:
            cip_data = bytes([len(req_id)]) + req_id + pccc_cmd
            cip = _cip_request(_SVC_EXEC_PCCC, pccc_path, cip_data)
            return _unconnected_msg(cip, session)

        def pccc(cmd: int, sts: int, tns: int, fnc: int = None, data: bytes = b'') -> bytes:
            base = bytes([cmd, sts]) + struct.pack('<H', tns)
            if fnc is not None:
                base += bytes([fnc])
            return base + data

        tns = 0x0001

        # Standard CMD=0x0F FNC variants (protected typed logical read/write)
        add("Execute PCCC CMD=0x0F FNC=0xA2 (Read SINT array)",
            exec_pccc(pccc(0x0F, 0x00, tns, 0xA2, b'\x00\x00\x00\x01\x00')))
        add("Execute PCCC CMD=0x0F FNC=0xA8 (Read INT array)",
            exec_pccc(pccc(0x0F, 0x00, tns, 0xA8, b'\x00\x00\x00\x01\x00')))
        add("Execute PCCC CMD=0x0F FNC=0xAB (Read DINT array)",
            exec_pccc(pccc(0x0F, 0x00, tns, 0xAB, b'\x00\x00\x00\x01\x00')))
        add("Execute PCCC CMD=0x0F FNC=0xAA (Write INT array)",
            exec_pccc(pccc(0x0F, 0x00, tns, 0xAA, b'\x00\x00\x00\x01\x00\x00\x00')))
        add("Execute PCCC CMD=0x0F FNC=0xBD (Read STRING element)",
            exec_pccc(pccc(0x0F, 0x00, tns, 0xBD, b'\x00\x00\x00\x01\x00')))

        # FNC sweep at extremes
        add("Execute PCCC CMD=0x0F FNC=0x00 (undefined low FNC)",
            exec_pccc(pccc(0x0F, 0x00, tns, 0x00)))
        add("Execute PCCC CMD=0x0F FNC=0x7F (mid-range FNC)",
            exec_pccc(pccc(0x0F, 0x00, tns, 0x7F)))
        add("Execute PCCC CMD=0x0F FNC=0xFF (high FNC)",
            exec_pccc(pccc(0x0F, 0x00, tns, 0xFF)))

        # CMD sweep
        add("Execute PCCC CMD=0x06 (Diagnostic Status, no FNC)",
            exec_pccc(pccc(0x06, 0x00, tns)))
        add("Execute PCCC CMD=0x00 (reserved low)",
            exec_pccc(pccc(0x00, 0x00, tns)))
        add("Execute PCCC CMD=0x01 (reserved)",
            exec_pccc(pccc(0x01, 0x00, tns)))
        add("Execute PCCC CMD=0xFF (reserved high)",
            exec_pccc(pccc(0xFF, 0x00, tns)))

        # TNS extremes
        add("Execute PCCC CMD=0x0F TNS=0 (zero transaction number)",
            exec_pccc(pccc(0x0F, 0x00, 0x0000, 0xA2)))
        add("Execute PCCC CMD=0x0F TNS=0xFFFF (max transaction number)",
            exec_pccc(pccc(0x0F, 0x00, 0xFFFF, 0xA2)))

        # Requestor ID edge cases
        add("Execute PCCC zero requestor_id length",
            exec_pccc(pccc(0x0F, 0x00, tns, 0xA2), req_id=b''))
        add("Execute PCCC oversized requestor_id (32 bytes)",
            exec_pccc(pccc(0x0F, 0x00, tns, 0xA2), req_id=b'\xFF' * 32))

        # Truncated PCCC payloads
        add("Execute PCCC empty PCCC payload",       exec_pccc(b''))
        add("Execute PCCC CMD+STS only (no TNS)",    exec_pccc(bytes([0x0F, 0x00])))
        add("Execute PCCC CMD+STS+TNS no FNC/data",
            exec_pccc(bytes([0x0F, 0x00]) + struct.pack('<H', tns)))

        # STS non-zero
        add("Execute PCCC CMD=0x0F STS=0xFF (error status byte pre-set)",
            exec_pccc(pccc(0x0F, 0xFF, tns, 0xA2)))

        return cases
