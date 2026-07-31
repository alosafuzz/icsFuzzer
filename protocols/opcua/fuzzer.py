"""OPC-UA (OPC Unified Architecture) fuzzer — TCP port 4840.

UA Binary transport, SecurityMode=None, pure Python stdlib only (no asyncua/opcua).
Session flow: HEL→ACK → OPN→OPN_resp → CreateSession→resp → ActivateSession→resp → services.
Spec: IEC 62541, OPC UA Part 4 (Services) + Part 6 (Mappings).
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
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
    FuzzModule,
    FuzzResult,
)

# Protocol-specific fuzz categories
CATEGORY_SERVICE_SWEEP   = "service_id_sweep"
CATEGORY_NODEID_VARIANTS = "nodeid_variants"
CATEGORY_SUBSCRIPTION    = "subscription_flood"
CATEGORY_CHUNKED         = "chunked_message_abuse"

# Well-known service request NodeIds (namespace 0)
SVC_GET_ENDPOINTS       = 426
SVC_CREATE_SESSION      = 461
SVC_ACTIVATE_SESSION    = 467
SVC_CLOSE_SESSION       = 473
SVC_BROWSE              = 527
SVC_READ                = 631
SVC_WRITE               = 673
SVC_CREATE_SUBSCRIPTION = 787
SVC_DELETE_SUBSCRIPTIONS = 845

SC_GOOD = 0x00000000

_POLICY_NONE = b"http://opcfoundation.org/UA/SecurityPolicy#None"

# ---------------------------------------------------------------------------
# Encoding helpers — module-level pure functions, no I/O
# ---------------------------------------------------------------------------

def _ua_string(s) -> bytes:
    """OPC-UA String: Int32 LE length (or -1 for null) + UTF-8 bytes."""
    if s is None:
        return struct.pack('<i', -1)
    b = s.encode('utf-8') if isinstance(s, str) else bytes(s)
    return struct.pack('<i', len(b)) + b

def _ua_bytestring(b) -> bytes:
    """OPC-UA ByteString: same wire format as String."""
    if b is None:
        return struct.pack('<i', -1)
    return struct.pack('<i', len(b)) + bytes(b)

def _ua_nodeid_null() -> bytes:
    return b'\x00\x00'

def _ua_qualifiedname_null() -> bytes:
    """OPC-UA QualifiedName: UInt16 NamespaceIndex + String Name.
    Null form is NamespaceIndex=0 + null String (length=-1, no bytes) = 6 bytes.
    Distinct from a null NodeId (_ua_nodeid_null, 2 bytes) — mixing the two up
    here caused a 4-byte-short ReadValueId.DataEncoding field wherever this was
    needed, corrupting the tail of every Read request built with _read_body()."""
    return struct.pack('<H', 0) + _ua_string(None)

def _ua_nodeid_twobyte(id_: int) -> bytes:
    return struct.pack('<BB', 0x00, id_ & 0xFF)

def _ua_nodeid_fourbyte(ns: int, id_: int) -> bytes:
    return struct.pack('<BBH', 0x01, ns & 0xFF, id_ & 0xFFFF)

def _ua_nodeid_numeric(ns: int, id_: int) -> bytes:
    return struct.pack('<BHI', 0x02, ns & 0xFFFF, id_ & 0xFFFFFFFF)

def _ua_nodeid_string(ns: int, s) -> bytes:
    return struct.pack('<BH', 0x03, ns & 0xFFFF) + _ua_string(s)

def _ua_nodeid_bytestring(ns: int, b: bytes) -> bytes:
    return struct.pack('<BH', 0x05, ns & 0xFFFF) + _ua_bytestring(b)

def _ua_nodeid_guid(ns: int, guid_bytes: bytes) -> bytes:
    return struct.pack('<BH', 0x04, ns & 0xFFFF) + (guid_bytes[:16]).ljust(16, b'\x00')

def _svc_nodeid(svc_id: int) -> bytes:
    return _ua_nodeid_fourbyte(0, svc_id)

def _ua_datetime_now() -> bytes:
    epoch_diff = 116444736000000000
    ticks = int(time.time() * 1e7) + epoch_diff
    return struct.pack('<q', ticks)

def _request_header(auth_token: bytes = None, req_handle: int = 1) -> bytes:
    if auth_token is None:
        auth_token = _ua_nodeid_null()
    h  = auth_token
    h += _ua_datetime_now()
    h += struct.pack('<I', req_handle)
    h += struct.pack('<I', 0)          # ReturnDiagnostics
    h += _ua_string(None)             # AuditEntryId
    h += struct.pack('<I', 0)          # TimeoutHint
    h += b'\x00\x00\x00'             # AdditionalHeader (null ExtensionObject)
    return h

def _ua_msg_header(msg_type: bytes, chunk_type: bytes, body_len: int) -> bytes:
    return msg_type[:3] + chunk_type[:1] + struct.pack('<I', 8 + body_len)

def _hel(endpoint_url: str) -> bytes:
    body  = struct.pack('<I', 0)
    body += struct.pack('<I', 65536)
    body += struct.pack('<I', 65536)
    body += struct.pack('<I', 0)
    body += struct.pack('<I', 0)
    body += _ua_string(endpoint_url)
    return _ua_msg_header(b'HEL', b'F', len(body)) + body

def _opn_request(seq_num: int = 1, req_id: int = 1) -> bytes:
    sec_hdr  = struct.pack('<I', 0)
    sec_hdr += _ua_bytestring(_POLICY_NONE)
    sec_hdr += _ua_bytestring(None)
    sec_hdr += _ua_bytestring(None)
    seq_hdr  = struct.pack('<I', seq_num)
    seq_hdr += struct.pack('<I', req_id)
    body  = _svc_nodeid(446)
    body += _request_header(req_handle=req_id)
    body += struct.pack('<I', 0)     # ClientProtocolVersion
    body += struct.pack('<I', 0)     # RequestType=ISSUE
    body += struct.pack('<I', 1)     # SecurityMode=None
    body += _ua_bytestring(None)     # ClientNonce
    body += struct.pack('<I', 3600000)
    inner = sec_hdr + seq_hdr + body
    return _ua_msg_header(b'OPN', b'F', len(inner)) + inner

def _msg_frame(channel_id: int, token_id: int, seq_num: int, req_id: int,
               svc_id: int, svc_body: bytes,
               auth_token: bytes = None, chunk: bytes = b'F') -> bytes:
    sym  = struct.pack('<I', channel_id) + struct.pack('<I', token_id)
    seq  = struct.pack('<I', seq_num)    + struct.pack('<I', req_id)
    body = _svc_nodeid(svc_id) + _request_header(auth_token=auth_token, req_handle=req_id) + svc_body
    inner = sym + seq + body
    return _ua_msg_header(b'MSG', chunk, len(inner)) + inner

def _read_body(node_ns: int, node_id: int, attr_id: int = 13) -> bytes:
    body  = struct.pack('<d', 0.0)                    # MaxAge
    body += struct.pack('<I', 0)                       # TimestampsToReturn
    body += struct.pack('<I', 1)                       # NodesToRead array count
    body += _ua_nodeid_fourbyte(node_ns, node_id)       # ReadValueId.NodeId
    body += struct.pack('<I', attr_id)                  # ReadValueId.AttributeId
    body += _ua_string(None)                            # ReadValueId.IndexRange
    body += _ua_qualifiedname_null()                    # ReadValueId.DataEncoding
    return body

def _browse_body(node_ns: int = 0, node_id: int = 84, direction: int = 0) -> bytes:
    body  = _ua_nodeid_null()
    body += struct.pack('<q', 0)
    body += struct.pack('<I', 0)
    body += struct.pack('<I', 0)
    body += struct.pack('<I', 1)
    body += _ua_nodeid_fourbyte(node_ns, node_id)
    body += struct.pack('<I', direction)
    body += _ua_nodeid_null()
    body += struct.pack('<B', 1)
    body += struct.pack('<I', 0)
    body += struct.pack('<I', 0x3F)
    return body

def _write_body(node_ns: int, node_id: int, val: int = 0) -> bytes:
    body  = struct.pack('<I', 1)
    body += _ua_nodeid_fourbyte(node_ns, node_id)
    body += struct.pack('<I', 13)
    body += _ua_string(None)
    body += struct.pack('<B', 0x01)    # DataValue mask: value present
    body += struct.pack('<B', 0x07)    # VariantType: UInt32
    body += struct.pack('<I', val)
    return body

def _create_session_body(endpoint_url: str) -> bytes:
    app  = _ua_string("urn:icsfuzzer:client")
    app += _ua_string(None)
    app += struct.pack('<B', 0x02)     # LocalizedText mask: text only
    app += _ua_string("icsFuzzer")
    app += struct.pack('<I', 1)        # ApplicationType=Client
    app += _ua_string(None)
    app += _ua_string(None)
    app += struct.pack('<I', 0)        # DiscoveryUrls array empty
    body  = app
    body += _ua_string(None)
    body += _ua_string(endpoint_url)
    body += _ua_string("icsFuzzerSession_1")
    body += _ua_bytestring(None)
    body += _ua_bytestring(None)
    body += struct.pack('<d', 3600000.0)
    body += struct.pack('<I', 0)
    return body

def _activate_session_body() -> bytes:
    body  = _ua_string(None)           # ClientSignature.Algorithm
    body += _ua_bytestring(None)       # ClientSignature.Signature
    body += struct.pack('<I', 0)       # ClientSoftwareCertificates (empty)
    body += struct.pack('<I', 1)       # LocaleIds count
    body += _ua_string("en")
    body += _ua_nodeid_fourbyte(0, 321)  # AnonymousIdentityToken TypeId
    body += struct.pack('<B', 1)       # EncodingMask: ByteString body
    anon = _ua_string(None)
    body += struct.pack('<I', len(anon))
    body += anon
    body += _ua_string(None)           # UserTokenSignature.Algorithm
    body += _ua_bytestring(None)       # UserTokenSignature.Signature
    return body

def _create_subscription_body(interval_ms: float = 500.0) -> bytes:
    body  = struct.pack('<d', interval_ms)
    body += struct.pack('<I', 10)
    body += struct.pack('<I', 3)
    body += struct.pack('<I', 100)
    body += struct.pack('<B', 1)       # PublishingEnabled=True
    body += struct.pack('<B', 0)       # Priority
    return body

def _delete_subscriptions_body(sub_ids: list) -> bytes:
    body = struct.pack('<I', len(sub_ids))
    for sid in sub_ids:
        body += struct.pack('<I', sid)
    return body

# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

class _BufReader:
    def __init__(self, data: bytes):
        self._d = data
        self._p = 0

    def remaining(self) -> int:
        return max(0, len(self._d) - self._p)

    def read(self, n: int) -> bytes:
        if n <= 0:
            return b''
        chunk = self._d[self._p:self._p + n]
        self._p += n
        return chunk

    def read_uint8(self) -> int:
        v = struct.unpack_from('<B', self._d, self._p)[0]
        self._p += 1
        return v

    def read_uint16(self) -> int:
        v = struct.unpack_from('<H', self._d, self._p)[0]
        self._p += 2
        return v

    def read_int32(self) -> int:
        v = struct.unpack_from('<i', self._d, self._p)[0]
        self._p += 4
        return v

    def read_uint32(self) -> int:
        v = struct.unpack_from('<I', self._d, self._p)[0]
        self._p += 4
        return v

    def skip_ua_string(self):
        length = self.read_int32()
        if length > 0:
            self.read(length)

    def skip_nodeid(self):
        enc = self.read_uint8()
        if enc == 0x00:
            self._p += 1
        elif enc == 0x01:
            self._p += 3
        elif enc == 0x02:
            self._p += 6
        elif enc == 0x03:
            self._p += 2
            self.skip_ua_string()
        elif enc == 0x04:
            self._p += 18
        elif enc == 0x05:
            self._p += 2
            self.skip_ua_string()
        else:
            raise ValueError(f"Unknown NodeId encoding 0x{enc:02X}")

    def read_nodeid_raw(self) -> bytes:
        start = self._p
        self.skip_nodeid()
        return self._d[start:self._p]

    def skip_response_header(self) -> int:
        self.read(8)                # Timestamp
        self.read(4)                # RequestHandle
        svc_result = self.read_uint32()
        enc = self.read_uint8()     # DiagnosticInfo encoding mask
        if enc != 0:
            if enc & 0x01: self.skip_ua_string()
            if enc & 0x02: self.skip_ua_string()
            if enc & 0x04: self.skip_ua_string()
            if enc & 0x08: self.skip_ua_string()
            if enc & 0x10: self.skip_ua_string()
            if enc & 0x20: self.read(4)
            # ignore InnerDiagnosticInfo recursion
        count = self.read_int32()   # StringTable
        for _ in range(max(0, count)):
            self.skip_ua_string()
        self.skip_nodeid()          # AdditionalHeader TypeId
        enc2 = self.read_uint8()    # EncodingMask
        if enc2 != 0:
            length = self.read_int32()
            if length > 0:
                self.read(length)
        return svc_result


# ── Fingerprint helpers (module-level, no I/O dependency) ────────────────────

def _recv_opcua(sock: "socket.socket") -> Optional[bytes]:
    """Read one complete OPC-UA message from sock (8-byte header + body)."""
    buf = b''
    try:
        while len(buf) < 8:
            chunk = sock.recv(8 - len(buf))
            if not chunk:
                return buf if buf else None
            buf += chunk
        total = struct.unpack_from('<I', buf, 4)[0]
        if total < 8:
            return buf
        remaining = total - 8
        while remaining > 0:
            chunk = sock.recv(min(remaining, 4096))
            if not chunk:
                return buf
            buf += chunk
            remaining -= len(chunk)
    except socket.timeout:
        return None
    return buf


def _extract_ua_strings(data: bytes) -> list:
    """Extract all OPC-UA String values (Int32 LE length + UTF-8) from a raw frame.

    Scans linearly for plausible string patterns (non-negative length < 512,
    printable ASCII/UTF-8 content). Returns up to 10 strings.
    """
    results = []
    pos = 0
    while pos < len(data) - 4 and len(results) < 10:
        try:
            length = struct.unpack_from('<i', data, pos)[0]
        except struct.error:
            break
        if 1 <= length <= 512 and pos + 4 + length <= len(data):
            raw = data[pos + 4: pos + 4 + length]
            try:
                s = raw.decode('utf-8')
                # Require mostly printable content
                printable = sum(32 <= b < 127 for b in raw)
                if printable >= len(raw) * 0.8:
                    results.append(s.strip())
                    pos += 4 + length
                    continue
            except (UnicodeDecodeError, ValueError):
                pass
        pos += 1
    return results


# ---------------------------------------------------------------------------
# OpcuaFuzzer
# ---------------------------------------------------------------------------

class OpcuaFuzzer(FuzzModule):
    """OPC-UA fuzzer — TCP port 4840, SecurityMode=None, pure stdlib."""

    PROTOCOL_NAME = "opcua"
    DEFAULT_PORT  = 4840
    FUZZ_CATEGORIES = [
        CATEGORY_BOUNDARY,
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_STATE_MACHINE,
        CATEGORY_SEQUENCE,
        CATEGORY_SERVICE_SWEEP,
        CATEGORY_NODEID_VARIANTS,
        CATEGORY_SUBSCRIPTION,
        CATEGORY_CHUNKED,
    ]

    _RECV_TIMEOUT    = 4.0
    _CONNECT_TIMEOUT = 8.0

    def __init__(self, target: Device, logger, delay: float = 0.0, seeds=None):
        super().__init__(target=target, logger=logger, delay=delay, seeds=seeds)
        self._sock:       Optional[socket.socket] = None
        self._channel_id: int   = 0
        self._token_id:   int   = 0
        self._auth_token: Optional[bytes] = None
        self._seq:        int   = 0
        self._req_id:     int   = 0
        # Independent counter used to patch SequenceNumber at send time (see
        # _patch_sym_seq). Deliberately NOT the same counter as self._seq:
        # generate_cases() builds all cases for every category in one call,
        # and some category generators (state_machine, sequence) call
        # _next_seq()/_next_req() themselves while constructing their own
        # test payloads — by the time generate_cases() returns, self._seq has
        # already raced ahead of where the live wire session actually is.
        # _send_seq is seeded once from self._seq right after connect()
        # finishes (before generate_cases() ever runs) and only advanced by
        # _patch_sym_seq at actual send time, so it always reflects "how many
        # symmetric messages have really gone out on the wire."
        self._send_seq:   int   = 0

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _next_req(self) -> int:
        self._req_id += 1
        return self._req_id

    def _next_send_seq(self) -> int:
        self._send_seq += 1
        return self._send_seq

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self, target: Optional[Device] = None) -> None:
        t = target or self.target
        endpoint = f"opc.tcp://{t.ip}:{t.port}"
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self._CONNECT_TIMEOUT)
        self._sock.connect((t.ip, t.port))
        self._sock.settimeout(self._RECV_TIMEOUT)
        self._seq = 0
        self._req_id = 0

        # Step 1: HEL → ACK
        self._sock.sendall(_hel(endpoint))
        ack = self._recv_msg()
        if not ack or not ack.startswith(b'ACK'):
            raise ConnectionError(f"HEL/ACK failed: {ack[:8]!r}")

        # Step 2: OPN → channel_id + token_id
        self._sock.sendall(_opn_request(seq_num=self._next_seq(), req_id=self._next_req()))
        opn = self._recv_msg()
        if not opn or not opn.startswith(b'OPN'):
            raise ConnectionError(f"OPN failed: {opn[:8]!r}")
        self._channel_id, self._token_id = self._parse_opn_response(opn)

        # Step 3: CreateSession → auth_token
        cs_body = _create_session_body(endpoint)
        self._sock.sendall(_msg_frame(
            self._channel_id, self._token_id,
            self._next_seq(), self._next_req(),
            SVC_CREATE_SESSION, cs_body))
        cs = self._recv_msg()
        if not cs or not cs.startswith(b'MSG'):
            raise ConnectionError(f"CreateSession failed: {cs[:8]!r}")
        self._auth_token = self._parse_create_session_response(cs)

        # Step 4: ActivateSession
        self._sock.sendall(_msg_frame(
            self._channel_id, self._token_id,
            self._next_seq(), self._next_req(),
            SVC_ACTIVATE_SESSION, _activate_session_body(),
            auth_token=self._auth_token))
        as_resp = self._recv_msg()
        if not as_resp or not as_resp.startswith(b'MSG'):
            raise ConnectionError(f"ActivateSession failed: {as_resp[:8]!r}")

        # Seed the send-time counter from the real handshake state, before
        # generate_cases() gets a chance to advance self._seq further for
        # its own internal purposes (see _send_seq comment in __init__).
        self._send_seq = self._seq

    def _parse_opn_response(self, data: bytes):
        r = _BufReader(data[8:])
        r.read_uint32()                 # SecureChannelId (asymmetric header —
                                         # NOT what the server validates future
                                         # symmetric messages against; see below)
        r.skip_ua_string()              # SecurityPolicyUri
        r.skip_ua_string()              # SenderCertificate
        r.skip_ua_string()              # ReceiverCertThumbprint
        r.read(8)                       # SequenceNumber + RequestId
        r.skip_nodeid()                 # TypeId i=449
        r.skip_response_header()
        r.read(4)                       # ServerProtocolVersion
        # SecurityToken.ChannelId — this is the value the server actually
        # checks incoming symmetric MSG frames against (asyncua's
        # _check_incoming_chunk compares against self.security_token.ChannelId,
        # which is populated from this field, not the outer asymmetric
        # header's SecureChannelId read above). Previously this field was
        # read-and-discarded and the outer header's value was returned
        # instead, which silently diverges from the real value whenever the
        # two aren't numerically identical — confirmed via server-side
        # "Wrong channel id X, expected Y" errors where X was the outer
        # header's value and Y was this one.
        channel_id = r.read_uint32()    # SecurityToken.ChannelId
        token_id   = r.read_uint32()    # SecurityToken.TokenId
        return channel_id, token_id

    def _parse_create_session_response(self, data: bytes) -> bytes:
        r = _BufReader(data[8:])
        r.read(8)                       # Symmetric Security Header
        r.read(8)                       # Sequence Header
        r.skip_nodeid()                 # TypeId i=464
        r.skip_response_header()
        r.skip_nodeid()                 # SessionId
        return r.read_nodeid_raw()      # AuthenticationToken

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._channel_id = 0
        self._token_id   = 0
        self._auth_token = None

    def _reconnect(self) -> None:
        self.close()
        try:
            self.connect()
        except Exception:
            pass

    def _recv_msg(self) -> Optional[bytes]:
        buf = b''
        try:
            while len(buf) < 8:
                chunk = self._sock.recv(8 - len(buf))
                if not chunk:
                    return buf if buf else None
                buf += chunk
            total = struct.unpack_from('<I', buf, 4)[0]
            if total < 8:
                return buf
            remaining = total - 8
            while remaining > 0:
                chunk = self._sock.recv(min(remaining, 4096))
                if not chunk:
                    return buf
                buf += chunk
                remaining -= len(chunk)
        except socket.timeout:
            return None
        return buf

    def discover(self, interface: str, timeout: int = 30) -> list:
        raise NotImplementedError("OPC-UA discovery not implemented.")

    def fingerprint(self, active: bool = True) -> "FingerprintResult":
        """OPC-UA fingerprint.

        Passive: OUI lookup from ARP cache.
        Active:  connect (HEL→ACK→OPN→OPN-ACK), then send a Read request for
                 ServerStatus/BuildInfo nodes (ProductName ns=0;i=2261,
                 ManufacturerName ns=0;i=2262, SoftwareVersion ns=0;i=2264).
                 Falls back to GetEndpoints ApplicationDescription if Read fails.
        """
        from core.fingerprint import FingerprintResult, fingerprint_from_oui

        oui_result = fingerprint_from_oui(self.target.ip)
        if not active:
            return oui_result

        # Open a short-lived connection, run HEL→OPN→Read in one session.
        vendor   = "unknown"
        model    = "unknown"
        firmware = "unknown"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(4.0)
            endpoint = f"opc.tcp://{self.target.ip}:{self.target.port}"
            s.connect((self.target.ip, self.target.port))
            s.sendall(_hel(endpoint))
            ack = _recv_opcua(s)
            if not ack or ack[:3] != b'ACK':
                return oui_result
            s.sendall(_opn_request(seq_num=1, req_id=1))
            opn_resp = _recv_opcua(s)

            # Parse OPN response using the same parser as connect() — it skips
            # the variable-length SecurityPolicyUri / certificate fields correctly.
            channel_id = 0
            token_id   = 0
            if opn_resp:
                try:
                    channel_id, token_id = self._parse_opn_response(opn_resp)
                except Exception:
                    pass

            # Build Read request for ServerStatus BuildInfo nodes
            # Node IDs: ProductName=2261, ManufacturerName=2262, SoftwareVersion=2264
            read_nodes = [2261, 2262, 2264]
            read_b  = struct.pack('<d', 0.0)   # maxAge
            read_b += struct.pack('<I', 0)      # timestampsToReturn=Source
            read_b += struct.pack('<I', len(read_nodes))
            for nid in read_nodes:
                read_b += _ua_nodeid_fourbyte(0, nid)
                read_b += struct.pack('<I', 13)  # Value attribute
                read_b += _ua_string(None)        # indexRange
                read_b += _ua_qualifiedname_null() # dataEncoding

            read_frame = _msg_frame(channel_id, token_id, seq_num=2, req_id=2,
                                    svc_id=SVC_READ, svc_body=read_b)
            s.sendall(read_frame)
            resp = _recv_opcua(s)
            if resp and len(resp) > 32:
                strs = _extract_ua_strings(resp)
                if len(strs) >= 1:
                    model    = strs[0] or "unknown"   # ProductName
                if len(strs) >= 2:
                    vendor   = strs[1] or "unknown"   # ManufacturerName
                if len(strs) >= 3:
                    firmware = strs[2] or "unknown"   # SoftwareVersion
        except OSError:
            pass
        finally:
            s.close()

        confidence = "high" if vendor != "unknown" and model != "unknown" else "medium"
        result = FingerprintResult(
            vendor=vendor,
            model=model,
            firmware=firmware,
            confidence=confidence,
            method="opcua_read_serverstatus",
        )
        if oui_result.is_known():
            result.extra["oui_vendor"] = oui_result.vendor
        return result

    def replay_payload(self, payload: bytes) -> Optional[bytes]:
        if self._sock is None:
            raise RuntimeError("call connect() before replay_payload()")
        self._sock.sendall(payload)
        return self._recv_msg()

    # ------------------------------------------------------------------
    # generate_cases — builds complete wire frames using current session state
    # ------------------------------------------------------------------

    def generate_cases(self, categories=None):
        cats = self._resolve_categories(categories)
        cases = []
        for cat in cats:
            if cat == CATEGORY_BOUNDARY:
                cases.extend(self._gen_boundary())
            elif cat == CATEGORY_BINARY_CORRUPTION:
                cases.extend(self._gen_binary_corruption())
            elif cat == CATEGORY_STATE_MACHINE:
                cases.extend(self._gen_state_machine())
            elif cat == CATEGORY_SEQUENCE:
                cases.extend(self._gen_sequence())
            elif cat == CATEGORY_SERVICE_SWEEP:
                cases.extend(self._gen_service_sweep())
            elif cat == CATEGORY_NODEID_VARIANTS:
                cases.extend(self._gen_nodeid_variants())
            elif cat == CATEGORY_SUBSCRIPTION:
                cases.extend(self._gen_subscription_flood())
            elif cat == CATEGORY_CHUNKED:
                cases.extend(self._gen_chunked_abuse())
        return cases

    def _case(self, cat, desc, payload):
        return (self._next_id(), cat, desc, payload)

    def _msg(self, svc_id: int, svc_body: bytes, seq: int = 1, req: int = 1) -> bytes:
        return _msg_frame(self._channel_id, self._token_id, seq, req,
                          svc_id, svc_body, auth_token=self._auth_token)

    # ------------------------------------------------------------------
    # Category generators
    # ------------------------------------------------------------------

    def _gen_boundary(self):
        C = CATEGORY_BOUNDARY
        cases = []

        # Read well-known nodes with multiple attributes
        for ns, nid, attr, desc in [
            (0, 2258, 13, "Read ServerStatus ns=0;i=2258 attr=Value(13)"),
            (0, 2258,  4, "Read ServerStatus ns=0;i=2258 attr=DisplayName(4)"),
            (0,   85, 13, "Read Root ns=0;i=85 attr=Value(13)"),
            (0,   84, 13, "Read Objects ns=0;i=84 attr=Value(13)"),
            (0, 2253,  1, "Read Server ns=0;i=2253 attr=NodeId(1)"),
            (0, 2253,  2, "Read Server ns=0;i=2253 attr=NodeClass(2)"),
            (0, 2255, 13, "Read ServerArray ns=0;i=2255 attr=Value(13)"),
        ]:
            cases.append(self._case(C, desc, self._msg(SVC_READ, _read_body(ns, nid, attr))))

        # Attribute ID sweep 1–22 (all defined in OPC UA spec)
        for attr_id in range(1, 23):
            cases.append(self._case(C, f"Read ns=0;i=2258 attr={attr_id} (attr sweep)",
                self._msg(SVC_READ, _read_body(0, 2258, attr_id))))

        # Browse directions
        for direction, dlabel in [(0, "Forward"), (1, "Inverse"), (2, "Both")]:
            cases.append(self._case(C, f"Browse Objects i=84 dir={dlabel}",
                self._msg(SVC_BROWSE, _browse_body(0, 84, direction))))

        # Browse well-known nodes
        for nid, label in [(84, "Objects"), (85, "Root"), (2253, "Server")]:
            cases.append(self._case(C, f"Browse ns=0;i={nid} ({label})",
                self._msg(SVC_BROWSE, _browse_body(0, nid, 0))))

        # Write to read-only node (expect BadNotWritable or exception)
        cases.append(self._case(C, "Write Value to Server node (expect rejection)",
            self._msg(SVC_WRITE, _write_body(0, 2253, 0))))

        # GetEndpoints
        ep_body  = _ua_string(f"opc.tcp://{self.target.ip}:{self.target.port}")
        ep_body += struct.pack('<I', 0)
        ep_body += struct.pack('<I', 0)
        cases.append(self._case(C, "GetEndpoints discovery",
            self._msg(SVC_GET_ENDPOINTS, ep_body, req=999)))

        return cases

    def _gen_binary_corruption(self):
        C = CATEGORY_BINARY_CORRUPTION
        cases = []
        base_hel = _hel(f"opc.tcp://{self.target.ip}:{self.target.port}")

        # HEL truncations at key boundaries
        for i in [1, 4, 7, 8, 12, 16, 20, 24, len(base_hel) - 1]:
            if 0 < i <= len(base_hel):
                cases.append(self._case(C, f"HEL truncated at byte {i}", base_hel[:i]))

        # Wrong MessageType
        for mt, label in [
            (b'XYZ', "type=XYZ"),
            (b'\x00\x00\x00', "null type"),
            (b'\xff\xff\xff', "all-FF type"),
            (b'ACK', "ACK from client"),
            (b'ERR', "ERR from client"),
        ]:
            cases.append(self._case(C, f"Wrong msg type {label}",
                mt + base_hel[3:]))

        # Wrong ChunkType in HEL
        for chunk, label in [
            (b'X', "invalid 'X'"), (b'C', "chunk 'C'"),
            (b'A', "abort 'A'"), (b'\x00', "null")
        ]:
            cases.append(self._case(C, f"HEL ChunkType='{label}'",
                base_hel[:3] + chunk + base_hel[4:]))

        # MessageSize edge cases
        cases.append(self._case(C, "MessageSize=0",
            base_hel[:4] + struct.pack('<I', 0) + base_hel[8:]))
        cases.append(self._case(C, "MessageSize=0xFFFFFFFF (overflow claim)",
            base_hel[:4] + struct.pack('<I', 0xFFFFFFFF) + base_hel[8:]))
        cases.append(self._case(C, "MessageSize=7 (less than header)",
            base_hel[:4] + struct.pack('<I', 7) + base_hel[8:]))

        # All-zero frames
        for sz in [8, 28, 56, 100]:
            cases.append(self._case(C, f"All-zero {sz} bytes", b'\x00' * sz))
        cases.append(self._case(C, "All-0xFF 28 bytes", b'\xFF' * 28))

        # Corrupt OPN (flip SecurityPolicyUri length)
        opn = _opn_request(seq_num=1, req_id=1)
        corrupt_opn = bytearray(opn)
        if len(corrupt_opn) > 13:
            corrupt_opn[12] = 0xFF
        cases.append(self._case(C, "OPN corrupted SecurityPolicyUri length",
            bytes(corrupt_opn)))

        # Bit flips on valid MSG
        valid_msg = self._msg(SVC_READ, _read_body(0, 2258, 13))
        for offset in [0, 4, 8, 12, 16, 20, 24]:
            if offset < len(valid_msg):
                flipped = bytearray(valid_msg)
                flipped[offset] ^= 0x80
                cases.append(self._case(C, f"MSG bit-flip at offset {offset}",
                    bytes(flipped)))

        # Random pattern
        cases.append(self._case(C, "Bytes 0x00..0x1B pattern", bytes(range(28))))
        cases.append(self._case(C, "Empty payload (0 bytes)", b''))
        cases.append(self._case(C, "Single null byte", b'\x00'))

        return cases

    def _gen_state_machine(self):
        C = CATEGORY_STATE_MACHINE
        cases = []
        endpoint = f"opc.tcp://{self.target.ip}:{self.target.port}"

        # Second HEL on active session
        cases.append(self._case(C, "Second HEL on active session", _hel(endpoint)))

        # OPN RENEW on established channel
        opn_renew = _opn_request(seq_num=self._seq + 1, req_id=self._req_id + 1)
        cases.append(self._case(C, "OPN RequestType=RENEW (refresh)", opn_renew))

        # MSG channel_id=0 (no channel established)
        cases.append(self._case(C, "MSG channel_id=0 (no channel)",
            _msg_frame(0, 0, 1, 1, SVC_READ, _read_body(0, 2258, 13))))

        # MSG wrong token_id
        cases.append(self._case(C, "MSG invalid token_id=0xDEADBEEF",
            _msg_frame(self._channel_id, 0xDEADBEEF,
                       self._next_seq(), self._next_req(),
                       SVC_READ, _read_body(0, 2258, 13))))

        # ERR injected by client
        err_body  = struct.pack('<I', 0x80820000)
        err_body += _ua_string("fuzzer error injection")
        cases.append(self._case(C, "ERR frame injected by client",
            _ua_msg_header(b'ERR', b'F', len(err_body)) + err_body))

        # CLO mid-session
        clo_inner  = struct.pack('<I', self._channel_id)
        clo_inner += struct.pack('<I', self._token_id)
        cases.append(self._case(C, "CLO (CloseSecureChannel) mid-session",
            _ua_msg_header(b'CLO', b'F', len(clo_inner)) + clo_inner))

        # OPN body sent inside MSG (type confusion)
        cases.append(self._case(C, "MSG wrapping OPN body (type confusion)",
            _msg_frame(self._channel_id, self._token_id,
                       self._next_seq(), self._next_req(), 446, b'')))

        # CloseSession (terminates session)
        close_body = struct.pack('<B', 1)   # DeleteSubscriptions=True
        cases.append(self._case(C, "CloseSession (terminate active session)",
            self._msg(SVC_CLOSE_SESSION, close_body, req=self._next_req())))

        # Read after CloseSession (post-close access)
        cases.append(self._case(C, "Read after CloseSession (post-close)",
            self._msg(SVC_READ, _read_body(0, 2258, 13), req=self._next_req())))

        # MSG with all-zero symmetric security header
        zz  = b'MSG' + b'F'
        inner = b'\x00' * 16 + _svc_nodeid(SVC_READ) + _request_header() + _read_body(0, 2258, 13)
        zz += struct.pack('<I', 8 + len(inner)) + inner
        cases.append(self._case(C, "MSG all-zero security+sequence headers", zz))

        return cases

    def _gen_sequence(self):
        C = CATEGORY_SEQUENCE
        cases = []

        # SequenceNumber boundary values
        for seqn, label in [
            (0, "seq=0 (restart)"),
            (0xFFFFFFFF, "seq=0xFFFFFFFF (max/wrap)"),
            (1, "seq=1 (replay of initial)"),
            (2, "seq=2 (replay)"),
        ]:
            cases.append(self._case(C, f"MSG {label}",
                _msg_frame(self._channel_id, self._token_id, seqn, 1,
                           SVC_READ, _read_body(0, 2258, 13))))

        # RequestId boundary values
        for reqn, label in [
            (0, "req_id=0"),
            (0xFFFFFFFF, "req_id=0xFFFFFFFF (max)"),
        ]:
            cases.append(self._case(C, f"MSG {label}",
                _msg_frame(self._channel_id, self._token_id, 1, reqn,
                           SVC_READ, _read_body(0, 2258, 13))))

        # Jump forward then backward
        cases.append(self._case(C, "SequenceNumber=0x01000000 (large jump)",
            _msg_frame(self._channel_id, self._token_id, 0x01000000, 10,
                       SVC_READ, _read_body(0, 2258, 13))))
        cases.append(self._case(C, "SequenceNumber=50 (backward after jump)",
            _msg_frame(self._channel_id, self._token_id, 50, 11,
                       SVC_READ, _read_body(0, 2258, 13))))

        # Rapid reads with incrementing sequence
        for i in range(5):
            cases.append(self._case(C, f"Rapid Read seq={200+i}",
                _msg_frame(self._channel_id, self._token_id, 200+i, 200+i,
                           SVC_READ, _read_body(0, 2258, 13))))

        return cases

    def _gen_service_sweep(self):
        C = CATEGORY_SERVICE_SWEEP
        cases = []

        known = {
            420, 423, 426, 429, 435, 438, 446, 449, 452, 455,
            461, 464, 467, 470, 473, 476, 479, 482, 488, 491,
            494, 497, 500, 503, 506, 509, 527, 530, 533, 536,
            552, 555, 558, 561, 564, 567, 570, 573, 576, 579,
            631, 634, 664, 667, 673, 676, 700, 703, 712, 715,
            751, 754, 763, 766, 769, 772, 775, 778, 781, 784,
            787, 790, 793, 796, 800, 803, 806, 809, 812, 815,
            818, 821, 824, 827, 830, 833, 836, 839, 842, 845,
            847, 850, 12208, 12209,
        }

        seq = 500
        for svc_id in range(400, 901):
            if svc_id not in known:
                cases.append(self._case(C, f"Unknown service i={svc_id} (empty body)",
                    _msg_frame(self._channel_id, self._token_id, seq, seq,
                               svc_id, b'', auth_token=self._auth_token)))
                seq += 1

        # Known services with empty body (parser stress)
        for svc_id in [SVC_BROWSE, SVC_READ, SVC_WRITE, SVC_CREATE_SUBSCRIPTION]:
            cases.append(self._case(C, f"Known service i={svc_id} with empty body",
                _msg_frame(self._channel_id, self._token_id, seq, seq,
                           svc_id, b'', auth_token=self._auth_token)))
            seq += 1

        return cases

    def _gen_nodeid_variants(self):
        C = CATEGORY_NODEID_VARIANTS
        cases = []

        variants = [
            (_ua_nodeid_twobyte(0),                  "TwoByte ns=0 id=0 (null)"),
            (_ua_nodeid_twobyte(1),                  "TwoByte ns=0 id=1"),
            (_ua_nodeid_twobyte(0xFF),               "TwoByte ns=0 id=0xFF (max)"),
            (_ua_nodeid_fourbyte(0, 0),              "FourByte ns=0 id=0"),
            (_ua_nodeid_fourbyte(0, 0xFFFF),         "FourByte ns=0 id=0xFFFF (max)"),
            (_ua_nodeid_fourbyte(0xFF, 0x7FFF),      "FourByte ns=0xFF id=0x7FFF"),
            (_ua_nodeid_numeric(0, 0),               "Numeric ns=0 id=0"),
            (_ua_nodeid_numeric(0, 0xFFFFFFFF),      "Numeric ns=0 id=0xFFFFFFFF (max)"),
            (_ua_nodeid_numeric(0xFFFF, 1),          "Numeric ns=0xFFFF id=1 (max ns)"),
            (_ua_nodeid_string(0, ""),               "String ns=0 empty id"),
            (_ua_nodeid_string(0, "A" * 64),         "String ns=0 64-char id"),
            (_ua_nodeid_string(0, "A" * 1024),       "String ns=0 1024-char id (long)"),
            (_ua_nodeid_bytestring(0, b''),          "ByteString ns=0 empty"),
            (_ua_nodeid_bytestring(0, b'\x00' * 16), "ByteString ns=0 16-null bytes"),
        ]

        for node_bytes, label in variants:
            rb  = struct.pack('<d', 0.0)
            rb += struct.pack('<I', 0)
            rb += struct.pack('<I', 1)
            rb += node_bytes
            rb += struct.pack('<I', 13)
            rb += _ua_string(None)
            rb += _ua_qualifiedname_null()
            cases.append(self._case(C, f"Read with NodeId: {label}",
                self._msg(SVC_READ, rb)))

        # Invalid encoding bytes
        for enc in (0x06, 0x10, 0xFF):
            bad = bytes([enc]) + b'\x00' * 8
            rb  = struct.pack('<d', 0.0) + struct.pack('<I', 0) + struct.pack('<I', 1)
            rb += bad + struct.pack('<I', 13) + _ua_string(None) + _ua_qualifiedname_null()
            cases.append(self._case(C, f"Read with invalid NodeId encoding 0x{enc:02X}",
                self._msg(SVC_READ, rb)))

        return cases

    def _gen_subscription_flood(self):
        C = CATEGORY_SUBSCRIPTION
        cases = []

        # Interval variants
        for i, interval in enumerate([0.0, 1.0, 100.0, 500.0, 1000.0, 60000.0,
                                       -1.0, 0.001, 1e15, 1e-15]):
            try:
                body = _create_subscription_body(interval)
                cases.append(self._case(C, f"CreateSubscription interval={interval}ms",
                    self._msg(SVC_CREATE_SUBSCRIPTION, body, req=1000+i)))
            except (struct.error, OverflowError):
                pass

        # Flood: 20 rapid subscriptions
        for i in range(20):
            body = _create_subscription_body(500.0)
            cases.append(self._case(C, f"CreateSubscription flood #{i+1}",
                self._msg(SVC_CREATE_SUBSCRIPTION, body, req=2000+i)))

        # DeleteSubscriptions with non-existent IDs
        for bad_id in [0, 1, 0xFFFF, 0xFFFFFFFF, 9999]:
            body = _delete_subscriptions_body([bad_id])
            cases.append(self._case(C, f"DeleteSubscriptions id={bad_id} (non-existent)",
                self._msg(SVC_DELETE_SUBSCRIPTIONS, body, req=3000+bad_id % 100)))

        return cases

    def _gen_chunked_abuse(self):
        C = CATEGORY_CHUNKED
        cases = []
        valid_body = _read_body(0, 2258, 13)

        def _inner(seq, req):
            i  = struct.pack('<I', self._channel_id)
            i += struct.pack('<I', self._token_id)
            i += struct.pack('<I', seq)
            i += struct.pack('<I', req)
            i += _svc_nodeid(SVC_READ)
            i += _request_header(auth_token=self._auth_token)
            i += valid_body
            return i

        # ChunkType='C' without follow-up 'F'
        inner_c = _inner(1, 1)
        cases.append(self._case(C, "MSG ChunkType='C' (intermediate, no follow-up 'F')",
            _ua_msg_header(b'MSG', b'C', len(inner_c)) + inner_c))

        # ChunkType='A' standalone
        abort_body  = struct.pack('<I', self._channel_id)
        abort_body += struct.pack('<I', self._token_id)
        abort_body += struct.pack('<I', 1) + struct.pack('<I', 1)
        abort_body += struct.pack('<I', 0x80350000)   # BadConnectionClosed
        abort_body += _ua_string("fuzzer abort")
        cases.append(self._case(C, "MSG ChunkType='A' (abort without prior chunk)",
            _ua_msg_header(b'MSG', b'A', len(abort_body)) + abort_body))

        # MessageSize=0
        cases.append(self._case(C, "MSG MessageSize=0 (underflow)",
            b'MSG' + b'F' + struct.pack('<I', 0) + struct.pack('<II', self._channel_id, self._token_id)))

        # MessageSize=0xFFFFFFFF
        cases.append(self._case(C, "MSG MessageSize=0xFFFFFFFF (overflow claim)",
            b'MSG' + b'F' + struct.pack('<I', 0xFFFFFFFF) + struct.pack('<II', self._channel_id, self._token_id)))

        # Valid 'F' then 'C' (reversed order)
        inner_f = _inner(2, 2)
        cases.append(self._case(C, "MSG ChunkType='F' seq=2 (normal final)",
            _ua_msg_header(b'MSG', b'F', len(inner_f)) + inner_f))
        inner_c2 = _inner(3, 2)
        cases.append(self._case(C, "MSG ChunkType='C' seq=3 same req_id (reversed)",
            _ua_msg_header(b'MSG', b'C', len(inner_c2)) + inner_c2))

        # Interleaved chunks: req10 chunk1, req11 chunk1, req10 final
        inner10a = _inner(4, 10)
        inner11a = _inner(5, 11)
        inner10b = _inner(6, 10)
        cases.append(self._case(C, "MSG Chunk C: req10 part1",
            _ua_msg_header(b'MSG', b'C', len(inner10a)) + inner10a))
        cases.append(self._case(C, "MSG Chunk C: req11 interleaved",
            _ua_msg_header(b'MSG', b'C', len(inner11a)) + inner11a))
        cases.append(self._case(C, "MSG Chunk F: req10 final (after interleave)",
            _ua_msg_header(b'MSG', b'F', len(inner10b)) + inner10b))

        return cases

    # ------------------------------------------------------------------
    # Send phase
    # ------------------------------------------------------------------

    def fuzz(self, categories=None) -> list:
        if self._sock is None:
            raise RuntimeError("call connect() before fuzz()")
        cases   = self.generate_cases(categories)
        results = []
        total   = len(cases)
        for i, (case_id, cat, desc, payload) in enumerate(cases, 1):
            print(f"\r[opcua] {i}/{total}  {case_id}  {desc[:55]}", end="", flush=True)
            result = self._send_case(case_id, cat, desc, payload)
            results.append(result)
            if self.logger:
                self.logger.log(result)
            if self.delay:
                time.sleep(self.delay)
        print()
        return results

    # Categories that deliberately corrupt/control SequenceNumber themselves —
    # auto-patching would defeat the point of these tests.
    _SEQ_EXEMPT_CATEGORIES = (CATEGORY_SEQUENCE, CATEGORY_STATE_MACHINE)

    def _patch_sym_seq(self, payload: bytes, category: str) -> bytes:
        """Rewrite the SequenceNumber field of a pre-generated symmetric MSG
        payload to match what the live session actually expects next.

        Cases are built once via generate_cases(), which bakes in a
        placeholder SequenceNumber (typically 1) via the _msg() helper's
        default. That value is only ever correct for the very first
        symmetric message after a fresh handshake — every case after that
        needs the real next-in-sequence number, and every value goes stale
        again after any reconnect.

        self._seq already tracks this correctly: it's incremented once each
        for OPN, CreateSession, and ActivateSession during connect() (all
        three count toward the server's peer_sequence_number, confirmed via
        the server's own asyncua source — there's no separate counter for
        the channel-opening exchange despite what OPC-UA's part 6 spec
        section numbering might suggest), so it already sits at exactly the
        right value to hand to _next_seq() for the first case, and stays
        correct for every case after that. Without this patch the server
        responds "wrong sequence ... spec says to close connection" and
        silently drops every case (confirmed via server-side traceback) —
        this was the actual root cause of the near-100% false-positive
        timeout rate, not a channel/token mismatch as first suspected.
        """
        if category in self._SEQ_EXEMPT_CATEGORIES:
            return payload
        if len(payload) < 20 or payload[:3] != b'MSG':
            return payload
        new_seq = self._next_send_seq()
        return payload[:16] + struct.pack('<I', new_seq) + payload[20:]

    def _send_case(self, case_id: str, category: str,
                   description: str, payload: bytes) -> FuzzResult:
        payload = self._patch_sym_seq(payload, category)
        result = FuzzResult(
            case_id=case_id,
            protocol=self.PROTOCOL_NAME,
            target=f"{self.target.ip}:{self.target.port}",
            category=category,
            description=description,
            payload=payload,
        )
        t0 = time.monotonic()
        try:
            self._sock.sendall(payload)
            data = self._recv_msg()
            result.duration_ms = (time.monotonic() - t0) * 1000
            if data is None:
                result.anomaly         = ANOMALY_TIMEOUT
                result.crash_indicator = True
                self._reconnect()
            elif len(data) == 0:
                result.anomaly         = ANOMALY_NO_RESPONSE
                result.crash_indicator = True
                self._reconnect()
            else:
                result.response = data
                self._classify_response(data, result)
        except (BrokenPipeError, ConnectionResetError, OSError):
            result.anomaly         = ANOMALY_CONNECTION_RESET
            result.crash_indicator = True
            result.duration_ms     = (time.monotonic() - t0) * 1000
            self._reconnect()
        return result

    def _classify_response(self, data: bytes, result: FuzzResult) -> None:
        if len(data) < 8:
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        msg_type = data[:3]
        total    = struct.unpack_from('<I', data, 4)[0]

        if msg_type == b'ERR':
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        if total != len(data):
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        if msg_type not in (b'MSG', b'OPN', b'ACK', b'CLO'):
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        if msg_type == b'ACK':
            return

        if msg_type in (b'MSG', b'OPN') and len(data) >= 24:
            try:
                r = _BufReader(data[8:])
                if msg_type == b'MSG':
                    r.read(8)
                else:  # OPN
                    r.read(4)
                    r.skip_ua_string()
                    r.skip_ua_string()
                    r.skip_ua_string()
                r.read(8)            # Sequence Header
                r.skip_nodeid()      # TypeId
                svc_result = r.skip_response_header()
                if svc_result != SC_GOOD:
                    result.anomaly         = ANOMALY_EXCEPTION
                    result.crash_indicator = False
            except Exception:
                result.anomaly         = ANOMALY_MALFORMED_RESPONSE
                result.crash_indicator = True
