"""IEC 61850 MMS-over-TCP fuzzer module.

Protocol stack (port 102):
  TCP → TPKT (RFC 1006) → ISO COTP Class 0 → ISO Session → ISO Presentation → ACSE → MMS

Connection sequence:
  1. TCP connect
  2. COTP CR  →  COTP CC
  3. TPKT + COTP DT + Session CN + Presentation CP + ACSE AARQ  →  AARE
  4. MMS confirmed service requests (each wrapped in Session DATA + Presentation FCD)

All multi-byte integers are big-endian.
BER encoding: tag + definite-length + value (no indefinite form).
GOOSE (raw Ethernet EtherType 0x88B8) is hardware-required; only PDU
byte-sequences are generated here.
"""

import socket
import struct
import time

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

# ── Extra category constants ───────────────────────────────────────────────────
CATEGORY_SERVICE_SWEEP = "mms_service_sweep"
CATEGORY_ASN1          = "asn1_ber_corruption"
CATEGORY_FRAG          = "pdu_fragmentation"
CATEGORY_ADDR          = "mms_address_sweep"

# COTP PDU type bytes
_COTP_CR = 0xE0
_COTP_CC = 0xD0
_COTP_DT = 0xF0
_COTP_DR = 0x80

# ACSE PDU outer tags
_ACSE_AARQ = 0x60   # APPLICATION 0 CONSTRUCTED
_ACSE_AARE = 0x61   # APPLICATION 1 CONSTRUCTED

# MMS PDU outer tags (context-class, constructed)
_MMS_CONFIRMED_REQ = 0xA0   # confirmedRequestPDU  [0]
_MMS_CONFIRMED_RSP = 0xA1   # confirmedResponsePDU [1]
_MMS_CONFIRMED_ERR = 0xA2   # confirmedErrorPDU    [2]
_MMS_REJECT_PDU    = 0xA4   # rejectPDU            [4] (valid rejection, not a crash)

# MMS service choice tags inside confirmedRequestPDU
_SVC_GETNAMELIST = 0xA1   # [1]
_SVC_IDENTIFY    = 0xA2   # [2]
_SVC_READ        = 0xA4   # [4]
_SVC_WRITE       = 0xA5   # [5]

# ── BER helpers ───────────────────────────────────────────────────────────────

def _ber_len(n: int) -> bytes:
    """BER definite-length encoding."""
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def _ber(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(body)) + body


def _vis(s) -> bytes:
    """VisibleString TLV (tag 0x1A)."""
    b = s.encode() if isinstance(s, str) else bytes(s)
    return _ber(0x1A, b)


# ── TPKT / COTP DT framing ────────────────────────────────────────────────────

def _tpkt(payload: bytes) -> bytes:
    """Wrap MMS PDU in TPKT + COTP DT + Session DATA SPDU + Presentation FULLY-ENCODED-DATA."""
    # Presentation: context-id=3 (MMS) + single-ASN1-type [0] containing the MMS PDU
    inner  = bytes([0x02, 0x01, 0x03]) + _ber(0xA0, payload)
    fcd    = _ber(0x61, _ber(0x30, inner))   # FULLY-ENCODED-DATA [APPLICATION 1]
    # Session DATA SPDU: type=1 (DATA TRANSFER), param-length=0, then user-data tag + len
    body   = bytes([0x01, 0x00, 0x01, 0x00]) + fcd
    cotp_dt = bytes([0x02, 0xF0, 0x80])
    total   = 4 + len(cotp_dt) + len(body)
    return struct.pack('!BBH', 0x03, 0x00, total) + cotp_dt + body


# ── Pre-computed connection sequences ─────────────────────────────────────────

# COTP Connection Request (22 bytes)
COTP_CR = struct.pack('!BBH', 0x03, 0x00, 22) + bytes([
    0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,   # LI=17, CR, DST-REF=0, SRC-REF=1, class=0
    0xC0, 0x01, 0x0A,                            # param: TPDU-size = 1024
    0xC1, 0x02, 0x00, 0x01,                      # param: SRC-TSAP = 1
    0xC2, 0x02, 0x00, 0x01,                      # param: DST-TSAP = 1
])

# Full IEC 61850 MMS association request captured from libiec61850 client:
#   TPKT + COTP DT + ISO Session CN SPDU + ISO Presentation CP PPDU + ACSE AARQ
# The Presentation CP defines two contexts: 1=ACSE (OID 2.1.0.1), 3=MMS (OID 1.0.9506.2.1).
# The AARQ inside uses app-context OID 1.0.9506.2.3 and MMS initiate-RequestPDU [8].
ACSE_AARQ = bytes.fromhex(
    "030000bb02f080"                               # TPKT (len=187) + COTP DT
    "0db2"                                         # Session CN type=13, length=178
    "05061301001601021402000233020001"             # ConnectAcceptItem + SessionReq + CallingSelector
    "34020001"                                     # CalledSessionSelector
    "c19c"                                         # SessionUserData length=156
    "318199"                                       # Presentation SEQUENCE length=153
    "a003800101"                                   # mode-selector [0]: normal mode
    "a28191"                                       # normal-mode-parameters [2] length=145
    "810400000001820400000001"                     # called-psel + calling-psel
    "a423"                                         # context-def-list [4] length=35
    "300f020101060452010001300406025101"           # context 1: ACSE (OID 2.1.0.1 + BER)
    "3010020103060528ca220201300406025101"         # context 3: MMS (OID 1.0.9506.2.1 + BER)
    "615e"                                         # FULLY-ENCODED-DATA [APPLICATION 1] length=94
    "305c020101a057"                               # SEQUENCE, context-id=1, single-ASN1-type [0]
    "6055"                                         # ACSE AARQ [APPLICATION 0] length=85
    "a107060528ca220203"                           # app-context-name OID 1.0.9506.2.3
    "a20706052901876701"                           # called-AP-title OID
    "a30302010c"                                   # called-AE-qualifier = 12
    "a606060429018767"                             # calling-AP-title OID
    "a70302010c"                                   # calling-AE-qualifier = 12
    "be2f282d"                                     # user-information [30] EXTERNAL [40]
    "020103"                                       # indirect-reference = 3
    "a028a826"                                     # encoding [0] + initiate-RequestPDU [8]
    "800300fde8"                                   # localDetailCalling = 65000
    "81010582010583010a"                           # max-outstanding calling/called + nest=10
    "a416"                                         # initRequestDetail [4] length=22
    "800101"                                       # proposedVersion = 1
    "810305f100"                                   # proposedParameterCBB
    "820c03ee1c00000408000079ef18"                # servicesSupportedCalling
)

# ── MMS PDU builders ─────────────────────────────────────────────────────────

def _mms_getnamelist(invoke_id: int = 1, obj_class: int = 9,
                     domain: bytes = None) -> bytes:
    """GetNameList request. obj_class=9 = domain."""
    obj_class_tlv = _ber(0xA0, _ber(0x80, bytes([obj_class & 0xFF])))
    if domain is None:
        scope = _ber(0xA1, bytes([0x80, 0x00]))   # vmdSpecific NULL
    else:
        scope = _ber(0xA1, _ber(0x81, domain))    # domainSpecific identifier
    svc = _ber(_SVC_GETNAMELIST, obj_class_tlv + scope)
    req = _ber(_MMS_CONFIRMED_REQ, bytes([0x02, 0x01, invoke_id & 0xFF]) + svc)
    return _tpkt(req)


def _mms_identify(invoke_id: int = 1) -> bytes:
    """Identify confirmed request (empty service body)."""
    svc = _ber(_SVC_IDENTIFY, b'')
    req = _ber(_MMS_CONFIRMED_REQ, bytes([0x02, 0x01, invoke_id & 0xFF]) + svc)
    return _tpkt(req)


def _parse_mms_identify_response(pdu: bytes) -> tuple:
    """Parse MMS Identify confirmed-response PDU body.

    pdu: starts at the MMS PDU tag byte (0xA1 = confirmedResponsePDU).
    Returns (vendor, model, revision) strings; unknown if not parseable.
    """
    # Extract VISIBLE STRING (0x1A) values from anywhere in the PDU
    strings = []
    pos = 0
    while pos < len(pdu) and len(strings) < 3:
        if pdu[pos] == 0x1A:  # VISIBLE STRING universal tag
            pos += 1
            if pos >= len(pdu):
                break
            tag_len = pdu[pos]
            pos += 1
            if tag_len >= 0x80:
                # Long-form: skip
                extra = tag_len & 0x7F
                pos += extra
                continue
            raw = pdu[pos: pos + tag_len]
            try:
                strings.append(raw.decode("ascii", errors="replace").strip())
            except Exception:
                pass
            pos += tag_len
        else:
            pos += 1
    vendor   = strings[0] if len(strings) > 0 else "unknown"
    model    = strings[1] if len(strings) > 1 else "unknown"
    revision = strings[2] if len(strings) > 2 else "unknown"
    return vendor, model, revision


def _mms_read(invoke_id: int, domain: bytes, item: bytes) -> bytes:
    """Read named variable from a domain."""
    obj_name   = _ber(0xA2, _vis(domain) + _vis(item))   # domainSpecific [2]
    var_spec   = _ber(0xA0, obj_name)                     # name [0]
    list_var   = _ber(0xA0, _ber(0xA0, var_spec))        # listOfVariable [0]
    var_access = _ber(0xA0, list_var)
    svc  = _ber(_SVC_READ, var_access)
    req  = _ber(_MMS_CONFIRMED_REQ, bytes([0x02, 0x01, invoke_id & 0xFF]) + svc)
    return _tpkt(req)


def _mms_write(invoke_id: int, domain: bytes, item: bytes, value: bytes) -> bytes:
    """Write named variable."""
    obj_name   = _ber(0xA2, _vis(domain) + _vis(item))
    var_spec   = _ber(0xA0, obj_name)
    list_var   = _ber(0xA0, _ber(0xA0, var_spec))
    var_access = _ber(0xA0, list_var)
    list_data  = _ber(0xA1, _ber(0xA0, _ber(0x84, value)))  # data [0] = structure, value [4]
    svc  = _ber(_SVC_WRITE, var_access + list_data)
    req  = _ber(_MMS_CONFIRMED_REQ, bytes([0x02, 0x01, invoke_id & 0xFF]) + svc)
    return _tpkt(req)


def _mms_svc_sweep(invoke_id: int, svc_tag: int) -> bytes:
    """MMS confirmed request with arbitrary service choice tag, empty body."""
    svc = bytes([svc_tag, 0x00])
    req = _ber(_MMS_CONFIRMED_REQ, bytes([0x02, 0x01, invoke_id & 0xFF]) + svc)
    return _tpkt(req)


# ── TPKT reader ───────────────────────────────────────────────────────────────

def _extract_mms_pdu(raw: bytes) -> bytes:
    """Strip TPKT/COTP DT/Session DATA/Presentation headers; return bare MMS PDU bytes."""
    if not raw or len(raw) < 8:
        return raw
    pos = 7  # skip TPKT (4) + COTP DT (3)
    # Session DATA SPDU: 01 00 01 00
    if pos + 3 < len(raw) and raw[pos] == 0x01 and raw[pos + 1] == 0x00:
        pos += 4
    # FULLY-ENCODED-DATA [APPLICATION 1] = 0x61
    if pos < len(raw) and raw[pos] == 0x61:
        pos += 1
        pos = _skip_ber_len(raw, pos)
    else:
        return raw[pos:]
    # SEQUENCE 0x30
    if pos < len(raw) and raw[pos] == 0x30:
        pos += 1
        pos = _skip_ber_len(raw, pos)
    # context-id: 02 01 03
    if pos + 2 < len(raw) and raw[pos:pos + 3] == b'\x02\x01\x03':
        pos += 3
    # single-ASN1-type [0] = 0xa0
    if pos < len(raw) and raw[pos] == 0xa0:
        pos += 1
        pos = _skip_ber_len(raw, pos)
    return raw[pos:] if pos < len(raw) else raw[7:]


def _skip_ber_len(buf: bytes, pos: int) -> int:
    """Advance pos past one BER length field; return new pos."""
    if pos >= len(buf):
        return pos
    b = buf[pos]
    pos += 1
    if b & 0x80:
        pos += b & 0x7F
    return pos


def _recv_tpkt(sock: socket.socket, timeout: float = 5.0):
    """
    Read one complete TPKT frame.
    Returns bytes on success, None on timeout, b'' on connection close/error.
    """
    sock.settimeout(timeout)
    try:
        hdr = b''
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                return b''
            hdr += chunk
        if hdr[0] != 0x03:
            return hdr   # malformed — caller classifies
        claimed = struct.unpack('!H', hdr[2:4])[0]
        rest    = claimed - 4
        if rest <= 0:
            return hdr
        body = b''
        while len(body) < rest:
            chunk = sock.recv(min(rest - len(body), 65536))
            if not chunk:
                break
            body += chunk
        return hdr + body
    except socket.timeout:
        return None
    except (ConnectionResetError, OSError):
        return b''


# ── Fuzzer ────────────────────────────────────────────────────────────────────

class Iec61850Fuzzer(FuzzModule):
    """IEC 61850 MMS over TCP fuzzer (port 102).

    8 categories targeting TPKT/COTP/ACSE/MMS stack in pure Python stdlib.
    GOOSE raw-Ethernet cases produce PDU byte sequences only; actual
    transmission requires CAP_NET_RAW (hardware phase).
    """

    PROTOCOL_NAME   = "iec61850"
    DEFAULT_PORT    = 102
    FUZZ_CATEGORIES = [
        CATEGORY_BOUNDARY,
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_SEQUENCE,
        CATEGORY_STATE_MACHINE,
        CATEGORY_SERVICE_SWEEP,
        CATEGORY_ASN1,
        CATEGORY_FRAG,
        CATEGORY_ADDR,
    ]

    def __init__(self, target: Device, logger, delay: float = 0.0, seeds: list = None):
        super().__init__(target=target, logger=logger, delay=delay, seeds=seeds)
        self._sock   = None
        self._invoke = 0

    # ── helpers ───────────────────────────────────────────────────────────────

    def _nxt(self) -> int:
        self._invoke = (self._invoke + 1) & 0xFF
        return self._invoke

    def _raw_send_recv(self, payload: bytes, timeout: float = 5.0):
        if self._sock is None:
            raise RuntimeError("call connect() before fuzz()")
        try:
            self._sock.sendall(payload)
        except (BrokenPipeError, OSError):
            return b''
        return _recv_tpkt(self._sock, timeout)

    # ── public API ────────────────────────────────────────────────────────────

    def connect(self, target=None) -> None:
        if target is not None:
            self.target = target
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((self.target.ip, self.target.port))
        self._sock   = s
        self._invoke = 0

        # COTP handshake
        s.sendall(COTP_CR)
        cc = _recv_tpkt(s, timeout=5.0)
        if not cc or len(cc) < 6 or cc[5] != _COTP_CC:
            raise ConnectionError(f"COTP CC not received (got {cc!r})")

        # ACSE handshake (response contains Session ACCEPT + Presentation + ACSE AARE)
        s.sendall(ACSE_AARQ)
        aare = _recv_tpkt(s, timeout=5.0)
        if not aare or len(aare) < 8:
            raise ConnectionError("ACSE AARE not received")
        if _ACSE_AARE not in aare:
            raise ConnectionError("AARE (0x61) not found in association response")

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock   = None
            self._invoke = 0

    def fuzz(self, categories=None) -> list:
        if self._sock is None:
            raise RuntimeError("call connect() before fuzz()")
        cats    = self._resolve_categories(categories)
        cases   = self.generate_cases(cats)
        results = []
        for case_id, cat, desc, payload in cases:
            r = self._send_case(case_id, cat, desc, payload)
            if self.logger:
                self.logger.log(r)
            results.append(r)
            if r.crash_indicator and self._sock is None:
                try:
                    self.connect()
                except Exception:
                    pass
            if self.delay:
                time.sleep(self.delay)
        return results

    # ── generator ─────────────────────────────────────────────────────────────

    def generate_cases(self, categories=None):
        cats   = self._resolve_categories(categories)
        cases  = []
        inv    = [0]

        def nxt():
            inv[0] = (inv[0] + 1) & 0xFF
            return inv[0]

        def add(cat, desc, payload):
            cases.append((self._next_id(), cat, desc, payload))

        # ── boundary ─────────────────────────────────────────────────────────
        if CATEGORY_BOUNDARY in cats:
            cls_names = {
                0: "namedVariable", 1: "scatteredAccess", 2: "namedVariableList",
                3: "namedType",     4: "semaphore",       5: "eventCondition",
                6: "eventAction",   7: "eventEnrollment", 8: "journal",
                9: "domain",       10: "programInvocation", 11: "operatorStation",
            }
            for c, name in cls_names.items():
                add(CATEGORY_BOUNDARY, f"GetNameList objectClass={name}({c}) vmdSpecific",
                    _mms_getnamelist(nxt(), c))

            add(CATEGORY_BOUNDARY, "GetNameList domainSpecific ICS_FUZZER_TARGET",
                _mms_getnamelist(nxt(), 9, b"ICS_FUZZER_TARGET"))
            add(CATEGORY_BOUNDARY, "GetNameList domainSpecific empty domain",
                _mms_getnamelist(nxt(), 9, b""))
            add(CATEGORY_BOUNDARY, "Identify request",
                _mms_identify(nxt()))

            for domain, item in [
                (b"ICS_FUZZER_TARGET", b"LLN0$DC$NamPlt"),
                (b"ICS_FUZZER_TARGET", b"XCBR1$CO$Pos$Oper"),
                (b"ICS_FUZZER_TARGET", b"MMXU1$MX$A$phsA$instMag$f"),
                (b"ICS_FUZZER_TARGET", b"LLN0$GO$GoCB01$GoEna"),
            ]:
                add(CATEGORY_BOUNDARY,
                    f"Read {domain.decode()}/{item.decode()}",
                    _mms_read(nxt(), domain, item))

            add(CATEGORY_BOUNDARY, "Write XCBR1 Oper (expect ServiceError)",
                _mms_write(nxt(), b"ICS_FUZZER_TARGET",
                           b"XCBR1$CO$Pos$Oper", bytes([0x01])))

            add(CATEGORY_BOUNDARY, "GetNameList invoke_id=0xFF",
                _mms_getnamelist(0xFF, 9))
            add(CATEGORY_BOUNDARY, "GetNameList invoke_id=0x00",
                _mms_getnamelist(0x00, 9))
            add(CATEGORY_BOUNDARY, "GetNameList domain len=64 (IEC 61850 max)",
                _mms_getnamelist(nxt(), 9, b"A" * 64))
            add(CATEGORY_BOUNDARY, "GetNameList domain len=65 (over limit)",
                _mms_getnamelist(nxt(), 9, b"A" * 65))

        # ── binary_corruption ─────────────────────────────────────────────────
        if CATEGORY_BINARY_CORRUPTION in cats:
            baseline = _mms_getnamelist(1, 9)

            for i, desc in [
                (0, "TPKT version byte"),
                (2, "TPKT length high byte"),
                (3, "TPKT length low byte"),
                (4, "COTP LI"),
                (5, "COTP PDU type"),
                (6, "COTP EOT flag"),
                (7, "MMS outer tag"),
                (8, "MMS outer length"),
            ]:
                b = bytearray(baseline)
                if i < len(b):
                    b[i] ^= 0xFF
                add(CATEGORY_BINARY_CORRUPTION, f"Flip byte[{i}]: {desc}", bytes(b))

            for cut in [4, 7, 9, 12, 15, 18, 20]:
                add(CATEGORY_BINARY_CORRUPTION, f"Truncate PDU at byte {cut}",
                    baseline[:cut] if cut < len(baseline) else baseline)

            acse_zap = bytearray(ACSE_AARQ)
            for i in range(7, len(acse_zap)):
                acse_zap[i] = 0x00
            add(CATEGORY_BINARY_CORRUPTION, "Zero-fill ACSE AARQ body", bytes(acse_zap))

            mid = len(baseline) // 2
            add(CATEGORY_BINARY_CORRUPTION, "Insert 0xFF x4 mid-PDU",
                baseline[:mid] + bytes([0xFF] * 4) + baseline[mid:])

            for xv, label in [(0xAA, "0xAA"), (0x55, "0x55"), (0x00, "0x00")]:
                b = bytearray(baseline)
                for i in range(7, len(b)):
                    b[i] = xv
                add(CATEGORY_BINARY_CORRUPTION, f"Fill MMS body with {label}", bytes(b))

            for bad_tag in [0x00, 0x61, 0xFF, 0x40]:
                b = bytearray(ACSE_AARQ)
                if len(b) > 7:
                    b[7] = bad_tag
                add(CATEGORY_BINARY_CORRUPTION,
                    f"ACSE AARQ outer tag replaced with 0x{bad_tag:02X}", bytes(b))

            b = bytearray(baseline)
            b[4:7] = bytes([0x00, 0x00, 0x00])
            add(CATEGORY_BINARY_CORRUPTION, "Zero COTP DT header bytes", bytes(b))

            for inv_val in [0x00, 0x7F, 0x80, 0xFF]:
                b = bytearray(baseline)
                if len(b) > 12:
                    b[12] = inv_val
                add(CATEGORY_BINARY_CORRUPTION,
                    f"MMS invokeID byte overwritten with 0x{inv_val:02X}", bytes(b))

        # ── sequence ──────────────────────────────────────────────────────────
        if CATEGORY_SEQUENCE in cats:
            baseline = _mms_getnamelist(1, 9)

            add(CATEGORY_SEQUENCE, "Raw MMS body without TPKT+COTP framing",
                baseline[7:])   # strip the 4+3-byte header

            add(CATEGORY_SEQUENCE, "ACSE AARQ without prior COTP CR",
                ACSE_AARQ)

            add(CATEGORY_SEQUENCE, "COTP CR again mid-session (re-connect attempt)",
                COTP_CR)

            add(CATEGORY_SEQUENCE, "Duplicate ACSE AARQ mid-session", ACSE_AARQ)

            # Pipelined: two MMS PDUs concatenated
            add(CATEGORY_SEQUENCE, "GetNameList + Identify back-to-back (pipelined)",
                _mms_getnamelist(1, 9) + _mms_identify(2))

            for i_id in [0xFF, 0x00, 0x01]:
                add(CATEGORY_SEQUENCE,
                    f"GetNameList invoke_id regression to 0x{i_id:02X}",
                    _mms_getnamelist(i_id, 9))

            # COTP DR + MMS
            cotp_dr = struct.pack('!BBH', 3, 0, 11) + bytes([
                0x06, _COTP_DR, 0x00, 0x01, 0x00, 0x00, 0x00,
            ])
            add(CATEGORY_SEQUENCE, "Send COTP DR then MMS GetNameList",
                cotp_dr + _mms_getnamelist(1, 9))

            add(CATEGORY_SEQUENCE, "COTP DT with empty payload", _tpkt(b''))

            for i in range(1, 4):
                add(CATEGORY_SEQUENCE, f"GetNameList burst request #{i}",
                    _mms_getnamelist(i, 9))

        # ── state_machine ─────────────────────────────────────────────────────
        if CATEGORY_STATE_MACHINE in cats:
            for cls_byte in [0x10, 0x20, 0x30, 0xF0]:
                b = bytearray(COTP_CR)
                if len(b) > 10:
                    b[10] = cls_byte
                add(CATEGORY_STATE_MACHINE,
                    f"COTP CR class byte = 0x{cls_byte:02X} (non-zero)", bytes(b))

            cotp_cr_bare = struct.pack('!BBH', 3, 0, 7) + bytes([
                0x02, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
            ])
            add(CATEGORY_STATE_MACHINE, "COTP CR with no optional parameters", cotp_cr_bare)

            b = bytearray(COTP_CR)
            if len(b) > 18:
                b[17] = 0xAB; b[18] = 0xCD
            add(CATEGORY_STATE_MACHINE, "COTP CR wrong DST-TSAP (0xABCD)", bytes(b))

            for bad_ver in [0x00, 0x01, 0x02, 0xFF]:
                b = bytearray(COTP_CR)
                b[0] = bad_ver
                add(CATEGORY_STATE_MACHINE,
                    f"TPKT version = 0x{bad_ver:02X} (not 0x03)", bytes(b))

            add(CATEGORY_STATE_MACHINE, "TPKT header only (4 bytes, no payload)",
                bytes([0x03, 0x00, 0x00, 0x04]))

            oid_pattern = bytes([0x28, 0xCA, 0x22, 0x02, 0x01])
            oid_offset  = ACSE_AARQ.find(oid_pattern)
            b = bytearray(ACSE_AARQ)
            if oid_offset >= 0:
                for i, v in enumerate([0xFF, 0xFF, 0xFF, 0xFF, 0xFF]):
                    b[oid_offset + i] = v
            add(CATEGORY_STATE_MACHINE, "ACSE AARQ unknown application context OID",
                bytes(b))

            be_off = ACSE_AARQ.find(bytes([0xBE]))
            b = bytearray(ACSE_AARQ)
            if be_off >= 0 and be_off + 1 < len(b):
                b[be_off + 1] = 0x00
            add(CATEGORY_STATE_MACHINE, "ACSE AARQ zero-length user-information",
                bytes(b))

        # ── mms_service_sweep ─────────────────────────────────────────────────
        if CATEGORY_SERVICE_SWEEP in cats:
            for svc_tag in range(0xA0, 0xC0):
                add(CATEGORY_SERVICE_SWEEP,
                    f"MMS service choice sweep tag=0x{svc_tag:02X}",
                    _mms_svc_sweep(nxt(), svc_tag))
            for svc_tag in range(0x80, 0x90):
                add(CATEGORY_SERVICE_SWEEP,
                    f"MMS primitive service choice tag=0x{svc_tag:02X}",
                    _mms_svc_sweep(nxt(), svc_tag))

        # ── asn1_ber_corruption ───────────────────────────────────────────────
        if CATEGORY_ASN1 in cats:
            baseline = _mms_getnamelist(1, 9)

            # Indefinite-length form (0x80 as length byte)
            indef = bytearray(baseline)
            if len(indef) > 8:
                indef[8] = 0x80
                indef += bytes([0x00, 0x00])
            add(CATEGORY_ASN1, "BER indefinite length on MMS outer tag", bytes(indef))

            # 4-byte long-form length
            inner_len = len(baseline) - 9
            lf_len = bytes([0x84, 0x00, 0x00, 0x00, inner_len & 0xFF])
            lf = bytearray(baseline[:8]) + bytearray(lf_len) + bytearray(baseline[9:])
            add(CATEGORY_ASN1, "BER 4-byte long-form length field", bytes(lf))

            for extra in [1, 10, 100, 0xFF]:
                b = bytearray(baseline)
                if len(b) > 8:
                    b[8] = (baseline[8] + extra) & 0xFF
                add(CATEGORY_ASN1, f"BER claimed length+{extra} (overflow)", bytes(b))

            add(CATEGORY_ASN1, "MMS confirmedRequestPDU length=0",
                _tpkt(bytes([_MMS_CONFIRMED_REQ, 0x00])))

            for tag in [0x1F, 0x3F, 0x5F, 0x7F]:
                add(CATEGORY_ASN1, f"Unknown universal tag 0x{tag:02X} as MMS PDU",
                    _tpkt(bytes([tag, 0x02, 0x01, 0x01])))

            for tag in [0x40, 0x41, 0x5F, 0x7E]:
                add(CATEGORY_ASN1, f"APPLICATION class tag 0x{tag:02X}",
                    _tpkt(bytes([tag, 0x02, 0xFF, 0xFF])))

            add(CATEGORY_ASN1, "Nested BER length overflow (inner len=0xFF)",
                _tpkt(_ber(_MMS_CONFIRMED_REQ,
                           bytes([0xA0, 0xFF, 0x02, 0x01, 0x01]))))

            add(CATEGORY_ASN1, "INTEGER with constructed bit set (tag=0x22)",
                _tpkt(bytes([_MMS_CONFIRMED_REQ, 0x05,
                             0x22, 0x01, 0x01, _SVC_IDENTIFY, 0x00])))

            add(CATEGORY_ASN1, "INTEGER with redundant leading zeros",
                _tpkt(_ber(_MMS_CONFIRMED_REQ,
                           bytes([0x02, 0x04, 0x00, 0x00, 0x00, 0x01]) +
                           _ber(_SVC_IDENTIFY, b''))))

            add(CATEGORY_ASN1, "OID tag with length=255 (0x81 0xFF) overrun",
                _tpkt(bytes([0x06, 0x81, 0xFF] + [0x81] * 50)))

        # ── pdu_fragmentation ─────────────────────────────────────────────────
        if CATEGORY_FRAG in cats:
            baseline = _mms_getnamelist(1, 9)

            for extra in [1, 10, 100, 1000]:
                b = bytearray(baseline)
                claimed = min(len(baseline) + extra, 0xFFFF)
                struct.pack_into('!H', b, 2, claimed)
                add(CATEGORY_FRAG, f"TPKT claimed_len+{extra} (truncated payload)",
                    bytes(b))

            add(CATEGORY_FRAG, "TPKT length=4 (no COTP or MMS payload)",
                bytes([0x03, 0x00, 0x00, 0x04]))

            add(CATEGORY_FRAG, "TPKT length=0",
                bytes([0x03, 0x00, 0x00, 0x00]))

            add(CATEGORY_FRAG, "TPKT length=3 (below minimum header)",
                bytes([0x03, 0x00, 0x00, 0x03]))

            b = bytearray(baseline); b[4] = 0x00
            add(CATEGORY_FRAG, "COTP LI=0 (zero length indicator)", bytes(b))

            b = bytearray(baseline); b[4] = 0xFF
            add(CATEGORY_FRAG, "COTP LI=0xFF (overflows frame)", bytes(b))

            add(CATEGORY_FRAG, "TPKT claiming 65535 bytes (max uint16)",
                bytes([0x03, 0x00, 0xFF, 0xFF]))

            add(CATEGORY_FRAG, "Duplicate identical MMS TPKT (back-to-back)",
                baseline + baseline)

            half = len(baseline) // 2
            first_half = bytearray(baseline[:half])
            struct.pack_into('!H', first_half, 2, half)
            add(CATEGORY_FRAG, "First half of MMS PDU re-framed as its own TPKT",
                bytes(first_half))

        # ── mms_address_sweep ─────────────────────────────────────────────────
        if CATEGORY_ADDR in cats:
            for domain in [
                b"",
                b"\x00",
                b"A" * 64,
                b"A" * 128,
                b"\xFF" * 8,
                b"../../../etc/passwd",
                b"$LN0",
            ]:
                add(CATEGORY_ADDR,
                    f"GetNameList domain={repr(domain)[:25]}",
                    _mms_getnamelist(nxt(), 9, domain))

            for domain, item in [
                (b"ICS_FUZZER_TARGET", b"LLN0$DC$NamPlt$vendor"),
                (b"ICS_FUZZER_TARGET", b"\x00" * 4),
                (b"ICS_FUZZER_TARGET", b"X" * 128),
                (b"ICS_FUZZER_TARGET", b"XCBR1$ST$Pos$stVal"),
                (b"ICS_FUZZER_TARGET", b"MMXU1$MX$A$phsA$instMag$f"),
                (b"ICS_FUZZER_TARGET", b"\xFF\xFE\xFD"),
            ]:
                add(CATEGORY_ADDR,
                    f"Read {domain.decode(errors='replace')}/{repr(item)[:20]}",
                    _mms_read(nxt(), domain, item))

            add(CATEGORY_ADDR, "Write empty-value payload",
                _mms_write(nxt(), b"ICS_FUZZER_TARGET", b"LLN0$DC$NamPlt", b""))

            # GetNameList with continueAfter parameter (pagination)
            cont          = b"Z" * 64
            obj_class_tlv = _ber(0xA0, _ber(0x80, bytes([9])))
            scope         = _ber(0xA1, bytes([0x80, 0x00]))
            after         = _ber(0x82, cont)
            body          = obj_class_tlv + scope + after
            svc           = _ber(_SVC_GETNAMELIST, body)
            req           = _ber(_MMS_CONFIRMED_REQ,
                                 bytes([0x02, 0x01, nxt()]) + svc)
            add(CATEGORY_ADDR, "GetNameList continueAfter max-length identifier",
                _tpkt(req))

        return cases

    # ── send / classify ───────────────────────────────────────────────────────

    def _send_case(self, case_id: str, category: str, description: str,
                   payload: bytes) -> FuzzResult:
        t0   = time.monotonic()
        resp = self._raw_send_recv(payload)
        dur  = round((time.monotonic() - t0) * 1000, 2)

        anomaly, crash = self._classify_response(resp)
        if crash:
            self.close()

        return FuzzResult(
            case_id=case_id,
            protocol=self.PROTOCOL_NAME,
            target=f"{self.target.ip}:{self.target.port}",
            category=category,
            description=description,
            payload=payload,
            response=resp if resp else b'',
            anomaly=anomaly,
            crash_indicator=crash,
            duration_ms=dur,
        )

    def _classify_response(self, resp) -> tuple:
        if resp is None:
            return ANOMALY_TIMEOUT, True
        if resp == b'':
            return ANOMALY_CONNECTION_RESET, True
        if len(resp) < 4:
            return ANOMALY_MALFORMED_RESPONSE, True
        if resp[0] != 0x03:
            return ANOMALY_MALFORMED_RESPONSE, True
        claimed = struct.unpack('!H', resp[2:4])[0]
        if claimed != len(resp):
            return ANOMALY_MALFORMED_RESPONSE, True
        if len(resp) < 8:
            return ANOMALY_MALFORMED_RESPONSE, True
        if resp[5] == _COTP_DR:
            return ANOMALY_CONNECTION_RESET, True
        if resp[5] != _COTP_DT:
            return ANOMALY_MALFORMED_RESPONSE, True
        mms = _extract_mms_pdu(resp)
        if not mms:
            return ANOMALY_MALFORMED_RESPONSE, True
        mms_tag = mms[0]
        if mms_tag == _MMS_CONFIRMED_RSP:
            return None, False
        if mms_tag in (_MMS_CONFIRMED_ERR, _MMS_REJECT_PDU):
            return ANOMALY_EXCEPTION, False
        return ANOMALY_MALFORMED_RESPONSE, True

    # ── discover (hardware phase) ─────────────────────────────────────────────

    def discover(self, interface: str, timeout: int = 30) -> list:
        raise NotImplementedError("IEC 61850 discovery not yet implemented.")

    def fingerprint(self, active: bool = True) -> "FingerprintResult":
        """IEC 61850 MMS fingerprint.

        Passive: OUI lookup from ARP cache.
        Active:  open TPKT/COTP/ACSE session, send MMS Identify request (service 0xA2),
                 parse the confirmed-response PDU for vendorName, modelName, revision.
        """
        from core.fingerprint import FingerprintResult, fingerprint_from_oui

        oui_result = fingerprint_from_oui(self.target.ip)
        if not active:
            return oui_result

        # Establish a fresh TPKT/COTP/ACSE session and send MMS Identify
        vendor   = "unknown"
        model    = "unknown"
        firmware = "unknown"
        resp = None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(4.0)
            s.connect((self.target.ip, self.target.port))
            s.sendall(COTP_CR)
            cc = _recv_tpkt(s, 4.0)
            if not cc or len(cc) < 6 or cc[5] != 0xD0:  # COTP CC
                return oui_result
            s.sendall(ACSE_AARQ)
            aare = _recv_tpkt(s, 4.0)
            # Verify AARE (0x61) present AND result = accepted (A2 03 02 01 00).
            if (not aare or len(aare) < 8 or _ACSE_AARE not in aare
                    or b'\xA2\x03\x02\x01\x00' not in aare):
                return oui_result
            s.sendall(_mms_identify(invoke_id=1))
            resp = _recv_tpkt(s, 4.0)
        except OSError:
            return oui_result
        finally:
            s.close()

        if not resp or len(resp) < 10:
            return oui_result

        mms = _extract_mms_pdu(resp)
        if not mms or mms[0] != _MMS_CONFIRMED_RSP:
            return oui_result

        vendor, model, firmware = _parse_mms_identify_response(mms)
        confidence = "high" if vendor != "unknown" and model != "unknown" else "medium"
        result = FingerprintResult(
            vendor=vendor,
            model=model,
            firmware=firmware,
            confidence=confidence,
            method="iec61850_mms_identify",
        )
        if oui_result.is_known():
            result.extra["oui_vendor"] = oui_result.vendor
        return result
