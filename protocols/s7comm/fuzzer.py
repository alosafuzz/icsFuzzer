"""Siemens S7comm fuzzer — ISO-on-TCP port 102.

Transport stack: TCP → TPKT (RFC 1006) → ISO COTP Class 0 → S7 PDU.

Connection sequence:
  1. TCP connect
  2. TPKT + COTP CR  →  TPKT + COTP CC
  3. TPKT + COTP DT + S7 Setup Communication  →  S7 Ack_Data

References:
  Wireshark packet-s7comm.c
  Bihlmaier 2011 — "Protocols in Industrial Automation Systems"
  pyad (snap7 Python wrapper) source
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
# Protocol-specific categories
# ---------------------------------------------------------------------------

CATEGORY_PDU_NEGOTIATION = "pdu_negotiation"
CATEGORY_READ_WRITE      = "read_write"
CATEGORY_SZL_READ        = "szl_read"
CATEGORY_CPU_CONTROL     = "cpu_control"

# ---------------------------------------------------------------------------
# COTP PDU types
# ---------------------------------------------------------------------------

_COTP_CR = 0xE0   # Connection Request
_COTP_CC = 0xD0   # Connection Confirm
_COTP_DT = 0xF0   # Data Transfer

# ---------------------------------------------------------------------------
# S7 ROSCTR values
# ---------------------------------------------------------------------------

_ROSCTR_JOB       = 0x01   # request
_ROSCTR_ACK       = 0x02   # acknowledgement (no data)
_ROSCTR_ACK_DATA  = 0x03   # acknowledgement with data
_ROSCTR_USERDATA  = 0x07   # userdata (SZL reads etc.)

# ---------------------------------------------------------------------------
# S7 function codes (parameter byte 0)
# ---------------------------------------------------------------------------

_FC_SETUP_COMM  = 0xF0
_FC_READ_VAR    = 0x04
_FC_WRITE_VAR   = 0x05
_FC_PI_SERVICE  = 0x28
_FC_PLC_STOP    = 0x29

# ---------------------------------------------------------------------------
# S7 variable item areas
# ---------------------------------------------------------------------------

AREA_INPUTS    = 0x81
AREA_OUTPUTS   = 0x82
AREA_FLAGS     = 0x83   # merker (M)
AREA_DB        = 0x84   # data block
AREA_LOCAL     = 0x1C

# ---------------------------------------------------------------------------
# Common TSAP values for S7 PLCs
# ---------------------------------------------------------------------------

_COMMON_TSAPS = [
    (0x0100, 0x0200),
    (0x0100, 0x0201),
    (0x0100, 0x0202),
    (0x0100, 0x0300),
    (0x0100, 0x0301),
    (0x0100, 0x0302),
    (0x0101, 0x0200),
    (0x0101, 0x0201),
]

# ---------------------------------------------------------------------------
# Wire-level builders
# ---------------------------------------------------------------------------

def _tpkt(payload: bytes) -> bytes:
    """Wrap in TPKT header (4 bytes, big-endian length)."""
    return struct.pack('!BBH', 0x03, 0x00, 4 + len(payload)) + payload


def _cotp_dt(payload: bytes) -> bytes:
    """Wrap in COTP DT header (02 F0 80)."""
    return bytes([0x02, _COTP_DT, 0x80]) + payload


def _s7_pkt(s7_payload: bytes) -> bytes:
    """Wrap S7 PDU in TPKT + COTP DT."""
    return _tpkt(_cotp_dt(s7_payload))


def _cotp_cr(src_tsap: int = 0x0100, dst_tsap: int = 0x0200) -> bytes:
    """Build TPKT + COTP Connection Request with TSAP params."""
    cotp = bytes([
        0x11, _COTP_CR,        # LI=17, CR
        0x00, 0x00,            # DST-REF = 0
        0x00, 0x01,            # SRC-REF = 1
        0x00,                  # class 0
        0xC0, 0x01, 0x0A,      # TPDU-size = 1024
        0xC1, 0x02,            # calling TSAP tag + length=2
    ]) + struct.pack('!H', src_tsap) + bytes([
        0xC2, 0x02,            # called TSAP tag + length=2
    ]) + struct.pack('!H', dst_tsap)
    return _tpkt(cotp)


def _s7_header(rosctr: int = _ROSCTR_JOB, pdu_ref: int = 1,
               param_len: int = 0, data_len: int = 0) -> bytes:
    """Build 10-byte S7 PDU header."""
    return bytes([0x32, rosctr, 0x00, 0x00]) + \
           struct.pack('!HHH', pdu_ref, param_len, data_len)


def _s7_setup_comm(pdu_ref: int = 1, max_amq: int = 1,
                   pdu_len: int = 480) -> bytes:
    """S7 Setup Communication request wrapped in TPKT+COTP-DT."""
    param = bytes([_FC_SETUP_COMM, 0x00]) + struct.pack('!HHH', max_amq, max_amq, pdu_len)
    hdr   = _s7_header(rosctr=_ROSCTR_JOB, pdu_ref=pdu_ref,
                       param_len=len(param), data_len=0)
    return _s7_pkt(hdr + param)


def _s7_read_var(area: int = AREA_DB, db_num: int = 1, address: int = 0,
                 count: int = 1, transport_size: int = 0x04,
                 pdu_ref: int = 1) -> bytes:
    """S7 Read Variable request for a single item."""
    # Variable item (12 bytes): ANY syntax
    item = bytes([0x12, 0x0A, 0x10, transport_size]) + \
           struct.pack('!HH', count, db_num) + \
           bytes([area]) + struct.pack('!I', address << 3)[1:]   # byte addr × 8 in 3B BE
    param = bytes([_FC_READ_VAR, 0x01]) + item  # function + num_items=1
    hdr   = _s7_header(rosctr=_ROSCTR_JOB, pdu_ref=pdu_ref,
                       param_len=len(param), data_len=0)
    return _s7_pkt(hdr + param)


def _s7_write_var(area: int = AREA_DB, db_num: int = 1, address: int = 0,
                  count: int = 1, data: bytes = b'\x00\x00',
                  transport_size: int = 0x04, pdu_ref: int = 1) -> bytes:
    """S7 Write Variable request."""
    item  = bytes([0x12, 0x0A, 0x10, transport_size]) + \
            struct.pack('!HH', count, db_num) + \
            bytes([area]) + struct.pack('!I', address << 3)[1:]
    param = bytes([_FC_WRITE_VAR, 0x01]) + item
    # Data section: return_code(0x00) + transport_size_type(0x04=BYTE) + data_len_bits(2B BE)
    data_bits = len(data) * 8
    data_sec  = bytes([0x00, 0x04]) + struct.pack('!H', data_bits) + data
    hdr   = _s7_header(rosctr=_ROSCTR_JOB, pdu_ref=pdu_ref,
                       param_len=len(param), data_len=len(data_sec))
    return _s7_pkt(hdr + param + data_sec)


def _s7_szl_read(szl_id: int = 0x0011, szl_index: int = 0x0000,
                 pdu_ref: int = 1) -> bytes:
    """S7 UserData SZL (System Status List) read request."""
    param = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
    data  = bytes([0xFF, 0x09]) + struct.pack('!H', 4) + \
            struct.pack('!HH', szl_id, szl_index)
    hdr   = _s7_header(rosctr=_ROSCTR_USERDATA, pdu_ref=pdu_ref,
                       param_len=len(param), data_len=len(data))
    return _s7_pkt(hdr + param + data)


def _s7_plc_stop(pdu_ref: int = 1) -> bytes:
    """S7 PLC Stop request (ROSCTR=Job, FC=0x29)."""
    param = bytes([_FC_PLC_STOP, 0x00, 0x00, 0x00, 0x00, 0x00])
    hdr   = _s7_header(rosctr=_ROSCTR_JOB, pdu_ref=pdu_ref,
                       param_len=len(param), data_len=0)
    return _s7_pkt(hdr + param)


def _s7_pi_service(pi_name: bytes = b'_INSE', pdu_ref: int = 1) -> bytes:
    """S7 PI-Service request (ROSCTR=Job, FC=0x28)."""
    # PI service: service-param + service-name
    name_len = len(pi_name)
    param = bytes([_FC_PI_SERVICE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + \
            struct.pack('!H', name_len) + pi_name
    hdr   = _s7_header(rosctr=_ROSCTR_JOB, pdu_ref=pdu_ref,
                       param_len=len(param), data_len=0)
    return _s7_pkt(hdr + param)


# ---------------------------------------------------------------------------
# S7commFuzzer
# ---------------------------------------------------------------------------

class S7commFuzzer(FuzzModule):
    """Siemens S7comm fuzzer — TCP port 102, TPKT+COTP+S7 transport."""

    PROTOCOL_NAME   = "s7comm"
    DEFAULT_PORT    = 102
    FUZZ_CATEGORIES = [
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_STATE_MACHINE,
        CATEGORY_SEQUENCE,
        CATEGORY_PDU_NEGOTIATION,
        CATEGORY_READ_WRITE,
        CATEGORY_SZL_READ,
        CATEGORY_CPU_CONTROL,
        CATEGORY_BOUNDARY,       # last — contains count=0xFFFF which crashes snap7
    ]

    _RECV_TIMEOUT    = 3.0
    _CONNECT_TIMEOUT = 5.0

    def __init__(self, target: Device, logger, delay: float = 0.0,
                 seeds=None, src_tsap: int = 0x0100, dst_tsap: int = 0x0200):
        super().__init__(target=target, logger=logger, delay=delay, seeds=seeds)
        self._sock: Optional[socket.socket] = None
        self._src_tsap = src_tsap
        self._dst_tsap = dst_tsap
        self._pdu_ref  = 0

    def _next_pdu_ref(self) -> int:
        self._pdu_ref = (self._pdu_ref + 1) & 0xFFFF
        return self._pdu_ref

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self, target: Optional[Device] = None) -> None:
        t = target or self.target
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self._CONNECT_TIMEOUT)
        self._sock.connect((t.ip, t.port))
        self._sock.settimeout(self._RECV_TIMEOUT)
        self._pdu_ref = 0

        # Step 1: COTP CR/CC handshake
        self._sock.sendall(_cotp_cr(self._src_tsap, self._dst_tsap))
        cc = self._recv_response()
        if not cc or len(cc) < 6 or cc[5] != _COTP_CC:
            raise ConnectionError(
                f"S7comm COTP handshake failed: "
                f"got {cc[5:6].hex() if cc and len(cc) > 5 else None}, expected CC (0xD0)"
            )

        # Step 2: S7 Setup Communication
        self._sock.sendall(_s7_setup_comm(pdu_ref=self._next_pdu_ref()))
        resp = self._recv_response()
        if not resp or len(resp) < 9:
            raise ConnectionError("S7comm Setup Communication failed: no response")
        if resp[8] != _ROSCTR_ACK_DATA:
            raise ConnectionError(
                f"S7comm Setup Communication failed: ROSCTR=0x{resp[8]:02X}"
            )

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _reconnect(self) -> None:
        self.close()
        for delay in (0.3, 1.0, 2.0):
            time.sleep(delay)
            try:
                self.connect()
                return
            except Exception:
                self.close()   # ensure _sock=None on failure

    def _recv_fixed(self, n: int) -> Optional[bytes]:
        buf = b''
        try:
            while len(buf) < n:
                chunk = self._sock.recv(n - len(buf))
                if not chunk:
                    return buf if buf else None
                buf += chunk
        except socket.timeout:
            return None
        return buf

    def _recv_response(self) -> Optional[bytes]:
        """Read one TPKT-framed response."""
        hdr = self._recv_fixed(4)
        if not hdr or len(hdr) < 4:
            return hdr
        total_len = struct.unpack('!H', hdr[2:4])[0]
        if total_len <= 4:
            return hdr
        rest = self._recv_fixed(total_len - 4)
        if rest is None:
            return hdr
        return hdr + rest

    def discover(self, interface: str, timeout: int = 30) -> list:
        """Scan common TSAP values; return Device list with valid TSAPs."""
        found = []
        for src_tsap, dst_tsap in _COMMON_TSAPS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target.ip, self.target.port))
                s.sendall(_cotp_cr(src_tsap, dst_tsap))
                data = s.recv(32)
                s.close()
                if data and len(data) >= 6 and data[5] == _COTP_CC:
                    d = Device(ip=self.target.ip, port=self.target.port, protocol="s7comm")
                    d.metadata["src_tsap"] = f"0x{src_tsap:04X}"
                    d.metadata["dst_tsap"] = f"0x{dst_tsap:04X}"
                    found.append(d)
            except OSError:
                pass
        return found

    def replay_payload(self, payload: bytes) -> Optional[bytes]:
        if self._sock is None:
            raise RuntimeError("call connect() before replay_payload()")
        self._sock.sendall(payload)
        return self._recv_response()

    # ------------------------------------------------------------------
    # generate_cases
    # ------------------------------------------------------------------

    def generate_cases(self, categories=None):
        cats  = self._resolve_categories(categories)
        cases = []
        for cat in cats:
            if   cat == CATEGORY_BOUNDARY:
                cases.extend(self._gen_boundary())
            elif cat == CATEGORY_BINARY_CORRUPTION:
                cases.extend(self._gen_binary_corruption())
            elif cat == CATEGORY_STATE_MACHINE:
                cases.extend(self._gen_state_machine())
            elif cat == CATEGORY_SEQUENCE:
                cases.extend(self._gen_sequence())
            elif cat == CATEGORY_PDU_NEGOTIATION:
                cases.extend(self._gen_pdu_negotiation())
            elif cat == CATEGORY_READ_WRITE:
                cases.extend(self._gen_read_write())
            elif cat == CATEGORY_SZL_READ:
                cases.extend(self._gen_szl_read())
            elif cat == CATEGORY_CPU_CONTROL:
                cases.extend(self._gen_cpu_control())
        return cases

    def _case(self, cat, desc, payload):
        return (self._next_id(), cat, desc, payload)

    def _ref(self) -> int:
        return self._next_pdu_ref()

    # ------------------------------------------------------------------
    # Category: boundary
    # ------------------------------------------------------------------

    def _gen_boundary(self):
        C = CATEGORY_BOUNDARY
        cases = []

        # Valid requests at boundary sizes
        cases.append(self._case(C, "Setup Communication (normal)",
                                _s7_setup_comm(pdu_ref=self._ref())))
        cases.append(self._case(C, "Read DB1.DBW0 count=1",
                                _s7_read_var(area=AREA_DB, db_num=1,
                                             address=0, count=1,
                                             pdu_ref=self._ref())))
        cases.append(self._case(C, "Read Inputs byte 0 count=1",
                                _s7_read_var(area=AREA_INPUTS, db_num=0,
                                             address=0, count=1,
                                             pdu_ref=self._ref())))
        cases.append(self._case(C, "Read Flags (M) byte 0 count=1",
                                _s7_read_var(area=AREA_FLAGS, db_num=0,
                                             address=0, count=1,
                                             pdu_ref=self._ref())))
        cases.append(self._case(C, "Read Outputs byte 0 count=1",
                                _s7_read_var(area=AREA_OUTPUTS, db_num=0,
                                             address=0, count=1,
                                             pdu_ref=self._ref())))
        cases.append(self._case(C, "Read DB1 count=1 address=max word (0x7FFE)",
                                _s7_read_var(area=AREA_DB, db_num=1,
                                             address=0x7FFE, count=1,
                                             pdu_ref=self._ref())))
        cases.append(self._case(C, "Read DB1 count=1 address=0 DWORD transport",
                                _s7_read_var(area=AREA_DB, db_num=1,
                                             address=0, count=1,
                                             transport_size=0x06,
                                             pdu_ref=self._ref())))
        cases.append(self._case(C, "Read DB0 (does not exist)",
                                _s7_read_var(area=AREA_DB, db_num=0,
                                             address=0, count=1,
                                             pdu_ref=self._ref())))
        cases.append(self._case(C, "Read DB max (0xFFFF)",
                                _s7_read_var(area=AREA_DB, db_num=0xFFFF,
                                             address=0, count=1,
                                             pdu_ref=self._ref())))
        cases.append(self._case(C, "SZL read module list (0x0011)",
                                _s7_szl_read(szl_id=0x0011, pdu_ref=self._ref())))
        cases.append(self._case(C, "SZL read component list (0x001C)",
                                _s7_szl_read(szl_id=0x001C, pdu_ref=self._ref())))
        cases.append(self._case(C, "SZL read CPU characteristics (0x0111)",
                                _s7_szl_read(szl_id=0x0111, pdu_ref=self._ref())))
        cases.append(self._case(C, "Write DB1.DBW0 = 0x0000",
                                _s7_write_var(area=AREA_DB, db_num=1,
                                              address=0, count=1,
                                              data=b'\x00\x00',
                                              pdu_ref=self._ref())))
        cases.append(self._case(C, "Write DB1.DBW0 = 0xFFFF",
                                _s7_write_var(area=AREA_DB, db_num=1,
                                              address=0, count=1,
                                              data=b'\xFF\xFF',
                                              pdu_ref=self._ref())))
        cases.append(self._case(C, "Write Outputs byte 0 = 0x00",
                                _s7_write_var(area=AREA_OUTPUTS, db_num=0,
                                              address=0, count=1,
                                              data=b'\x00',
                                              pdu_ref=self._ref())))
        cases.append(self._case(C, "Write empty data (0 bytes)",
                                _s7_write_var(area=AREA_DB, db_num=1,
                                              address=0, count=0,
                                              data=b'',
                                              pdu_ref=self._ref())))
        cases.append(self._case(C, "Write DB1 512 bytes",
                                _s7_write_var(area=AREA_DB, db_num=1,
                                              address=0, count=256,
                                              data=b'\x00' * 512,
                                              pdu_ref=self._ref())))
        # Known crash trigger — placed last so all prior cases execute before snap7 goes down
        cases.append(self._case(C, "Read DB1 count=max (0xFFFF)",
                                _s7_read_var(area=AREA_DB, db_num=1,
                                             address=0, count=0xFFFF,
                                             pdu_ref=self._ref())))

        return cases

    # ------------------------------------------------------------------
    # Category: binary_corruption
    # ------------------------------------------------------------------

    def _gen_binary_corruption(self):
        C = CATEGORY_BINARY_CORRUPTION
        cases = []

        # Empty and very short
        cases.append(self._case(C, "Empty payload", b''))
        cases.append(self._case(C, "1 byte 0x03", b'\x03'))
        cases.append(self._case(C, "4 bytes TPKT header only (len=4)",
                                bytes([0x03, 0x00, 0x00, 0x04])))
        cases.append(self._case(C, "7 bytes TPKT+COTP-DT only (no S7)",
                                bytes([0x03, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80])))

        # All-zero and all-one
        base = _s7_read_var(pdu_ref=self._ref())
        cases.append(self._case(C, "All-zero 30 bytes", b'\x00' * 30))
        cases.append(self._case(C, "All-0xFF 30 bytes", b'\xFF' * 30))

        # S7 magic byte mutations (should be 0x32)
        for magic, label in [(0x00, "0x00"), (0x31, "0x31"), (0x33, "0x33"), (0xFF, "0xFF")]:
            bad = bytearray(_s7_read_var(pdu_ref=self._ref()))
            bad[7] = magic
            cases.append(self._case(C, f"S7 magic={label} (should be 0x32)", bytes(bad)))

        # ROSCTR mutations on a read request
        for rosctr, label in [
            (0x00, "0x00 invalid"), (0x02, "0x02 ACK"), (0x03, "0x03 ACK_DATA"),
            (0x07, "0x07 UserData"), (0xFF, "0xFF unknown")
        ]:
            bad = bytearray(_s7_read_var(pdu_ref=self._ref()))
            bad[8] = rosctr
            cases.append(self._case(C, f"Read req ROSCTR={label}", bytes(bad)))

        # PDU ref mutations
        for ref, label in [(0x0000, "0"), (0xFFFF, "0xFFFF")]:
            bad = bytearray(_s7_read_var(pdu_ref=1))
            struct.pack_into('!H', bad, 11, ref)
            cases.append(self._case(C, f"Read req pdu_ref={label}", bytes(bad)))

        # param_len claims beyond actual PDU
        bad = bytearray(_s7_read_var(pdu_ref=self._ref()))
        struct.pack_into('!H', bad, 13, 0xFFFF)
        cases.append(self._case(C, "Read req param_len=0xFFFF (overflow)", bytes(bad)))

        # data_len claims beyond actual PDU
        bad = bytearray(_s7_read_var(pdu_ref=self._ref()))
        struct.pack_into('!H', bad, 15, 0xFFFF)
        cases.append(self._case(C, "Read req data_len=0xFFFF (overflow)", bytes(bad)))

        # TPKT length mutations
        bad = bytearray(_s7_read_var(pdu_ref=self._ref()))
        struct.pack_into('!H', bad, 2, 0)
        cases.append(self._case(C, "TPKT total_len=0", bytes(bad)))

        bad = bytearray(_s7_read_var(pdu_ref=self._ref()))
        struct.pack_into('!H', bad, 2, 0xFFFF)
        cases.append(self._case(C, "TPKT total_len=0xFFFF (overflow)", bytes(bad)))

        # COTP DT byte mutations
        bad = bytearray(_s7_read_var(pdu_ref=self._ref()))
        bad[4] = 0x00
        cases.append(self._case(C, "COTP DT LI=0 (should be 2)", bytes(bad)))

        bad = bytearray(_s7_read_var(pdu_ref=self._ref()))
        bad[5] = 0xE0  # CR instead of DT
        cases.append(self._case(C, "COTP DT PTYPE=E0 (CR instead of DT)", bytes(bad)))

        # Function code mutations
        for fc, label in [(0x00, "0x00"), (0x01, "0x01"), (0xFF, "0xFF")]:
            bad = bytearray(_s7_read_var(pdu_ref=self._ref()))
            bad[17] = fc
            cases.append(self._case(C, f"Read param function_code={label}", bytes(bad)))

        # Item syntax ID mutation
        bad = bytearray(_s7_read_var(pdu_ref=self._ref()))
        bad[19] = 0xFF  # syntax_id (normally 0x12 = S7ANY)
        cases.append(self._case(C, "Read item syntax_id=0xFF (should be 0x12)", bytes(bad)))

        # Area code mutations
        for area, label in [(0x00, "0x00 invalid"), (0xFF, "0xFF invalid"),
                             (0x1D, "0x1D LocalData word")]:
            bad = bytearray(_s7_read_var(pdu_ref=self._ref()))
            bad[24] = area
            cases.append(self._case(C, f"Read item area=0x{area:02X} ({label})", bytes(bad)))

        # Truncated at each TPKT boundary
        base = _s7_setup_comm(pdu_ref=self._ref())
        for i in [1, 4, 7, 10, 15, 20]:
            cases.append(self._case(C, f"Setup Comm truncated at byte {i}",
                                    base[:i]))

        return cases

    # ------------------------------------------------------------------
    # Category: state_machine
    # ------------------------------------------------------------------

    def _gen_state_machine(self):
        C = CATEGORY_STATE_MACHINE
        cases = []

        # Read without prior Setup Communication (sent raw — state_machine skip reconnect)
        cases.append(self._case(C, "Read DB1 without Setup Comm first",
                                _s7_read_var(area=AREA_DB, db_num=1,
                                             address=0, count=1,
                                             pdu_ref=self._ref())))

        # Second Setup Communication (re-negotiate after already connected)
        cases.append(self._case(C, "Second Setup Communication (re-negotiate)",
                                _s7_setup_comm(pdu_ref=self._ref())))

        # Setup Comm immediately followed by another Setup Comm
        sc1 = _s7_setup_comm(pdu_ref=self._ref())
        sc2 = _s7_setup_comm(pdu_ref=self._ref())
        cases.append(self._case(C, "Double Setup Comm in one payload",
                                sc1 + sc2))

        # COTP CR sent after already established (wrong direction)
        cases.append(self._case(C, "COTP CR after session established",
                                _cotp_cr(0x0100, 0x0200)))

        # S7 ACK sent from client (wrong direction)
        hdr = _s7_header(rosctr=_ROSCTR_ACK, pdu_ref=self._ref())
        cases.append(self._case(C, "S7 ACK ROSCTR=0x02 sent as client",
                                _s7_pkt(hdr)))

        # S7 ACK_DATA sent from client (wrong direction)
        hdr = _s7_header(rosctr=_ROSCTR_ACK_DATA, pdu_ref=self._ref())
        cases.append(self._case(C, "S7 ACK_DATA ROSCTR=0x03 sent as client",
                                _s7_pkt(hdr)))

        # Write before Setup Comm
        cases.append(self._case(C, "Write DB1 before Setup Comm",
                                _s7_write_var(area=AREA_DB, db_num=1,
                                              address=0, count=1,
                                              data=b'\x00\x00',
                                              pdu_ref=self._ref())))

        # SZL read with wrong UserData method byte (0x12 instead of 0x11)
        param = bytes([0x00, 0x01, 0x12, 0x04, 0x12, 0x44, 0x01, 0x00])  # 0x12=response
        data  = bytes([0xFF, 0x09]) + struct.pack('!H', 4) + struct.pack('!HH', 0x0011, 0)
        hdr   = _s7_header(rosctr=_ROSCTR_USERDATA, pdu_ref=self._ref(),
                           param_len=len(param), data_len=len(data))
        cases.append(self._case(C, "SZL read with method=0x12 (response) as client",
                                _s7_pkt(hdr + param + data)))

        # Unknown ROSCTR values
        for rosctr, label in [(0x04, "0x04"), (0x05, "0x05"), (0x06, "0x06"),
                              (0x08, "0x08"), (0xFF, "0xFF")]:
            hdr = _s7_header(rosctr=rosctr, pdu_ref=self._ref())
            cases.append(self._case(C, f"Unknown ROSCTR=0x{rosctr:02X} ({label})",
                                    _s7_pkt(hdr)))

        # S7 PDU with function code not valid for current state
        cases.append(self._case(C, "PLC Stop without prior auth (read-only test)",
                                _s7_plc_stop(pdu_ref=self._ref())))

        # Just the COTP DT header, no S7 payload
        cases.append(self._case(C, "COTP DT with empty S7 body",
                                _tpkt(bytes([0x02, _COTP_DT, 0x80]))))

        return cases

    # ------------------------------------------------------------------
    # Category: sequence
    # ------------------------------------------------------------------

    def _gen_sequence(self):
        C = CATEGORY_SEQUENCE
        cases = []

        # Repeated identical reads (same pdu_ref)
        pkt = _s7_read_var(area=AREA_DB, db_num=1, address=0, count=1, pdu_ref=1)
        for _ in range(4):
            cases.append(self._case(C, "Repeated Read DB1 same pdu_ref=1", pkt))

        # pdu_ref wraps: 0xFFFE → 0xFFFF → 0x0000
        for ref in (0xFFFE, 0xFFFF, 0x0000):
            cases.append(self._case(C, f"Read DB1 pdu_ref=0x{ref:04X} (boundary)",
                                    _s7_read_var(area=AREA_DB, db_num=1,
                                                 address=0, count=1, pdu_ref=ref)))

        # Large pdu_ref jump
        cases.append(self._case(C, "Read DB1 pdu_ref=0x1234 (large jump)",
                                _s7_read_var(area=AREA_DB, db_num=1,
                                             address=0, count=1, pdu_ref=0x1234)))

        # Interleave reads of different areas
        for area, name in [(AREA_INPUTS, "Inputs"), (AREA_OUTPUTS, "Outputs"),
                           (AREA_FLAGS, "Flags"), (AREA_DB, "DB1")]:
            db = 1 if area == AREA_DB else 0
            cases.append(self._case(C, f"Sequence Read {name}",
                                    _s7_read_var(area=area, db_num=db,
                                                 address=0, count=1,
                                                 pdu_ref=self._ref())))

        # Read followed by write same address
        cases.append(self._case(C, "Read DB1.DBW0 (sequence step 1)",
                                _s7_read_var(area=AREA_DB, db_num=1,
                                             address=0, count=1,
                                             pdu_ref=self._ref())))
        cases.append(self._case(C, "Write DB1.DBW0=0xABCD after Read (sequence step 2)",
                                _s7_write_var(area=AREA_DB, db_num=1,
                                              address=0, count=1,
                                              data=b'\xAB\xCD',
                                              pdu_ref=self._ref())))
        cases.append(self._case(C, "Read DB1.DBW0 again after Write (sequence step 3)",
                                _s7_read_var(area=AREA_DB, db_num=1,
                                             address=0, count=1,
                                             pdu_ref=self._ref())))

        # SZL reads in sequence
        for szl in (0x0011, 0x001C, 0x0111, 0xFFFF):
            cases.append(self._case(C, f"SZL read 0x{szl:04X} in sequence",
                                    _s7_szl_read(szl_id=szl, pdu_ref=self._ref())))

        return cases

    # ------------------------------------------------------------------
    # Category: pdu_negotiation
    # ------------------------------------------------------------------

    def _gen_pdu_negotiation(self):
        C = CATEGORY_PDU_NEGOTIATION
        cases = []

        # Normal setup comms
        cases.append(self._case(C, "Setup Comm PDU=480 (normal S7-300)",
                                _s7_setup_comm(pdu_ref=self._ref(), pdu_len=480)))
        cases.append(self._case(C, "Setup Comm PDU=960 (S7-400)",
                                _s7_setup_comm(pdu_ref=self._ref(), pdu_len=960)))
        cases.append(self._case(C, "Setup Comm PDU=1472 (S7-1500 max)",
                                _s7_setup_comm(pdu_ref=self._ref(), pdu_len=1472)))

        # Boundary PDU sizes
        cases.append(self._case(C, "Setup Comm PDU=0 (zero length)",
                                _s7_setup_comm(pdu_ref=self._ref(), pdu_len=0)))
        cases.append(self._case(C, "Setup Comm PDU=1 (minimum)",
                                _s7_setup_comm(pdu_ref=self._ref(), pdu_len=1)))
        cases.append(self._case(C, "Setup Comm PDU=0xFFFF (max 16-bit)",
                                _s7_setup_comm(pdu_ref=self._ref(), pdu_len=0xFFFF)))

        # AMQ (outstanding request) variants
        cases.append(self._case(C, "Setup Comm max_amq=0 (zero)",
                                _s7_setup_comm(pdu_ref=self._ref(), max_amq=0)))
        cases.append(self._case(C, "Setup Comm max_amq=0xFFFF (max)",
                                _s7_setup_comm(pdu_ref=self._ref(), max_amq=0xFFFF)))
        cases.append(self._case(C, "Setup Comm max_amq=100 (high)",
                                _s7_setup_comm(pdu_ref=self._ref(), max_amq=100)))

        # Corrupted Setup Comm parameter
        bad = bytearray(_s7_setup_comm(pdu_ref=self._ref()))
        bad[17] = 0x00  # function code 0x00 instead of 0xF0
        cases.append(self._case(C, "Setup Comm function_code=0x00 (corrupted)",
                                bytes(bad)))

        bad = bytearray(_s7_setup_comm(pdu_ref=self._ref()))
        bad[17] = 0xFF  # function code 0xFF
        cases.append(self._case(C, "Setup Comm function_code=0xFF (corrupted)",
                                bytes(bad)))

        # Setup Comm with truncated parameter block
        cases.append(self._case(C, "Setup Comm param truncated to 2 bytes",
                                _s7_pkt(_s7_header(rosctr=_ROSCTR_JOB,
                                                   pdu_ref=self._ref(),
                                                   param_len=2, data_len=0)
                                        + bytes([_FC_SETUP_COMM, 0x00]))))

        # Setup Comm with param_len mismatch
        bad = bytearray(_s7_setup_comm(pdu_ref=self._ref()))
        struct.pack_into('!H', bad, 13, 0)   # param_len=0 but 8B param follows
        cases.append(self._case(C, "Setup Comm param_len=0 (mismatch)", bytes(bad)))

        # Setup Comm repeated
        cases.append(self._case(C, "Setup Comm re-negotiate (3rd time)",
                                _s7_setup_comm(pdu_ref=self._ref(), pdu_len=240)))

        # Setup Comm with data section (should have none)
        hdr   = _s7_header(rosctr=_ROSCTR_JOB, pdu_ref=self._ref(),
                           param_len=8, data_len=4)
        param = bytes([_FC_SETUP_COMM, 0x00]) + struct.pack('!HHH', 1, 1, 480)
        cases.append(self._case(C, "Setup Comm with unexpected 4-byte data section",
                                _s7_pkt(hdr + param + b'\xDE\xAD\xBE\xEF')))

        return cases

    # ------------------------------------------------------------------
    # Category: read_write
    # ------------------------------------------------------------------

    def _gen_read_write(self):
        C = CATEGORY_READ_WRITE
        cases = []

        # All documented area codes
        for area, name in [
            (AREA_INPUTS,  "Inputs"),
            (AREA_OUTPUTS, "Outputs"),
            (AREA_FLAGS,   "Flags (M)"),
            (AREA_DB,      "DB1"),
            (AREA_LOCAL,   "LocalData"),
            (0x86,         "0x86 (unknown)"),
            (0xFF,         "0xFF (all-ones)"),
        ]:
            db = 1 if area == AREA_DB else 0
            cases.append(self._case(C, f"Read area=0x{area:02X} ({name}) count=1",
                                    _s7_read_var(area=area, db_num=db,
                                                 address=0, count=1,
                                                 pdu_ref=self._ref())))

        # DB number boundaries
        for db, label in [(0, "0 none"), (1, "1 normal"), (1000, "1000 large"),
                          (0x7FFF, "0x7FFF max"), (0xFFFF, "0xFFFF all-ones")]:
            cases.append(self._case(C, f"Read DB#{label} address=0 count=1",
                                    _s7_read_var(area=AREA_DB, db_num=db,
                                                 address=0, count=1,
                                                 pdu_ref=self._ref())))

        # Address boundaries
        for addr, label in [(0, "0 min"), (0x7FFF, "0x7FFF mid"), (0xFFFF, "0xFFFF max")]:
            cases.append(self._case(C, f"Read DB1 address=0x{addr:04X} ({label}) count=1",
                                    _s7_read_var(area=AREA_DB, db_num=1,
                                                 address=addr, count=1,
                                                 pdu_ref=self._ref())))

        # Count boundaries
        for count, label in [(0, "0 zero"), (1, "1 min"), (100, "100 normal"),
                             (0x7FFF, "0x7FFF max PDU")]:
            cases.append(self._case(C, f"Read DB1 count={label}",
                                    _s7_read_var(area=AREA_DB, db_num=1,
                                                 address=0, count=count,
                                                 pdu_ref=self._ref())))

        # Transport size mutations (valid/unknown values first; 0x00=none last)
        for ts, label in [(0x01, "0x01 BIT"), (0x02, "0x02 BYTE"),
                          (0x04, "0x04 WORD"), (0x06, "0x06 DWORD"), (0xFF, "0xFF all-ones")]:
            cases.append(self._case(C, f"Read DB1 transport_size=0x{ts:02X} ({label})",
                                    _s7_read_var(area=AREA_DB, db_num=1,
                                                 address=0, count=1,
                                                 transport_size=ts,
                                                 pdu_ref=self._ref())))

        # Write with various data sizes
        for size, label in [(0, "0 bytes"), (1, "1 byte"), (2, "2 bytes"),
                             (100, "100 bytes"), (480, "480 bytes (PDU max)")]:
            cases.append(self._case(C, f"Write DB1 {label} of data",
                                    _s7_write_var(area=AREA_DB, db_num=1,
                                                  address=0, count=max(1, size // 2),
                                                  data=b'\xAA' * size if size else b'',
                                                  pdu_ref=self._ref())))

        # Write to read-only areas
        cases.append(self._case(C, "Write Inputs area (read-only)",
                                _s7_write_var(area=AREA_INPUTS, db_num=0,
                                              address=0, count=1,
                                              data=b'\xFF',
                                              pdu_ref=self._ref())))

        # transport_size=0x00 is invalid (no element type maps to 0); snap7 returns a valid Ack_Data
        cases.append(self._case(C, "Read DB1 transport_size=0x00 (invalid — no type)",
                                _s7_read_var(area=AREA_DB, db_num=1,
                                             address=0, count=1,
                                             transport_size=0x00,
                                             pdu_ref=self._ref())))

        return cases

    # ------------------------------------------------------------------
    # Category: szl_read
    # ------------------------------------------------------------------

    def _gen_szl_read(self):
        C = CATEGORY_SZL_READ
        cases = []

        # All documented SZL IDs
        for szl_id, name in [
            (0x0011, "module list"),
            (0x001C, "component list"),
            (0x0111, "CPU characteristics"),
            (0x0112, "protection levels"),
            (0x0113, "communication capability"),
            (0x0114, "CPU block list"),
            (0x0115, "object count"),
            (0x0222, "diagnostic messages"),
            (0x0424, "status modules"),
        ]:
            cases.append(self._case(C, f"SZL read 0x{szl_id:04X} ({name})",
                                    _s7_szl_read(szl_id=szl_id, pdu_ref=self._ref())))

        # Unknown SZL IDs
        for szl_id in (0x0000, 0x0001, 0x00FF, 0x1234, 0xFFFF):
            cases.append(self._case(C, f"SZL read unknown ID 0x{szl_id:04X}",
                                    _s7_szl_read(szl_id=szl_id, pdu_ref=self._ref())))

        # SZL index variants
        for idx in (0x0000, 0x0001, 0x00FF, 0xFFFF):
            cases.append(self._case(C, f"SZL read 0x0011 index=0x{idx:04X}",
                                    _s7_szl_read(szl_id=0x0011, szl_index=idx,
                                                 pdu_ref=self._ref())))

        # Corrupted SZL UserData parameter
        bad = bytearray(_s7_szl_read(szl_id=0x0011, pdu_ref=self._ref()))
        bad[17] = 0xFF  # corrupt param header[0]
        cases.append(self._case(C, "SZL read corrupted param header[0]=0xFF", bytes(bad)))

        bad = bytearray(_s7_szl_read(szl_id=0x0011, pdu_ref=self._ref()))
        bad[21] = 0x00  # subfunction=0x00 (should be 0x44)
        cases.append(self._case(C, "SZL read subfunction=0x00 (should be 0x44)", bytes(bad)))

        # SZL read with wrong ROSCTR
        param = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
        data  = bytes([0xFF, 0x09]) + struct.pack('!H', 4) + struct.pack('!HH', 0x0011, 0)
        hdr   = _s7_header(rosctr=_ROSCTR_JOB, pdu_ref=self._ref(),  # Job not UserData
                           param_len=len(param), data_len=len(data))
        cases.append(self._case(C, "SZL read with ROSCTR=Job (should be UserData)",
                                _s7_pkt(hdr + param + data)))

        # Truncated SZL data section
        cases.append(self._case(C, "SZL read truncated data to 2 bytes",
                                _s7_pkt(_s7_header(rosctr=_ROSCTR_USERDATA,
                                                   pdu_ref=self._ref(),
                                                   param_len=8, data_len=2)
                                        + bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
                                        + bytes([0xFF, 0x09]))))

        return cases

    # ------------------------------------------------------------------
    # Category: cpu_control
    # ------------------------------------------------------------------

    def _gen_cpu_control(self):
        C = CATEGORY_CPU_CONTROL
        cases = []

        # PI service codes (PLC control)
        for pi_name, label in [
            (b'_INSE', "load block (INSE)"),
            (b'_DELE', "delete block (DELE)"),
            (b'_INSM', "run after load (INSM)"),
            (b'_GARB', "memory compress (GARB)"),
            (b'AAAA', "unknown PI service"),
            (b'', "empty PI name"),
            (b'A' * 50, "PI name 50 bytes"),
            (b'_INSE\x00BAD', "PI name with embedded null"),
        ]:
            cases.append(self._case(C, f"PI service {label}",
                                    _s7_pi_service(pi_name=pi_name, pdu_ref=self._ref())))

        # PLC Stop
        cases.append(self._case(C, "PLC Stop request (FC=0x29)",
                                _s7_plc_stop(pdu_ref=self._ref())))

        # PLC Stop with malformed parameter
        hdr = _s7_header(rosctr=_ROSCTR_JOB, pdu_ref=self._ref(), param_len=1, data_len=0)
        cases.append(self._case(C, "PLC Stop param truncated to 1 byte",
                                _s7_pkt(hdr + bytes([_FC_PLC_STOP]))))

        # FC=0x29 (Stop) with oversized param
        hdr = _s7_header(rosctr=_ROSCTR_JOB, pdu_ref=self._ref(), param_len=16, data_len=0)
        cases.append(self._case(C, "PLC Stop param 16 bytes (oversized)",
                                _s7_pkt(hdr + bytes([_FC_PLC_STOP]) + b'\x00' * 15)))

        # Download sequence attempt (FC=0x1A Start, FC=0x1B Download, FC=0x1C End)
        for fc, label in [(0x1A, "0x1A Start Download"),
                          (0x1B, "0x1B Download Block"),
                          (0x1C, "0x1C Download End"),
                          (0x1D, "0x1D Start Upload"),
                          (0x1E, "0x1E Upload"),
                          (0x1F, "0x1F End Upload")]:
            hdr = _s7_header(rosctr=_ROSCTR_JOB, pdu_ref=self._ref(), param_len=2, data_len=0)
            cases.append(self._case(C, f"FC=0x{fc:02X} ({label})",
                                    _s7_pkt(hdr + bytes([fc, 0x00]))))

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
            print(f"\r[s7comm] {i}/{total}  {case_id}  {desc[:55]}",
                  end="", flush=True)
            result = self._send_case(case_id, cat, desc, payload)
            results.append(result)
            if self.logger:
                self.logger.log(result)
            if self.delay:
                time.sleep(self.delay)
        print()
        return results

    def _send_case(self, case_id: str, category: str,
                   description: str, payload: bytes) -> FuzzResult:
        result = FuzzResult(
            case_id=case_id,
            protocol=self.PROTOCOL_NAME,
            target=f"{self.target.ip}:{self.target.port}",
            category=category,
            description=description,
            payload=payload,
        )
        t0 = time.monotonic()
        if self._sock is None:
            result.anomaly         = ANOMALY_CONNECTION_RESET
            result.crash_indicator = True
            result.duration_ms     = 0.0
            return result
        try:
            self._sock.sendall(payload)
            data = self._recv_response()
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
        # Minimum: TPKT(4) + COTP-DT(3) + S7-magic(1) + ROSCTR(1) = 9 bytes
        if len(data) < 9:
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        if data[7] != 0x32:
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        rosctr = data[8]

        if rosctr == _ROSCTR_ACK:
            # Bare acknowledgement — no error bytes, no data
            return

        if rosctr in (_ROSCTR_ACK_DATA, _ROSCTR_USERDATA):
            # Response header is 12B (2 extra error bytes after 10B base)
            if len(data) < 19:
                result.anomaly         = ANOMALY_MALFORMED_RESPONSE
                result.crash_indicator = True
                return
            error_class = data[17]
            error_code  = data[18]
            if error_class != 0x00 or error_code != 0x00:
                result.anomaly         = ANOMALY_EXCEPTION
                result.crash_indicator = False
            # else: clean response — anomaly stays None, crash stays False
            return

        # Unexpected ROSCTR
        result.anomaly         = ANOMALY_UNEXPECTED_DATA
        result.crash_indicator = True
