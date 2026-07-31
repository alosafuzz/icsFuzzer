"""OMRON FINS fuzzer — UDP port 9600.

FINS (Factory Interface Network Service) is a fixed-header, connectionless
UDP protocol. No session negotiation — each frame is self-contained.

Frame format (12-byte header, then command-specific data):
  [0]  ICF  0x80=command, 0xC0=response; bit6=GW, bit0=response-required
  [1]  RSV  0x00 (reserved)
  [2]  GCT  gateway count (default 0x02)
  [3]  DNA  destination network (0x00=local)
  [4]  DA1  destination node address
  [5]  DA2  destination unit address (0x00=CPU)
  [6]  SNA  source network (0x00=local)
  [7]  SA1  source node address
  [8]  SA2  source unit address (0x00)
  [9]  SID  service ID (transaction counter, 0x00–0xFF)
  [10] MRC  main request code
  [11] SRC  sub request code
  [12+] command data (variable length)

Response frames mirror the header (ICF=0xC0, MRC/SRC echoed), then:
  [12] MRES  main response code (0x00=OK)
  [13] SRES  sub response code (0x00=OK)
  [14+] response data

References:
  OMRON CJ2 CPU Unit Manual (Cat. No. W472)
  FINS Command Reference (W227)
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

CATEGORY_MEMORY_READ  = "memory_read"
CATEGORY_MEMORY_WRITE = "memory_write"
CATEGORY_CPU_CONTROL  = "cpu_control"
CATEGORY_COMMAND_SWEEP = "command_sweep"

# ---------------------------------------------------------------------------
# ICF field flags
# ---------------------------------------------------------------------------

_ICF_COMMAND  = 0x80
_ICF_RESPONSE = 0xC0
_ICF_GW_BIT   = 0x40
_ICF_RESP_REQ = 0x01   # bit 0: response required

# ---------------------------------------------------------------------------
# MRC/SRC command codes
# ---------------------------------------------------------------------------

_MRC_MEMORY_READ  = 0x01; _SRC_MEMORY_READ  = 0x01
_MRC_MEMORY_WRITE = 0x01; _SRC_MEMORY_WRITE = 0x02
_MRC_MEMORY_FILL  = 0x01; _SRC_MEMORY_FILL  = 0x03
_MRC_CPU_RUN      = 0x04; _SRC_CPU_RUN      = 0x01
_MRC_CPU_STOP     = 0x04; _SRC_CPU_STOP     = 0x02
_MRC_CPU_RESET    = 0x04; _SRC_CPU_RESET    = 0x03
_MRC_CLOCK_READ   = 0x07; _SRC_CLOCK_READ   = 0x01
_MRC_CTRL_DATA    = 0x05; _SRC_CTRL_DATA    = 0x01
_MRC_CTRL_STATUS  = 0x06; _SRC_CTRL_STATUS  = 0x01

# ---------------------------------------------------------------------------
# Memory area codes
# ---------------------------------------------------------------------------

AREA_CIO_WORD    = 0x82
AREA_CIO_BIT     = 0x80
AREA_DM_WORD     = 0x02
AREA_DM_BIT      = 0x30
AREA_EM0_WORD    = 0x0A
AREA_HR_WORD     = 0x52
AREA_TIMER_PV    = 0xB0
AREA_COUNTER_PV  = 0xB1

_KNOWN_AREAS = frozenset([
    AREA_CIO_WORD, AREA_CIO_BIT, AREA_DM_WORD, AREA_DM_BIT,
    AREA_EM0_WORD, AREA_HR_WORD, AREA_TIMER_PV, AREA_COUNTER_PV,
])

# ---------------------------------------------------------------------------
# Wire-level builders
# ---------------------------------------------------------------------------

def _fins_header(icf: int = _ICF_COMMAND, gct: int = 0x02,
                 dna: int = 0x00, da1: int = 0x00, da2: int = 0x00,
                 sna: int = 0x00, sa1: int = 0x01, sa2: int = 0x00,
                 sid: int = 1, mrc: int = 0x01, src: int = 0x01) -> bytes:
    """Build 12-byte FINS header."""
    return bytes([icf, 0x00, gct, dna, da1, da2, sna, sa1, sa2, sid, mrc, src])


def _fins_read(area: int = AREA_CIO_WORD, address: int = 0, bit: int = 0,
               count: int = 1, sid: int = 1, da1: int = 0x00) -> bytes:
    """FINS Memory Area Read (MRC=0x01, SRC=0x01)."""
    hdr  = _fins_header(mrc=_MRC_MEMORY_READ, src=_SRC_MEMORY_READ,
                        da1=da1, sid=sid)
    data = bytes([area]) + struct.pack('!H', address) + bytes([bit]) + \
           struct.pack('!H', count)
    return hdr + data


def _fins_write(area: int = AREA_CIO_WORD, address: int = 0, bit: int = 0,
                count: int = 1, data: bytes = b'\x00\x00',
                sid: int = 1, da1: int = 0x00) -> bytes:
    """FINS Memory Area Write (MRC=0x01, SRC=0x02)."""
    hdr = _fins_header(mrc=_MRC_MEMORY_WRITE, src=_SRC_MEMORY_WRITE,
                       da1=da1, sid=sid)
    cmd = bytes([area]) + struct.pack('!H', address) + bytes([bit]) + \
          struct.pack('!H', count) + data
    return hdr + cmd


def _fins_fill(area: int = AREA_CIO_WORD, address: int = 0,
               count: int = 1, fill_data: bytes = b'\x00\x00',
               sid: int = 1) -> bytes:
    """FINS Memory Area Fill (MRC=0x01, SRC=0x03)."""
    hdr = _fins_header(mrc=_MRC_MEMORY_FILL, src=_SRC_MEMORY_FILL, sid=sid)
    cmd = bytes([area]) + struct.pack('!H', address) + bytes([0x00]) + \
          struct.pack('!H', count) + fill_data
    return hdr + cmd


def _fins_run(mode: int = 0x00, sid: int = 1) -> bytes:
    """FINS CPU Run (MRC=0x04, SRC=0x01)."""
    hdr = _fins_header(mrc=_MRC_CPU_RUN, src=_SRC_CPU_RUN, sid=sid)
    return hdr + bytes([mode, 0x00, 0x00])


def _fins_stop(sid: int = 1) -> bytes:
    """FINS CPU Stop (MRC=0x04, SRC=0x02)."""
    return _fins_header(mrc=_MRC_CPU_STOP, src=_SRC_CPU_STOP, sid=sid)


def _fins_reset(sid: int = 1) -> bytes:
    """FINS CPU Reset (MRC=0x04, SRC=0x03)."""
    return _fins_header(mrc=_MRC_CPU_RESET, src=_SRC_CPU_RESET, sid=sid)


def _fins_clock_read(sid: int = 1) -> bytes:
    """FINS Clock Read (MRC=0x07, SRC=0x01)."""
    return _fins_header(mrc=_MRC_CLOCK_READ, src=_SRC_CLOCK_READ, sid=sid)


def _fins_status(sid: int = 1) -> bytes:
    """FINS Controller Status Read (MRC=0x06, SRC=0x01)."""
    return _fins_header(mrc=_MRC_CTRL_STATUS, src=_SRC_CTRL_STATUS, sid=sid)


def _fins_ctrl_data(sid: int = 1) -> bytes:
    """FINS Controller Data Read (MRC=0x05, SRC=0x01)."""
    return _fins_header(mrc=_MRC_CTRL_DATA, src=_SRC_CTRL_DATA, sid=sid)


# ---------------------------------------------------------------------------
# FinsFuzzer
# ---------------------------------------------------------------------------

class FinsFuzzer(FuzzModule):
    """OMRON FINS fuzzer — UDP port 9600, no session required."""

    PROTOCOL_NAME   = "fins"
    DEFAULT_PORT    = 9600
    FUZZ_CATEGORIES = [
        CATEGORY_BOUNDARY,
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_SEQUENCE,
        CATEGORY_STATE_MACHINE,
        CATEGORY_MEMORY_READ,
        CATEGORY_MEMORY_WRITE,
        CATEGORY_CPU_CONTROL,
        CATEGORY_COMMAND_SWEEP,
    ]

    _RECV_TIMEOUT = 3.0

    def __init__(self, target: Device, logger, delay: float = 0.0,
                 seeds=None, da1: int = 0x00, sa1: int = 0x01):
        super().__init__(target=target, logger=logger, delay=delay, seeds=seeds)
        self._sock: Optional[socket.socket] = None
        self._da1  = da1    # destination node
        self._sa1  = sa1    # source node
        self._sid  = 0      # service ID counter (0–255)

    def _next_sid(self) -> int:
        self._sid = (self._sid + 1) & 0xFF
        return self._sid

    # ------------------------------------------------------------------
    # Connection management (UDP — no handshake, just socket setup)
    # ------------------------------------------------------------------

    def connect(self, target: Optional[Device] = None) -> None:
        t = target or self.target
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(self._RECV_TIMEOUT)
        self._target_addr = (t.ip, t.port)
        self._sid = 0

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _reconnect(self) -> None:
        self.close()
        try:
            self.connect()
        except Exception:
            pass

    def discover(self, interface: str, timeout: int = 30) -> list:
        """Broadcast FINS status request; return responding Device instances."""
        found = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(2.0)
            pkt = _fins_status(sid=1)
            s.sendto(pkt, ('<broadcast>', self.target.port))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    data, addr = s.recvfrom(512)
                    if data and len(data) >= 14:
                        d = Device(ip=addr[0], port=addr[1], protocol="fins")
                        found.append(d)
                except socket.timeout:
                    break
            s.close()
        except OSError:
            pass
        return found

    def replay_payload(self, payload: bytes) -> Optional[bytes]:
        if self._sock is None:
            raise RuntimeError("call connect() before replay_payload()")
        self._sock.sendto(payload, self._target_addr)
        try:
            data, _ = self._sock.recvfrom(2048)
            return data
        except socket.timeout:
            return None

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
            elif cat == CATEGORY_SEQUENCE:
                cases.extend(self._gen_sequence())
            elif cat == CATEGORY_STATE_MACHINE:
                cases.extend(self._gen_state_machine())
            elif cat == CATEGORY_MEMORY_READ:
                cases.extend(self._gen_memory_read())
            elif cat == CATEGORY_MEMORY_WRITE:
                cases.extend(self._gen_memory_write())
            elif cat == CATEGORY_CPU_CONTROL:
                cases.extend(self._gen_cpu_control())
            elif cat == CATEGORY_COMMAND_SWEEP:
                cases.extend(self._gen_command_sweep())
        return cases

    def _case(self, cat, desc, payload):
        return (self._next_id(), cat, desc, payload)

    def _sid_val(self) -> int:
        return self._next_sid()

    # ------------------------------------------------------------------
    # Category: boundary
    # ------------------------------------------------------------------

    def _gen_boundary(self):
        C = CATEGORY_BOUNDARY
        cases = []

        # Minimum valid packets
        cases.append(self._case(C, "Status read (minimum 12-byte command)",
                                _fins_status(sid=self._sid_val())))
        cases.append(self._case(C, "Memory read CIO.W[0] count=1",
                                _fins_read(area=AREA_CIO_WORD, address=0,
                                           count=1, sid=self._sid_val())))
        cases.append(self._case(C, "Memory read DM[0] count=1",
                                _fins_read(area=AREA_DM_WORD, address=0,
                                           count=1, sid=self._sid_val())))
        cases.append(self._case(C, "Memory read HR[0] count=1",
                                _fins_read(area=AREA_HR_WORD, address=0,
                                           count=1, sid=self._sid_val())))

        # Count boundaries
        cases.append(self._case(C, "Memory read count=0 (zero items)",
                                _fins_read(area=AREA_CIO_WORD, address=0,
                                           count=0, sid=self._sid_val())))
        cases.append(self._case(C, "Memory read count=1 (minimum)",
                                _fins_read(area=AREA_CIO_WORD, address=0,
                                           count=1, sid=self._sid_val())))
        cases.append(self._case(C, "Memory read count=255 (large)",
                                _fins_read(area=AREA_CIO_WORD, address=0,
                                           count=255, sid=self._sid_val())))
        cases.append(self._case(C, "Memory read count=0xFFFF (max 16-bit)",
                                _fins_read(area=AREA_CIO_WORD, address=0,
                                           count=0xFFFF, sid=self._sid_val())))

        # Address boundaries
        cases.append(self._case(C, "Memory read CIO.W[0x0000] count=1",
                                _fins_read(area=AREA_CIO_WORD, address=0x0000,
                                           count=1, sid=self._sid_val())))
        cases.append(self._case(C, "Memory read CIO.W[0x7FFF] count=1",
                                _fins_read(area=AREA_CIO_WORD, address=0x7FFF,
                                           count=1, sid=self._sid_val())))
        cases.append(self._case(C, "Memory read CIO.W[0xFFFF] count=1",
                                _fins_read(area=AREA_CIO_WORD, address=0xFFFF,
                                           count=1, sid=self._sid_val())))

        # Write boundaries
        cases.append(self._case(C, "Memory write DM[0] 0 bytes data",
                                _fins_write(area=AREA_DM_WORD, address=0,
                                            count=0, data=b'',
                                            sid=self._sid_val())))
        cases.append(self._case(C, "Memory write DM[0] 2 bytes 0x0000",
                                _fins_write(area=AREA_DM_WORD, address=0,
                                            count=1, data=b'\x00\x00',
                                            sid=self._sid_val())))
        cases.append(self._case(C, "Memory write DM[0] 2 bytes 0xFFFF",
                                _fins_write(area=AREA_DM_WORD, address=0,
                                            count=1, data=b'\xFF\xFF',
                                            sid=self._sid_val())))
        cases.append(self._case(C, "Memory write 200 bytes to DM",
                                _fins_write(area=AREA_DM_WORD, address=0,
                                            count=100, data=b'\x00' * 200,
                                            sid=self._sid_val())))

        # SID boundary
        cases.append(self._case(C, "SID=0 (minimum)",
                                _fins_read(area=AREA_CIO_WORD, address=0,
                                           count=1, sid=0)))
        cases.append(self._case(C, "SID=0xFF (maximum)",
                                _fins_read(area=AREA_CIO_WORD, address=0,
                                           count=1, sid=0xFF)))

        # Control data and clock
        cases.append(self._case(C, "Controller data read",
                                _fins_ctrl_data(sid=self._sid_val())))
        cases.append(self._case(C, "Clock read",
                                _fins_clock_read(sid=self._sid_val())))

        return cases

    # ------------------------------------------------------------------
    # Category: binary_corruption
    # ------------------------------------------------------------------

    def _gen_binary_corruption(self):
        C = CATEGORY_BINARY_CORRUPTION
        cases = []

        # Empty and very short
        cases.append(self._case(C, "Empty payload", b''))
        cases.append(self._case(C, "1 byte 0x80", b'\x80'))
        cases.append(self._case(C, "11 bytes (1 short of header)", b'\x80' + b'\x00' * 10))
        cases.append(self._case(C, "12 bytes all-zero", b'\x00' * 12))
        cases.append(self._case(C, "12 bytes all-0xFF", b'\xFF' * 12))

        # ICF mutations
        base = _fins_read(area=AREA_CIO_WORD, address=0, count=1, sid=self._sid_val())
        for icf, label in [
            (0x00, "0x00 (no flags)"),
            (0x40, "0x40 (GW bit only)"),
            (0xC0, "0xC0 (response ICF from client)"),
            (0xFF, "0xFF (all bits set)"),
        ]:
            bad = bytearray(base)
            bad[0] = icf
            cases.append(self._case(C, f"ICF={label}", bytes(bad)))

        # GCT mutations
        for gct, label in [(0x00, "0"), (0x01, "1"), (0x7E, "max-1"), (0x7F, "max"), (0xFF, "255")]:
            bad = bytearray(_fins_read(area=AREA_CIO_WORD, address=0, count=1,
                                       sid=self._sid_val()))
            bad[2] = gct
            cases.append(self._case(C, f"GCT={label}", bytes(bad)))

        # Node address mutations (DA1/SA1)
        for da1, label in [(0x00, "0"), (0x01, "1"), (0x7E, "126"), (0xFF, "255")]:
            bad = bytearray(_fins_read(area=AREA_CIO_WORD, address=0, count=1,
                                       sid=self._sid_val()))
            bad[4] = da1
            cases.append(self._case(C, f"DA1={label}", bytes(bad)))

        # SID mutations
        for sid, label in [(0, "0"), (0x80, "128"), (0xFF, "255")]:
            bad = bytearray(_fins_read(area=AREA_CIO_WORD, address=0, count=1,
                                       sid=self._sid_val()))
            bad[9] = sid
            cases.append(self._case(C, f"SID={label}", bytes(bad)))

        # MRC mutations
        for mrc, label in [(0x00, "0x00"), (0x03, "0x03"), (0x0F, "0x0F"),
                            (0x80, "0x80"), (0xFF, "0xFF")]:
            bad = bytearray(_fins_read(area=AREA_CIO_WORD, address=0, count=1,
                                       sid=self._sid_val()))
            bad[10] = mrc
            cases.append(self._case(C, f"MRC=0x{mrc:02X} ({label})", bytes(bad)))

        # SRC mutations
        for src, label in [(0x00, "0x00"), (0x04, "0x04"), (0xFF, "0xFF")]:
            bad = bytearray(_fins_read(area=AREA_CIO_WORD, address=0, count=1,
                                       sid=self._sid_val()))
            bad[11] = src
            cases.append(self._case(C, f"SRC=0x{src:02X} ({label})", bytes(bad)))

        # Area code mutations in read command
        for area, label in [(0x00, "0x00"), (0x01, "0x01"), (0x7F, "0x7F"),
                             (0xFE, "0xFE"), (0xFF, "0xFF")]:
            bad = bytearray(_fins_read(area=AREA_CIO_WORD, address=0, count=1,
                                       sid=self._sid_val()))
            bad[12] = area
            cases.append(self._case(C, f"Memory area=0x{area:02X} ({label})", bytes(bad)))

        # Truncated at each byte boundary (2B intervals)
        full = _fins_read(area=AREA_CIO_WORD, address=0, count=1, sid=self._sid_val())
        for i in [1, 4, 6, 8, 10, 12, 14, 16]:
            if i <= len(full):
                cases.append(self._case(C, f"Read command truncated at byte {i}", full[:i]))

        # All-zero memory read data section (address=0, count=0)
        cases.append(self._case(C, "Read with all-zero data after header",
                                bytes([0x80, 0x00, 0x02, 0x00, 0x00, 0x00,
                                       0x00, 0x01, 0x00, 0x01, 0x01, 0x01] +
                                      [0x00] * 6)))

        return cases

    # ------------------------------------------------------------------
    # Category: sequence
    # ------------------------------------------------------------------

    def _gen_sequence(self):
        C = CATEGORY_SEQUENCE
        cases = []

        # Same SID repeated (no response ordering guarantee in UDP)
        for _ in range(4):
            cases.append(self._case(C, "Repeated read SID=1 (same)",
                                    _fins_read(area=AREA_CIO_WORD, address=0,
                                               count=1, sid=1)))

        # SID wraps around
        for sid in (0xFE, 0xFF, 0x00, 0x01):
            cases.append(self._case(C, f"SID=0x{sid:02X} (boundary wrap)",
                                    _fins_read(area=AREA_CIO_WORD, address=0,
                                               count=1, sid=sid)))

        # Interleave different commands with sequential SIDs
        for i, (area, name) in enumerate(
            [(AREA_CIO_WORD, "CIO"), (AREA_DM_WORD, "DM"),
             (AREA_HR_WORD, "HR"), (AREA_EM0_WORD, "EM0")]
        ):
            cases.append(self._case(C, f"Read {name} SID={i+1} (sequence)",
                                    _fins_read(area=area, address=0,
                                               count=1, sid=i + 1)))

        # Read then write then read same address
        cases.append(self._case(C, "Sequence: Read DM[10]",
                                _fins_read(area=AREA_DM_WORD, address=10,
                                           count=1, sid=self._sid_val())))
        cases.append(self._case(C, "Sequence: Write DM[10]=0xABCD",
                                _fins_write(area=AREA_DM_WORD, address=10,
                                            count=1, data=b'\xAB\xCD',
                                            sid=self._sid_val())))
        cases.append(self._case(C, "Sequence: Re-read DM[10] after write",
                                _fins_read(area=AREA_DM_WORD, address=10,
                                           count=1, sid=self._sid_val())))

        # Status reads interspersed
        cases.append(self._case(C, "Status between reads (sequence step)",
                                _fins_status(sid=self._sid_val())))

        # DA1 variants (addressing different nodes)
        for da1, label in [(0x00, "0 CPU"), (0x01, "1 node1"), (0xFF, "255 broadcast")]:
            cases.append(self._case(C, f"Read CIO DA1={label}",
                                    _fins_read(area=AREA_CIO_WORD, address=0,
                                               count=1, sid=self._sid_val(),
                                               da1=da1)))

        return cases

    # ------------------------------------------------------------------
    # Category: state_machine
    # ------------------------------------------------------------------

    def _gen_state_machine(self):
        C = CATEGORY_STATE_MACHINE
        cases = []

        # Response-type ICF sent from client (server should handle gracefully)
        response_hdr = _fins_header(icf=_ICF_RESPONSE, sid=self._sid_val(),
                                    mrc=0x01, src=0x01)
        cases.append(self._case(C, "Response ICF (0xC0) sent as command from client",
                                response_hdr + bytes([AREA_CIO_WORD, 0x00, 0x00, 0x00, 0x00, 0x01])))

        # GW bit variations
        hdr_gw = _fins_header(icf=_ICF_COMMAND | _ICF_GW_BIT, sid=self._sid_val(),
                              mrc=0x01, src=0x01)
        cases.append(self._case(C, "ICF with gateway bit set",
                                hdr_gw + bytes([AREA_CIO_WORD, 0x00, 0x00, 0x00, 0x00, 0x01])))

        # Response-not-required flag (bit 0 cleared → no response expected)
        no_resp_hdr = bytes([_ICF_COMMAND & ~_ICF_RESP_REQ, 0x00, 0x02,
                             0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                             self._sid_val(), 0x01, 0x01])
        cases.append(self._case(C, "ICF response-not-required flag cleared",
                                no_resp_hdr + bytes([AREA_CIO_WORD, 0x00, 0x00, 0x00, 0x00, 0x01])))

        # Write before read (no ordering enforcement in stateless UDP)
        cases.append(self._case(C, "Write to area without prior read",
                                _fins_write(area=AREA_DM_WORD, address=0,
                                            count=1, data=b'\xDE\xAD',
                                            sid=self._sid_val())))

        # Fill command (unusual ordering — fill, then read)
        cases.append(self._case(C, "Memory fill DM[0..9] with 0x0000",
                                _fins_fill(area=AREA_DM_WORD, address=0,
                                           count=10, fill_data=b'\x00\x00',
                                           sid=self._sid_val())))

        # CPU stop before run (out of order)
        cases.append(self._case(C, "CPU Stop (state: assume running)",
                                _fins_stop(sid=self._sid_val())))

        # Multiple rapid status reads
        for _ in range(3):
            cases.append(self._case(C, "Rapid status read (state machine stress)",
                                    _fins_status(sid=self._sid_val())))

        # Reset command (most disruptive)
        cases.append(self._case(C, "CPU Reset request",
                                _fins_reset(sid=self._sid_val())))

        # Unknown MRC/SRC combination (no valid state)
        unk = _fins_header(mrc=0xAA, src=0xBB, sid=self._sid_val())
        cases.append(self._case(C, "Unknown MRC=0xAA SRC=0xBB",
                                unk))

        return cases

    # ------------------------------------------------------------------
    # Category: memory_read
    # ------------------------------------------------------------------

    def _gen_memory_read(self):
        C = CATEGORY_MEMORY_READ
        cases = []

        # All documented area codes
        for area, name in [
            (AREA_CIO_WORD,   "CIO word"),
            (AREA_CIO_BIT,    "CIO bit"),
            (AREA_DM_WORD,    "DM word"),
            (AREA_DM_BIT,     "DM bit"),
            (AREA_EM0_WORD,   "EM0 word"),
            (AREA_HR_WORD,    "HR word"),
            (AREA_TIMER_PV,   "Timer PV"),
            (AREA_COUNTER_PV, "Counter PV"),
        ]:
            cases.append(self._case(C, f"Read area=0x{area:02X} ({name}) addr=0 count=1",
                                    _fins_read(area=area, address=0, count=1,
                                               sid=self._sid_val())))

        # Unknown area codes
        for area in (0x01, 0x10, 0x40, 0x55, 0xAA, 0xFE, 0xFF):
            cases.append(self._case(C, f"Read unknown area=0x{area:02X}",
                                    _fins_read(area=area, address=0, count=1,
                                               sid=self._sid_val())))

        # Address boundaries
        for addr, label in [(0, "0 min"), (100, "100 mid"), (0x7FFF, "0x7FFF large"),
                             (0xFFFF, "0xFFFF max")]:
            cases.append(self._case(C, f"Read CIO.W[{label}] count=1",
                                    _fins_read(area=AREA_CIO_WORD, address=addr,
                                               count=1, sid=self._sid_val())))

        # Count boundaries
        for count, label in [(0, "0 zero"), (1, "1 min"), (50, "50 normal"),
                              (256, "256 large"), (0x7FFF, "0x7FFF very large")]:
            cases.append(self._case(C, f"Read DM count={label}",
                                    _fins_read(area=AREA_DM_WORD, address=0,
                                               count=count, sid=self._sid_val())))

        # Bit-address variations (bit field non-zero)
        for bit, label in [(0, "0 word"), (1, "1 bit1"), (15, "15 last bit")]:
            cases.append(self._case(C, f"Read CIO.BIT[0] bit={label}",
                                    _fins_read(area=AREA_CIO_BIT, address=0,
                                               bit=bit, count=1,
                                               sid=self._sid_val())))

        # Read with all-zero count data (should return empty or error)
        cases.append(self._case(C, "Read CIO.W address=0xFFFF count=0xFFFF (max both)",
                                _fins_read(area=AREA_CIO_WORD, address=0xFFFF,
                                           count=0xFFFF, sid=self._sid_val())))

        # Back-to-back reads different areas
        for area, name in [(AREA_CIO_WORD, "CIO"), (AREA_DM_WORD, "DM"),
                           (AREA_HR_WORD, "HR")]:
            cases.append(self._case(C, f"Rapid {name} read",
                                    _fins_read(area=area, address=0, count=10,
                                               sid=self._sid_val())))

        return cases

    # ------------------------------------------------------------------
    # Category: memory_write
    # ------------------------------------------------------------------

    def _gen_memory_write(self):
        C = CATEGORY_MEMORY_WRITE
        cases = []

        # Write to all writable areas
        for area, name in [
            (AREA_CIO_WORD,   "CIO word"),
            (AREA_DM_WORD,    "DM word"),
            (AREA_EM0_WORD,   "EM0 word"),
            (AREA_HR_WORD,    "HR word"),
        ]:
            cases.append(self._case(C, f"Write area=0x{area:02X} ({name}) 2 bytes",
                                    _fins_write(area=area, address=0, count=1,
                                                data=b'\xAA\x55',
                                                sid=self._sid_val())))

        # Write to read-only / restricted areas
        for area, name in [
            (AREA_TIMER_PV,   "Timer PV"),
            (AREA_COUNTER_PV, "Counter PV"),
            (AREA_CIO_BIT,    "CIO bit"),
        ]:
            cases.append(self._case(C, f"Write restricted area=0x{area:02X} ({name})",
                                    _fins_write(area=area, address=0, count=1,
                                                data=b'\x00\x01',
                                                sid=self._sid_val())))

        # Unknown area write
        for area in (0x00, 0x01, 0xFF):
            cases.append(self._case(C, f"Write unknown area=0x{area:02X}",
                                    _fins_write(area=area, address=0, count=1,
                                                data=b'\xDE\xAD',
                                                sid=self._sid_val())))

        # Data length mismatches
        cases.append(self._case(C, "Write DM count=10 but only 2 bytes data (mismatch)",
                                _fins_write(area=AREA_DM_WORD, address=0,
                                            count=10, data=b'\x00\x00',
                                            sid=self._sid_val())))
        cases.append(self._case(C, "Write DM count=1 but 100 bytes data (excess)",
                                _fins_write(area=AREA_DM_WORD, address=0,
                                            count=1, data=b'\x00' * 100,
                                            sid=self._sid_val())))
        cases.append(self._case(C, "Write DM count=0 zero data",
                                _fins_write(area=AREA_DM_WORD, address=0,
                                            count=0, data=b'',
                                            sid=self._sid_val())))

        # Address edge
        cases.append(self._case(C, "Write CIO.W at address 0xFFFF",
                                _fins_write(area=AREA_CIO_WORD, address=0xFFFF,
                                            count=1, data=b'\xFF\xFF',
                                            sid=self._sid_val())))

        # Pattern data
        for pattern, label in [(b'\x00\x00', "zeros"), (b'\xFF\xFF', "ones"),
                                (b'\x55\xAA', "alt"), (b'\xAA\x55', "alt-inv")]:
            cases.append(self._case(C, f"Write CIO.W data={label}",
                                    _fins_write(area=AREA_CIO_WORD, address=0,
                                                count=1, data=pattern,
                                                sid=self._sid_val())))

        # Fill command (variant of write)
        cases.append(self._case(C, "Fill CIO.W[0..99] with 0xAAAA",
                                _fins_fill(area=AREA_CIO_WORD, address=0,
                                           count=100, fill_data=b'\xAA\xAA',
                                           sid=self._sid_val())))
        cases.append(self._case(C, "Fill DM[0..0xFFFF] with 0x0000 (overflow count)",
                                _fins_fill(area=AREA_DM_WORD, address=0,
                                           count=0xFFFF, fill_data=b'\x00\x00',
                                           sid=self._sid_val())))

        return cases

    # ------------------------------------------------------------------
    # Category: cpu_control
    # ------------------------------------------------------------------

    def _gen_cpu_control(self):
        C = CATEGORY_CPU_CONTROL
        cases = []

        # Standard CPU control commands
        cases.append(self._case(C, "CPU Run (mode=0x00)",
                                _fins_run(mode=0x00, sid=self._sid_val())))
        cases.append(self._case(C, "CPU Run (mode=0x02 monitor mode)",
                                _fins_run(mode=0x02, sid=self._sid_val())))
        cases.append(self._case(C, "CPU Run (mode=0xFF unknown mode)",
                                _fins_run(mode=0xFF, sid=self._sid_val())))
        cases.append(self._case(C, "CPU Stop",
                                _fins_stop(sid=self._sid_val())))
        cases.append(self._case(C, "CPU Reset",
                                _fins_reset(sid=self._sid_val())))

        # Clock and status
        cases.append(self._case(C, "Clock read (0x07/0x01)",
                                _fins_clock_read(sid=self._sid_val())))
        cases.append(self._case(C, "Controller status read (0x06/0x01)",
                                _fins_status(sid=self._sid_val())))
        cases.append(self._case(C, "Controller data read (0x05/0x01)",
                                _fins_ctrl_data(sid=self._sid_val())))

        # Unknown sub-commands under MRC=0x04 (CPU control group)
        for src in (0x00, 0x04, 0x05, 0xFF):
            hdr = _fins_header(mrc=0x04, src=src, sid=self._sid_val())
            cases.append(self._case(C, f"MRC=0x04 SRC=0x{src:02X} (unknown subcommand)",
                                    hdr))

        # MRC=0x06 (status) with unknown SRC
        for src in (0x00, 0x02, 0xFF):
            hdr = _fins_header(mrc=0x06, src=src, sid=self._sid_val())
            cases.append(self._case(C, f"MRC=0x06 SRC=0x{src:02X}",
                                    hdr))

        return cases

    # ------------------------------------------------------------------
    # Category: command_sweep
    # ------------------------------------------------------------------

    def _gen_command_sweep(self):
        C = CATEGORY_COMMAND_SWEEP
        cases = []

        # All documented MRC values with their standard SRC
        for mrc, src, label in [
            (0x01, 0x01, "Memory Read"),
            (0x01, 0x02, "Memory Write"),
            (0x01, 0x03, "Memory Fill"),
            (0x01, 0x04, "Multiple Memory Read"),
            (0x01, 0x05, "Memory Write (NOP)"),
            (0x02, 0x01, "IO Read"),
            (0x02, 0x02, "IO Write"),
            (0x03, 0x06, "CPU Unit Status Read"),
            (0x04, 0x01, "CPU Run"),
            (0x04, 0x02, "CPU Stop"),
            (0x04, 0x03, "CPU Reset"),
            (0x05, 0x01, "Controller Data Read"),
            (0x06, 0x01, "Controller Status Read"),
            (0x07, 0x01, "Clock Read"),
            (0x07, 0x02, "Clock Write"),
            (0x21, 0x01, "Error Read"),
            (0x21, 0x02, "Error Clear"),
            (0x22, 0x01, "Error Log Read"),
            (0x22, 0x02, "Error Log Clear"),
            (0x22, 0x03, "FM Write"),
        ]:
            hdr = _fins_header(mrc=mrc, src=src, sid=self._sid_val())
            # Append minimal data to avoid truncation errors
            cases.append(self._case(C, f"MRC=0x{mrc:02X} SRC=0x{src:02X} ({label})",
                                    hdr + b'\x00' * 6))

        # Reserved and unknown MRC values
        for mrc in (0x00, 0x08, 0x09, 0x10, 0x11, 0xFF):
            hdr = _fins_header(mrc=mrc, src=0x01, sid=self._sid_val())
            cases.append(self._case(C, f"Reserved MRC=0x{mrc:02X} SRC=0x01",
                                    hdr + b'\x00' * 6))

        # All-zero command after valid header
        hdr = _fins_header(mrc=0x01, src=0x01, sid=self._sid_val())
        cases.append(self._case(C, "MRC=0x01 SRC=0x01 data=all-zeros",
                                hdr + b'\x00' * 8))

        # All-0xFF command data
        hdr = _fins_header(mrc=0x01, src=0x01, sid=self._sid_val())
        cases.append(self._case(C, "MRC=0x01 SRC=0x01 data=all-0xFF",
                                hdr + b'\xFF' * 8))

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
            print(f"\r[fins] {i}/{total}  {case_id}  {desc[:55]}",
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
        try:
            self._sock.sendto(payload, self._target_addr)
            try:
                data, _ = self._sock.recvfrom(2048)
                result.duration_ms = (time.monotonic() - t0) * 1000
                if not data:
                    result.anomaly         = ANOMALY_NO_RESPONSE
                    result.crash_indicator = True
                else:
                    result.response = data
                    self._classify_response(data, payload, result)
            except socket.timeout:
                result.anomaly         = ANOMALY_TIMEOUT
                result.crash_indicator = True
                result.duration_ms     = (time.monotonic() - t0) * 1000
        except OSError as e:
            result.anomaly         = ANOMALY_CONNECTION_RESET
            result.crash_indicator = True
            result.duration_ms     = (time.monotonic() - t0) * 1000
        return result

    def _classify_response(self, data: bytes, request: bytes,
                            result: FuzzResult) -> None:
        # Minimum: 12-byte header + 2-byte end_code = 14
        if len(data) < 14:
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        # Check ICF response bit
        if (data[0] & 0xC0) != 0xC0:
            result.anomaly         = ANOMALY_UNEXPECTED_DATA
            result.crash_indicator = False
            return

        # Check SID matches (best-effort for UDP — warn but don't crash-flag)
        if len(request) >= 10 and data[9] != request[9]:
            result.anomaly         = ANOMALY_UNEXPECTED_DATA
            result.crash_indicator = False
            return

        # End code: bytes 12-13 (MRES/SRES)
        end_code = (data[12] << 8) | data[13]
        if end_code != 0x0000:
            result.anomaly         = ANOMALY_EXCEPTION
            result.crash_indicator = False
