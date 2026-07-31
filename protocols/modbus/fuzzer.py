"""Modbus TCP fuzzer module.

Spec: MODBUS Application Protocol Specification V1.1b3 (modbus.org, 2012-04-26)
TCP:  MODBUS Messaging on TCP/IP Implementation Guide V1.0b (modbus.org, 2006-10-24)
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
    CATEGORY_AUTH,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_INJECTION,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
    FuzzModule,
    FuzzResult,
    INJECTION_STRINGS,
)

# ---------------------------------------------------------------------------
# Function codes (V1.1b3 §3)
# ---------------------------------------------------------------------------
FC_READ_COILS               = 0x01
FC_READ_DISCRETE_INPUTS     = 0x02
FC_READ_HOLDING_REGS        = 0x03
FC_READ_INPUT_REGS          = 0x04
FC_WRITE_SINGLE_COIL        = 0x05
FC_WRITE_SINGLE_REG         = 0x06
FC_WRITE_MULTIPLE_COILS     = 0x0F
FC_WRITE_MULTIPLE_REGS      = 0x10
FC_MASK_WRITE_REG           = 0x16
FC_READ_WRITE_MULTIPLE_REGS = 0x17
FC_ENCAPSULATED_IF          = 0x2B   # MEI type 0x0E = Read Device ID

COIL_ON  = 0xFF00
COIL_OFF = 0x0000

# Unassigned codes in the public ranges (1-64, 73-99, 111-127) per V1.1b3 §3.
# Devices must return Exception 01 (Illegal Function) — or may crash.
_ASSIGNED_PUBLIC = frozenset([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x2B,
])
_GAP_CODES = [0x00] + sorted(
    set(list(range(0x01, 0x41)) + list(range(0x49, 0x64)) + list(range(0x6F, 0x80)))
    - _ASSIGNED_PUBLIC
)
_USER_DEFINED_CODES = list(range(0x41, 0x49)) + list(range(0x64, 0x6F))
_EXCEPTION_SPACE    = list(range(0x80, 0x100))


class ModbusFuzzer(FuzzModule):
    """Modbus TCP fuzzer.

    Library: pymodbus>=3.6.0 (send phase, hardware required)
    Spec reference: MODBUS Application Protocol Specification V1.1b3

    Protocol-specific fuzz categories beyond the standard set:
      - invalid_function_codes: unassigned public codes, user-defined, exception space
      - broadcast_abuse: unit ID 0x00 (serial broadcast) and reserved range 0xF8-0xFF
      - coil_aliasing: read/write across coil/register address boundaries
    """

    PROTOCOL_NAME = "modbus"
    DEFAULT_PORT = 502
    FUZZ_CATEGORIES = [
        CATEGORY_BOUNDARY,
        CATEGORY_INJECTION,
        CATEGORY_STATE_MACHINE,
        CATEGORY_SEQUENCE,
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_AUTH,
        "invalid_function_codes",
        "broadcast_abuse",
        "coil_aliasing",
    ]

    def __init__(
        self,
        target: Device,
        logger,
        delay: float = 0.1,
        seeds: list = None,
        injection_file: str = None,
        unit_id: int = 0x01,
    ):
        super().__init__(target, logger, delay, seeds)
        self._sock: Optional[socket.socket] = None
        self._unit_id = unit_id
        self._injection_payloads = list(INJECTION_STRINGS)
        if injection_file:
            with open(injection_file) as fh:
                extras = [line.rstrip("\n") for line in fh if line.strip()]
            self._injection_payloads.extend(extras)

    # ------------------------------------------------------------------
    # MBAP / PDU helpers
    # ------------------------------------------------------------------

    def _mbap(self, pdu: bytes, unit_id: int = None, tid: int = 0x0001) -> bytes:
        """Build a complete Modbus TCP ADU (MBAP header + PDU).

        MBAP layout (7 bytes):
          [0:2] Transaction ID  — echoed in server response
          [2:4] Protocol ID     — always 0x0000 for Modbus
          [4:6] Length          — byte count of unit_id + PDU
          [6]   Unit Identifier — defaults to self._unit_id (set via --unit-id, default 0x01)
        """
        if unit_id is None:
            unit_id = self._unit_id
        return struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), unit_id) + pdu

    @staticmethod
    def _mbap_raw(tid: int, proto_id: int, length: int, unit_id: int, pdu: bytes) -> bytes:
        """Build an ADU with fully explicit MBAP fields — used for malformed-frame tests."""
        return struct.pack(">HHHB", tid, proto_id, length, unit_id) + pdu

    @staticmethod
    def _pdu_read(fc: int, start: int, qty: int) -> bytes:
        return struct.pack(">BHH", fc, start, qty)

    @staticmethod
    def _pdu_write_single_coil(addr: int, value: int) -> bytes:
        return struct.pack(">BHH", FC_WRITE_SINGLE_COIL, addr, value)

    @staticmethod
    def _pdu_write_single_reg(addr: int, value: int) -> bytes:
        return struct.pack(">BHH", FC_WRITE_SINGLE_REG, addr, value)

    @staticmethod
    def _pdu_write_multiple_regs(start: int, values: list) -> bytes:
        count = len(values)
        header = struct.pack(">BHHB", FC_WRITE_MULTIPLE_REGS, start, count, count * 2)
        return header + struct.pack(f">{count}H", *values)

    # ------------------------------------------------------------------
    # Fuzz case generators
    # Each returns list[tuple[str, bytes]]: (description, raw_ADU_bytes)
    # ------------------------------------------------------------------

    def _generate_boundary(self) -> list:
        cases = []

        # FC01 / FC02: Read Coils / Read Discrete Inputs
        # Spec §6.1-6.2: quantity must be 1–2000; addresses 0x0000–0xFFFF
        for fc, name in [
            (FC_READ_COILS,           "FC01 Read Coils"),
            (FC_READ_DISCRETE_INPUTS, "FC02 Read Discrete Inputs"),
        ]:
            for qty, label in [
                (0,      "qty=0 (below minimum)"),
                (1,      "qty=1 (spec minimum)"),
                (2000,   "qty=2000 (spec maximum)"),
                (2001,   "qty=2001 (one above max → Exception 03)"),
                (0xFFFF, "qty=0xFFFF (16-bit max)"),
            ]:
                cases.append((f"{name}: {label}", self._mbap(self._pdu_read(fc, 0x0000, qty))))

            for addr, qty, label in [
                (0x0000, 1,    "addr=0x0000 (floor)"),
                (0xFFFF, 1,    "addr=0xFFFF (ceiling)"),
                (0xFFFE, 2,    "addr=0xFFFE qty=2 (straddles ceiling)"),
                (0xFFFF, 2000, "addr=0xFFFF qty=2000 (max count at ceiling)"),
            ]:
                cases.append((f"{name}: {label}", self._mbap(self._pdu_read(fc, addr, qty))))

        # FC03 / FC04: Read Holding / Input Registers
        # Spec §6.3-6.4: quantity must be 1–125
        for fc, name in [
            (FC_READ_HOLDING_REGS, "FC03 Read Holding Registers"),
            (FC_READ_INPUT_REGS,   "FC04 Read Input Registers"),
        ]:
            for qty, label in [
                (0,      "qty=0 (below minimum)"),
                (1,      "qty=1 (spec minimum)"),
                (125,    "qty=125 (spec maximum)"),
                (126,    "qty=126 (one above max → Exception 03)"),
                (0xFFFF, "qty=0xFFFF (16-bit max)"),
            ]:
                cases.append((f"{name}: {label}", self._mbap(self._pdu_read(fc, 0x0000, qty))))

            for addr, qty, label in [
                (0x0000,  1,   "addr=0x0000 (floor)"),
                (0xFFFF,  1,   "addr=0xFFFF (ceiling)"),
                (0xFFFF, 125,  "addr=0xFFFF qty=125 (overflow address space)"),
                (0xFF80,  125, "addr near end qty=125 (boundary straddle)"),
            ]:
                cases.append((f"{name}: {label}", self._mbap(self._pdu_read(fc, addr, qty))))

        # FC05: Write Single Coil
        # Spec §6.5: only 0xFF00 (ON) or 0x0000 (OFF) are valid; all others → Exception 03
        for val, label in [
            (0xFF00, "0xFF00 (valid ON)"),
            (0x0000, "0x0000 (valid OFF)"),
            (0x0001, "0x0001 (invalid → Exception 03)"),
            (0x00FF, "0x00FF (invalid)"),
            (0xFFFE, "0xFFFE (invalid)"),
            (0x8000, "0x8000 (high bit set, invalid)"),
            (0x0100, "0x0100 (off-by-one from valid ON)"),
            (0xFFFF, "0xFFFF (all bits set, invalid)"),
        ]:
            cases.append((
                f"FC05 Write Single Coil: value={label}",
                self._mbap(self._pdu_write_single_coil(0x0000, val)),
            ))

        # FC06: Write Single Register
        # Spec §6.6: all 16-bit values are valid; testing arithmetic edge cases
        for val, label in [
            (0x0000, "0x0000 (min)"),
            (0xFFFF, "0xFFFF (max)"),
            (0x8000, "0x8000 (INT16 sign boundary)"),
            (0x7FFF, "0x7FFF (INT16 max positive)"),
        ]:
            cases.append((
                f"FC06 Write Single Register: value={label}",
                self._mbap(self._pdu_write_single_reg(0x0000, val)),
            ))

        # FC0F: Write Multiple Coils
        # Spec §6.11: quantity 1–1968; byte_count = ceil(qty/8)
        for qty, byte_count, data, label in [
            (0,    0,   b"",           "qty=0 (below minimum)"),
            (1,    1,   b"\xFF",       "qty=1 (minimum)"),
            (1968, 246, b"\xFF" * 246, "qty=1968 (spec maximum)"),
            (1969, 247, b"\xFF" * 247, "qty=1969 (one above max)"),
            (2000, 250, b"\xFF" * 250, "qty=2000 (FC01 max, above FC0F max)"),
            (8,    0,   b"",           "qty=8 byte_count=0 (undercount)"),
            (8,    2,   b"\xFF\xFF",   "qty=8 byte_count=2 (should be 1)"),
        ]:
            pdu = struct.pack(">BHHB", FC_WRITE_MULTIPLE_COILS, 0x0000, qty, byte_count) + data
            cases.append((f"FC0F Write Multiple Coils: {label}", self._mbap(pdu)))

        # FC10: Write Multiple Registers
        # Spec §6.12: quantity 1–123; byte_count = qty*2
        for qty, byte_count, data, label in [
            (0,   0,   b"",                "qty=0 (below minimum)"),
            (1,   2,   b"\x00\x01",        "qty=1 (minimum)"),
            (123, 246, b"\xAB\xCD" * 123,  "qty=123 (spec maximum)"),
            (124, 248, b"\xAB\xCD" * 124,  "qty=124 (one above max)"),
            (125, 250, b"\xAB\xCD" * 125,  "qty=125 (FC03 max, above FC10 max)"),
            (2,   0,   b"",                "qty=2 byte_count=0 (empty data)"),
            (2,   2,   b"\x00\x01",        "qty=2 byte_count=2 (half expected)"),
            (1,   4,   b"\x00\x01\x00\x02","qty=1 byte_count=4 (double expected)"),
        ]:
            pdu = struct.pack(">BHHB", FC_WRITE_MULTIPLE_REGS, 0x0000, qty, byte_count) + data
            cases.append((f"FC10 Write Multiple Registers: {label}", self._mbap(pdu)))

        # MBAP Length field boundaries (PDU kept valid, only Length mutated)
        valid_pdu = self._pdu_read(FC_READ_HOLDING_REGS, 0x0000, 0x0001)
        for length_val, label in [
            (0x0000, "0 (zero)"),
            (0x0001, "1 (unit_id only, no FC)"),
            (0x0006, "6 (correct for FC03 request)"),
            (0x00FF, "255 (spec PDU ceiling)"),
            (0x0100, "256 (one over spec ceiling)"),
            (0xFFFF, "65535 (16-bit max)"),
        ]:
            cases.append((
                f"MBAP Length boundary: {label}",
                self._mbap_raw(0x0001, 0x0000, length_val, self._unit_id, valid_pdu),
            ))

        return cases

    def _generate_injection(self) -> list:
        cases = []

        # Write payloads as holding register data via FC10 (Write Multiple Registers).
        # Modbus has no native string type; strings occupy consecutive 16-bit registers
        # (2 bytes per register, big-endian). Payloads are included to surface
        # vulnerabilities in HMI / historian / SCADA systems that display or log
        # register values. This is secondary to protocol-level fuzzing — see
        # lab-notes/modbus-research.md §Secondary Injection.
        for payload_str in self._injection_payloads:
            raw = payload_str.encode("utf-8", errors="replace")
            if len(raw) % 2:
                raw += b"\x00"
            word_count = min(len(raw) // 2, 123)
            if word_count == 0:
                raw = b"\x00\x00"
                word_count = 1
            raw = raw[: word_count * 2]
            pdu = struct.pack(">BHHB", FC_WRITE_MULTIPLE_REGS, 0x0000, word_count, word_count * 2) + raw
            cases.append((f"Injection FC10: {payload_str[:60]!r}", self._mbap(pdu)))

        # Also push single-register probes via FC06 (first two bytes of payload)
        for payload_str in self._injection_payloads:
            raw = (payload_str.encode("utf-8", errors="replace") + b"\x00\x00")[:2]
            val = struct.unpack(">H", raw)[0]
            cases.append((
                f"Injection FC06: {payload_str[:60]!r}",
                self._mbap(self._pdu_write_single_reg(0x0000, val)),
            ))

        return cases

    def _generate_state_machine(self) -> list:
        cases = []
        valid_pdu = self._pdu_read(FC_READ_HOLDING_REGS, 0x0000, 0x0001)

        # MBAP Protocol ID != 0x0000
        # Spec TCP guide §3.1: "0 for Modbus; other values reserved for future use"
        for proto_id, label in [
            (0x0001, "Protocol ID=0x0001 (reserved)"),
            (0x00FF, "Protocol ID=0x00FF"),
            (0xFFFF, "Protocol ID=0xFFFF (max)"),
        ]:
            cases.append((
                f"State machine: MBAP {label}",
                self._mbap_raw(0x0001, proto_id, 1 + len(valid_pdu), self._unit_id, valid_pdu),
            ))

        # Zero-length PDU: Length=1 means only the unit_id byte, no function code
        cases.append((
            "State machine: Length=1 (unit_id only, no function code)",
            self._mbap_raw(0x0001, 0x0000, 1, self._unit_id, b""),
        ))

        # Length > actual payload (starvation — server blocks waiting for bytes that never arrive)
        cases.append((
            "State machine: Length=255 but PDU is 5 bytes (starvation)",
            self._mbap_raw(0x0001, 0x0000, 0x00FF, self._unit_id, valid_pdu),
        ))

        # Length < actual payload (truncation — server reads partial PDU)
        cases.append((
            "State machine: Length=2 but PDU is 5 bytes (truncation)",
            self._mbap_raw(0x0001, 0x0000, 2, self._unit_id, valid_pdu),
        ))

        # Exception-space FC values sent as requests (0x80+ are server-response-only per spec)
        for fc in [0x80, 0x83, 0x90, 0xC0, 0xFF]:
            pdu = bytes([fc]) + b"\x00\x00\x00\x01"
            cases.append((
                f"State machine: FC=0x{fc:02X} (exception space as request)",
                self._mbap(pdu),
            ))

        # Duplicate transaction ID across two pipelined requests
        pdu_a = self._pdu_read(FC_READ_HOLDING_REGS, 0x0000, 1)
        pdu_b = self._pdu_read(FC_READ_HOLDING_REGS, 0x0001, 1)
        adu_a = self._mbap_raw(0xAAAA, 0x0000, 1 + len(pdu_a), self._unit_id, pdu_a)
        adu_b = self._mbap_raw(0xAAAA, 0x0000, 1 + len(pdu_b), self._unit_id, pdu_b)
        cases.append(("State machine: duplicate TID=0xAAAA in two pipelined requests", adu_a + adu_b))

        # Two complete ADUs in one TCP segment (tests ADU boundary parsing)
        adu_1 = self._mbap(self._pdu_read(FC_READ_HOLDING_REGS, 0x0000, 1), tid=0x0001)
        adu_2 = self._mbap(self._pdu_read(FC_READ_HOLDING_REGS, 0x0001, 1), tid=0x0002)
        cases.append(("State machine: two complete ADUs in single TCP segment", adu_1 + adu_2))

        # Read + write to same address in one segment (interleaved)
        read_adu  = self._mbap(self._pdu_read(FC_READ_HOLDING_REGS, 0x0000, 1), tid=0x0001)
        write_adu = self._mbap(self._pdu_write_single_reg(0x0000, 0xDEAD), tid=0x0002)
        cases.append((
            "State machine: FC03 read + FC06 write to same address in one segment",
            read_adu + write_adu,
        ))

        return cases

    def _generate_sequence(self) -> list:
        cases = []

        # 5 pipelined FC03 reads with sequential TIDs (no wait between sends)
        pipeline = b""
        for i in range(5):
            pipeline += self._mbap(self._pdu_read(FC_READ_HOLDING_REGS, i, 1), tid=i + 1)
        cases.append(("Sequence: 5 pipelined FC03 reads TID 1-5", pipeline))

        # 10 pipelined FC06 writes to consecutive registers
        writes = b""
        for i in range(10):
            writes += self._mbap(self._pdu_write_single_reg(i, 0xBEEF), tid=i + 1)
        cases.append(("Sequence: 10 pipelined FC06 writes to regs 0-9", writes))

        # Read → write → read same register in one segment
        r1 = self._mbap(self._pdu_read(FC_READ_HOLDING_REGS, 0x0000, 1), tid=0x0001)
        w1 = self._mbap(self._pdu_write_single_reg(0x0000, 0xBEEF), tid=0x0002)
        r2 = self._mbap(self._pdu_read(FC_READ_HOLDING_REGS, 0x0000, 1), tid=0x0003)
        cases.append(("Sequence: read→write→read same register", r1 + w1 + r2))

        # TID wraparound: 0xFFFF immediately followed by 0x0000
        pdu = self._pdu_read(FC_READ_HOLDING_REGS, 0x0000, 1)
        cases.append((
            "Sequence: TID 0xFFFF→0x0000 wraparound",
            self._mbap(pdu, tid=0xFFFF) + self._mbap(pdu, tid=0x0000),
        ))

        # TID=0x0000 (some implementations reject or misroute zero TID)
        cases.append(("Sequence: TID=0x0000 (zero)", self._mbap(pdu, tid=0x0000)))

        # FC17: Read/Write Multiple Registers — atomic read+write in single request
        rw_pdu = (
            struct.pack(
                ">BHHHHB",
                FC_READ_WRITE_MULTIPLE_REGS,
                0x0000, 2,   # read start, read qty
                0x0000, 2,   # write start, write qty
                4,           # byte count
            )
            + struct.pack(">HH", 0xCAFE, 0xBABE)
        )
        cases.append(("Sequence: FC23 Read/Write Multiple Registers (atomic)", self._mbap(rw_pdu)))

        # FC10 with byte_count field inconsistent with quantity
        for qty, byte_count, label in [
            (2, 3, "qty=2 byte_count=3 (odd, should be 4)"),
            (2, 5, "qty=2 byte_count=5 (over by one)"),
            (2, 2, "qty=2 byte_count=2 (half expected)"),
        ]:
            pdu = struct.pack(">BHHB", FC_WRITE_MULTIPLE_REGS, 0x0000, qty, byte_count) + b"\xAB" * byte_count
            cases.append((f"Sequence: FC10 byte_count mismatch — {label}", self._mbap(pdu)))

        return cases

    def _generate_binary_corruption(self) -> list:
        cases = []

        # Canonical valid FC03 request: 7-byte MBAP + 5-byte PDU = 12 bytes
        valid_pdu = self._pdu_read(FC_READ_HOLDING_REGS, 0x0000, 0x0001)
        base = self._mbap(valid_pdu, tid=0x0001)

        # Single-bit flip at every bit position in the frame
        for byte_idx in range(len(base)):
            for bit in range(8):
                corrupted = bytearray(base)
                corrupted[byte_idx] ^= 1 << bit
                cases.append((
                    f"Bit flip byte[{byte_idx}] bit {bit}: "
                    f"0x{base[byte_idx]:02X}→0x{corrupted[byte_idx]:02X}",
                    bytes(corrupted),
                ))

        # Truncation at each byte boundary
        for length in range(1, len(base)):
            cases.append((f"Truncation: {length}/{len(base)} bytes", base[:length]))

        # Byte substitution: 0x00, 0xFF, 0xAA at each position
        for byte_idx in range(len(base)):
            for val in (0x00, 0xFF, 0xAA):
                corrupted = bytearray(base)
                corrupted[byte_idx] = val
                cases.append((
                    f"Byte sub byte[{byte_idx}]=0x{val:02X} (was 0x{base[byte_idx]:02X})",
                    bytes(corrupted),
                ))

        # Adjacent byte swaps
        for i in range(len(base) - 1):
            corrupted = bytearray(base)
            corrupted[i], corrupted[i + 1] = corrupted[i + 1], corrupted[i]
            cases.append((f"Byte swap byte[{i}]↔byte[{i+1}]", bytes(corrupted)))

        # MBAP Length field swept over boundary values with fixed valid PDU
        for length_val, label in [
            (0x0000, "0"),
            (0x0001, "1"),
            (0x0006, "6 (correct)"),
            (0x00FF, "255"),
            (0x0100, "256"),
            (0xFFFF, "65535"),
        ]:
            cases.append((
                f"Binary corruption: MBAP Length={label}",
                self._mbap_raw(0x0001, 0x0000, length_val, self._unit_id, valid_pdu),
            ))

        return cases

    def _generate_auth(self) -> list:
        cases = []
        read_pdu = self._pdu_read(FC_READ_HOLDING_REGS, 0x0000, 1)

        # Full unit ID sweep via FC03 — maps which unit IDs respond.
        # Spec serial ranges: 0x00 broadcast, 0x01-0xF7 individual, 0xF8-0xFF reserved.
        # On TCP-direct connections all UIDs are delivered to the same device; behavior varies.
        for uid in range(0x00, 0x100):
            cases.append((
                f"Auth: unit ID sweep UID=0x{uid:02X} FC03",
                self._mbap(read_pdu, unit_id=uid),
            ))

        # Write commands to reserved UIDs (may gateway-forward as serial broadcast or to specific slave)
        write_pdu = self._pdu_write_single_reg(0x0000, 0xDEAD)
        for uid in range(0xF8, 0x100):
            cases.append((
                f"Auth: FC06 write to reserved UID=0x{uid:02X}",
                self._mbap(write_pdu, unit_id=uid),
            ))

        # Transaction ID probing — spec defines no auth on TID;
        # some implementations mishandle boundary values
        for tid, label in [
            (0x0000, "TID=0x0000 (zero)"),
            (0x0001, "TID=0x0001 (minimum)"),
            (0x7FFF, "TID=0x7FFF (INT16 max positive)"),
            (0x8000, "TID=0x8000 (INT16 sign boundary)"),
            (0xDEAD, "TID=0xDEAD"),
            (0xFFFF, "TID=0xFFFF (max)"),
        ]:
            cases.append((f"Auth: transaction ID probe {label}", self._mbap(read_pdu, tid=tid)))

        return cases

    def _generate_invalid_function_codes(self) -> list:
        cases = []

        # Unassigned codes in the public range — spec requires Exception 01 (Illegal Function).
        # Devices that crash or behave unexpectedly on these are non-compliant and vulnerable.
        for fc in _GAP_CODES:
            cases.append((
                f"FC probe 0x{fc:02X}: gap/unassigned, no data",
                self._mbap(bytes([fc])),
            ))
            cases.append((
                f"FC probe 0x{fc:02X}: gap/unassigned, 4-byte data",
                self._mbap(bytes([fc]) + b"\x00\x00\x00\x01"),
            ))

        # User-defined codes (0x41-0x48, 0x64-0x6E) — device response is implementation-defined
        for fc in _USER_DEFINED_CODES:
            cases.append((
                f"FC probe 0x{fc:02X}: user-defined, no data",
                self._mbap(bytes([fc])),
            ))
            cases.append((
                f"FC probe 0x{fc:02X}: user-defined, 4-byte data",
                self._mbap(bytes([fc]) + b"\x00\x00\x00\x01"),
            ))

        # Exception space (0x80-0xFF) sent as requests — server-only per spec
        for fc in _EXCEPTION_SPACE:
            cases.append((
                f"FC probe 0x{fc:02X}: exception space as request",
                self._mbap(bytes([fc]) + b"\x00\x00\x00\x01"),
            ))

        return cases

    def _generate_broadcast_abuse(self) -> list:
        cases = []

        # Serial broadcast (UID=0x00): spec says all slaves accept, none respond.
        # On a TCP→serial gateway this write hits every downstream slave simultaneously.
        broadcast_targets = [
            (0x00, "UID=0x00 (serial broadcast)"),
            (0xFF, "UID=0xFF (TCP unspecified convention)"),
        ]
        reserved_targets = [(u, f"UID=0x{u:02X} (serial reserved)") for u in range(0xF8, 0xFF)]

        write_commands = [
            ("FC05 Write Coil ON",        self._pdu_write_single_coil(0x0000, COIL_ON)),
            ("FC05 Write Coil OFF",       self._pdu_write_single_coil(0x0000, COIL_OFF)),
            ("FC06 Write Single Reg",     self._pdu_write_single_reg(0x0000, 0xDEAD)),
            ("FC0F Write Multiple Coils", struct.pack(">BHHB", FC_WRITE_MULTIPLE_COILS, 0x0000, 8, 1) + b"\xFF"),
            ("FC10 Write Multiple Regs",  self._pdu_write_multiple_regs(0x0000, [0xDEAD, 0xBEEF])),
        ]

        for uid, uid_label in broadcast_targets + reserved_targets:
            for cmd_label, pdu in write_commands:
                cases.append((
                    f"Broadcast: {uid_label} — {cmd_label}",
                    self._mbap(pdu, unit_id=uid),
                ))

        # Read via broadcast — spec prohibits responses, but non-compliant devices may reply
        for uid, uid_label in broadcast_targets:
            pdu = self._pdu_read(FC_READ_HOLDING_REGS, 0x0000, 1)
            cases.append((
                f"Broadcast: {uid_label} — FC03 read (expect no response per spec)",
                self._mbap(pdu, unit_id=uid),
            ))

        return cases

    def _generate_coil_aliasing(self) -> list:
        cases = []

        # Write via one data type, immediately read back via another.
        # Some PLCs share physical storage between the coil and register address spaces;
        # a register write at address N may flip coil bits N*16 through N*16+15.
        for write_label, write_pdu in [
            ("FC05 coil ON at 0x0000",     self._pdu_write_single_coil(0x0000, COIL_ON)),
            ("FC06 reg=0xFFFF at 0x0000",  self._pdu_write_single_reg(0x0000, 0xFFFF)),
            ("FC06 reg=0x0000 at 0x0000",  self._pdu_write_single_reg(0x0000, 0x0000)),
        ]:
            for read_fc, read_label in [
                (FC_READ_COILS,           "FC01 read coil at 0x0000"),
                (FC_READ_HOLDING_REGS,    "FC03 read reg at 0x0000"),
                (FC_READ_INPUT_REGS,      "FC04 read input reg at 0x0000"),
                (FC_READ_DISCRETE_INPUTS, "FC02 read discrete input at 0x0000"),
            ]:
                read_pdu = self._pdu_read(read_fc, 0x0000, 1)
                cases.append((
                    f"Coil aliasing: {write_label} → {read_label}",
                    self._mbap(write_pdu, tid=0x0001) + self._mbap(read_pdu, tid=0x0002),
                ))

        # Addresses that commonly straddle coil/register memory in PLC implementations
        for addr in [0x0000, 0x0001, 0x000F, 0x0010, 0x001F, 0x0020]:
            write_pdu = self._pdu_write_single_reg(addr, 0xFFFF)
            read_pdu  = self._pdu_read(FC_READ_COILS, addr, 16)
            cases.append((
                f"Coil aliasing: write reg 0xFFFF at 0x{addr:04X}, read 16 coils at same addr",
                self._mbap(write_pdu, tid=0x0001) + self._mbap(read_pdu, tid=0x0002),
            ))

        # Write coil block that spans into register-addressed space
        for start, qty in [(0x0000, 16), (0x0010, 16), (0x0000, 1968)]:
            byte_count = (qty + 7) // 8
            coil_pdu = (
                struct.pack(">BHHB", FC_WRITE_MULTIPLE_COILS, start, qty, byte_count)
                + b"\xFF" * byte_count
            )
            reg_addr = start // 16
            reg_qty  = min(max(1, qty // 16), 125)
            reg_pdu  = self._pdu_read(FC_READ_HOLDING_REGS, reg_addr, reg_qty)
            cases.append((
                f"Coil aliasing: write {qty} coils from 0x{start:04X}, "
                f"read overlapping regs at 0x{reg_addr:04X}",
                self._mbap(coil_pdu, tid=0x0001) + self._mbap(reg_pdu, tid=0x0002),
            ))

        return cases

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate_cases(self, categories=None) -> list:
        """Return all fuzz cases without sending. Hardware-independent.

        Returns list of (case_id, category, description, payload_bytes).
        Use for inspection, export, or unit testing without a live target.
        """
        active = self._resolve_categories(categories)
        generator_map = {
            CATEGORY_BOUNDARY:          self._generate_boundary,
            CATEGORY_INJECTION:         self._generate_injection,
            CATEGORY_STATE_MACHINE:     self._generate_state_machine,
            CATEGORY_SEQUENCE:          self._generate_sequence,
            CATEGORY_BINARY_CORRUPTION: self._generate_binary_corruption,
            CATEGORY_AUTH:              self._generate_auth,
            "invalid_function_codes":   self._generate_invalid_function_codes,
            "broadcast_abuse":          self._generate_broadcast_abuse,
            "coil_aliasing":            self._generate_coil_aliasing,
        }
        cases = []
        for category in active:
            gen = generator_map.get(category)
            if gen is None:
                continue
            for description, payload in gen():
                cases.append((self._next_id(), category, description, payload))
        return cases

    def fuzz(self, categories=None) -> list:
        active = self._resolve_categories(categories)
        generator_map = {
            CATEGORY_BOUNDARY:          self._generate_boundary,
            CATEGORY_INJECTION:         self._generate_injection,
            CATEGORY_STATE_MACHINE:     self._generate_state_machine,
            CATEGORY_SEQUENCE:          self._generate_sequence,
            CATEGORY_BINARY_CORRUPTION: self._generate_binary_corruption,
            CATEGORY_AUTH:              self._generate_auth,
            "invalid_function_codes":   self._generate_invalid_function_codes,
            "broadcast_abuse":          self._generate_broadcast_abuse,
            "coil_aliasing":            self._generate_coil_aliasing,
        }

        # Pre-generate all cases so we know the total count for progress output.
        category_cases: dict[str, list] = {}
        for category in active:
            gen = generator_map.get(category)
            if gen is not None:
                category_cases[category] = gen()
        total_cases = sum(len(v) for v in category_cases.values())

        print(f"[modbus] {total_cases} cases  {len(category_cases)} categor{'y' if len(category_cases) == 1 else 'ies'}")

        results = []
        sent = 0
        for category, cases in category_cases.items():
            print(f"[modbus] ── {category}  ({len(cases)} cases)")
            for description, payload in cases:
                case_id = self._next_id()
                result = self._send_case(case_id, category, description, payload)
                results.append(result)
                sent += 1
                if result.anomaly and not result.crash_indicator:
                    print(f"  [~] {case_id}  {result.anomaly}  {description[:55]}")
                if sent % 50 == 0:
                    pct = sent / total_cases * 100
                    print(f"[modbus] {case_id}  {sent}/{total_cases} ({pct:.0f}%)  {description[:45]}")

        return results

    def _send_case(self, case_id: str, category: str, description: str, payload: bytes) -> FuzzResult:
        if self._sock is None:
            raise RuntimeError(
                "Not connected — call connect() before fuzz(). "
                "Use generate_cases() to build payloads without a live target."
            )
        start = time.monotonic()
        result = FuzzResult(
            case_id=case_id,
            protocol=self.PROTOCOL_NAME,
            target=f"{self.target.ip}:{self.target.port}",
            category=category,
            description=description,
            payload=payload,
        )
        try:
            self._sock.sendall(payload)
            # Multi-ADU payloads (pipelined sequences, aliasing pairs) generate one
            # response per ADU. Drain all but the last to prevent TCP buffer
            # contamination for subsequent cases.
            for _ in range(self._count_adus(payload) - 1):
                self._recv_response()
            response = self._recv_response()
            result.response = response
            if not response:
                result.anomaly = ANOMALY_NO_RESPONSE
                result.crash_indicator = True
            elif len(response) < 7:
                result.anomaly = ANOMALY_MALFORMED_RESPONSE
                result.crash_indicator = True
            else:
                # Compare against the last ADU's TID — for single-ADU cases this is
                # identical to payload[0:2]; for pipelined/aliasing pairs we drained
                # N-1 responses and now hold the Nth ADU's response.
                self._classify_response(
                    payload, response, result,
                    expected_tid=self._last_adu_tid(payload),
                )
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

    @staticmethod
    def _count_adus(payload: bytes) -> int:
        """Count complete Modbus ADUs in a payload (multi-ADU cases: pipelines, aliasing pairs)."""
        count, offset = 0, 0
        while offset + 7 <= len(payload):
            _, _, length, _ = struct.unpack(">HHHB", payload[offset:offset + 7])
            adu_len = 6 + length
            if adu_len < 7 or offset + adu_len > len(payload):
                break
            count += 1
            offset += adu_len
        return max(count, 1)

    @staticmethod
    def _last_adu_tid(payload: bytes) -> int:
        """Return the TID from the last complete ADU in payload.

        For single-ADU payloads this equals payload[0:2]. For multi-ADU cases
        (pipelined sequences, aliasing pairs) the drain loop in _send_case
        consumes N-1 responses and reads the Nth; we must compare TIDs against
        the Nth ADU, not the first.
        """
        last_tid = struct.unpack(">H", payload[0:2])[0] if len(payload) >= 2 else 0
        offset = 0
        while offset + 7 <= len(payload):
            tid, _, length, _ = struct.unpack(">HHHB", payload[offset:offset + 7])
            adu_len = 6 + length
            if adu_len < 7 or offset + adu_len > len(payload):
                break
            last_tid = tid
            offset += adu_len
        return last_tid

    def _recv_response(self) -> bytes:
        """Read one complete Modbus ADU from the socket."""
        header = self._recv_exact(7)
        if len(header) < 7:
            return header
        _, _, length, _ = struct.unpack(">HHHB", header)
        pdu_len = length - 1
        if pdu_len <= 0:
            return header
        body = self._recv_exact(pdu_len)
        return header + body

    def _recv_exact(self, n: int) -> bytes:
        """Read up to n bytes; returns fewer bytes on connection close."""
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _classify_response(
        self,
        payload: bytes,
        response: bytes,
        result: FuzzResult,
        *,
        expected_tid: Optional[int] = None,
    ) -> None:
        """Classify the response and set result.anomaly / result.crash_indicator.

        expected_tid: TID to compare against the response. Defaults to payload[0:2]
        (correct for single-ADU cases). Pass _last_adu_tid(payload) when calling
        after a multi-ADU drain so the comparison targets the last ADU's TID.
        """
        # Transaction ID must echo the request
        if len(payload) >= 2:
            req_tid = expected_tid if expected_tid is not None else struct.unpack(">H", payload[0:2])[0]
            res_tid = struct.unpack(">H", response[0:2])[0]
            if req_tid != res_tid:
                result.anomaly = ANOMALY_MALFORMED_RESPONSE
                result.crash_indicator = True
                return
        # Protocol ID must be 0x0000
        proto_id = struct.unpack(">H", response[2:4])[0]
        if proto_id != 0x0000:
            result.anomaly = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return
        # Declared length must match actual bytes received after the length field
        declared_len = struct.unpack(">H", response[4:6])[0]
        if len(response) - 6 != declared_len:
            result.anomaly = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return
        # Exception response: MSB of FC is set — spec-compliant, not a crash
        if len(response) >= 8 and (response[7] & 0x80):
            exc_code = response[8] if len(response) > 8 else None
            result.anomaly = ANOMALY_EXCEPTION
            result.response_decoded = {
                "exception_fc": hex(response[7]),
                "exception_code": hex(exc_code) if exc_code is not None else None,
            }

    def _reconnect(self) -> bool:
        """Try to re-establish the TCP connection after a send/recv failure."""
        try:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(5.0)
            self._sock.connect((self.target.ip, self.target.port))
            return True
        except Exception:
            self._sock = None
            return False

    def discover(self, interface: str, timeout: int = 30) -> list:
        raise NotImplementedError(
            "Modbus discovery requires scapy + CAP_NET_RAW and live Modbus traffic on the interface."
        )

    def connect(self, target: Device) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(5.0)
        self._sock.connect((target.ip, target.port))

    def fingerprint(self, active: bool = True) -> "FingerprintResult":
        """Modbus fingerprint.

        Passive: OUI lookup from ARP cache.
        Active:  send FC43 MEI sub-code 14 (Read Device Identification, basic stream).
                 Many devices return exception 0x01 (Illegal Function) — treated as
                 "not supported" and falls back to OUI result.
        """
        from core.fingerprint import FingerprintResult, fingerprint_from_oui, parse_modbus_fc43_mei

        oui_result = fingerprint_from_oui(self.target.ip)
        if not active:
            return oui_result

        # FC43 MEI Read Device Identification (basic stream = 0x01)
        pdu = bytes([0x2B, 0x0E, 0x01, 0x00])   # FC=0x2B, MEI=0x0E, ReadDevID=basic, ObjID=0
        req = self._mbap(pdu, unit_id=0xFF, tid=0xFD00)
        raw = b""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(3.0)
            s.connect((self.target.ip, self.target.port))
            s.sendall(req)
            try:
                raw = s.recv(256)
            except socket.timeout:
                pass
        except OSError:
            return oui_result
        finally:
            s.close()

        # Strip MBAP (7 bytes) to get PDU
        if len(raw) < 9:
            return oui_result
        pdu_resp = raw[7:]

        result = parse_modbus_fc43_mei(pdu_resp)
        if result is None:
            return oui_result

        if oui_result.is_known():
            result.extra["oui_vendor"] = oui_result.vendor
        return result

    def replay_payload(self, payload: bytes) -> Optional[bytes]:
        if self._sock is None:
            raise RuntimeError("Not connected — call connect() before replay_payload().")
        self._sock.sendall(payload)
        return self._recv_response()

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
