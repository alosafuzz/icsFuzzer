"""IEC 60870-5-104 fuzzer module.

Spec: IEC 60870-5-104:2006 + Amendment 1:2016
      IEC 60870-5-101:2003 (ASDU definitions shared with 104)

APDU structure:
  APCI (6 bytes): 0x68 | length | CF1 | CF2 | CF3 | CF4
  ASDU (variable): TypeID | VSQ | COT_lo | OA | CA (2B LE) | Information Objects

Frame types (determined by CF1 bits[1:0]):
  I-frame  CF1[0]=0            data transfer; CF1-CF2=SSN, CF3-CF4=RSN
  S-frame  CF1[1:0]=0b01       supervisory; CF3-CF4=RSN, no ASDU
  U-frame  CF1[1:0]=0b11       session control (STARTDT/STOPDT/TESTFR)

Connection sequence:
  TCP connect → send STARTDT_ACT → recv STARTDT_CON → send I-frames

SSN / RSN encoding (15-bit, little-endian, bit 0 always 0):
  encode:  struct.pack("<H", (n & 0x7FFF) << 1)
  decode:  struct.unpack("<H", cf_bytes)[0] >> 1
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
    CATEGORY_TIMESTAMP,
    Device,
    FuzzModule,
    FuzzResult,
)

# ---------------------------------------------------------------------------
# Frame-type identifiers (CF1 low bits)
# ---------------------------------------------------------------------------
_CF1_I_MASK   = 0x01   # bit 0 = 0 → I-frame
_CF1_S_BITS   = 0x01   # CF1 & 0x03 == 0x01 → S-frame
_CF1_U_BITS   = 0x03   # CF1 & 0x03 == 0x03 → U-frame

# U-frame CF1 function codes
_CF1_STARTDT_ACT = 0x07
_CF1_STARTDT_CON = 0x0B
_CF1_STOPDT_ACT  = 0x13
_CF1_STOPDT_CON  = 0x23
_CF1_TESTFR_ACT  = 0x43
_CF1_TESTFR_CON  = 0x83

_U_FRAME_CF1S = frozenset([
    _CF1_STARTDT_ACT, _CF1_STARTDT_CON,
    _CF1_STOPDT_ACT,  _CF1_STOPDT_CON,
    _CF1_TESTFR_ACT,  _CF1_TESTFR_CON,
])

# ---------------------------------------------------------------------------
# TypeIDs (IEC 60870-5-101 §7.3)
# ---------------------------------------------------------------------------
TYPEID_M_SP_NA_1  = 1    # Single-point information
TYPEID_M_DP_NA_1  = 3    # Double-point information
TYPEID_M_ME_NC_1  = 13   # Measured value, short float
TYPEID_C_SC_NA_1  = 45   # Single command
TYPEID_C_DC_NA_1  = 46   # Double command
TYPEID_C_SE_NA_1  = 48   # Set-point command, normalised
TYPEID_C_SE_NB_1  = 50   # Set-point command, scaled
TYPEID_C_SE_NC_1  = 51   # Set-point command, short float
TYPEID_C_IC_NA_1  = 100  # General Interrogation Command
TYPEID_C_CI_NA_1  = 101  # Counter Interrogation Command
TYPEID_C_CS_NA_1  = 103  # Clock Synchronisation Command

# ---------------------------------------------------------------------------
# Cause of Transmission (IEC 60870-5-101 §7.2.3)
# ---------------------------------------------------------------------------
COT_PERIODIC      = 1
COT_SPONTANEOUS   = 3
COT_REQUESTED     = 5
COT_ACTIVATION    = 6
COT_ACT_CON       = 7
COT_ACT_TERM      = 10
COT_UNKNOWN_TI    = 44
COT_UNKNOWN_COT   = 45
COT_UNKNOWN_CA    = 46
COT_UNKNOWN_IOA   = 47

_EXCEPTION_COTS = frozenset([44, 45, 46, 47])

# Categories that must be sent verbatim (no SSN patching)
_NO_SSN_PATCH = frozenset([CATEGORY_SEQUENCE, CATEGORY_BINARY_CORRUPTION])


# ---------------------------------------------------------------------------
# Wire-level builders
# ---------------------------------------------------------------------------

def _u_frame(cf1: int) -> bytes:
    return bytes([0x68, 4, cf1, 0x00, 0x00, 0x00])


def _s_frame(rsn: int = 0) -> bytes:
    return bytes([0x68, 4, 0x01, 0x00]) + struct.pack("<H", (rsn & 0x7FFF) << 1)


def _i_frame(asdu: bytes, ssn: int = 0, rsn: int = 0) -> bytes:
    return (bytes([0x68, 4 + len(asdu)])
            + struct.pack("<H", (ssn & 0x7FFF) << 1)
            + struct.pack("<H", (rsn & 0x7FFF) << 1)
            + asdu)


def _asdu(type_id: int, n_obj: int, cot: int, ca: int, objects: bytes,
          sq: int = 0, t: int = 0, pn: int = 0, oa: int = 0) -> bytes:
    vsq    = ((sq & 1) << 7) | (n_obj & 0x7F)
    cot_lo = ((t & 1) << 7) | ((pn & 1) << 6) | (cot & 0x3F)
    return struct.pack("<BBBBH", type_id, vsq, cot_lo, oa, ca) + objects


def _ioa(addr: int) -> bytes:
    """3-byte little-endian IOA."""
    return struct.pack("<I", addr & 0xFFFFFF)[:3]


def _gi(ca: int = 1, cot: int = COT_ACTIVATION, qoi: int = 20) -> bytes:
    """General Interrogation I-frame (TypeID=100)."""
    return _i_frame(_asdu(TYPEID_C_IC_NA_1, 1, cot, ca, _ioa(0) + bytes([qoi])))


# CP56Time2a (7 bytes): ms_lo, ms_hi, min, hr, day_dow, mon, yr
_CP56_ZERO    = bytes(7)
_CP56_CURRENT = bytes([0xE8, 0x03,  # 1000 ms
                       0x01,        # 1 min
                       0x01,        # 1 hr
                       0x01,        # day=1, dow=0
                       0x01,        # Jan
                       0x19])       # year 25 (2025)
_CP56_FUTURE  = bytes([0xFF, 0x3B,  # 15359 ms
                       0x3B,        # 59 min
                       0x17,        # 23 hr
                       0x1F,        # day=31, dow=0
                       0x0C,        # Dec
                       0x63])       # year 99 (2099)


class Iec104Fuzzer(FuzzModule):
    """IEC 60870-5-104 fuzzer — generator and send phase.

    Protocol-specific categories (beyond standard ones):
      type_id_exhaustion  all 256 TypeID values
      ioa_exhaustion      IOA boundary and multi-object testing
      frame_interleaving  mixed I/S/U frame types in a single TCP write
      gi_timing           General Interrogation abuse
      cot_exhaustion      all 64 COT values
      command_flood       write-command edge cases (float NaN/Inf, extremes)
    """

    PROTOCOL_NAME = "iec104"
    DEFAULT_PORT  = 2404
    FUZZ_CATEGORIES = [
        CATEGORY_BOUNDARY,
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_SEQUENCE,
        CATEGORY_STATE_MACHINE,
        CATEGORY_TIMESTAMP,
        "type_id_exhaustion",
        "ioa_exhaustion",
        "frame_interleaving",
        "gi_timing",
        "cot_exhaustion",
        "command_flood",
    ]

    def __init__(self, target: Device, logger, delay: float = 0.1, seeds: list = None):
        super().__init__(target, logger, delay, seeds)
        self._sock: Optional[socket.socket] = None
        self._ssn: int = 0   # our Send Sequence Number
        self._rsn: int = 0   # their SSN (last received from target)

    # -----------------------------------------------------------------------
    # Connection lifecycle
    # -----------------------------------------------------------------------

    def discover(self, interface: str, timeout: int = 30) -> list:
        raise NotImplementedError("IEC 104 discovery requires passive sniff (CAP_NET_RAW).")

    def fingerprint(self, active: bool = True) -> "FingerprintResult":
        """IEC 104 fingerprint.

        IEC 60870-5-104 has no standard identity object.
        Passive: OUI lookup from ARP cache.
        Active:  OUI lookup + TCP banner grab (check if any readable string
                 appears in the STARTDT-CON or first I-frame).  Most RTUs
                 return only protocol frames with no banner, so confidence
                 rarely exceeds "low".
        """
        from core.fingerprint import FingerprintResult, fingerprint_from_oui

        oui_result = fingerprint_from_oui(self.target.ip)
        if not active or oui_result.is_known():
            return oui_result

        # Best effort: connect, send STARTDT, look for any ASCII in the response
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((self.target.ip, self.target.port))
            s.sendall(_u_frame(_CF1_STARTDT_ACT))
            banner = b''
            try:
                banner = s.recv(256)
            except socket.timeout:
                pass
            s.close()
            # Look for printable runs of 8+ chars
            run = b''
            for b in banner:
                if 32 <= b < 127:
                    run += bytes([b])
                elif len(run) >= 8:
                    txt = run.decode("ascii", errors="replace").strip()
                    if txt:
                        return FingerprintResult(
                            model=txt[:64],
                            confidence="low",
                            method="iec104_banner",
                        )
                    run = b''
                else:
                    run = b''
        except OSError:
            pass
        return oui_result

    def connect(self, target: Device) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(5.0)
        self._sock.connect((target.ip, target.port))
        self._ssn = 0
        self._rsn = 0
        # IEC 104 requires STARTDT_ACT / STARTDT_CON before I-frames
        self._sock.sendall(_u_frame(_CF1_STARTDT_ACT))
        hdr = _u_frame(_CF1_STARTDT_CON)
        response = self._recv_apdu()
        if not response or response != hdr:
            # If we don't get STARTDT_CON, still proceed — test target may behave differently
            pass

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
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(5.0)
            self._sock.connect((self.target.ip, self.target.port))
            self._ssn = 0
            self._rsn = 0
            self._sock.sendall(_u_frame(_CF1_STARTDT_ACT))
            self._recv_apdu()  # consume STARTDT_CON (or whatever)
        except Exception:
            self.close()

    def replay_payload(self, payload: bytes) -> Optional[bytes]:
        if self._sock is None:
            raise RuntimeError(
                "Not connected — call connect() before replay_payload(). "
                "Use generate_cases() to build payloads without a live target."
            )
        self._sock.sendall(payload)
        return self._recv_apdu()

    # -----------------------------------------------------------------------
    # Generator phase (hardware-free)
    # -----------------------------------------------------------------------

    def generate_cases(self, categories=None):
        """Return list of (case_id, category, description, payload)."""
        cats = self._resolve_categories(categories)
        cases = []
        generators = {
            CATEGORY_BOUNDARY:          self._gen_boundary,
            CATEGORY_BINARY_CORRUPTION: self._gen_binary_corruption,
            CATEGORY_SEQUENCE:          self._gen_sequence_number,
            CATEGORY_STATE_MACHINE:     self._gen_state_machine,
            CATEGORY_TIMESTAMP:         self._gen_timestamp,
            "type_id_exhaustion":       self._gen_type_id_exhaustion,
            "ioa_exhaustion":           self._gen_ioa_exhaustion,
            "frame_interleaving":       self._gen_frame_interleaving,
            "gi_timing":                self._gen_gi_timing,
            "cot_exhaustion":           self._gen_cot_exhaustion,
            "command_flood":            self._gen_command_flood,
        }
        for cat in cats:
            if cat in generators:
                cases.extend(generators[cat]())
        return cases

    # -----------------------------------------------------------------------
    # Fuzz (send phase)
    # -----------------------------------------------------------------------

    def fuzz(self, categories=None) -> list:
        if self._sock is None:
            raise RuntimeError(
                "Not connected — call connect() before fuzz(). "
                "Use generate_cases() to build payloads without a live target."
            )
        cases = self.generate_cases(categories)
        total  = len(cases)
        results = []

        current_cat = None
        for i, (case_id, category, description, payload) in enumerate(cases, 1):
            if category != current_cat:
                current_cat = category
                print(f"\n[fuzz] ── {category} ──")
            if i % 50 == 0:
                print(f"[fuzz] {i}/{total}  {case_id}")

            result = self._send_case(case_id, category, description, payload)
            results.append(result)

            if result.crash_indicator and result.anomaly not in (
                ANOMALY_EXCEPTION, None
            ):
                print(f"[fuzz] !! {case_id}  {result.anomaly}  {description[:60]}")

        print(f"\n[fuzz] Completed {total} cases for {self.target.ip}:{self.target.port}")
        return results

    # -----------------------------------------------------------------------
    # Send / receive / classify
    # -----------------------------------------------------------------------

    def _send_case(self, case_id: str, category: str, description: str, payload: bytes) -> FuzzResult:
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

            # drain N-1 APDUs for multi-APDU payloads (frame_interleaving, gi_timing)
            n = self._count_apdus(payload)
            for _ in range(n - 1):
                self._recv_apdu()

            response = self._recv_apdu()
            result.response = response

            if not response:
                result.anomaly       = ANOMALY_NO_RESPONSE
                result.crash_indicator = True
            elif len(response) < 6:
                result.anomaly       = ANOMALY_MALFORMED_RESPONSE
                result.crash_indicator = True
            else:
                self._classify_response(payload, response, result)

        except socket.timeout:
            result.anomaly       = ANOMALY_TIMEOUT
            result.crash_indicator = True
            self._reconnect()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
            result.anomaly       = ANOMALY_CONNECTION_RESET
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
        """Patch SSN in I-frames for non-sequence-attack categories."""
        if category in _NO_SSN_PATCH:
            return payload
        if len(payload) >= 6 and payload[0] == 0x68 and (payload[2] & 0x01) == 0:
            # Single I-frame: patch CF1-CF2 with current SSN
            patched = (payload[:2]
                       + struct.pack("<H", (self._ssn & 0x7FFF) << 1)
                       + payload[4:])
            self._ssn = (self._ssn + 1) & 0x7FFF
            return patched
        return payload

    def _recv_apdu(self) -> bytes:
        """Read one complete APDU (start byte + length byte + CF + ASDU)."""
        hdr = self._recv_exact(2)
        if len(hdr) < 2:
            return hdr
        if hdr[0] != 0x68:
            return hdr
        length = hdr[1]
        body = self._recv_exact(length)
        return hdr + body

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _classify_response(self, payload: bytes, response: bytes, result: FuzzResult) -> None:
        if response[0] != 0x68:
            result.anomaly       = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        declared_body_len = response[1]
        if len(response) - 2 != declared_body_len:
            result.anomaly       = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        cf1 = response[2]

        if cf1 & 0x01 == 0:  # I-frame response
            if len(response) >= 8:
                self._classify_i_response(response, result)
            # else: too short for ASDU — malformed
            elif len(response) < 8:
                result.anomaly       = ANOMALY_MALFORMED_RESPONSE
                result.crash_indicator = True

        elif cf1 & 0x03 == 0x01:  # S-frame — just an acknowledgment
            pass  # no anomaly

        else:  # U-frame response
            self._classify_u_response(payload, response, result)

    def _classify_i_response(self, response: bytes, result: FuzzResult) -> None:
        asdu = response[6:]
        if len(asdu) < 6:
            result.anomaly       = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return
        cot_lo = asdu[2]
        pn  = (cot_lo >> 6) & 1
        cot = cot_lo & 0x3F

        if cot in _EXCEPTION_COTS or pn:
            result.anomaly = ANOMALY_EXCEPTION
            result.response_decoded = {
                "cot":   cot,
                "pn":    pn,
                "type_id": asdu[0],
            }
        # else: legitimate data response, no anomaly

    def _classify_u_response(self, payload: bytes, response: bytes, result: FuzzResult) -> None:
        cf1 = response[2]
        # TESTFR_CON and STARTDT_CON are expected; anything else is unexpected
        if cf1 in (_CF1_TESTFR_CON, _CF1_STARTDT_CON, _CF1_STOPDT_CON):
            return  # normal
        result.anomaly       = ANOMALY_UNEXPECTED_DATA
        result.crash_indicator = True
        result.response_decoded = {"u_frame_cf1": hex(cf1)}

    @staticmethod
    def _count_apdus(payload: bytes) -> int:
        """Count complete APDUs in a payload (for multi-APDU interleaving cases)."""
        count, offset = 0, 0
        while offset + 2 <= len(payload):
            if payload[offset] != 0x68:
                break
            length = payload[offset + 1]
            apdu_len = 2 + length
            if offset + apdu_len > len(payload):
                break
            count += 1
            offset += apdu_len
        return max(count, 1)

    # -----------------------------------------------------------------------
    # Generators
    # -----------------------------------------------------------------------

    def _gen_boundary(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_BOUNDARY, desc, payload))

        # U-frame types
        add("U-frame: STARTDT_ACT",  _u_frame(_CF1_STARTDT_ACT))
        add("U-frame: STOPDT_ACT",   _u_frame(_CF1_STOPDT_ACT))
        add("U-frame: TESTFR_ACT",   _u_frame(_CF1_TESTFR_ACT))

        # S-frames with boundary RSN
        add("S-frame RSN=0",         _s_frame(0))
        add("S-frame RSN=1",         _s_frame(1))
        add("S-frame RSN=0x3FFF",    _s_frame(0x3FFF))
        add("S-frame RSN=0x7FFF",    _s_frame(0x7FFF))

        # I-frames with boundary SSN
        for ssn, label in [(0, "SSN=0"), (1, "SSN=1"), (0x3FFF, "SSN=0x3FFF"), (0x7FFF, "SSN=0x7FFF")]:
            add(f"I-frame {label}: GI", _i_frame(
                _asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1, _ioa(0) + b"\x14"),
                ssn=ssn))

        # CA boundary values
        for ca, label in [(0x0000, "CA=0"), (0x0001, "CA=1"), (0xFFFE, "CA=0xFFFE"), (0xFFFF, "CA=0xFFFF")]:
            add(f"GI CA={label}",
                _i_frame(_asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, ca, _ioa(0) + b"\x14")))

        # IOA boundary values in GI
        for ioa_addr, label in [
            (0x000000, "IOA=0"), (0x000001, "IOA=1"),
            (0x7FFFFF, "IOA=0x7FFFFF"), (0x800000, "IOA=0x800000"),
            (0xFFFFFF, "IOA=0xFFFFFF"),
        ]:
            add(f"GI {label}",
                _i_frame(_asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1, _ioa(ioa_addr) + b"\x14")))

        # TypeID boundary values (in minimal I-frame with 1 null object)
        for tid, label in [(0, "TypeID=0"), (1, "TypeID=1"), (127, "TypeID=127"),
                           (128, "TypeID=128"), (255, "TypeID=255")]:
            add(f"Boundary TypeID={label}",
                _i_frame(_asdu(tid, 1, COT_ACTIVATION, 1, _ioa(0) + b"\x00")))

        # VSQ variants
        for vsq, label in [
            (0x00, "VSQ=0x00 (0 obj, SQ=0)"),
            (0x01, "VSQ=0x01 (1 obj, SQ=0)"),
            (0x7F, "VSQ=0x7F (127 obj, SQ=0)"),
            (0x80, "VSQ=0x80 (0 obj, SQ=1)"),
            (0xFF, "VSQ=0xFF (127 obj, SQ=1)"),
        ]:
            raw_asdu = bytes([TYPEID_C_IC_NA_1, vsq, COT_ACTIVATION, 0, 0x01, 0x00])
            add(f"I-frame {label}", _i_frame(raw_asdu))

        # I-frame: no ASDU (length=4, just CF)
        add("I-frame with no ASDU (length=4)", bytes([0x68, 4, 0x00, 0x00, 0x00, 0x00]))

        # I-frame: ASDU truncated (1 byte)
        add("I-frame ASDU 1 byte", bytes([0x68, 5, 0x00, 0x00, 0x00, 0x00, TYPEID_C_IC_NA_1]))

        # I-frame: maximum length (253 = CF(4) + ASDU(249))
        max_asdu = _asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1,
                         _ioa(0) + b"\x14" + b"\x00" * 243)  # padded to 249
        add("I-frame max length (APCI length=253)", _i_frame(max_asdu[:249]))

        # COT boundary values with GI TypeID
        for cot, label in [(0, "COT=0"), (63, "COT=63"), (44, "COT=44 exception"), (47, "COT=47 exception")]:
            add(f"GI with {label}",
                _i_frame(_asdu(TYPEID_C_IC_NA_1, 1, cot, 1, _ioa(0) + b"\x14")))

        return cases

    def _gen_binary_corruption(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_BINARY_CORRUPTION, desc, payload))

        # Wrong start byte
        for sb, label in [(0x00, "start=0x00"), (0x67, "start=0x67"),
                          (0x69, "start=0x69"), (0x7F, "start=0x7F"),
                          (0xFF, "start=0xFF"), (0xAA, "start=0xAA")]:
            # Build a GI frame but replace the start byte
            gi = bytearray(_gi())
            gi[0] = sb
            add(f"Wrong start byte ({label})", bytes(gi))

        # APCI length field edge cases (valid start byte, CF preserved from GI)
        for length, label in [(0, "length=0"), (1, "length=1"), (2, "length=2"),
                               (3, "length=3"), (254, "length=254"), (255, "length=255")]:
            add(f"APCI length={label}",
                bytes([0x68, length, 0x00, 0x00, 0x00, 0x00]))

        # Truncated after various positions
        gi_bytes = _gi()
        for cut in range(1, 7):
            add(f"Truncated APDU at byte {cut}", gi_bytes[:cut])

        # Truncated ASDU mid-field
        for cut in range(7, 15):
            add(f"Truncated APDU mid-ASDU at byte {cut}", gi_bytes[:cut])

        # CF1 with invalid frame type bits — not a defined U/S/I frame
        for cf1, label in [(0x03, "CF1=0x03 U undefined"), (0x05, "CF1=0x05"),
                           (0x0F, "CF1=0x0F"), (0xFF, "CF1=0xFF")]:
            add(f"Invalid CF1={label}",
                bytes([0x68, 4, cf1, 0x00, 0x00, 0x00]))

        # Random-looking payloads with valid start byte
        import random
        rng = random.Random(0xBEEF)
        for i in range(10):
            size = rng.randint(1, 20)
            body = bytes([rng.randint(0, 255) for _ in range(size)])
            add(f"Random APDU variant {i+1}", bytes([0x68]) + body)

        # Null payload
        add("Empty payload (zero bytes)", b"")

        # Single start byte
        add("Single start byte", bytes([0x68]))

        # All-zero 6-byte APDU (I-frame: SSN=0, RSN=0, no ASDU)
        add("All-zero 6 bytes", bytes(6))

        # All-0xFF
        add("All-0xFF 6 bytes", bytes([0xFF] * 6))

        # Declared length way beyond what's sent (truncated write)
        add("APCI claims length=200 but only 6 bytes sent",
            bytes([0x68, 200, 0x00, 0x00, 0x00, 0x00]))

        # GI with TypeID and ASDU but CF1 claims S-frame (conflicting frame type)
        add("S-frame CF with ASDU bytes appended",
            bytes([0x68, 4 + 10, 0x01, 0x00, 0x00, 0x00])
            + _asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1, _ioa(0) + b"\x14"))

        return cases

    def _gen_sequence_number(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_SEQUENCE, desc, payload))

        gi_asdu = _asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1, _ioa(0) + b"\x14")

        # SSN boundary values
        add("I-frame SSN=0, RSN=0 (initial state)",     _i_frame(gi_asdu, ssn=0, rsn=0))
        add("I-frame SSN=1, RSN=0",                     _i_frame(gi_asdu, ssn=1, rsn=0))
        add("I-frame SSN=0x7FFE (near-max)",             _i_frame(gi_asdu, ssn=0x7FFE))
        add("I-frame SSN=0x7FFF (max)",                      _i_frame(gi_asdu, ssn=0x7FFF))
        add("I-frame SSN wraparound: send max (0x7FFF)",     _i_frame(gi_asdu, ssn=0x7FFF))
        add("I-frame SSN wraparound: send zero after max",   _i_frame(gi_asdu, ssn=0x0000))

        # RSN attacks
        add("I-frame RSN ahead of any sent (RSN=100)",  _i_frame(gi_asdu, ssn=0, rsn=100))
        add("I-frame RSN=0x7FFF (ack all future)",      _i_frame(gi_asdu, ssn=0, rsn=0x7FFF))
        add("I-frame RSN == SSN (self-ack)",            _i_frame(gi_asdu, ssn=5, rsn=5))
        add("I-frame RSN > SSN (ack not-yet-sent)",     _i_frame(gi_asdu, ssn=3, rsn=10))

        # SSN gaps
        add("I-frame SSN gap: 0→100",                   _i_frame(gi_asdu, ssn=100))
        add("I-frame SSN gap: 0→0x4000 (half-max)",     _i_frame(gi_asdu, ssn=0x4000))

        # Duplicate SSN (send same SSN twice; this is the same payload twice)
        dup = _i_frame(gi_asdu, ssn=5)
        add("I-frame duplicate SSN=5 (first)",          dup)
        add("I-frame duplicate SSN=5 (second)",         dup)

        # S-frame RSN attacks
        add("S-frame RSN=0x7FFF (ack all future)",      _s_frame(rsn=0x7FFF))
        add("S-frame RSN=100 (ack not-yet-sent)",       _s_frame(rsn=100))

        return cases

    def _gen_state_machine(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_STATE_MACHINE, desc, payload))

        gi_asdu = _asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1, _ioa(0) + b"\x14")

        # Send wrong-direction U-frame CON types (server→client frames sent by us)
        add("U-frame STARTDT_CON (server-direction, sent by client)",
            _u_frame(_CF1_STARTDT_CON))
        add("U-frame STOPDT_CON (server-direction)",
            _u_frame(_CF1_STOPDT_CON))
        add("U-frame TESTFR_CON (server-direction, sent by client)",
            _u_frame(_CF1_TESTFR_CON))

        # Duplicate STARTDT_ACT
        add("Duplicate STARTDT_ACT (session already started)",
            _u_frame(_CF1_STARTDT_ACT))

        # STOPDT in mid-session
        add("STOPDT_ACT during data transfer",
            _u_frame(_CF1_STOPDT_ACT))

        # TESTFR flood
        for i in range(5):
            add(f"TESTFR_ACT flood #{i+1}", _u_frame(_CF1_TESTFR_ACT))

        # Invalid U-frame CF1 values
        for cf1, label in [(0x0F, "0x0F"), (0x1F, "0x1F"),
                           (0x47, "0x47"), (0xFF, "0xFF"), (0xBB, "0xBB")]:
            add(f"Invalid U-frame CF1=0x{cf1:02X}",
                bytes([0x68, 4, cf1, 0x00, 0x00, 0x00]))

        # S-frame as very first frame (before any I-frame exchange)
        add("S-frame before any I-frame exchange", _s_frame(0))

        # STOPDT_ACT immediately after STARTDT
        add("STOPDT_ACT immediately after data session begin",
            _u_frame(_CF1_STOPDT_ACT))

        # I-frame then immediate STOPDT in same TCP write
        i_then_stop = _i_frame(gi_asdu) + _u_frame(_CF1_STOPDT_ACT)
        add("I-frame + STOPDT_ACT concatenated", i_then_stop)

        return cases

    def _gen_timestamp(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_TIMESTAMP, desc, payload))

        def cs(cp56: bytes, cot: int = COT_ACTIVATION, ca: int = 1) -> bytes:
            return _i_frame(_asdu(TYPEID_C_CS_NA_1, 1, cot, ca, _ioa(0) + cp56))

        add("Clock sync: current time (valid)",          cs(_CP56_CURRENT))
        add("Clock sync: zero time (epoch)",             cs(_CP56_ZERO))
        add("Clock sync: far future (year 2099)",        cs(_CP56_FUTURE))
        add("Clock sync: all 0xFF bytes",                cs(b"\xFF" * 7))
        add("Clock sync: invalid day=0",
            cs(bytes([0xE8, 0x03, 0x01, 0x01, 0x00, 0x01, 0x19])))
        add("Clock sync: invalid day=32",
            cs(bytes([0xE8, 0x03, 0x01, 0x01, 0x20, 0x01, 0x19])))
        add("Clock sync: invalid month=0",
            cs(bytes([0xE8, 0x03, 0x01, 0x01, 0x01, 0x00, 0x19])))
        add("Clock sync: invalid month=13",
            cs(bytes([0xE8, 0x03, 0x01, 0x01, 0x01, 0x0D, 0x19])))
        add("Clock sync: wrong COT=3 (spontaneous)",
            cs(_CP56_CURRENT, cot=COT_SPONTANEOUS))
        add("Clock sync: wrong COT=5 (requested)",
            cs(_CP56_CURRENT, cot=COT_REQUESTED))
        add("Clock sync: COT=0 (undefined)",
            cs(_CP56_CURRENT, cot=0))
        add("Clock sync: broadcast CA=0xFFFF",           cs(_CP56_CURRENT, ca=0xFFFF))
        add("Clock sync truncated (4-byte CP56)",
            _i_frame(_asdu(TYPEID_C_CS_NA_1, 1, COT_ACTIVATION, 1,
                           _ioa(0) + _CP56_CURRENT[:4])))
        add("Clock sync with T=1 (test flag set)",
            _i_frame(_asdu(TYPEID_C_CS_NA_1, 1, COT_ACTIVATION, 1,
                           _ioa(0) + _CP56_CURRENT, t=1)))
        add("Clock sync with SU bit set in hour byte",
            cs(bytes([0xE8, 0x03, 0x01, 0x81, 0x01, 0x01, 0x19])))  # SU=1 in hour

        return cases

    def _gen_type_id_exhaustion(self):
        cases = []
        for tid in range(256):
            payload = _i_frame(_asdu(tid, 1, COT_ACTIVATION, 1, _ioa(0) + b"\x00"))
            cases.append((
                self._next_id(),
                "type_id_exhaustion",
                f"TypeID=0x{tid:02X} ({tid}) with 1-byte object",
                payload,
            ))
        return cases

    def _gen_ioa_exhaustion(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), "ioa_exhaustion", desc, payload))

        boundaries = [
            (0x000000, "IOA=0x000000 (broadcast/invalid)"),
            (0x000001, "IOA=0x000001 (first valid)"),
            (0x00FFFF, "IOA=0x00FFFF"),
            (0x010000, "IOA=0x010000 (group boundary)"),
            (0x7FFFFF, "IOA=0x7FFFFF (mid-range max)"),
            (0x800000, "IOA=0x800000 (bit-23 set)"),
            (0xFF0000, "IOA=0xFF0000 (high byte only)"),
            (0xFFFF00, "IOA=0xFFFF00"),
            (0xFFFFFE, "IOA=0xFFFFFE"),
            (0xFFFFFF, "IOA=0xFFFFFF (max)"),
        ]
        for addr, label in boundaries:
            add(f"GI with {label}",
                _i_frame(_asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1,
                               _ioa(addr) + b"\x14")))

        # Multi-object ASDU (VSQ says 3 objects, only 1 IOA worth of data)
        add("VSQ says 3 objects, only 1 IOA provided",
            _i_frame(bytes([TYPEID_C_IC_NA_1, 0x03, COT_ACTIVATION, 0, 0x01, 0x00])
                     + _ioa(1) + b"\x14"))

        # SQ=1 sequence of elements: base IOA + N sequential addresses
        for n in [1, 5, 127]:
            vsq = 0x80 | (n & 0x7F)
            raw_asdu = (bytes([TYPEID_C_IC_NA_1, vsq, COT_ACTIVATION, 0, 0x01, 0x00])
                        + _ioa(0) + b"\x14" * n)
            add(f"SQ=1 with {n} objects from IOA=0", _i_frame(raw_asdu))

        # All three IOA bytes independently at 0xFF
        for mask in [0x0000FF, 0x00FF00, 0xFF0000]:
            add(f"IOA byte mask 0x{mask:06X}",
                _i_frame(_asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1,
                               _ioa(mask) + b"\x14")))

        return cases

    def _gen_frame_interleaving(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), "frame_interleaving", desc, payload))

        gi  = _gi()
        sac = _u_frame(_CF1_STARTDT_ACT)
        soc = _u_frame(_CF1_STOPDT_ACT)
        tfr = _u_frame(_CF1_TESTFR_ACT)
        s0  = _s_frame(0)

        # I-frame + S-frame in one TCP write
        add("I-frame + S-frame concatenated",           gi + s0)
        # I-frame + TESTFR_ACT
        add("I-frame + TESTFR_ACT concatenated",        gi + tfr)
        # TESTFR_ACT + I-frame
        add("TESTFR_ACT + I-frame concatenated",        tfr + gi)
        # S-frame + I-frame
        add("S-frame + I-frame concatenated",           s0 + gi)
        # S-frame + S-frame
        add("S-frame + S-frame concatenated",           s0 + _s_frame(1))
        # Three I-frames
        add("Three GI I-frames concatenated",           gi + gi + gi)
        # Two GI I-frames
        add("Two GI I-frames concatenated",             gi + gi)
        # STARTDT_ACT + GI (simulate reconnect in-session)
        add("STARTDT_ACT + GI I-frame in one write",   sac + gi)
        # STOPDT_ACT + GI
        add("STOPDT_ACT + GI I-frame in one write",    soc + gi)
        # All three U-frame types
        add("STARTDT + STOPDT + TESTFR concatenated",   sac + soc + tfr)
        # U + I + S interleaved
        add("TESTFR_ACT + I-frame + S-frame",           tfr + gi + s0)
        # I + U + I
        add("I-frame + TESTFR_ACT + I-frame",           gi + tfr + gi)
        # Five TESTFR in a row
        add("5× TESTFR_ACT burst",                      tfr * 5)
        # Long sequence: 10 GIs
        add("10× GI I-frame burst",                     gi * 10)

        # S-frame with RSN=0 and RSN=0x7FFF in same write
        add("S-frame RSN=0 + S-frame RSN=0x7FFF",      _s_frame(0) + _s_frame(0x7FFF))

        return cases

    def _gen_gi_timing(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), "gi_timing", desc, payload))

        # Normal GI
        add("GI: correct COT=6, CA=1, QOI=20 (global)", _gi(ca=1, cot=COT_ACTIVATION, qoi=20))

        # Wrong COT values for GI
        for cot, label in [
            (COT_SPONTANEOUS, "COT=3 (spontaneous)"),
            (COT_REQUESTED,   "COT=5 (requested)"),
            (COT_PERIODIC,    "COT=1 (periodic)"),
            (COT_ACT_CON,     "COT=7 (act-con)"),
            (0,               "COT=0 (undefined)"),
            (63,              "COT=63 (max)"),
        ]:
            add(f"GI {label}", _gi(ca=1, cot=cot))

        # CA variants for GI
        for ca, label in [(0x0000, "CA=0"), (0xFFFF, "CA=0xFFFF global"),
                          (0x0001, "CA=1"), (0xFFFE, "CA=0xFFFE")]:
            add(f"GI CA={label}", _gi(ca=ca))

        # QOI variants (interrogation group)
        for qoi, label in [
            (0,   "QOI=0 (invalid)"),
            (1,   "QOI=1 (group 1)"),
            (16,  "QOI=16 (group 16)"),
            (20,  "QOI=20 (global, standard)"),
            (21,  "QOI=21 (reserved)"),
            (255, "QOI=255 (max)"),
        ]:
            add(f"GI {label}", _gi(qoi=qoi))

        # GI + TESTFR in one TCP write
        add("GI I-frame + TESTFR_ACT in one write",
            _gi() + _u_frame(_CF1_TESTFR_ACT))

        # Rapid GI burst (3 concatenated)
        add("3× GI burst (pipelined GI requests)", _gi() + _gi() + _gi())

        # Counter Interrogation (TypeID=101)
        add("Counter Interrogation (TypeID=101, QCC=0x05)",
            _i_frame(_asdu(TYPEID_C_CI_NA_1, 1, COT_ACTIVATION, 1,
                           _ioa(0) + b"\x05")))

        # GI with P/N bit set (negative confirm attempt)
        add("GI with P/N bit set in COT",
            _i_frame(_asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1,
                           _ioa(0) + b"\x14", pn=1)))

        # GI with T (test) bit set
        add("GI with test bit (T=1) in COT",
            _i_frame(_asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1,
                           _ioa(0) + b"\x14", t=1)))

        return cases

    def _gen_cot_exhaustion(self):
        cases = []
        for cot in range(64):
            payload = _i_frame(_asdu(TYPEID_C_IC_NA_1, 1, cot, 1, _ioa(0) + b"\x14"))
            cases.append((
                self._next_id(),
                "cot_exhaustion",
                f"GI (TypeID=100) with COT={cot} (0x{cot:02X})",
                payload,
            ))
        return cases

    def _gen_command_flood(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), "command_flood", desc, payload))

        # C_SC_NA_1 (TypeID=45): Single Command — SCO byte bit 0=ON/OFF, bits 1-1=reserved, bit 2=SCS, bits 3-6=QU, bit 7=SE
        for sco, label in [
            (0x00, "SCO=0x00 OFF"),
            (0x01, "SCO=0x01 ON"),
            (0x02, "SCO=0x02 reserved SCS"),
            (0x03, "SCO=0x03 ON + reserved"),
            (0x80, "SCO=0x80 SELECT OFF"),
            (0x81, "SCO=0x81 SELECT ON"),
            (0xFF, "SCO=0xFF all bits"),
        ]:
            add(f"C_SC_NA_1 (single command) {label}",
                _i_frame(_asdu(TYPEID_C_SC_NA_1, 1, COT_ACTIVATION, 1,
                               _ioa(1) + bytes([sco]))))

        # C_DC_NA_1 (TypeID=46): Double Command — DCS 2-bit: 0=not permitted, 1=OFF, 2=ON, 3=not permitted
        for dcs, label in [(0, "DCS=0 (not permitted)"), (1, "DCS=1 OFF"),
                           (2, "DCS=2 ON"), (3, "DCS=3 (not permitted)")]:
            add(f"C_DC_NA_1 (double command) {label}",
                _i_frame(_asdu(TYPEID_C_DC_NA_1, 1, COT_ACTIVATION, 1,
                               _ioa(1) + bytes([dcs]))))

        # C_SE_NC_1 (TypeID=51): Set-point float — 4-byte IEEE 754 + 1-byte QL
        for value, label in [
            (0.0,           "float=0.0"),
            (float("nan"),  "float=NaN"),
            (float("inf"),  "float=+Inf"),
            (float("-inf"), "float=-Inf"),
            (3.4028235e38,  "float=+MAX"),
            (-3.4028235e38, "float=-MAX"),
        ]:
            raw = struct.pack("<f", value)
            add(f"C_SE_NC_1 (set-point float) {label}",
                _i_frame(_asdu(TYPEID_C_SE_NC_1, 1, COT_ACTIVATION, 1,
                               _ioa(1) + raw + b"\x00")))

        # C_SE_NA_1 (TypeID=48): Set-point normalised — 2-byte + 1-byte QL
        for val, label in [(0x0000, "NVA=0"), (0x7FFF, "NVA=0x7FFF +max"),
                           (0x8000, "NVA=0x8000 -1.0"), (0xFFFF, "NVA=0xFFFF")]:
            add(f"C_SE_NA_1 (set-point normalised) {label}",
                _i_frame(_asdu(TYPEID_C_SE_NA_1, 1, COT_ACTIVATION, 1,
                               _ioa(1) + struct.pack("<H", val) + b"\x00")))

        # C_SE_NB_1 (TypeID=50): Set-point scaled — 2-byte signed + 1-byte QL
        for val, label in [(0x0000, "SVA=0"), (0x7FFF, "SVA=0x7FFF max"),
                           (0x8000, "SVA=0x8000 min"), (0xFFFF, "SVA=-1")]:
            add(f"C_SE_NB_1 (set-point scaled) {label}",
                _i_frame(_asdu(TYPEID_C_SE_NB_1, 1, COT_ACTIVATION, 1,
                               _ioa(1) + struct.pack("<H", val) + b"\x00")))

        # Commands with wrong COT (should be COT_ACTIVATION=6)
        for tid, label in [(TYPEID_C_SC_NA_1, "SC"), (TYPEID_C_SE_NC_1, "SE_NC")]:
            for cot, cot_label in [(COT_SPONTANEOUS, "COT=3"), (0, "COT=0")]:
                data = b"\x01\x00" if tid == TYPEID_C_SE_NC_1 else b"\x01"
                add(f"C_{label} wrong {cot_label}",
                    _i_frame(_asdu(tid, 1, cot, 1, _ioa(1) + data)))

        # Commands targeting IOA=0xFFFFFF
        add("C_SC_NA_1 to IOA=0xFFFFFF (broadcast IOA)",
            _i_frame(_asdu(TYPEID_C_SC_NA_1, 1, COT_ACTIVATION, 1,
                           _ioa(0xFFFFFF) + b"\x01")))

        # SE float to IOA=0 (often undefined address)
        add("C_SE_NC_1 float=NaN to IOA=0x000000",
            _i_frame(_asdu(TYPEID_C_SE_NC_1, 1, COT_ACTIVATION, 1,
                           _ioa(0) + struct.pack("<f", float("nan")) + b"\x00")))

        return cases
