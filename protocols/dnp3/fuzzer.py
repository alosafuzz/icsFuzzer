"""DNP3 fuzzer module — IEEE Std 1815-2012.

Three-layer stack:
  Data Link Layer (DLL): 0x05 0x64 | LEN | CTRL | DST(2 LE) | SRC(2 LE) | HDR_CRC(2) | blocks
  Transport Layer (TL):  1-byte header [FIR<<7 | FIN<<6 | SEQ<<0:5]
  Application Layer (AL): AC(1B) | FC(1B) | Objects

CRC-16/DNP: poly=0x3D65 (reflected 0xA6BC), init=0x0000, RefIn=True, RefOut=True, XorOut=0xFFFF
  Header CRC: over LEN+CTRL+DST+SRC (6 bytes)
  Block CRC: over each 16-byte data block (last block may be shorter)

No protocol handshake required before sending user data (unlike IEC 104 STARTDT).
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
# DLL constants
# ---------------------------------------------------------------------------
_START      = b'\x05\x64'
_MASTER_ADDR     = 1
_OUTSTATION_ADDR = 10

# CTRL for master→outstation unconfirmed user data (DIR=1,PRM=1,FCB=0,FCV=0,FC=4)
_CTRL_UNCONF   = 0xC4
# CTRL for master→outstation confirmed user data (DIR=1,PRM=1,FCB=0,FCV=1,FC=3)
_CTRL_CONF     = 0xC3
# CTRL with FCB=1 (DIR=1,PRM=1,FCB=1,FCV=1,FC=3)
_CTRL_CONF_FCB = 0xEB
# CTRL for secondary response unconfirmed user data (DIR=0,PRM=0,FC=14)
_CTRL_SEC_DATA = 0x0E

# DLL primary function codes (PRM=1)
_DLL_FC_RESET_LINK     = 0x00
_DLL_FC_RESET_PROCESS  = 0x01
_DLL_FC_TEST_LINK      = 0x02
_DLL_FC_USER_DATA_CON  = 0x03
_DLL_FC_USER_DATA_UNC  = 0x04
_DLL_FC_REQUEST_LINK   = 0x09

# AL function codes
_FC_READ              = 0x01
_FC_WRITE             = 0x02
_FC_SELECT            = 0x03
_FC_OPERATE           = 0x04
_FC_DIRECT_OPERATE    = 0x05
_FC_DIRECT_OPERATE_NR = 0x06
_FC_IMMED_FREEZE      = 0x07
_FC_FREEZE_CLEAR      = 0x09
_FC_FREEZE_AT_TIME    = 0x0B
_FC_COLD_RESTART      = 0x0D
_FC_WARM_RESTART      = 0x0E
_FC_INIT_APPL         = 0x10
_FC_START_APPL        = 0x11
_FC_STOP_APPL         = 0x12
_FC_ENABLE_UNSOL      = 0x14
_FC_DISABLE_UNSOL     = 0x15
_FC_AUTH_REQ          = 0x20   # SAv5
_FC_RESPONSE          = 0x81
_FC_UNSOL_RESPONSE    = 0x82
_FC_AUTH_CHALLENGE    = 0x83   # SAv5

# IIN2 exception bits (response → ANOMALY_EXCEPTION, not crash)
_IIN2_FUNC_NOT_SUPP = 0x01
_IIN2_OBJ_UNKNOWN   = 0x02
_IIN2_PARAM_ERROR   = 0x04
_IIN2_EXCEPTION_MASK = _IIN2_FUNC_NOT_SUPP | _IIN2_OBJ_UNKNOWN | _IIN2_PARAM_ERROR

CATEGORY_LINK_LAYER    = "link_layer"
CATEGORY_OBJ_VARIATION = "object_variation"
CATEGORY_APP_FRAG      = "app_layer_frag"
CATEGORY_SAV5_BYPASS   = "sav5_sav6_bypass"


# ---------------------------------------------------------------------------
# CRC-16/DNP
# ---------------------------------------------------------------------------

def _crc16(data: bytes) -> bytes:
    """CRC-16/DNP: poly=0x3D65 (reflected 0xA6BC), init=0, xorout=0xFFFF, little-endian."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", (crc ^ 0xFFFF) & 0xFFFF)


# ---------------------------------------------------------------------------
# Wire-level builders
# ---------------------------------------------------------------------------

def _dll_frame(user_data: bytes, dst: int = _OUTSTATION_ADDR,
               src: int = _MASTER_ADDR, ctrl: int = _CTRL_UNCONF) -> bytes:
    """Build a complete DNP3 DLL frame with correct CRCs."""
    length = 5 + len(user_data)
    hdr_body = bytes([length & 0xFF, ctrl,
                      dst & 0xFF, (dst >> 8) & 0xFF,
                      src & 0xFF, (src >> 8) & 0xFF])
    header = _START + hdr_body + _crc16(_START + hdr_body)
    blocks = b""
    for i in range(0, len(user_data), 16):
        chunk = user_data[i:i + 16]
        blocks += chunk + _crc16(chunk)
    return header + blocks


def _dll_frame_bad_hdr_crc(user_data: bytes, dst: int = _OUTSTATION_ADDR,
                             src: int = _MASTER_ADDR) -> bytes:
    """DLL frame with deliberately flipped header CRC byte."""
    good = _dll_frame(user_data, dst=dst, src=src)
    ba = bytearray(good)
    ba[8] ^= 0xFF   # flip header CRC low byte
    return bytes(ba)


def _dll_frame_bad_block_crc(user_data: bytes) -> bytes:
    """DLL frame with deliberately flipped first block CRC."""
    good = _dll_frame(user_data)
    if len(good) <= 12:
        return good
    ba = bytearray(good)
    # block CRC starts at byte 10 + min(len(user_data),16)
    block_data_len = min(len(user_data), 16)
    crc_offset = 10 + block_data_len
    if crc_offset < len(ba):
        ba[crc_offset] ^= 0xFF
    return bytes(ba)


def _tl_byte(fir: bool = True, fin: bool = True, seq: int = 0) -> bytes:
    return bytes([(fir << 7) | (fin << 6) | (seq & 0x3F)])


def _ac_byte(fir: bool = True, fin: bool = True,
             con: bool = False, uns: bool = False, seq: int = 0) -> int:
    return ((fir << 7) | (fin << 6) | (con << 5) | (uns << 4) | (seq & 0x0F))


def _app_request(fc: int, objects: bytes = b"", seq: int = 0,
                 fir: bool = True, fin: bool = True,
                 con: bool = False, uns: bool = False) -> bytes:
    ac = _ac_byte(fir=fir, fin=fin, con=con, uns=uns, seq=seq)
    return bytes([ac, fc]) + objects


def _read_frame(objects: bytes = b"", dst: int = _OUTSTATION_ADDR,
                seq: int = 0, tl_seq: int = 0) -> bytes:
    """Standard READ request frame."""
    al = _app_request(_FC_READ, objects, seq=seq)
    tl = _tl_byte(seq=tl_seq)
    return _dll_frame(tl + al, dst=dst)


def _read_class0(dst: int = _OUTSTATION_ADDR, seq: int = 0) -> bytes:
    """READ Class 0 (G60V1, qualifier=0x06 = all objects)."""
    return _read_frame(bytes([60, 1, 0x06]), dst=dst, seq=seq)


def _read_gv(group: int, variation: int, qualifier: int = 0x06,
             dst: int = _OUTSTATION_ADDR) -> bytes:
    return _read_frame(bytes([group & 0xFF, variation & 0xFF, qualifier]))


def _dll_only(ctrl: int, dst: int = _OUTSTATION_ADDR,
              src: int = _MASTER_ADDR) -> bytes:
    """DLL-only frame with no user data (link-layer frames like RESET_LINK)."""
    hdr_body = bytes([5, ctrl,
                      dst & 0xFF, (dst >> 8) & 0xFF,
                      src & 0xFF, (src >> 8) & 0xFF])
    return _START + hdr_body + _crc16(_START + hdr_body)


def _ctrl_primary(fc: int, dir_: int = 1, prm: int = 1,
                  fcb: int = 0, fcv: int = 0) -> int:
    return ((dir_ & 1) << 7) | ((prm & 1) << 6) | ((fcb & 1) << 5) | ((fcv & 1) << 4) | (fc & 0x0F)


# ── Fingerprint helpers ───────────────────────────────────────────────────────

def _recv_dnp3(sock: "socket.socket", timeout: float = 3.0) -> Optional[bytes]:
    """Read one DNP3 DLL frame (10-byte header + data blocks + CRCs)."""
    buf = b''
    sock.settimeout(timeout)
    try:
        # Read until we see the start bytes and have the length field
        while len(buf) < 10:
            chunk = sock.recv(10 - len(buf))
            if not chunk:
                return None
            buf += chunk
        if buf[:2] != _START:
            return None
        dll_len = buf[2]  # length field in DLL header = user data bytes + 3 hdr bytes
        user_data = max(0, dll_len - 5)
        n_blocks = (user_data + 15) // 16   # each 16-byte block is followed by a 2-byte CRC
        total_with_crc = 10 + user_data + n_blocks * 2
        while len(buf) < total_with_crc:
            chunk = sock.recv(total_with_crc - len(buf))
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        return None
    return buf


def _extract_dnp3_string(frame: bytes, group: int, variation: int) -> Optional[str]:
    """Extract an ASCII string from a DNP3 Device Attribute response frame.

    DNP3 Group 0 attribute objects: the value is a length-prefixed ASCII string
    encoded in the application layer object header.
    Scans for printable ASCII runs of length 4+ in the frame payload.
    """
    if not frame or len(frame) < 12:
        return None
    # Skip DLL header (10 bytes) + TL byte (1) + AC byte (1) + FC byte (1) = 13
    # Then scan for our group/variation and extract the string value
    data = frame[13:]
    # Look for the group/variation header: group(1) var(1) qualifier(1) count(1) then value
    i = 0
    while i < len(data) - 4:
        if data[i] == group and data[i + 1] == variation:
            # Found the object header: qualifier(1) count_or_index(1) attr_type(1) len(1) value
            attr_pos = i + 4
            if attr_pos + 1 < len(data):
                str_len = data[attr_pos]
                raw = data[attr_pos + 1: attr_pos + 1 + str_len]
                try:
                    s = raw.decode("ascii", errors="replace").strip()
                    if len(s) >= 2:
                        return s
                except Exception:
                    pass
        i += 1
    # Fallback: scan for printable ASCII run of length 8+
    start = None
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= 8:
                run = data[start:i].decode("ascii", errors="replace").strip()
                if run:
                    return run
            start = None
    return None


# ---------------------------------------------------------------------------
# Fuzzer
# ---------------------------------------------------------------------------

class Dnp3Fuzzer(FuzzModule):
    """DNP3 (IEEE 1815) fuzzer — generator and send phase.

    Protocol-specific categories:
      link_layer       DLL-level attacks (FC exhaustion, CTRL bit manipulation)
      object_variation G/V exhaustion, undefined combinations, qualifier abuse
      app_layer_frag   AL fragmentation: FIR/FIN bits, multi-frame writes
      sav5_sav6_bypass SAv5/SAv6 authentication bypass and replay attempts
    """

    PROTOCOL_NAME = "dnp3"
    DEFAULT_PORT  = 20000
    FUZZ_CATEGORIES = [
        CATEGORY_BOUNDARY,
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_SEQUENCE,
        CATEGORY_STATE_MACHINE,
        CATEGORY_LINK_LAYER,
        CATEGORY_OBJ_VARIATION,
        CATEGORY_APP_FRAG,
        CATEGORY_SAV5_BYPASS,
    ]

    def __init__(self, target: Device, logger, delay: float = 0.1, seeds: list = None):
        super().__init__(target, logger, delay, seeds)
        self._sock: Optional[socket.socket] = None

    # -----------------------------------------------------------------------
    # Connection lifecycle
    # -----------------------------------------------------------------------

    def discover(self, interface: str, timeout: int = 30) -> list:
        raise NotImplementedError("DNP3 discovery requires passive sniff (CAP_NET_RAW).")

    def fingerprint(self, active: bool = True) -> "FingerprintResult":
        """DNP3 fingerprint.

        Passive: OUI lookup from ARP cache.
        Active:  Read Group 0 Device Attributes (Var 243 = vendor, Var 245 = model).
                 Note: Group 0 is optional per the spec — many field devices return
                 Function Code Not Implemented (IIN bit 1.0). Returns low confidence
                 OUI result if the request is not supported.
        """
        from core.fingerprint import FingerprintResult, fingerprint_from_oui

        oui_result = fingerprint_from_oui(self.target.ip)
        if not active:
            return oui_result

        # DNP3 Read Group 0 All (Qualifier 0x06 = all objects): Var 243 (Vendor Name)
        # Group 0 Var 243 = manufacturer, Var 245 = device model
        vendor   = "unknown"
        model    = "unknown"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4.0)
            s.connect((self.target.ip, self.target.port))
            # Read Group 0 Var 243 (Vendor Name)
            al_vendor = _app_request(_FC_READ, bytes([0x00, 0xF3, 0x06]), seq=1)
            s.sendall(_dll_frame(al_vendor))
            resp = _recv_dnp3(s)
            if resp:
                txt = _extract_dnp3_string(resp, 0x00, 0xF3)
                if txt:
                    vendor = txt
            # Read Group 0 Var 245 (Device Model)
            al_model = _app_request(_FC_READ, bytes([0x00, 0xF5, 0x06]), seq=2)
            s.sendall(_dll_frame(al_model))
            resp2 = _recv_dnp3(s)
            if resp2:
                txt2 = _extract_dnp3_string(resp2, 0x00, 0xF5)
                if txt2:
                    model = txt2
            s.close()
        except OSError:
            return oui_result

        if vendor == "unknown" and not oui_result.is_known():
            return FingerprintResult(confidence="none", method="dnp3_group0_unsupported")

        effective_vendor = vendor if vendor != "unknown" else oui_result.vendor
        confidence = "medium" if vendor != "unknown" else "low"
        return FingerprintResult(
            vendor=effective_vendor,
            model=model,
            confidence=confidence,
            method="dnp3_group0_device_attributes",
            extra={"oui_vendor": oui_result.vendor} if oui_result.is_known() else {},
        )

    def connect(self, target: Device) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(5.0)
        self._sock.connect((target.ip, target.port))

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
        except Exception:
            self.close()

    def replay_payload(self, payload: bytes) -> Optional[bytes]:
        if self._sock is None:
            raise RuntimeError(
                "Not connected — call connect() before replay_payload(). "
                "Use generate_cases() to build payloads without a live target."
            )
        self._sock.sendall(payload)
        return self._recv_frame()

    # -----------------------------------------------------------------------
    # Generator phase (hardware-free)
    # -----------------------------------------------------------------------

    def generate_cases(self, categories=None):
        """Return list of (case_id, category, description, payload)."""
        cats = self._resolve_categories(categories)
        generators = {
            CATEGORY_BOUNDARY:       self._gen_boundary,
            CATEGORY_BINARY_CORRUPTION: self._gen_binary_corruption,
            CATEGORY_SEQUENCE:       self._gen_sequence,
            CATEGORY_STATE_MACHINE:  self._gen_state_machine,
            CATEGORY_LINK_LAYER:     self._gen_link_layer,
            CATEGORY_OBJ_VARIATION:  self._gen_object_variation,
            CATEGORY_APP_FRAG:       self._gen_app_layer_frag,
            CATEGORY_SAV5_BYPASS:    self._gen_sav5_bypass,
        }
        cases = []
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
        cases   = self.generate_cases(categories)
        total   = len(cases)
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

            if result.crash_indicator and result.anomaly not in (ANOMALY_EXCEPTION, None):
                print(f"[fuzz] !! {case_id}  {result.anomaly}  {description[:60]}")

        print(f"\n[fuzz] Completed {total} cases for {self.target.ip}:{self.target.port}")
        return results

    # -----------------------------------------------------------------------
    # Send / receive / classify
    # -----------------------------------------------------------------------

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
            self._sock.sendall(payload)

            # drain N-1 frames for multi-frame payloads (app_layer_frag)
            n = self._count_frames(payload)
            for _ in range(n - 1):
                self._recv_frame()

            response = self._recv_frame()
            # opendnp3 sends large responses in 2 transport segments.
            # If we read a frame with TL.FIN=0 (first segment, more coming),
            # drain until TL.FIN=1 so we classify the complete response.
            _MAX_TL_DRAIN = 8
            for _ in range(_MAX_TL_DRAIN):
                if not response or len(response) <= 10:
                    break
                _udlen = max(0, response[2] - 5)
                _ud = self._extract_user_data(response[10:], _udlen)
                if _ud and not (_ud[0] & 0x40):  # TL.FIN == 0
                    response = self._recv_frame()
                else:
                    break
            result.response = response

            if not response:
                result.anomaly       = ANOMALY_NO_RESPONSE
                result.crash_indicator = True
                self._reconnect()
            elif len(response) < 10:
                result.anomaly       = ANOMALY_MALFORMED_RESPONSE
                result.crash_indicator = True
                self._reconnect()
            else:
                self._classify_response(response, result)

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

    def _recv_frame(self) -> bytes:
        """Read one complete DNP3 DLL frame from socket."""
        hdr = self._recv_exact(10)
        if len(hdr) < 10:
            return hdr
        length = hdr[2]
        if length < 5:
            return hdr
        user_data_len = length - 5
        if user_data_len == 0:
            return hdr
        # Wire bytes: ceil(user_data_len/16) blocks × (block_data + 2 CRC)
        n_blocks = (user_data_len + 15) // 16
        wire_body = user_data_len + n_blocks * 2
        body = self._recv_exact(wire_body)
        return hdr + body

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _classify_response(self, response: bytes, result: FuzzResult) -> None:
        if response[:2] != _START:
            result.anomaly       = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        length = response[2]
        if length < 5:
            result.anomaly       = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        user_data_len = length - 5
        if user_data_len < 2:
            # DLL-only frame (ACK/NACK) — not an anomaly
            return

        user_data = self._extract_user_data(response[10:], user_data_len)
        if len(user_data) < 4:
            # Too short for TL(1) + AC(1) + FC(1) + IIN1(1)
            return

        # user_data[0] = TL, user_data[1] = AC, user_data[2] = FC
        al_fc = user_data[2]
        if al_fc not in (_FC_RESPONSE, _FC_UNSOL_RESPONSE, _FC_AUTH_CHALLENGE):
            result.anomaly       = ANOMALY_UNEXPECTED_DATA
            result.crash_indicator = True
            result.response_decoded = {"al_fc": f"0x{al_fc:02X}"}
            return

        if len(user_data) < 5:
            return  # FC=0x81 RESPONSE but no IIN bytes — still passable

        iin1 = user_data[3]
        iin2 = user_data[4] if len(user_data) >= 5 else 0
        result.response_decoded = {
            "al_fc": f"0x{al_fc:02X}",
            "iin1":  f"0x{iin1:02X}",
            "iin2":  f"0x{iin2:02X}",
        }
        if iin2 & _IIN2_EXCEPTION_MASK:
            result.anomaly = ANOMALY_EXCEPTION
            # crash_indicator stays False — spec-compliant rejection

    @staticmethod
    def _extract_user_data(body: bytes, user_data_len: int) -> bytes:
        """Strip block CRCs from DLL body, returning raw TL+AL bytes."""
        data = b""
        offset = 0
        remaining = user_data_len
        while remaining > 0 and offset < len(body):
            n = min(remaining, 16)
            data += body[offset:offset + n]
            offset += n + 2     # skip 2-byte block CRC
            remaining -= n
        return data

    @staticmethod
    def _count_frames(payload: bytes) -> int:
        """Count complete DLL frames in payload (for multi-frame drain loop)."""
        count, offset = 0, 0
        while offset + 10 <= len(payload):
            if payload[offset:offset + 2] != _START:
                break
            length = payload[offset + 2]
            if length < 5:
                break
            user_data_len = length - 5
            n_blocks = (user_data_len + 15) // 16 if user_data_len > 0 else 0
            wire_frame = 10 + user_data_len + n_blocks * 2
            if offset + wire_frame > len(payload):
                break
            count += 1
            offset += wire_frame
        return max(count, 1)

    # -----------------------------------------------------------------------
    # Generators
    # -----------------------------------------------------------------------

    def _gen_boundary(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_BOUNDARY, desc, payload))

        # Normal READ with various DST addresses
        for dst, label in [
            (0x0000, "DST=0x0000"),
            (_OUTSTATION_ADDR, f"DST=0x{_OUTSTATION_ADDR:04X} (standard outstation)"),
            (0x7FFE, "DST=0x7FFE"),
            (0x7FFF, "DST=0x7FFF"),
            (0xFFFE, "DST=0xFFFE"),
            (0xFFFF, "DST=0xFFFF broadcast"),
        ]:
            add(f"READ Class0 {label}", _read_class0(dst=dst))

        # SRC address boundary
        for src, label in [(0x0000, "SRC=0"), (0x0001, "SRC=1"),
                           (0x7FFF, "SRC=0x7FFF"), (0xFFFF, "SRC=0xFFFF")]:
            al = _app_request(_FC_READ, bytes([60, 1, 0x06]))
            add(f"READ Class0 {label}", _dll_frame(_tl_byte() + al, src=src))

        # App SEQ boundary values
        for seq in [0, 7, 15]:
            add(f"READ Class0 app-SEQ={seq}", _read_class0(seq=seq))

        # LEN=255 max (250 user data bytes, TL + 249 AL bytes)
        big_al = bytes([_FC_READ] + [60, 1, 0x06] * 40)  # AL only (no TL here)
        add("DLL LEN=255 (250 user-data bytes)", _dll_frame(_tl_byte() + big_al[:249]))

        # READ qualifier variants
        for qual, label in [
            (0x00, "start/stop 1-byte: start=0 stop=0"),
            (0x01, "start/stop 2-byte: start=0 stop=0"),
            (0x06, "all objects (standard)"),
            (0x07, "count 1-byte: count=1"),
            (0x08, "count 2-byte: count=1"),
        ]:
            obj = bytes([60, 1, qual])
            if qual in (0x00,):
                obj += bytes([0, 0])   # start, stop
            elif qual in (0x01,):
                obj += bytes([0, 0, 0, 0])  # start(2), stop(2)
            elif qual in (0x07,):
                obj += bytes([1])     # count=1
            elif qual in (0x08,):
                obj += bytes([1, 0])  # count=1 (2 bytes)
            add(f"READ G60V1 qualifier=0x{qual:02X} ({label})", _read_frame(obj))

        # Read class 1-4 individually
        for cls in range(1, 5):
            add(f"READ Class {cls} (G60V{cls})", _read_gv(60, cls))

        # Cold/warm restart
        add("AL FC=0x0D COLD_RESTART", _dll_frame(_tl_byte() + bytes([0xC0, _FC_COLD_RESTART])))
        add("AL FC=0x0E WARM_RESTART", _dll_frame(_tl_byte() + bytes([0xC0, _FC_WARM_RESTART])))

        # Enable/disable unsolicited (G60V2-G60V4, qualifier=0x06)
        obj_cls234 = bytes([60, 2, 0x06, 60, 3, 0x06, 60, 4, 0x06])
        add("ENABLE_UNSOLICITED G60V2-V4", _dll_frame(
            _tl_byte() + _app_request(_FC_ENABLE_UNSOL, obj_cls234)))
        add("DISABLE_UNSOLICITED G60V2-V4", _dll_frame(
            _tl_byte() + _app_request(_FC_DISABLE_UNSOL, obj_cls234)))

        # Write G80V1 (clear IIN1.0 DEVICE_RESTART bit)
        # G80V1: 1-byte per object, qualifier=0x00, start=7, stop=7 (bit 7 of IIN1)
        obj_iin = bytes([80, 1, 0x00, 7, 7, 0x00])  # write 0 to bit 7
        add("WRITE G80V1 clear DEVICE_RESTART (IIN1.0)", _dll_frame(
            _tl_byte() + _app_request(_FC_WRITE, obj_iin)))

        # READ G0V0 (undefined — all objects, group 0)
        add("READ G0V0 (undefined group 0)", _read_gv(0, 0))

        # READ with no objects (empty object list)
        add("READ with empty object list", _dll_frame(_tl_byte() + bytes([0xC0, _FC_READ])))

        # Direct operate CROB G12V1: PULSE_ON, count=1, on_time=1000ms, off_time=500ms
        crob = bytes([0x41, 1, 0xE8, 0x03, 0x00, 0x00, 0xF4, 0x01, 0x00, 0x00, 0x00])
        obj_crob = bytes([12, 1, 0x17, 1, 1]) + crob  # qualifier=0x17, 1-byte index=1
        add("DIRECT_OPERATE G12V1 CROB PULSE_ON index=1", _dll_frame(
            _tl_byte() + _app_request(_FC_DIRECT_OPERATE, obj_crob)))

        # Direct operate G41V1 analog output index=0, value=0
        obj_ao = bytes([41, 1, 0x17, 1, 0, 0x00, 0x00, 0x00, 0x00, 0x00])
        add("DIRECT_OPERATE G41V1 analog output 0.0 index=0", _dll_frame(
            _tl_byte() + _app_request(_FC_DIRECT_OPERATE, obj_ao)))

        return cases

    def _gen_binary_corruption(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_BINARY_CORRUPTION, desc, payload))

        # Wrong start bytes
        for b1, b2, label in [
            (0x00, 0x00, "0x0000"),
            (0x64, 0x05, "reversed start bytes"),
            (0x05, 0x00, "correct first, wrong second"),
            (0x00, 0x64, "wrong first, correct second"),
            (0xFF, 0xFF, "all-0xFF start"),
            (0x7E, 0x7F, "ASCII-looking start"),
        ]:
            good = _read_class0()
            ba = bytearray(good)
            ba[0] = b1
            ba[1] = b2
            add(f"Wrong start bytes {label}", bytes(ba))

        # LEN too small (below minimum 5)
        for length in [0, 1, 2, 3, 4]:
            hdr_body = bytes([length, _CTRL_UNCONF, 1, 0, 3, 0])
            add(f"DLL LEN={length} (< 5 minimum)", _START + hdr_body + _crc16(_START + hdr_body))

        # Truncated at various byte positions
        good = _read_class0()
        for cut in range(1, 10):
            add(f"Truncated at byte {cut} (of {len(good)})", good[:cut])

        # Truncated mid user-data block
        for cut in range(10, min(10 + 8, len(good))):
            add(f"Truncated at byte {cut} mid-block", good[:cut])

        # Corrupt header CRC
        add("Corrupt header CRC (low byte flipped)", _dll_frame_bad_hdr_crc(_tl_byte() + bytes([0xC0, _FC_READ, 60, 1, 0x06])))

        # Corrupt block CRC
        add("Corrupt first block CRC (low byte flipped)", _dll_frame_bad_block_crc(_tl_byte() + bytes([0xC0, _FC_READ, 60, 1, 0x06])))

        # All-zero payload
        add("All-zero 10 bytes", bytes(10))

        # All-0xFF payload
        add("All-0xFF 10 bytes", bytes([0xFF] * 10))

        # Empty payload
        add("Empty payload (zero bytes)", b"")

        # Two start bytes only
        add("Start bytes only (2 bytes)", _START)

        # Valid header but LEN claims 250 user bytes; only header sent
        hdr_body = bytes([255, _CTRL_UNCONF, 1, 0, 3, 0])
        add("LEN=255 claimed but only header sent (truncated write)",
            _START + hdr_body + _crc16(_START + hdr_body))

        # GI frame with all CRC bytes zeroed
        good = _read_class0()
        ba = bytearray(good)
        ba[8:10] = b'\x00\x00'   # zero header CRC
        if len(ba) > 12:
            ba[-2:] = b'\x00\x00'  # zero block CRC
        add("Header and block CRC zeroed", bytes(ba))

        # Random-looking payloads with valid start bytes
        import random
        rng = random.Random(0xD4B3)
        for i in range(10):
            size = rng.randint(1, 24)
            body = bytes([rng.randint(0, 255) for _ in range(size)])
            add(f"Valid start bytes + random body variant {i+1}", _START + body)

        # Bit-flipped single bytes in a valid frame
        good = _read_class0()
        for pos in [2, 3, 5, 9]:
            if pos < len(good):
                ba = bytearray(good)
                ba[pos] ^= 0x80
                add(f"Single bit-flip at byte {pos}", bytes(ba))

        return cases

    def _gen_sequence(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_SEQUENCE, desc, payload))

        # App SEQ: all 16 values
        for seq in range(16):
            add(f"App-layer SEQ={seq}", _read_class0(seq=seq))

        # TL SEQ boundary
        for tl_seq, label in [(0, "TL-SEQ=0"), (31, "TL-SEQ=31"), (63, "TL-SEQ=63")]:
            al = _app_request(_FC_READ, bytes([60, 1, 0x06]))
            add(f"TL {label}", _dll_frame(_tl_byte(seq=tl_seq) + al))

        # CON=1: request application confirmation
        al_con = bytes([_ac_byte(con=True), _FC_READ, 60, 1, 0x06])
        add("AL CON=1 (request application confirmation)", _dll_frame(_tl_byte() + al_con))

        # UNS=1: mark as unsolicited (master shouldn't send this)
        al_uns = bytes([_ac_byte(uns=True), _FC_READ, 60, 1, 0x06])
        add("AL UNS=1 (unsolicited flag from master — invalid)", _dll_frame(_tl_byte() + al_uns))

        # FCB attacks: send FC=3 (confirmed) with same FCB twice (should alternate)
        al = _app_request(_FC_READ, bytes([60, 1, 0x06]))
        tl = _tl_byte()
        add("FCB=0 confirmed user data (first)", _dll_frame(tl + al, ctrl=_CTRL_CONF))
        add("FCB=0 confirmed user data (second, FCB should have changed)", _dll_frame(tl + al, ctrl=_CTRL_CONF))
        add("FCB=1 confirmed user data", _dll_frame(tl + al, ctrl=_CTRL_CONF_FCB))

        return cases

    def _gen_state_machine(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_STATE_MACHINE, desc, payload))

        # Send RESPONSE (outstation FC) as if from master
        add("AL FC=0x81 RESPONSE sent by master (wrong direction)",
            _dll_frame(_tl_byte() + bytes([0xC0, _FC_RESPONSE, 0x00, 0x00])))

        # Send UNSOL_RESPONSE as if from master
        add("AL FC=0x82 UNSOL_RESPONSE sent by master",
            _dll_frame(_tl_byte() + bytes([0x40, _FC_UNSOL_RESPONSE, 0x20, 0x00])))

        # Send AUTH_CHALLENGE as if from master
        add("AL FC=0x83 AUTH_CHALLENGE sent by master",
            _dll_frame(_tl_byte() + bytes([0xC0, _FC_AUTH_CHALLENGE, 0x00, 0x01, 0x00])))

        # DLL link-layer only frames (no user data)
        add("DLL FC=0 RESET_LINK_STATES", _dll_only(_ctrl_primary(0)))
        add("DLL FC=1 RESET_USER_PROCESS", _dll_only(_ctrl_primary(1)))
        add("DLL FC=2 TEST_LINK_STATES",   _dll_only(_ctrl_primary(2)))
        add("DLL FC=9 REQUEST_LINK_STATUS", _dll_only(_ctrl_primary(9)))

        # DLL FC=3 confirmed user data (expects DLL ACK before AL processing)
        al = _app_request(_FC_READ, bytes([60, 1, 0x06]))
        add("DLL FC=3 confirmed user data (expect DLL ACK first)", _dll_frame(_tl_byte() + al, ctrl=_CTRL_CONF))

        # COLD_RESTART
        add("AL COLD_RESTART (FC=0x0D) — device should reboot",
            _dll_frame(_tl_byte() + bytes([0xC0, _FC_COLD_RESTART])))

        # WARM_RESTART
        add("AL WARM_RESTART (FC=0x0E)",
            _dll_frame(_tl_byte() + bytes([0xC0, _FC_WARM_RESTART])))

        # Double restart
        restart = _dll_frame(_tl_byte() + bytes([0xC0, _FC_COLD_RESTART]))
        add("Two COLD_RESTARTs concatenated (state machine stress)", restart + restart)

        # INIT_APPL, START_APPL, STOP_APPL (less-common control FCs)
        add("AL FC=0x10 INIT_APPL",  _dll_frame(_tl_byte() + bytes([0xC0, _FC_INIT_APPL])))
        add("AL FC=0x11 START_APPL", _dll_frame(_tl_byte() + bytes([0xC0, _FC_START_APPL])))
        add("AL FC=0x12 STOP_APPL",  _dll_frame(_tl_byte() + bytes([0xC0, _FC_STOP_APPL])))

        # ENABLE_UNSOLICITED without prior DISABLE (state confusion)
        obj = bytes([60, 2, 0x06, 60, 3, 0x06])
        add("ENABLE_UNSOLICITED without prior DISABLE", _dll_frame(
            _tl_byte() + _app_request(_FC_ENABLE_UNSOL, obj)))

        # DISABLE then immediate re-ENABLE
        dis = _dll_frame(_tl_byte() + _app_request(_FC_DISABLE_UNSOL, obj))
        en  = _dll_frame(_tl_byte() + _app_request(_FC_ENABLE_UNSOL, obj))
        add("DISABLE_UNSOLICITED + ENABLE_UNSOLICITED in one write", dis + en)

        # OPERATE without prior SELECT (SBO violation)
        crob = bytes([0x41, 1, 0xE8, 0x03, 0x00, 0x00, 0xF4, 0x01, 0x00, 0x00, 0x00])
        obj_crob = bytes([12, 1, 0x17, 1, 1]) + crob
        add("OPERATE (FC=0x04) without prior SELECT (SBO violation)", _dll_frame(
            _tl_byte() + _app_request(_FC_OPERATE, obj_crob)))

        return cases

    def _gen_link_layer(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_LINK_LAYER, desc, payload))

        al = _app_request(_FC_READ, bytes([60, 1, 0x06]))
        tl = _tl_byte()

        # All 16 primary DLL FC values
        for fc in range(16):
            ctrl = _ctrl_primary(fc)
            al_payload = tl + al if fc in (3, 4) else b""
            if al_payload:
                add(f"DLL primary FC={fc} with user data", _dll_frame(al_payload, ctrl=ctrl))
            else:
                add(f"DLL primary FC={fc} no user data (link-only)", _dll_only(ctrl))

        # CTRL DIR=0 from master (wrong direction)
        for fc, label in [(4, "USER_DATA_UNC"), (3, "USER_DATA_CON"), (0, "RESET_LINK")]:
            ctrl_wrong_dir = fc  # DIR=0, PRM=0
            if fc in (3, 4):
                add(f"DLL FC={fc} {label} with DIR=0 (outstation direction from master)",
                    _dll_frame(tl + al, ctrl=ctrl_wrong_dir))
            else:
                add(f"DLL FC={fc} {label} with DIR=0",
                    _dll_only(ctrl_wrong_dir))

        # CTRL PRM=0 from master (claiming secondary)
        ctrl_sec = 0x40 | 4  # DIR=1, PRM=0, FC=4
        add("DLL CTRL PRM=0 from master (claims secondary)", _dll_frame(tl + al, ctrl=ctrl_sec))

        # CTRL all-zeros
        add("DLL CTRL=0x00 (all zeros)", _dll_frame(tl + al, ctrl=0x00))

        # CTRL all-ones
        add("DLL CTRL=0xFF (all ones)", _dll_frame(tl + al, ctrl=0xFF))

        # CTRL FCV=1 without FCB set (FC=4 unconfirmed, FCV should be 0)
        ctrl_fcv_no_fcb = 0xD4  # DIR=1, PRM=1, FCB=0, FCV=1, FC=4
        add("DLL CTRL FCV=1 on unconfirmed FC=4", _dll_frame(tl + al, ctrl=ctrl_fcv_no_fcb))

        # DLL LEN boundary: LEN=5 (header only, no user data)
        hdr_body = bytes([5, _CTRL_UNCONF, 1, 0, 3, 0])
        add("DLL LEN=5 (header only, no user data)", _START + hdr_body + _crc16(_START + hdr_body))

        # DLL LEN boundary: LEN=6 (1 user-data byte, too short for AL parsing)
        add("DLL LEN=6 (1 user-data byte, too short for TL+AL)", _dll_frame(b"\xC0"))

        # DST=SRC (loopback address confusion)
        add("DLL DST=SRC=3 (master address as destination)",
            _dll_frame(tl + al, dst=_MASTER_ADDR, src=_MASTER_ADDR))

        # Broadcast DST with confirmed user data
        add("DLL FC=3 confirmed user data to broadcast DST=0xFFFF",
            _dll_frame(tl + al, dst=0xFFFF, ctrl=_CTRL_CONF))

        # Maximum address values
        add("DLL DST=0xFFFF, SRC=0xFFFF (both max)",
            _dll_frame(tl + al, dst=0xFFFF, src=0xFFFF))

        return cases

    def _gen_object_variation(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_OBJ_VARIATION, desc, payload))

        # Standard READ requests for all major groups
        for group, variation, label in [
            (1,  0, "G1V0 Binary Input auto-negotiate"),
            (1,  1, "G1V1 Binary Input packed"),
            (1,  2, "G1V2 Binary Input with flags"),
            (2,  1, "G2V1 Binary Input Event without time"),
            (2,  2, "G2V2 Binary Input Event with absolute time"),
            (10, 0, "G10V0 Binary Output auto-negotiate"),
            (10, 2, "G10V2 Binary Output Status with flags"),
            (20, 0, "G20V0 Binary Counter auto-negotiate"),
            (20, 5, "G20V5 Binary Counter 4-byte"),
            (22, 0, "G22V0 Counter Event auto-negotiate"),
            (30, 0, "G30V0 Analog Input auto-negotiate"),
            (30, 1, "G30V1 Analog Input 4-byte"),
            (30, 5, "G30V5 Analog Input single-float"),
            (32, 0, "G32V0 Analog Input Event auto-negotiate"),
            (40, 0, "G40V0 Analog Output Status auto-negotiate"),
            (40, 1, "G40V1 Analog Output Status 4-byte"),
            (50, 1, "G50V1 Time and Date"),
            (60, 1, "G60V1 Class 0 all static data"),
            (60, 2, "G60V2 Class 1 events"),
            (60, 3, "G60V3 Class 2 events"),
            (60, 4, "G60V4 Class 3 events"),
            (80, 1, "G80V1 Internal Indications"),
        ]:
            add(f"READ {label}", _read_gv(group, variation))

        # SAv5 objects as READ targets
        for variation, label in [(1, "Challenge"), (2, "Auth Reply"),
                                  (4, "Session Key Status"), (5, "Session Key Change")]:
            add(f"READ G120V{variation} SAv5 {label}", _read_gv(120, variation))

        # Undefined/reserved groups
        for group, variation, label in [
            (0,   0, "G0V0 (all, undefined)"),
            (100, 0, "G100V0 (reserved)"),
            (255, 255, "G255V255 (max, undefined)"),
            (13, 0,  "G13V0 Binary Output Event auto-negotiate (undefined in many devices)"),
            (90, 0,  "G90V0 (reserved)"),
        ]:
            add(f"READ {label}", _read_gv(group, variation))

        # Invalid qualifier codes
        for qual, label in [
            (0x10, "qualifier=0x10 (undefined range type)"),
            (0x40, "qualifier=0x40 (undefined)"),
            (0xFF, "qualifier=0xFF (all bits set)"),
        ]:
            add(f"READ G60V1 {label}", _read_frame(bytes([60, 1, qual])))

        # Qualifier 0x00 with start/stop range
        for start, stop, label in [(0, 0, "start=0 stop=0"),
                                    (0, 255, "start=0 stop=255"),
                                    (255, 0, "start=255 stop=0 (inverted)")]:
            add(f"READ G1V1 qualifier=0x00 {label}",
                _read_frame(bytes([1, 1, 0x00, start, stop])))

        # Qualifier 0x01 2-byte start/stop
        add("READ G30V1 qualifier=0x01 start=0 stop=65535",
            _read_frame(bytes([30, 1, 0x01, 0, 0, 0xFF, 0xFF])))

        # Count qualifier 0x07 with 0 and 255 objects
        add("READ G1V1 qualifier=0x07 count=0",  _read_frame(bytes([1, 1, 0x07, 0])))
        add("READ G1V1 qualifier=0x07 count=255", _read_frame(bytes([1, 1, 0x07, 255])))

        # Multiple object headers in one AL
        obj_multi = bytes([60, 1, 0x06, 1, 1, 0x06, 30, 1, 0x06])  # Class0 + BI + AI
        add("READ three object headers: G60V1+G1V1+G30V1", _read_frame(obj_multi))

        # WRITE G80V1 clear restart bit
        add("WRITE G80V1 clear IIN1.0 DEVICE_RESTART",
            _dll_frame(_tl_byte() + _app_request(_FC_WRITE,
                bytes([80, 1, 0x00, 7, 7, 0x00]))))

        # DIRECT_OPERATE CROB: NUL control code (Code=0)
        crob_nul = bytes([0x00, 1, 0xE8, 0x03, 0x00, 0x00, 0xF4, 0x01, 0x00, 0x00, 0x00])
        add("DIRECT_OPERATE G12V1 CROB Code=NUL (0)",
            _dll_frame(_tl_byte() + _app_request(_FC_DIRECT_OPERATE,
                bytes([12, 1, 0x17, 1, 1]) + crob_nul)))

        # DIRECT_OPERATE CROB: TRIP (TCC=2)
        crob_trip = bytes([0x81, 1, 0xE8, 0x03, 0x00, 0x00, 0xF4, 0x01, 0x00, 0x00, 0x00])
        add("DIRECT_OPERATE G12V1 CROB TRIP (TCC=2)",
            _dll_frame(_tl_byte() + _app_request(_FC_DIRECT_OPERATE,
                bytes([12, 1, 0x17, 1, 1]) + crob_trip)))

        # Analog output G41V1 with float NaN
        nan_bytes = struct.pack("<f", float("nan"))
        ao_nan = bytes([41, 1, 0x17, 1, 0]) + nan_bytes + bytes([0x00])
        add("DIRECT_OPERATE G41V1 float=NaN", _dll_frame(
            _tl_byte() + _app_request(_FC_DIRECT_OPERATE, ao_nan)))

        # Analog output G41V1 with float +Inf
        inf_bytes = struct.pack("<f", float("inf"))
        ao_inf = bytes([41, 1, 0x17, 1, 0]) + inf_bytes + bytes([0x00])
        add("DIRECT_OPERATE G41V1 float=+Inf", _dll_frame(
            _tl_byte() + _app_request(_FC_DIRECT_OPERATE, ao_inf)))

        # Analog output G41V2 (2-byte scaled) with min/max values
        ao_sc_max = bytes([41, 2, 0x17, 1, 0]) + struct.pack("<H", 0x7FFF) + bytes([0x00])
        add("DIRECT_OPERATE G41V2 scaled max 0x7FFF", _dll_frame(
            _tl_byte() + _app_request(_FC_DIRECT_OPERATE, ao_sc_max)))

        # IMMED_FREEZE G20V0 (counter freeze)
        add("IMMED_FREEZE G20V0", _dll_frame(
            _tl_byte() + _app_request(_FC_IMMED_FREEZE, bytes([20, 0, 0x06]))))

        return cases

    def _gen_app_layer_frag(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_APP_FRAG, desc, payload))

        al_read = bytes([60, 1, 0x06])

        # FIR=1 FIN=0 (first fragment, never completed)
        al_first = bytes([_ac_byte(fir=True, fin=False), _FC_READ]) + al_read
        add("AL FIR=1 FIN=0 (first fragment, no continuation)",
            _dll_frame(_tl_byte(fin=False) + al_first))

        # FIR=0 FIN=1 (last fragment without any prior)
        al_last = bytes([_ac_byte(fir=False, fin=True), _FC_READ]) + al_read
        add("AL FIR=0 FIN=1 (last fragment, no prior first)",
            _dll_frame(_tl_byte(fir=False) + al_last))

        # FIR=0 FIN=0 (middle fragment in isolation)
        al_mid = bytes([_ac_byte(fir=False, fin=False), _FC_READ]) + al_read
        add("AL FIR=0 FIN=0 (middle fragment in isolation)",
            _dll_frame(_tl_byte(fir=False, fin=False) + al_mid))

        # Standard single frame for reference
        f0 = _read_class0()

        # Two complete frames in one TCP write
        add("Two READ Class0 frames in one TCP write", f0 + f0)

        # Three complete frames
        add("Three READ Class0 frames in one TCP write", f0 + f0 + f0)

        # Five frames burst
        add("Five READ Class0 frames burst", f0 * 5)

        # Ten frames burst
        add("Ten READ Class0 frames burst", f0 * 10)

        # Two different read requests concatenated
        f_cls1 = _read_gv(60, 1)
        f_cls2 = _read_gv(60, 2)
        add("READ Class0 + READ Class1 concatenated", f_cls1 + f_cls2)

        # COLD_RESTART then READ (test post-restart behaviour)
        restart_frame = _dll_frame(_tl_byte() + bytes([0xC0, _FC_COLD_RESTART]))
        add("COLD_RESTART + READ Class0 in one write", restart_frame + f0)

        # FIR=1 FIN=0 followed by FIR=0 FIN=1 (proper two-fragment message)
        tl_f = _tl_byte(fin=False, seq=0)
        tl_l = _tl_byte(fir=False, fin=True, seq=1)
        al_f = bytes([_ac_byte(fir=True, fin=False, seq=0), _FC_READ]) + al_read
        al_l = bytes([_ac_byte(fir=False, fin=True, seq=0), _FC_READ]) + al_read
        frag1 = _dll_frame(tl_f + al_f)
        frag2 = _dll_frame(tl_l + al_l)
        add("Two-fragment AL: FIR fragment + FIN fragment", frag1 + frag2)

        # Reversed order: FIN fragment then FIR fragment
        add("Two-fragment AL reversed: FIN first, FIR second", frag2 + frag1)

        # CON=1 request in a multi-frame context
        al_con = bytes([_ac_byte(con=True), _FC_READ]) + al_read
        add("READ CON=1 + READ CON=1 burst",
            _dll_frame(_tl_byte() + al_con) + _dll_frame(_tl_byte() + al_con))

        # TL FIR/FIN mismatch vs AL FIR/FIN
        tl_single = _tl_byte(fir=True, fin=True)
        al_not_fin = bytes([_ac_byte(fir=True, fin=False), _FC_READ]) + al_read
        add("TL single-segment but AL FIN=0 (mismatch)",
            _dll_frame(tl_single + al_not_fin))

        # Large single-fragment READ (near 250-byte AL limit)
        big_obj = bytes([60, 1, 0x06] * 40)[:247]  # fills most of user data
        add("READ with large object list (near 250-byte limit)",
            _dll_frame(_tl_byte() + bytes([0xC0, _FC_READ]) + big_obj))

        return cases

    def _gen_sav5_bypass(self):
        cases = []

        def add(desc, payload):
            cases.append((self._next_id(), CATEGORY_SAV5_BYPASS, desc, payload))

        # AUTH_REQ (FC=0x20) empty
        add("AUTH_REQ (FC=0x20) with empty body",
            _dll_frame(_tl_byte() + bytes([0xC0, _FC_AUTH_REQ])))

        # AUTH_REQ with truncated G120V2 Auth Reply header (G=120, V=2, Qual=0x5B, ...)
        # G120V2: [challenge-seq-number 4B LE][user-number 2B LE][MAC ...]
        truncated_reply = bytes([120, 2, 0x5B, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00])
        add("AUTH_REQ FC=0x20 G120V2 truncated reply (no HMAC bytes)",
            _dll_frame(_tl_byte() + bytes([0xC0, _FC_AUTH_REQ]) + truncated_reply))

        # AUTH_REQ with zero-length HMAC (G120V2 with 0 MAC bytes)
        zero_mac_reply = bytes([120, 2, 0x5B]) + struct.pack("<IH", 1, 1)  # seq=1, user=1, no MAC
        add("AUTH_REQ G120V2 zero-length HMAC",
            _dll_frame(_tl_byte() + bytes([0xC0, _FC_AUTH_REQ]) + zero_mac_reply))

        # AUTH_REQ with oversized HMAC (G120V2, 100 bytes of zeroed HMAC)
        big_mac = bytes([120, 2, 0x5B]) + struct.pack("<IH", 2, 1) + bytes(100)
        add("AUTH_REQ G120V2 100-byte HMAC (oversized, likely invalid)",
            _dll_frame(_tl_byte() + bytes([0xC0, _FC_AUTH_REQ]) + big_mac))

        # Challenge replay: same challenge sequence number sent twice
        auth_reply = bytes([0xC0, _FC_AUTH_REQ,
                            120, 2, 0x5B]) + struct.pack("<IH", 5, 1) + bytes(10)
        frame_reply = _dll_frame(_tl_byte() + auth_reply)
        add("AUTH_REQ replay: challenge seq=5 sent twice (first)", frame_reply)
        add("AUTH_REQ replay: challenge seq=5 sent twice (second)", frame_reply)

        # Wrong key wrap (G120V5 Session Key Change): key status = 0xFF (undefined)
        key_change = bytes([0xC0, _FC_AUTH_REQ,
                            120, 5, 0x5B]) + struct.pack("<IHHH", 1, 1, 3, 0) + bytes(32)
        add("AUTH_REQ G120V5 session key change with zeros",
            _dll_frame(_tl_byte() + key_change))

        # Aggressive mode request (G120V3) without prior key exchange
        agm_req = bytes([0xC0, _FC_AUTH_REQ,
                         120, 3, 0x5B]) + struct.pack("<IH", 1, 1) + bytes(10)
        add("AUTH_REQ G120V3 aggressive mode without prior session key",
            _dll_frame(_tl_byte() + agm_req))

        # READ G120V1 Challenge as if master is requesting a challenge from itself
        add("READ G120V1 SAv5 Challenge (master requesting challenge from outstation)",
            _read_gv(120, 1))

        # READ G120V4 Session Key Status
        add("READ G120V4 SAv5 Session Key Status",
            _read_gv(120, 4))

        # SAv5 Error (G120V6) sent by master (wrong direction)
        sav5_err = bytes([0xC0, _FC_AUTH_REQ,
                          120, 6, 0x5B]) + struct.pack("<IHH", 1, 1, 5)  # seq, user, error-code
        add("AUTH_REQ G120V6 SAv5 Error sent by master (wrong direction)",
            _dll_frame(_tl_byte() + sav5_err))

        # Challenge sequence number wrap: seq=0xFFFFFFFF
        wrap_reply = bytes([0xC0, _FC_AUTH_REQ,
                            120, 2, 0x5B]) + struct.pack("<IH", 0xFFFFFFFF, 1) + bytes(10)
        add("AUTH_REQ G120V2 challenge seq=0xFFFFFFFF (wrap-around attack)",
            _dll_frame(_tl_byte() + wrap_reply))

        # AUTH_REQ (FC=0x20) instead of normal READ (try to bypass auth challenge)
        # Embed a READ G60V1 as if it's an authenticated request
        al_read_auth = bytes([0xC0, _FC_AUTH_REQ, 60, 1, 0x06])
        add("AUTH_REQ FC=0x20 with READ object (bypass attempt: embed READ in auth frame)",
            _dll_frame(_tl_byte() + al_read_auth))

        # Auth with user number 0 (invalid, users start at 1)
        reply_user0 = bytes([0xC0, _FC_AUTH_REQ,
                             120, 2, 0x5B]) + struct.pack("<IH", 1, 0) + bytes(10)
        add("AUTH_REQ G120V2 user-number=0 (invalid, users start at 1)",
            _dll_frame(_tl_byte() + reply_user0))

        # Auth with user number 0xFFFF (max)
        reply_usermax = bytes([0xC0, _FC_AUTH_REQ,
                               120, 2, 0x5B]) + struct.pack("<IH", 1, 0xFFFF) + bytes(10)
        add("AUTH_REQ G120V2 user-number=0xFFFF (max)",
            _dll_frame(_tl_byte() + reply_usermax))

        return cases
