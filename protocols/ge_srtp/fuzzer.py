"""GE SRTP (Service Request Transport Protocol) fuzzer — TCP port 18245.

GE Series 90-30, 90-70, and PACSystems RX3i/RX7i PLCs.
No authentication, no encryption by design.

References:
  Abbasi & Hollick 2017 (DFRWS) — session flow + memory acquisition
  Palatis/packet-ge-srtp (GitHub) — Wireshark Lua dissector (field offsets)
  TheMadHatt3r/ge-ethernet-SRTP (GitHub) — Python PoC
  CVE-2018-8867 / CVE-2019-13524 — PACSystems CWE-20 (same SRTP stack)
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

# ---------------------------------------------------------------------------
# Protocol-specific category names
# ---------------------------------------------------------------------------

CATEGORY_SERVICE_SWEEP  = "service_code_sweep"
CATEGORY_MEM_SWEEP      = "memory_selector_sweep"
CATEGORY_EXTENDED_MSG   = "extended_msg"
CATEGORY_MAILBOX        = "mailbox_abuse"
CATEGORY_DANGEROUS      = "dangerous_services"

# ---------------------------------------------------------------------------
# SRTP packet type constants
# ---------------------------------------------------------------------------

_PKT_INIT      = 0x0000
_PKT_INIT_ACK  = 0x0001
_PKT_REQ       = 0x0002
_PKT_REQ_ACK   = 0x0003

# ---------------------------------------------------------------------------
# Message type constants (offset 30, 1 byte)
# ---------------------------------------------------------------------------

_MSG_SHORT       = 0xC0
_MSG_SHORT_ACK   = 0xD4
_MSG_SHORT_ERR   = 0xD1
_MSG_EXTENDED    = 0x80
_MSG_EXTENDED_ACK = 0x94

# ---------------------------------------------------------------------------
# Service request codes (byte 42 in the 56-byte header)
# ---------------------------------------------------------------------------

SVC_STATUS         = 0x00
SVC_GET_PROGNAME   = 0x03
SVC_READ_SYS_MEM   = 0x04
SVC_READ_TASK_MEM  = 0x05
SVC_READ_PROG_MEM  = 0x06
SVC_WRITE_SYS_MEM  = 0x07
SVC_WRITE_TASK_MEM = 0x08
SVC_WRITE_PROG_MEM = 0x09
SVC_PROG_LOGON     = 0x20
SVC_CHANGE_PRIV    = 0x21
SVC_SET_CPU_ID     = 0x22
SVC_SET_PLC_RUN    = 0x23   # dangerous
SVC_SET_PLC_TIME   = 0x24
SVC_GET_TIME       = 0x25
SVC_GET_FAULT      = 0x38
SVC_CLR_FAULT      = 0x39
SVC_PROG_STORE     = 0x3F   # dangerous
SVC_PROG_LOAD      = 0x40   # dangerous
SVC_GET_INFO       = 0x43
SVC_TOGGLE_FORCE   = 0x44   # dangerous

# Safe read-only service codes (used in boundary/sweep categories)
_SAFE_READ_SVCS = [
    SVC_STATUS, SVC_GET_PROGNAME, SVC_READ_SYS_MEM, SVC_READ_TASK_MEM,
    SVC_READ_PROG_MEM, SVC_GET_TIME, SVC_GET_FAULT, SVC_GET_INFO,
]

# Dangerous codes (only included in CATEGORY_DANGEROUS)
_DANGEROUS_SVCS = [SVC_SET_PLC_RUN, SVC_WRITE_SYS_MEM, SVC_WRITE_TASK_MEM,
                   SVC_WRITE_PROG_MEM, SVC_PROG_STORE, SVC_PROG_LOAD,
                   SVC_TOGGLE_FORCE]

# ---------------------------------------------------------------------------
# Memory segment selector codes (byte 43)
# ---------------------------------------------------------------------------

SEG_R   = 0x08   # Register (word)
SEG_AI  = 0x0A   # Analog Input (word)
SEG_AQ  = 0x0C   # Analog Output (word)
SEG_I   = 0x10   # Discrete Input (byte)
SEG_Q   = 0x12   # Discrete Output (byte)
SEG_T   = 0x14   # Timer (byte)
SEG_M   = 0x16   # Internal (byte)
SEG_SA  = 0x18
SEG_SB  = 0x1A
SEG_SC  = 0x1C
SEG_S   = 0x1E   # Status (byte)
SEG_G   = 0x38   # Genius (byte)

_ALL_SEGS = [SEG_R, SEG_AI, SEG_AQ, SEG_I, SEG_Q, SEG_T, SEG_M,
             SEG_SA, SEG_SB, SEG_SC, SEG_S, SEG_G]

# Default mailbox values observed in normal operation
_MBOX_SRC_DEFAULT = 0x00010000
_MBOX_DST_DEFAULT = 0x000E1000

# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _srtp_header(pkt_type: int = _PKT_REQ,
                 index: int = 1,
                 payload_size: int = 0,
                 msg_seq: int = 1,
                 msg_type: int = _MSG_SHORT,
                 mbox_src: int = _MBOX_SRC_DEFAULT,
                 mbox_dst: int = _MBOX_DST_DEFAULT,
                 pkt_num: int = 1,
                 total_pkt_num: int = 1,
                 svc_req_code: int = SVC_STATUS,
                 seg_selector: int = SEG_R,
                 target_index: int = 0x0001,
                 target_count: int = 1,
                 data: bytes = b'\x00' * 6) -> bytes:
    """Build a 56-byte SRTP header.

    Offsets (0-based) per Palatis Wireshark dissector:
      0-1:  pkt_type (LE)
      2-3:  index (LE)
      4-5:  payload_size (LE)
      6-25: reserved/unknown (20 bytes, zeros)
      26-28: timestamp bytes (HH:MM:SS)
      29:   msg_seq
      30:   msg_type
      31:   pad byte (0x00)
      32-35: mbox_src (LE)
      36-39: mbox_dst (LE)
      40:   pkt_num
      41:   total_pkt_num
      42:   svc_req_code
      43:   seg_selector
      44-45: target_index (LE)
      46-47: target_count (LE)
      48-53: data (6 bytes)
      54-55: padding (2 zeros)
    """
    if len(data) < 6:
        data = data + b'\x00' * (6 - len(data))
    hdr  = struct.pack('<H', pkt_type & 0xFFFF)        # 0-1
    hdr += struct.pack('<H', index & 0xFFFF)            # 2-3
    hdr += struct.pack('<H', payload_size & 0xFFFF)     # 4-5
    hdr += b'\x00' * 20                                # 6-25
    hdr += bytes([0x00, 0x00, 0x00])                   # 26-28 timestamp
    hdr += bytes([msg_seq & 0xFF])                     # 29
    hdr += bytes([msg_type & 0xFF])                    # 30
    hdr += bytes([0x00])                               # 31
    hdr += struct.pack('<I', mbox_src & 0xFFFFFFFF)    # 32-35
    hdr += struct.pack('<I', mbox_dst & 0xFFFFFFFF)    # 36-39
    hdr += bytes([pkt_num & 0xFF])                     # 40
    hdr += bytes([total_pkt_num & 0xFF])               # 41
    hdr += bytes([svc_req_code & 0xFF])                # 42
    hdr += bytes([seg_selector & 0xFF])                # 43
    hdr += struct.pack('<H', target_index & 0xFFFF)    # 44-45
    hdr += struct.pack('<H', target_count & 0xFFFF)    # 46-47
    hdr += data[:6]                                    # 48-53
    hdr += b'\x00\x00'                                 # 54-55
    assert len(hdr) == 56
    return hdr


def _init_pkt() -> bytes:
    """56-byte INIT (all zeros, pkt_type=0x0000)."""
    return b'\x00' * 56


def _recv_srtp_fixed(sock: "socket.socket", n: int) -> Optional[bytes]:
    """Read exactly n bytes from sock. Returns None on timeout or disconnect."""
    buf = b''
    try:
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
    except socket.timeout:
        return None
    return buf


def _read_req(svc: int = SVC_READ_SYS_MEM,
              seg: int = SEG_R,
              index: int = 0x0001,
              count: int = 1,
              seq: int = 1) -> bytes:
    """Build a read service request."""
    return _srtp_header(pkt_type=_PKT_REQ, index=seq, payload_size=0,
                        msg_seq=seq, msg_type=_MSG_SHORT,
                        svc_req_code=svc, seg_selector=seg,
                        target_index=index, target_count=count)


def _write_req(svc: int = SVC_WRITE_SYS_MEM,
               seg: int = SEG_R,
               index: int = 0x0001,
               count: int = 1,
               data: bytes = b'\x00\x00',
               seq: int = 1) -> bytes:
    """Build a write service request."""
    return _srtp_header(pkt_type=_PKT_REQ, index=seq, payload_size=len(data),
                        msg_seq=seq, msg_type=_MSG_SHORT,
                        svc_req_code=svc, seg_selector=seg,
                        target_index=index, target_count=count,
                        data=data)


def _status_req(seq: int = 1) -> bytes:
    """PLC_SHORT_STATUS — safe fingerprint request."""
    return _srtp_header(pkt_type=_PKT_REQ, index=seq, msg_seq=seq,
                        svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                        target_index=0, target_count=0)


def _get_info_req(seq: int = 1) -> bytes:
    """GET_INFO — safe identity request."""
    return _srtp_header(pkt_type=_PKT_REQ, index=seq, msg_seq=seq,
                        svc_req_code=SVC_GET_INFO, seg_selector=SEG_R,
                        target_index=0, target_count=1)


# ---------------------------------------------------------------------------
# GeSrtpFuzzer
# ---------------------------------------------------------------------------

class GeSrtpFuzzer(FuzzModule):
    """GE SRTP fuzzer — TCP port 18245, no authentication required."""

    PROTOCOL_NAME  = "ge_srtp"
    DEFAULT_PORT   = 18245
    FUZZ_CATEGORIES = [
        CATEGORY_BOUNDARY,
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_STATE_MACHINE,
        CATEGORY_SEQUENCE,
        CATEGORY_SERVICE_SWEEP,
        CATEGORY_MEM_SWEEP,
        CATEGORY_EXTENDED_MSG,
        CATEGORY_MAILBOX,
    ]

    _RECV_TIMEOUT    = 3.0
    _CONNECT_TIMEOUT = 5.0

    def __init__(self, target: Device, logger, delay: float = 0.0,
                 seeds=None, dangerous: bool = False):
        super().__init__(target=target, logger=logger, delay=delay, seeds=seeds)
        self._sock: Optional[socket.socket] = None
        self._dangerous = dangerous
        self._seq = 0

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self, target: Optional[Device] = None) -> None:
        t = target or self.target
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self._CONNECT_TIMEOUT)
        self._sock.connect((t.ip, t.port))
        self._sock.settimeout(self._RECV_TIMEOUT)
        self._handshake()
        self._seq = 0

    def _handshake(self) -> None:
        """Send INIT and receive INIT_ACK — required before any REQ."""
        self._sock.sendall(_init_pkt())
        ack = self._recv_fixed(56)
        if not ack or len(ack) < 2:
            raise ConnectionError("SRTP handshake failed: no INIT_ACK received")
        pkt_type = struct.unpack_from('<H', ack, 0)[0]
        if pkt_type != _PKT_INIT_ACK:
            raise ConnectionError(f"SRTP handshake: expected INIT_ACK (0x0001), got 0x{pkt_type:04X}")

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

    def _recv_fixed(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes, return None on timeout/EOF."""
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
        """Read one SRTP response using header framing: 56-byte header + payload_size bytes."""
        hdr = self._recv_fixed(56)
        if not hdr or len(hdr) < 6:
            return hdr   # let caller treat as short/timeout
        payload_size = struct.unpack_from('<H', hdr, 4)[0]
        if payload_size == 0:
            return hdr
        extra = self._recv_fixed(payload_size)
        if extra is None:
            return hdr   # header only — caller still classifies
        return hdr + extra

    def discover(self, interface: str, timeout: int = 30) -> list:
        raise NotImplementedError("GE SRTP discovery requires scapy + CAP_NET_RAW.")

    def fingerprint(self, active: bool = True) -> "FingerprintResult":
        """GE SRTP fingerprint.

        Passive: OUI lookup from ARP cache.
        Active:  INIT handshake + GET_PROGNAME request (service 0x03).
                 The response payload contains the PLC program name, which
                 typically reveals the GE model and firmware version.
        """
        from core.fingerprint import FingerprintResult, fingerprint_from_oui

        oui_result = fingerprint_from_oui(self.target.ip)
        if not active:
            return oui_result

        model    = "unknown"
        firmware = "unknown"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(4.0)
            s.connect((self.target.ip, self.target.port))
            s.sendall(_init_pkt())
            ack = _recv_srtp_fixed(s, 56)
            if not ack or len(ack) < 2:
                return oui_result
            pkt_type = struct.unpack_from('<H', ack, 0)[0]
            if pkt_type != _PKT_INIT_ACK:
                return oui_result
            req = _read_req(svc=SVC_GET_PROGNAME, seg=SEG_R, index=0, count=1, seq=1)
            s.sendall(req)
            hdr = _recv_srtp_fixed(s, 56)
            if hdr and len(hdr) >= 56:
                payload_size = struct.unpack_from('<H', hdr, 4)[0]
                if 0 < payload_size <= 512:
                    payload = _recv_srtp_fixed(s, payload_size)
                    if payload:
                        raw = payload.rstrip(b'\x00')
                        model = raw.decode("ascii", errors="replace").strip() or "unknown"
        except OSError:
            return oui_result
        finally:
            s.close()

        vendor = oui_result.vendor if oui_result.is_known() else "GE Automation"
        confidence = "medium" if model != "unknown" else "low"
        return FingerprintResult(
            vendor=vendor,
            model=model,
            firmware=firmware,
            confidence=confidence,
            method="ge_srtp_get_progname",
            extra={"oui_vendor": oui_result.vendor} if oui_result.is_known() else {},
        )

    def replay_payload(self, payload: bytes) -> Optional[bytes]:
        if self._sock is None:
            raise RuntimeError("call connect() before replay_payload()")
        self._sock.sendall(payload)
        return self._recv_response()

    # ------------------------------------------------------------------
    # generate_cases
    # ------------------------------------------------------------------

    def generate_cases(self, categories=None):
        # Separate dangerous from the normal list so _resolve_categories doesn't drop it.
        want_dangerous = (categories is not None and CATEGORY_DANGEROUS in categories)
        normal_cats    = [c for c in (categories or []) if c != CATEGORY_DANGEROUS] \
                         if categories is not None else None
        cats  = self._resolve_categories(normal_cats)
        if want_dangerous and self._dangerous:
            cats = cats + [CATEGORY_DANGEROUS]
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
            elif cat == CATEGORY_MEM_SWEEP:
                cases.extend(self._gen_mem_sweep())
            elif cat == CATEGORY_EXTENDED_MSG:
                cases.extend(self._gen_extended_msg())
            elif cat == CATEGORY_MAILBOX:
                cases.extend(self._gen_mailbox())
            elif cat == CATEGORY_DANGEROUS:
                if self._dangerous:
                    cases.extend(self._gen_dangerous())
        return cases

    def _case(self, cat, desc, payload):
        return (self._next_id(), cat, desc, payload)

    # ------------------------------------------------------------------
    # Category generators
    # ------------------------------------------------------------------

    def _gen_boundary(self):
        C = CATEGORY_BOUNDARY
        cases = []

        # Status and info reads
        cases.append(self._case(C, "PLC_SHORT_STATUS (normal fingerprint)",
                                _status_req(1)))
        cases.append(self._case(C, "GET_INFO (identity fingerprint)",
                                _get_info_req(2)))
        cases.append(self._case(C, "GET_TIME", _read_req(SVC_GET_TIME, SEG_R, 0, 1, 3)))
        cases.append(self._case(C, "GET_FAULT", _read_req(SVC_GET_FAULT, SEG_R, 0, 1, 4)))
        cases.append(self._case(C, "GET_PROGNAME", _read_req(SVC_GET_PROGNAME, SEG_R, 0, 1, 5)))

        # READ_SYS_MEM — all documented memory types
        for i, (seg, name) in enumerate([
            (SEG_R, "%R Register"), (SEG_AI, "%AI Analog Input"),
            (SEG_AQ, "%AQ Analog Output"), (SEG_I, "%I Discrete Input"),
            (SEG_Q, "%Q Discrete Output"), (SEG_T, "%T Timer"),
            (SEG_M, "%M Internal"), (SEG_S, "%S Status"), (SEG_G, "%G Genius"),
        ], start=10):
            cases.append(self._case(C, f"READ_SYS_MEM {name} index=1 count=1",
                                    _read_req(SVC_READ_SYS_MEM, seg, 1, 1, i)))

        # target_index boundary values
        for idx, label in [(0, "index=0 (before-start)"),
                           (0xFFFF, "index=0xFFFF (max)"),
                           (32767, "index=32767 (mid-range)")]:
            cases.append(self._case(C, f"READ_SYS_MEM %R {label}",
                                    _read_req(SVC_READ_SYS_MEM, SEG_R, idx, 1, len(cases)+10)))

        # target_count boundary values
        for cnt, label in [(0, "count=0"),
                           (1, "count=1 (normal)"),
                           (0xFFFF, "count=0xFFFF (max)")]:
            cases.append(self._case(C, f"READ_SYS_MEM %R index=1 {label}",
                                    _read_req(SVC_READ_SYS_MEM, SEG_R, 1, cnt, len(cases)+10)))

        # READ_TASK_MEM and READ_PROG_MEM
        cases.append(self._case(C, "READ_TASK_MEM %R index=1 count=1",
                                _read_req(SVC_READ_TASK_MEM, SEG_R, 1, 1, 40)))
        cases.append(self._case(C, "READ_PROG_MEM %R index=1 count=1",
                                _read_req(SVC_READ_PROG_MEM, SEG_R, 1, 1, 41)))

        # Sequence counter extremes
        cases.append(self._case(C, "Status req msg_seq=0 (min)",
                                _srtp_header(pkt_type=_PKT_REQ, msg_seq=0, msg_type=_MSG_SHORT,
                                             svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                                             target_index=0, target_count=0)))
        cases.append(self._case(C, "Status req msg_seq=255 (max)",
                                _srtp_header(pkt_type=_PKT_REQ, msg_seq=255, msg_type=_MSG_SHORT,
                                             svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                                             target_index=0, target_count=0)))

        # payload_size field boundary values
        cases.append(self._case(C, "REQ payload_size=0 (read, normal)",
                                _srtp_header(pkt_type=_PKT_REQ, payload_size=0,
                                             svc_req_code=SVC_READ_SYS_MEM, seg_selector=SEG_R,
                                             target_index=1, target_count=1)))
        cases.append(self._case(C, "REQ payload_size=0xFFFF (claims huge payload)",
                                _srtp_header(pkt_type=_PKT_REQ, payload_size=0xFFFF,
                                             svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                                             target_index=0, target_count=0)))

        return cases

    def _gen_binary_corruption(self):
        C = CATEGORY_BINARY_CORRUPTION
        cases = []

        # Empty and near-empty
        cases.append(self._case(C, "Empty payload (0 bytes)", b''))
        cases.append(self._case(C, "1 byte 0x00", b'\x00'))
        cases.append(self._case(C, "4 bytes 0x02 0x00 0x00 0x00 (pkt_type=REQ, truncated)",
                                bytes([0x02, 0x00, 0x00, 0x00])))

        # All-zero
        cases.append(self._case(C, "56 zero bytes (all zeros, looks like INIT)", b'\x00' * 56))
        cases.append(self._case(C, "All-zero 57 bytes (INIT + 1)", b'\x00' * 57))

        # All-0xFF
        cases.append(self._case(C, "56 bytes all-0xFF", b'\xFF' * 56))

        # Wrong pkt_type in REQ
        base = _status_req(1)
        for pt, label in [(0xFFFF, "0xFFFF"), (0x0004, "0x0004"), (0x0100, "0x0100")]:
            payload = struct.pack('<H', pt) + base[2:]
            cases.append(self._case(C, f"REQ pkt_type={label} (invalid)",
                                    payload))

        # Truncated at each byte position (0 to 55)
        base = _status_req(1)
        for i in range(1, 56):
            cases.append(self._case(C, f"Status REQ truncated at byte {i}/56",
                                    base[:i]))

        # Single-bit flips at key offsets
        for byte_pos in (0, 1, 30, 32, 36, 40, 42, 43, 44, 46):
            flip = bytearray(_status_req(1))
            flip[byte_pos] ^= 0x01
            cases.append(self._case(C, f"Status REQ bit-flip at offset {byte_pos}",
                                    bytes(flip)))

        # Random-ish patterns
        cases.append(self._case(C, "Random 56 bytes", bytes(range(56))))
        cases.append(self._case(C, "Alternating 0xAA/0x55 56 bytes",
                                bytes([0xAA if i % 2 == 0 else 0x55 for i in range(56)])))

        return cases

    def _gen_state_machine(self):
        C = CATEGORY_STATE_MACHINE
        cases = []

        # These are sent as the raw payload; the fuzzer sends them after the normal INIT handshake.
        # The goal is to test how the PLC handles out-of-order session protocol messages.

        # Second INIT on established session (duplicate handshake)
        cases.append(self._case(C, "Second INIT on established session", _init_pkt()))

        # INIT_ACK sent from client (wrong direction)
        ack = _srtp_header(pkt_type=_PKT_INIT_ACK, svc_req_code=SVC_STATUS,
                           seg_selector=SEG_R, target_index=0, target_count=0)
        cases.append(self._case(C, "INIT_ACK sent from client (wrong direction)", ack))

        # REQ_ACK sent from client
        ra = _srtp_header(pkt_type=_PKT_REQ_ACK, svc_req_code=SVC_STATUS,
                          seg_selector=SEG_R, target_index=0, target_count=0)
        cases.append(self._case(C, "REQ_ACK sent from client (wrong direction)", ra))

        # Unknown pkt_type 0x0004–0x000F
        for pt in (0x0004, 0x0005, 0x000F, 0x00FF, 0xFFFF):
            payload = _srtp_header(pkt_type=pt, svc_req_code=SVC_STATUS,
                                   seg_selector=SEG_R, target_index=0, target_count=0)
            cases.append(self._case(C, f"REQ with unknown pkt_type=0x{pt:04X}", payload))

        # msg_type = EXTENDED (0x80) on a normal 56-byte body
        ext = _srtp_header(pkt_type=_PKT_REQ, msg_type=_MSG_EXTENDED,
                           svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                           target_index=0, target_count=0)
        cases.append(self._case(C, "msg_type=EXTENDED (0x80) with no extended body", ext))

        # PROG_LOGON (non-destructive session management)
        cases.append(self._case(C, "PROG_LOGON (session management)",
                                _read_req(SVC_PROG_LOGON, SEG_R, 0, 0, 1)))
        cases.append(self._case(C, "CHANGE_PRIV (privilege management)",
                                _read_req(SVC_CHANGE_PRIV, SEG_R, 0, 0, 2)))

        # CLR_FAULT (fault log clearing — medium risk, included in state_machine)
        cases.append(self._case(C, "CLR_FAULT (clear PLC fault log)",
                                _read_req(SVC_CLR_FAULT, SEG_R, 0, 0, 3)))

        # SET_PLC_TIME (set clock to zero)
        cases.append(self._case(C, "SET_PLC_TIME to 00:00:00",
                                _write_req(SVC_SET_PLC_TIME, SEG_R, 0, 0, b'\x00\x00\x00', 4)))

        # SET_CPU_ID
        cases.append(self._case(C, "SET_CPU_ID (station ID = 0x0000)",
                                _write_req(SVC_SET_CPU_ID, SEG_R, 0, 0, b'\x00\x00', 5)))

        # Large msg_seq wrap-around
        for seq in (0x00, 0x7F, 0x80, 0xFE, 0xFF):
            pkt = _srtp_header(pkt_type=_PKT_REQ, msg_seq=seq, msg_type=_MSG_SHORT,
                               svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                               target_index=0, target_count=0)
            cases.append(self._case(C, f"Status REQ msg_seq=0x{seq:02X}",
                                    pkt))

        return cases

    def _gen_sequence(self):
        C = CATEGORY_SEQUENCE
        cases = []
        seq = 1

        # Rapid repeated status requests
        for _ in range(5):
            cases.append(self._case(C, f"Rapid status req #{seq}",
                                    _status_req(seq)))
            seq += 1

        # Interleave reads of different memory types
        for seg, name in [(SEG_R, "R"), (SEG_I, "I"), (SEG_Q, "Q"), (SEG_AI, "AI")]:
            cases.append(self._case(C, f"READ_SYS_MEM %{name} seq={seq}",
                                    _read_req(SVC_READ_SYS_MEM, seg, 1, 1, seq)))
            seq += 1

        # Read after read of same register
        for _ in range(3):
            cases.append(self._case(C, f"READ %R[1] repeated #{seq}",
                                    _read_req(SVC_READ_SYS_MEM, SEG_R, 1, 1, seq)))
            seq += 1

        # Index counter cycling (0→0xFFFF→0)
        for idx in (0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF):
            cases.append(self._case(C, f"READ %R index=0x{idx:04X}",
                                    _read_req(SVC_READ_SYS_MEM, SEG_R, idx, 1, seq)))
            seq += 1

        # pkt index counter cycling
        for pidx in (0x0000, 0x0001, 0xFFFF):
            pkt = _srtp_header(pkt_type=_PKT_REQ, index=pidx, msg_seq=seq % 256,
                               svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                               target_index=0, target_count=0)
            cases.append(self._case(C, f"Status REQ pkt_index=0x{pidx:04X}", pkt))
            seq += 1

        return cases

    def _gen_service_sweep(self):
        C = CATEGORY_SERVICE_SWEEP
        cases = []

        # Documented read codes with all documented memory types
        for svc in _SAFE_READ_SVCS:
            for seg in _ALL_SEGS:
                cases.append(self._case(C, f"svc=0x{svc:02X} seg=0x{seg:02X} (documented read)",
                                        _read_req(svc, seg, 1, 1, 1)))

        # Undocumented service codes (the gaps — most likely to trigger CWE-20)
        documented = set([
            SVC_STATUS, SVC_GET_PROGNAME, SVC_READ_SYS_MEM, SVC_READ_TASK_MEM,
            SVC_READ_PROG_MEM, SVC_WRITE_SYS_MEM, SVC_WRITE_TASK_MEM, SVC_WRITE_PROG_MEM,
            SVC_PROG_LOGON, SVC_CHANGE_PRIV, SVC_SET_CPU_ID, SVC_SET_PLC_RUN,
            SVC_SET_PLC_TIME, SVC_GET_TIME, SVC_GET_FAULT, SVC_CLR_FAULT,
            SVC_PROG_STORE, SVC_PROG_LOAD, SVC_GET_INFO, SVC_TOGGLE_FORCE,
        ])
        for code in range(0x00, 0x50):
            if code not in documented:
                cases.append(self._case(C, f"svc=0x{code:02X} (UNDOCUMENTED) seg=R",
                                        _read_req(code, SEG_R, 1, 1, 1)))

        # Sweep 0x50–0xFF in larger steps (less likely to be populated)
        for code in range(0x50, 0x100, 8):
            cases.append(self._case(C, f"svc=0x{code:02X} (high-range undocumented) seg=R",
                                    _read_req(code, SEG_R, 1, 1, 1)))

        return cases

    def _gen_mem_sweep(self):
        C = CATEGORY_MEM_SWEEP
        cases = []

        # All byte values 0x00–0xFF as seg_selector with safe read service
        for seg in range(0x00, 0x100):
            label = "documented" if seg in _ALL_SEGS else "UNDOCUMENTED"
            cases.append(self._case(C, f"READ_SYS_MEM seg=0x{seg:02X} ({label})",
                                    _read_req(SVC_READ_SYS_MEM, seg, 1, 1, 1)))

        return cases

    def _gen_extended_msg(self):
        C = CATEGORY_EXTENDED_MSG
        cases = []

        # msg_type = EXTENDED (0x80) without multi-packet body
        cases.append(self._case(C, "EXTENDED msg (0x80) pkt_num=1 total=1",
                                _srtp_header(pkt_type=_PKT_REQ, msg_type=_MSG_EXTENDED,
                                             pkt_num=1, total_pkt_num=1,
                                             svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                                             target_index=0, target_count=0)))

        # pkt_num > total_pkt_num
        cases.append(self._case(C, "EXTENDED pkt_num=3 total=1 (pkt_num > total)",
                                _srtp_header(pkt_type=_PKT_REQ, msg_type=_MSG_EXTENDED,
                                             pkt_num=3, total_pkt_num=1,
                                             svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                                             target_index=0, target_count=0)))

        # pkt_num = 0
        cases.append(self._case(C, "EXTENDED pkt_num=0 total=1 (zero-based ambiguity)",
                                _srtp_header(pkt_type=_PKT_REQ, msg_type=_MSG_EXTENDED,
                                             pkt_num=0, total_pkt_num=1,
                                             svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                                             target_index=0, target_count=0)))

        # total_pkt_num = 0
        cases.append(self._case(C, "EXTENDED total=0 (no packets claimed)",
                                _srtp_header(pkt_type=_PKT_REQ, msg_type=_MSG_EXTENDED,
                                             pkt_num=1, total_pkt_num=0,
                                             svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                                             target_index=0, target_count=0)))

        # Large multi-packet claim
        for total in (2, 5, 0x7F, 0xFF):
            cases.append(self._case(C, f"EXTENDED pkt_num=1 total={total} (multi-packet claim)",
                                    _srtp_header(pkt_type=_PKT_REQ, msg_type=_MSG_EXTENDED,
                                                 pkt_num=1, total_pkt_num=total,
                                                 svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                                                 target_index=0, target_count=0)))

        # EXTENDED_ACK sent from client (wrong direction)
        cases.append(self._case(C, "EXTENDED_ACK (0x94) msg_type sent as request",
                                _srtp_header(pkt_type=_PKT_REQ, msg_type=_MSG_EXTENDED_ACK,
                                             pkt_num=1, total_pkt_num=1,
                                             svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                                             target_index=0, target_count=0)))

        # Unknown msg_type values
        for mt in (0x00, 0x01, 0xA0, 0xB0, 0xFF):
            cases.append(self._case(C, f"msg_type=0x{mt:02X} (unknown value)",
                                    _srtp_header(pkt_type=_PKT_REQ, msg_type=mt,
                                                 svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                                                 target_index=0, target_count=0)))

        return cases

    def _gen_mailbox(self):
        C = CATEGORY_MAILBOX
        cases = []

        # mbox_dst variants (normal is 0x000E1000)
        for dst, label in [
            (0x00000000, "zero"),
            (0xFFFFFFFF, "all-ones"),
            (0x000E1001, "normal+1"),
            (0x000E0FFF, "normal-1"),
            (0x00010000, "mbox_src value"),
            (0x00000001, "minimal"),
            (0xDEADBEEF, "garbage"),
        ]:
            pkt = _srtp_header(pkt_type=_PKT_REQ, mbox_dst=dst,
                               svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                               target_index=0, target_count=0)
            cases.append(self._case(C, f"mbox_dst=0x{dst:08X} ({label})", pkt))

        # mbox_src variants (normal is 0x00010000)
        for src, label in [
            (0x00000000, "zero"),
            (0xFFFFFFFF, "all-ones"),
            (0x00010001, "normal+1"),
            (0x00020000, "doubled"),
            (0xDEADBEEF, "garbage"),
        ]:
            pkt = _srtp_header(pkt_type=_PKT_REQ, mbox_src=src,
                               svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                               target_index=0, target_count=0)
            cases.append(self._case(C, f"mbox_src=0x{src:08X} ({label})", pkt))

        # mbox_src == mbox_dst
        pkt = _srtp_header(pkt_type=_PKT_REQ, mbox_src=_MBOX_DST_DEFAULT,
                           mbox_dst=_MBOX_DST_DEFAULT,
                           svc_req_code=SVC_STATUS, seg_selector=SEG_R,
                           target_index=0, target_count=0)
        cases.append(self._case(C, "mbox_src == mbox_dst (routing loop?)", pkt))

        return cases

    def _gen_dangerous(self):
        """Only included when --enable-dangerous is set. Do NOT include in default FUZZ_CATEGORIES."""
        C = CATEGORY_DANGEROUS
        cases = []

        # SET_PLC_RUN — halt the PLC (data=0x01=stop; data=0x00=run)
        cases.append(self._case(C, "SET_PLC_RUN stop (0x01) — HALTS PLC",
                                _write_req(SVC_SET_PLC_RUN, SEG_R, 0, 1,
                                           b'\x01\x00', 1)))
        cases.append(self._case(C, "SET_PLC_RUN run (0x00) — STARTS PLC",
                                _write_req(SVC_SET_PLC_RUN, SEG_R, 0, 1,
                                           b'\x00\x00', 2)))

        # WRITE_SYS_MEM — write to first register (may affect I/O)
        cases.append(self._case(C, "WRITE_SYS_MEM %R[1]=0x0000 (zero register 1)",
                                _write_req(SVC_WRITE_SYS_MEM, SEG_R, 1, 1,
                                           b'\x00\x00', 3)))
        cases.append(self._case(C, "WRITE_SYS_MEM %R[1]=0xFFFF (max register 1)",
                                _write_req(SVC_WRITE_SYS_MEM, SEG_R, 1, 1,
                                           b'\xFF\xFF', 4)))
        cases.append(self._case(C, "WRITE_SYS_MEM %R[0xFFFF]=0xAAAA (boundary address)",
                                _write_req(SVC_WRITE_SYS_MEM, SEG_R, 0xFFFF, 1,
                                           b'\xAA\xAA', 5)))

        # TOGGLE_FORCE_SYS_MEM — force I/O bits
        cases.append(self._case(C, "TOGGLE_FORCE_SYS_MEM %Q[1] (discrete output force)",
                                _write_req(SVC_TOGGLE_FORCE, SEG_Q, 1, 1,
                                           b'\xFF\x00', 6)))

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
            print(f"\r[ge_srtp] {i}/{total}  {case_id}  {desc[:55]}", end="", flush=True)
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
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            result.anomaly         = ANOMALY_CONNECTION_RESET
            result.crash_indicator = True
            result.duration_ms     = (time.monotonic() - t0) * 1000
            self._reconnect()
        return result

    def _classify_response(self, data: bytes, result: FuzzResult) -> None:
        if len(data) < 4:
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        pkt_type = struct.unpack_from('<H', data, 0)[0]
        if pkt_type != _PKT_REQ_ACK:
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        if len(data) < 56:
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        msg_type = data[30]

        if msg_type == _MSG_SHORT_ERR:
            result.anomaly         = ANOMALY_EXCEPTION
            result.crash_indicator = False
            return

        if msg_type not in (_MSG_SHORT_ACK, _MSG_EXTENDED_ACK):
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        # Check payload_size field: non-zero on expected read = data attached
        # Non-zero on status where no data expected is anomalous
        # For now: any valid SHORT_ACK/EXTENDED_ACK = no anomaly
