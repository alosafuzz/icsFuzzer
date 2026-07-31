"""PROFINET DCP and PNIO-CM fuzzer — Ethernet EtherType 0x8892 + UDP port 34964.

DCP (Discovery and Configuration Protocol): Ethernet-layer only.
PNIO-CM (Context Manager): DCE/RPC over UDP port 34964.

DCP cases generate frame bytes regardless. Network send requires scapy/CAP_NET_RAW;
without it, DCP cases skip the send and return anomaly=None, crash=False.

References:
  IEC 61158-6-10 (PROFINET IO v2.3 specification)
  Wireshark: packet-pn-dcp.c, packet-pn-rpc.c, packet-dcerpc-pn-io.c
  p-net (proplexing/p-net): open-source PROFINET IO device stack in C
"""

import socket
import struct
import time
from typing import Optional

from core.base_module import (
    ANOMALY_CONNECTION_RESET,
    ANOMALY_EXCEPTION,
    ANOMALY_MALFORMED_RESPONSE,
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

try:
    import scapy.all as _scapy  # noqa: F401
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False

# ---------------------------------------------------------------------------
# Protocol-specific categories
# ---------------------------------------------------------------------------

CATEGORY_DCP_DISCOVERY     = "dcp_discovery"
CATEGORY_DCP_CONFIGURATION = "dcp_configuration"
CATEGORY_PNIO_CONNECT      = "pnio_connect"
CATEGORY_RECORD_RW         = "record_rw"

# ---------------------------------------------------------------------------
# DCE/RPC constants
# ---------------------------------------------------------------------------

_PTYPE_REQUEST  = 0x0B
_PTYPE_RESPONSE = 0x0C
_PTYPE_BIND     = 0x0F
_PTYPE_BIND_ACK = 0x10
_PTYPE_FAULT    = 0x13
_PFC_FLAGS      = 0x03   # first + last fragment

# PNIO-CM interface UUID: DEC401D0-A91B-11D0-96E1-00A024517A00 (LE)
_PNIO_CM_UUID = bytes([
    0xD0, 0x01, 0xC4, 0xDE,
    0x1B, 0xA9,
    0xD0, 0x11,
    0x96, 0xE1,
    0x00, 0xA0, 0x24, 0x51, 0x7A, 0x00,
])

# NDR transfer syntax: 8A885D04-1CEB-11C9-9FE8-08002B104860 (LE)
_NDR_UUID = bytes([
    0x04, 0x5D, 0x88, 0x8A,
    0xEB, 0x1C,
    0xC9, 0x11,
    0x9F, 0xE8,
    0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
])

_BAD_UUID = bytes(16)   # all-zeros UUID for rejection tests

# PNIO-CM operations
_OP_CONNECT = 0x0000
_OP_RELEASE = 0x0001
_OP_READ    = 0x0002
_OP_WRITE   = 0x0003
_OP_CONTROL = 0x0004

# DCP FrameIDs (big-endian in wire)
_DCP_FRAME_IDENTIFY = 0xFEFC
_DCP_FRAME_HELLO    = 0xFEFD
_DCP_FRAME_GET_SET  = 0xFEFF

# DCP ServiceIDs
_DCP_SVC_GET      = 0x03
_DCP_SVC_SET      = 0x04
_DCP_SVC_IDENTIFY = 0x05

# Fixed AR UUID for test cases
_TEST_AR_UUID = bytes([
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
])

_INITIATOR_MAC = bytes([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])


# ---------------------------------------------------------------------------
# DCE/RPC frame builders
# ---------------------------------------------------------------------------

def _rpc_header(ptype: int, call_id: int, frag_len: int) -> bytes:
    """Build 16-byte DCE/RPC header (little-endian data representation)."""
    h  = bytes([0x04, 0x00])                 # version, minor
    h += bytes([ptype & 0xFF, _PFC_FLAGS])    # ptype, pfc_flags
    h += bytes([0x10, 0x00, 0x00, 0x00])     # data_repr = LE/IEEE/ASCII
    h += struct.pack('<H', frag_len & 0xFFFF) # frag_len
    h += struct.pack('<H', 0)                 # auth_len
    h += struct.pack('<I', call_id & 0xFFFFFFFF)  # call_id
    return h


def _rpc_bind(call_id: int = 1, uuid: bytes = _PNIO_CM_UUID) -> bytes:
    """Build 72-byte DCE/RPC Bind PDU for PNIO-CM interface."""
    body  = struct.pack('<HH', 5840, 5840)   # max_xmit_frag, max_recv_frag
    body += struct.pack('<I', 0)              # assoc_group_id
    body += bytes([1, 0, 0, 0])              # num_context_items=1, reserved(3)
    body += struct.pack('<HH', 0, 1)         # context_id=0, num_transfer_syntaxes=1
    body += uuid                              # interface UUID (16B)
    body += struct.pack('<HH', 1, 0)         # if_version = 1.0
    body += _NDR_UUID                         # transfer syntax UUID (16B)
    body += struct.pack('<HH', 2, 0)         # syntax_version = 2.0
    return _rpc_header(_PTYPE_BIND, call_id, 16 + len(body)) + body


def _rpc_request(op: int, payload: bytes, call_id: int, ctx_id: int = 0) -> bytes:
    """Build DCE/RPC Request PDU (PTYPE=0x0B)."""
    body  = struct.pack('<I', len(payload))   # alloc_hint
    body += struct.pack('<HH', ctx_id, op)    # context_id, op_num
    body += payload
    return _rpc_header(_PTYPE_REQUEST, call_id, 16 + len(body)) + body


def _split_pdus(data: bytes) -> list:
    """Split concatenated RPC PDUs into individual datagrams using frag_len.

    Falls back to sending remaining bytes as one datagram if frag_len is invalid.
    """
    pdus = []
    pos  = 0
    while pos < len(data):
        if pos + 10 > len(data):
            pdus.append(data[pos:])
            break
        frag_len = struct.unpack_from('<H', data, pos + 8)[0]
        end = pos + frag_len
        if frag_len < 16 or end > len(data):
            pdus.append(data[pos:])
            break
        pdus.append(data[pos:end])
        pos = end
    return pdus or [data]


# ---------------------------------------------------------------------------
# PNIO-CM payload builders
# ---------------------------------------------------------------------------

def _pnio_connect(ar_type: int = 0x0001,
                  ar_uuid: bytes = _TEST_AR_UUID,
                  session_key: int = 1,
                  station_name: bytes = b"icsfuzzer",
                  properties: int = 0x00000000) -> bytes:
    """Build minimal PNIO-CM Connect AR Block."""
    name_len = len(station_name)
    ar_data  = struct.pack('!H', ar_type)          # ARType
    ar_data += ar_uuid                              # ARUUID (16B)
    ar_data += struct.pack('!H', session_key)       # SessionKey
    ar_data += _INITIATOR_MAC                       # CMInitiatorMACAdd (6B)
    ar_data += _TEST_AR_UUID                        # CMInitiatorObjectUUID (16B)
    ar_data += struct.pack('!I', properties)        # ARProperties
    ar_data += struct.pack('!H', 0x00C8)            # CMInitiatorActivityTimeoutFactor
    ar_data += struct.pack('!H', 0x8892)            # CMInitiatorUDPRTPort
    ar_data += struct.pack('!H', name_len)          # StationNameLength
    ar_data += station_name
    block_hdr = struct.pack('!HH', 0x0101, 2 + len(ar_data))  # BlockType, BlockLength
    block_hdr += bytes([0x01, 0x00])                # VersionHigh, VersionLow
    return block_hdr + ar_data


def _pnio_read(slot: int = 0, subslot: int = 1,
               api: int = 0, index: int = 0xF000) -> bytes:
    """Build PNIO-CM RecordRead Request block."""
    b  = struct.pack('!HH', 0x0027, 0x0038)  # BlockType=RecordRead, BlockLength=56
    b += bytes([0x01, 0x00])                  # Version 1.0
    b += struct.pack('!H', 0)                 # SeqNum
    b += _TEST_AR_UUID                         # ARUUID (16B)
    b += struct.pack('!I', api)               # API
    b += struct.pack('!HH', slot, subslot)    # Slot, Subslot
    b += struct.pack('!H', 0)                 # Padding
    b += struct.pack('!H', index)             # Index
    b += struct.pack('!I', 0x1000)            # RecordDataLength (max)
    b += bytes(16)                             # TargetARUUID flag + reserved
    return b


def _pnio_write(slot: int = 0, subslot: int = 1,
                api: int = 0, index: int = 0xF000,
                data: bytes = b'\x00\x00') -> bytes:
    """Build PNIO-CM RecordWrite Request block."""
    dlen = len(data)
    block_len = min(0x003A + dlen, 0xFFFF)
    b  = struct.pack('!HH', 0x0008, block_len)  # BlockType=RecordWrite, BlockLength
    b += bytes([0x01, 0x00])
    b += struct.pack('!H', 0)
    b += _TEST_AR_UUID
    b += struct.pack('!I', api)
    b += struct.pack('!HH', slot, subslot)
    b += struct.pack('!H', 0)
    b += struct.pack('!H', index)
    b += struct.pack('!I', dlen)             # RecordDataLength
    b += bytes(16)
    b += data
    return b


# ---------------------------------------------------------------------------
# DCP frame builders (Ethernet-layer, EtherType 0x8892)
# ---------------------------------------------------------------------------

def _dcp_block(option: int, suboption: int, data: bytes) -> bytes:
    """Build one DCP TLV block with word-alignment padding."""
    b  = bytes([option & 0xFF, suboption & 0xFF])
    b += struct.pack('!H', len(data))
    b += data
    if len(data) % 2:
        b += b'\x00'
    return b


def _dcp_frame(frame_id: int = _DCP_FRAME_IDENTIFY,
               svc_id: int = _DCP_SVC_IDENTIFY,
               svc_type: int = 0x00,
               xid: int = 1,
               response_delay: int = 0x01F4,
               blocks: bytes = b'') -> bytes:
    """Build DCP frame payload (FrameID onwards, no Ethernet header).

    Returned bytes are stored in FuzzResult.payload. Network send requires
    a raw socket (scapy). Without scapy, _send_case skips the send.
    """
    f  = struct.pack('!H', frame_id & 0xFFFF)
    f += bytes([svc_id & 0xFF, svc_type & 0xFF])
    f += struct.pack('!I', xid & 0xFFFFFFFF)
    f += struct.pack('!H', response_delay & 0xFFFF)
    f += struct.pack('!H', len(blocks))
    f += blocks
    return f


# ---------------------------------------------------------------------------
# ProfinetFuzzer
# ---------------------------------------------------------------------------

class ProfinetFuzzer(FuzzModule):
    """PROFINET fuzzer — DCP (EtherType 0x8892) + PNIO-CM (DCE/RPC UDP port 34964)."""

    PROTOCOL_NAME   = "profinet"
    DEFAULT_PORT    = 34964
    FUZZ_CATEGORIES = [
        CATEGORY_BOUNDARY,
        CATEGORY_BINARY_CORRUPTION,
        CATEGORY_STATE_MACHINE,
        CATEGORY_SEQUENCE,
        CATEGORY_DCP_DISCOVERY,
        CATEGORY_DCP_CONFIGURATION,
        CATEGORY_PNIO_CONNECT,
        CATEGORY_RECORD_RW,
    ]

    _RECV_TIMEOUT    = 3.0
    _CONNECT_TIMEOUT = 5.0
    _DCP_CATS        = frozenset([CATEGORY_DCP_DISCOVERY, CATEGORY_DCP_CONFIGURATION])

    def __init__(self, target: Device, logger, delay: float = 0.0, seeds=None):
        super().__init__(target=target, logger=logger, delay=delay, seeds=seeds)
        self._sock: Optional[socket.socket] = None
        self._remote: tuple                 = ("", 0)
        self._call_id: int                  = 0

    def _cid(self) -> int:
        self._call_id = (self._call_id + 1) & 0xFFFFFFFF
        return self._call_id

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self, target: Optional[Device] = None) -> None:
        t = target or self.target
        self._sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(self._RECV_TIMEOUT)
        self._remote = (t.ip, t.port)

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def discover(self, interface: str, timeout: int = 30) -> list:
        raise NotImplementedError(
            "PROFINET discovery requires scapy + CAP_NET_RAW for DCP Identify multicast."
        )

    def _recv_response(self) -> Optional[bytes]:
        try:
            data, _ = self._sock.recvfrom(65535)
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
            elif cat == CATEGORY_STATE_MACHINE:
                cases.extend(self._gen_state_machine())
            elif cat == CATEGORY_SEQUENCE:
                cases.extend(self._gen_sequence())
            elif cat == CATEGORY_DCP_DISCOVERY:
                cases.extend(self._gen_dcp_discovery())
            elif cat == CATEGORY_DCP_CONFIGURATION:
                cases.extend(self._gen_dcp_configuration())
            elif cat == CATEGORY_PNIO_CONNECT:
                cases.extend(self._gen_pnio_connect())
            elif cat == CATEGORY_RECORD_RW:
                cases.extend(self._gen_record_rw())
        return cases

    def _case(self, cat, desc, payload):
        return (self._next_id(), cat, desc, payload)

    # ------------------------------------------------------------------
    # Category: boundary
    # ------------------------------------------------------------------

    def _gen_boundary(self):
        C = CATEGORY_BOUNDARY
        cases = []
        c = self._cid

        cid = c()
        cases.append(self._case(C, "RPC Bind correct PNIO-CM UUID", _rpc_bind(cid)))

        cid = c()
        cases.append(self._case(C, "RPC Bind only (no request follows)",
                                 _rpc_bind(cid)))

        cid = c()
        cases.append(self._case(C, "RPC Read I&M0 (index 0xF000)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_READ, _pnio_read(index=0xF000), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Read I&M1 (index 0xF001)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_READ, _pnio_read(index=0xF001), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Read I&M4 (index 0xF004)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_READ, _pnio_read(index=0xF004), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Read system log (index 0xF020)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_READ, _pnio_read(index=0xF020), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Connect standard AR IO Controller",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT, _pnio_connect(), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Connect empty station name",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT,
                                                _pnio_connect(station_name=b""), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Connect station name max (240 chars)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT,
                                                _pnio_connect(station_name=b"a" * 240), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Release with valid AR UUID",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_RELEASE, _TEST_AR_UUID, cid)))

        cid = c()
        cases.append(self._case(C, "RPC Write I&M1 (index 0xF001) 54-byte blank",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_WRITE,
                                                _pnio_write(index=0xF001,
                                                            data=b'\x00' * 54), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Read slot=0 subslot=0 index=0xF000",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_READ,
                                                _pnio_read(slot=0, subslot=0), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Read slot=0xFFFF subslot=0xFFFF (boundary)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_READ,
                                                _pnio_read(slot=0xFFFF,
                                                            subslot=0xFFFF), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Control Op empty payload",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONTROL, b'\x00\x00', cid)))

        cid = c()
        # Bind with assoc_group_id=1
        body  = struct.pack('<HH', 5840, 5840)
        body += struct.pack('<I', 1)
        body += bytes([1, 0, 0, 0])
        body += struct.pack('<HH', 0, 1)
        body += _PNIO_CM_UUID
        body += struct.pack('<HH', 1, 0)
        body += _NDR_UUID
        body += struct.pack('<HH', 2, 0)
        cases.append(self._case(C, "RPC Bind assoc_group_id=1",
                                 _rpc_header(_PTYPE_BIND, cid, 16 + len(body)) + body))

        cid = c()
        cases.append(self._case(C, "RPC Read API=1 (non-zero API)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_READ,
                                                _pnio_read(api=1, index=0xF000), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Write index=0xF001 zero-length data",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_WRITE,
                                                _pnio_write(index=0xF001, data=b''), cid)))

        cid = c()
        cases.append(self._case(C, "RPC Write index=0xF001 4096 bytes (max record)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_WRITE,
                                                _pnio_write(index=0xF001,
                                                            data=b'\x00' * 4096), cid)))

        return cases

    # ------------------------------------------------------------------
    # Category: binary_corruption
    # ------------------------------------------------------------------

    def _gen_binary_corruption(self):
        C = CATEGORY_BINARY_CORRUPTION
        cases = []
        c = self._cid

        def _mutate_bind(offset, value, desc):
            cid = c()
            bad = bytearray(_rpc_bind(cid))
            if isinstance(value, int):
                bad[offset] = value & 0xFF
            else:
                bad[offset:offset + len(value)] = value
            cases.append(self._case(C, desc, bytes(bad)))

        _mutate_bind(2, 0x00, "Bind PTYPE=0x00 (Request) instead of 0x0F")
        _mutate_bind(2, 0x01, "Bind PTYPE=0x01 (Ping)")
        _mutate_bind(2, 0xFF, "Bind PTYPE=0xFF (unknown)")
        _mutate_bind(3, 0x00, "Bind PFC_FLAGS=0x00 (no frag bits)")
        _mutate_bind(3, 0xFF, "Bind PFC_FLAGS=0xFF (all flags)")
        _mutate_bind(0, 0x05, "Bind RPC version=0x05 (should be 0x04)")
        _mutate_bind(4, 0x00, "Bind data_repr big-endian (0x00)")
        _mutate_bind(32, bytes(16), "Bind interface UUID all zeros")
        _mutate_bind(32, bytes([0xFF] * 16), "Bind interface UUID all 0xFF")
        _mutate_bind(52, bytes(16), "Bind NDR UUID all zeros")

        cid = c()
        bad = bytearray(_rpc_bind(cid))
        struct.pack_into('<H', bad, 8, 0)
        cases.append(self._case(C, "Bind frag_len=0", bytes(bad)))

        cid = c()
        bad = bytearray(_rpc_bind(cid))
        struct.pack_into('<H', bad, 8, 0xFFFF)
        cases.append(self._case(C, "Bind frag_len=0xFFFF", bytes(bad)))

        cid = c()
        bad = bytearray(_rpc_bind(cid))
        struct.pack_into('<I', bad, 12, 0)
        cases.append(self._case(C, "Bind call_id=0", bytes(bad)))

        cid = c()
        bad = bytearray(_rpc_bind(cid))
        struct.pack_into('<I', bad, 12, 0xFFFFFFFF)
        cases.append(self._case(C, "Bind call_id=0xFFFFFFFF", bytes(bad)))

        # Request mutations
        for op, name in [(0x00FF, "0x00FF"), (0x0005, "0x0005"), (0xFFFF, "0xFFFF")]:
            cid = c()
            req = bytearray(_rpc_request(op, _pnio_read(), cid))
            cases.append(self._case(C, f"Request op_num={name}",
                                     _rpc_bind(cid) + bytes(req)))

        cid = c()
        req = bytearray(_rpc_request(_OP_READ, _pnio_read(), cid))
        struct.pack_into('<H', req, 20, 1)
        cases.append(self._case(C, "Request context_id=1 (not negotiated)",
                                 _rpc_bind(cid) + bytes(req)))

        cid = c()
        req = bytearray(_rpc_request(_OP_READ, _pnio_read(), cid))
        struct.pack_into('<I', req, 16, 0xFFFFFFFF)
        cases.append(self._case(C, "Request alloc_hint=0xFFFFFFFF",
                                 _rpc_bind(cid) + bytes(req)))

        # Connect payload mutations
        for ar_type, name in [(0x0000, "0x0000 unknown"),
                              (0xFFFF, "0xFFFF all-ones")]:
            cid = c()
            cases.append(self._case(C, f"Connect AR type={name}",
                                     _rpc_bind(cid)
                                     + _rpc_request(_OP_CONNECT,
                                                    _pnio_connect(ar_type=ar_type), cid)))

        cid = c()
        cases.append(self._case(C, "Connect AR UUID all zeros",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT,
                                                _pnio_connect(ar_uuid=bytes(16)), cid)))

        cid = c()
        cases.append(self._case(C, "Connect session_key=0",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT,
                                                _pnio_connect(session_key=0), cid)))

        cid = c()
        cases.append(self._case(C, "Connect session_key=0xFFFF",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT,
                                                _pnio_connect(session_key=0xFFFF), cid)))

        # Truncated and trivial payloads
        cid = c()
        cases.append(self._case(C, "Truncated Bind (16 bytes — header only)",
                                 _rpc_bind(cid)[:16]))

        cid = c()
        cases.append(self._case(C, "Truncated Request header (no payload)",
                                 _rpc_bind(cid)
                                 + _rpc_header(_PTYPE_REQUEST, cid, 16)))

        cases.append(self._case(C, "Empty payload (0 bytes)", b''))
        cases.append(self._case(C, "1-byte payload (0x04)", b'\x04'))
        cases.append(self._case(C, "15-byte payload (one byte short of RPC header)",
                                 b'\x04\x00\x0F\x03\x10\x00\x00\x00'
                                 b'\x48\x00\x00\x00\x01\x00\x00'))

        return cases

    # ------------------------------------------------------------------
    # Category: state_machine
    # ------------------------------------------------------------------

    def _gen_state_machine(self):
        C = CATEGORY_STATE_MACHINE
        cases = []
        c = self._cid

        cid = c()
        cases.append(self._case(C, "Connect without prior Bind",
                                 _rpc_request(_OP_CONNECT, _pnio_connect(), cid)))

        cid = c()
        cases.append(self._case(C, "Read without prior Bind",
                                 _rpc_request(_OP_READ, _pnio_read(), cid)))

        cid = c()
        cases.append(self._case(C, "Release without Connect (Bind only exists)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_RELEASE, _TEST_AR_UUID, cid)))

        cid = c()
        bind = _rpc_bind(cid)
        cases.append(self._case(C, "Double Bind same call_id", bind + bind))

        cid1, cid2 = c(), c()
        cases.append(self._case(C, "Double Bind different call_ids",
                                 _rpc_bind(cid1) + _rpc_bind(cid2)))

        cid = c()
        cases.append(self._case(C, "Bind wrong UUID (all zeros) → expect BindNAK",
                                 _rpc_bind(cid, uuid=_BAD_UUID)))

        cid = c()
        cases.append(self._case(C, "PTYPE=0x0C Response sent as client request",
                                 _rpc_header(_PTYPE_RESPONSE, cid, 16)))

        cid = c()
        cases.append(self._case(C, "Write I&M0 (read-only record)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_WRITE,
                                                _pnio_write(index=0xF000,
                                                            data=b'\x01' * 32), cid)))

        cid = c()
        cases.append(self._case(C, "Control without Connect",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONTROL, b'\x00\x00', cid)))

        cid = c()
        conn = _pnio_connect()
        req = _rpc_request(_OP_CONNECT, conn, cid)
        cases.append(self._case(C, "Connect twice same AR UUID",
                                 _rpc_bind(cid) + req + req))

        cid = c()
        cases.append(self._case(C, "Release with all-zeros AR UUID",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_RELEASE, bytes(16), cid)))

        cid = c()
        fault = (_rpc_header(_PTYPE_FAULT, cid, 20)
                 + struct.pack('<I', 0x00000006))
        cases.append(self._case(C, "RPC Fault PDU sent as client",
                                 fault))

        return cases

    # ------------------------------------------------------------------
    # Category: sequence
    # ------------------------------------------------------------------

    def _gen_sequence(self):
        C = CATEGORY_SEQUENCE
        cases = []
        c = self._cid

        cases.append(self._case(C, "Bind call_id=1 then Request call_id=99 (mismatch)",
                                 _rpc_bind(1)
                                 + _rpc_request(_OP_READ, _pnio_read(), 99)))

        cases.append(self._case(C, "Bind call_id=2 then Request call_id=1 (decreasing)",
                                 _rpc_bind(2)
                                 + _rpc_request(_OP_READ, _pnio_read(), 1)))

        cases.append(self._case(C, "Both Bind and Request call_id=0",
                                 _rpc_bind(0)
                                 + _rpc_request(_OP_READ, _pnio_read(), 0)))

        cases.append(self._case(C, "Bind call_id=0xFFFFFFFF (max u32 wrap)",
                                 _rpc_bind(0xFFFFFFFF)
                                 + _rpc_request(_OP_READ, _pnio_read(), 0xFFFFFFFF)))

        cid = c()
        req = bytearray(_rpc_request(_OP_READ, _pnio_read(), cid))
        struct.pack_into('<H', req, 20, 1)
        cases.append(self._case(C, "Request context_id=1 (Bind only has ctx=0)",
                                 _rpc_bind(cid) + bytes(req)))

        cid = c()
        req = bytearray(_rpc_request(_OP_READ, _pnio_read(), cid))
        struct.pack_into('<H', req, 20, 0xFFFF)
        cases.append(self._case(C, "Request context_id=0xFFFF",
                                 _rpc_bind(cid) + bytes(req)))

        cid = c()
        bad = bytearray(_rpc_bind(cid))
        struct.pack_into('<H', bad, 10, 16)
        cases.append(self._case(C, "Bind auth_len=16 (claims auth trailer, none present)",
                                 bytes(bad)))

        cid = c()
        read = _rpc_request(_OP_READ, _pnio_read(), cid)
        cases.append(self._case(C, "Two Read requests same call_id after Bind",
                                 _rpc_bind(cid) + read + read))

        cases.append(self._case(C, "Request call_id=10000 after Bind call_id=1 (large gap)",
                                 _rpc_bind(1)
                                 + _rpc_request(_OP_READ, _pnio_read(), 10000)))

        cid = c()
        cases.append(self._case(C, "Request op_num=0xFFFF (unknown op)",
                                 _rpc_bind(cid)
                                 + _rpc_request(0xFFFF, b'', cid)))

        cid = c()
        req = bytearray(_rpc_request(_OP_READ, _pnio_read(), cid))
        struct.pack_into('<I', req, 16, 0)
        cases.append(self._case(C, "Request alloc_hint=0",
                                 _rpc_bind(cid) + bytes(req)))

        cases.append(self._case(C, "Bind call_id=0xFFFFFFFE near-max wrap",
                                 _rpc_bind(0xFFFFFFFE)
                                 + _rpc_request(_OP_READ, _pnio_read(), 0xFFFFFFFE)))

        return cases

    # ------------------------------------------------------------------
    # Category: dcp_discovery
    # ------------------------------------------------------------------

    def _gen_dcp_discovery(self):
        C = CATEGORY_DCP_DISCOVERY
        cases = []

        # "All" selector block
        blk_all  = _dcp_block(0xFF, 0xFF, b'')
        blk_ip   = _dcp_block(0x01, 0x01, b'\xC0\xA8\x00\x01')
        blk_name = _dcp_block(0x02, 0x02, b"profinet-device")
        blk_dev  = _dcp_block(0x02, 0x03, b'\x00\x2A\x00\x01')

        cases.append(self._case(C, "DCP Identify All (Option=0xFF SubOption=0xFF)",
                                 _dcp_frame(blocks=blk_all)))
        cases.append(self._case(C, "DCP Identify by IP (Option=0x01)",
                                 _dcp_frame(blocks=blk_ip)))
        cases.append(self._case(C, "DCP Identify by station name 'profinet-device'",
                                 _dcp_frame(blocks=blk_name)))
        cases.append(self._case(C, "DCP Identify by device ID (Vendor=42 Device=1)",
                                 _dcp_frame(blocks=blk_dev)))
        cases.append(self._case(C, "DCP Identify 3 blocks (All + IP + Name)",
                                 _dcp_frame(blocks=blk_all + blk_ip + blk_name)))

        cases.append(self._case(C, "DCP FrameID=0xFEFF (Get/Set, not Identify)",
                                 _dcp_frame(frame_id=_DCP_FRAME_GET_SET,
                                            svc_id=_DCP_SVC_GET, blocks=blk_all)))
        cases.append(self._case(C, "DCP ServiceType=0x80 (response bit set on request)",
                                 _dcp_frame(svc_type=0x80, blocks=blk_all)))
        cases.append(self._case(C, "DCP unknown ServiceID=0xFF",
                                 _dcp_frame(svc_id=0xFF, blocks=blk_all)))
        cases.append(self._case(C, "DCP unknown FrameID=0xFE00",
                                 _dcp_frame(frame_id=0xFE00, blocks=blk_all)))

        cases.append(self._case(C, "DCP XID=0",
                                 _dcp_frame(xid=0, blocks=blk_all)))
        cases.append(self._case(C, "DCP XID=0xFFFFFFFF",
                                 _dcp_frame(xid=0xFFFFFFFF, blocks=blk_all)))
        cases.append(self._case(C, "DCP response_delay=0",
                                 _dcp_frame(response_delay=0, blocks=blk_all)))
        cases.append(self._case(C, "DCP response_delay=0xFFFF",
                                 _dcp_frame(response_delay=0xFFFF, blocks=blk_all)))

        cases.append(self._case(C, "DCP Identify no blocks (DCPDataLength=0)",
                                 _dcp_frame(blocks=b'')))

        # Malformed blocks
        overflow_blk = bytes([0x02, 0x02]) + struct.pack('!H', 1000) + b'\x00' * 4
        cases.append(self._case(C, "DCP block DCPBlockLength=1000 but only 4 bytes follow",
                                 _dcp_frame(blocks=overflow_blk)))

        odd_blk = bytes([0x02, 0x02]) + struct.pack('!H', 7) + b'x' * 7
        cases.append(self._case(C, "DCP station name 7 bytes odd no padding",
                                 _dcp_frame(blocks=odd_blk)))

        cases.append(self._case(C, "DCP station name max (240 chars)",
                                 _dcp_frame(blocks=_dcp_block(0x02, 0x02, b"a" * 240))))
        cases.append(self._case(C, "DCP station name over max (241 chars)",
                                 _dcp_frame(blocks=_dcp_block(0x02, 0x02, b"a" * 241))))
        cases.append(self._case(C, "DCP station name with embedded null",
                                 _dcp_frame(blocks=_dcp_block(0x02, 0x02, b"test\x00name"))))

        cases.append(self._case(C, "DCP vendor-specific Option=0xFE block",
                                 _dcp_frame(blocks=_dcp_block(0xFE, 0x00,
                                                               b'\x00\x00\x00\x00'))))

        cases.append(self._case(C, "DCP frame truncated at 4 bytes",
                                 struct.pack('!HBB', _DCP_FRAME_IDENTIFY,
                                             _DCP_SVC_IDENTIFY, 0x00)))

        return cases

    # ------------------------------------------------------------------
    # Category: dcp_configuration
    # ------------------------------------------------------------------

    def _gen_dcp_configuration(self):
        C = CATEGORY_DCP_CONFIGURATION
        cases = []

        ip_data = (bytes([0x00, 0x00])
                   + b'\xC0\xA8\x01\x64'   # IP 192.168.1.100
                   + b'\xFF\xFF\xFF\x00'   # Mask
                   + b'\xC0\xA8\x01\x01')  # Gateway
        set_ip   = _dcp_block(0x01, 0x01, ip_data)
        set_name = _dcp_block(0x02, 0x02, bytes([0x00, 0x00]) + b"icsfuzzer")

        def _set(blocks):
            return _dcp_frame(frame_id=_DCP_FRAME_GET_SET,
                               svc_id=_DCP_SVC_SET, blocks=blocks)

        def _get(blocks):
            return _dcp_frame(frame_id=_DCP_FRAME_GET_SET,
                               svc_id=_DCP_SVC_GET, blocks=blocks)

        cases.append(self._case(C, "DCP Set IP 192.168.1.100/24", _set(set_ip)))
        cases.append(self._case(C, "DCP Set station name 'icsfuzzer'", _set(set_name)))
        cases.append(self._case(C, "DCP Set multiple blocks (IP + Name)",
                                 _set(set_ip + set_name)))
        cases.append(self._case(C, "DCP Set empty station name",
                                 _set(_dcp_block(0x02, 0x02, bytes([0x00, 0x00])))))
        cases.append(self._case(C, "DCP Set IP=0.0.0.0 (clear IP)",
                                 _set(_dcp_block(0x01, 0x01,
                                                  bytes([0x00, 0x00]) + b'\x00' * 12))))
        cases.append(self._case(C, "DCP Set IP=255.255.255.255 (broadcast)",
                                 _set(_dcp_block(0x01, 0x01,
                                                  bytes([0x00, 0x00]) + b'\xFF' * 12))))

        cases.append(self._case(C, "DCP Get IP block", _get(_dcp_block(0x01, 0x01, b''))))
        cases.append(self._case(C, "DCP Get station name", _get(_dcp_block(0x02, 0x02, b''))))
        cases.append(self._case(C, "DCP Get All", _get(_dcp_block(0xFF, 0xFF, b''))))

        cases.append(self._case(C, "DCP Set unknown SubOption=0xFF",
                                 _set(_dcp_block(0x02, 0xFF, bytes([0x00, 0x00])))))
        cases.append(self._case(C, "DCP Set IP truncated (4 bytes instead of 14)",
                                 _set(_dcp_block(0x01, 0x01,
                                                  bytes([0x00, 0x00]) + b'\xC0\xA8'))))
        cases.append(self._case(C, "DCP Set block BlockLength=0",
                                 _set(bytes([0x01, 0x01, 0x00, 0x00]))))
        overflow_blk = bytes([0x01, 0x01]) + struct.pack('!H', 500) + b'\x00' * 6
        cases.append(self._case(C, "DCP Set IP BlockLength=500 but only 6 bytes",
                                 _set(overflow_blk)))
        cases.append(self._case(C, "DCP Set station name with CRLF",
                                 _set(_dcp_block(0x02, 0x02,
                                                  bytes([0x00, 0x00]) + b"test\r\nname"))))
        cases.append(self._case(C, "DCP Set unknown Option=0xFE vendor-specific",
                                 _set(_dcp_block(0xFE, 0x00,
                                                  bytes([0x00, 0x00, 0xDE, 0xAD])))))
        cases.append(self._case(C, "DCP Set factory reset (Option=0x05 SubOption=0x05)",
                                 _set(_dcp_block(0x05, 0x05, bytes([0x00, 0x00])))))
        cases.append(self._case(C, "DCP Set ServiceType=0xFF (invalid)",
                                 _dcp_frame(frame_id=_DCP_FRAME_GET_SET,
                                            svc_id=_DCP_SVC_SET, svc_type=0xFF,
                                            blocks=set_ip)))

        return cases

    # ------------------------------------------------------------------
    # Category: pnio_connect
    # ------------------------------------------------------------------

    def _gen_pnio_connect(self):
        C = CATEGORY_PNIO_CONNECT
        cases = []
        c = self._cid

        cid = c()
        cases.append(self._case(C, "Connect standard AR type=0x0001 IO Controller",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT, _pnio_connect(), cid)))

        for ar_type, name in [(0x0000, "0x0000 unknown"),
                              (0x0002, "0x0002 IO Supervisor"),
                              (0x0004, "0x0004 Redundant IO Controller"),
                              (0x0006, "0x0006 Device Access"),
                              (0xFFFF, "0xFFFF all-ones")]:
            cid = c()
            cases.append(self._case(C, f"Connect AR type={name}",
                                     _rpc_bind(cid)
                                     + _rpc_request(_OP_CONNECT,
                                                    _pnio_connect(ar_type=ar_type), cid)))

        cid = c()
        cases.append(self._case(C, "Connect AR UUID all-zeros",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT,
                                                _pnio_connect(ar_uuid=bytes(16)), cid)))

        cid = c()
        cases.append(self._case(C, "Connect AR UUID all-0xFF",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT,
                                                _pnio_connect(ar_uuid=bytes([0xFF] * 16)), cid)))

        cid = c()
        cases.append(self._case(C, "Connect station name 241 chars (over max)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT,
                                                _pnio_connect(station_name=b"a" * 241), cid)))

        cid = c()
        cases.append(self._case(C, "Connect station name with CRLF",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT,
                                                _pnio_connect(station_name=b"bad\r\nname"), cid)))

        cid = c()
        cases.append(self._case(C, "Connect ARProperties=0xFFFFFFFF",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT,
                                                _pnio_connect(properties=0xFFFFFFFF), cid)))

        cid = c()
        bad = bytearray(_pnio_connect())
        struct.pack_into('!H', bad, 0, 0xFFFF)
        cases.append(self._case(C, "Connect corrupt block type=0xFFFF",
                                 _rpc_bind(cid) + _rpc_request(_OP_CONNECT,
                                                                bytes(bad), cid)))

        cid = c()
        bad = bytearray(_pnio_connect())
        struct.pack_into('!H', bad, 2, 4)
        cases.append(self._case(C, "Connect AR BlockLength=4 (too short)",
                                 _rpc_bind(cid) + _rpc_request(_OP_CONNECT,
                                                                bytes(bad), cid)))

        cid = c()
        bad = bytearray(_pnio_connect())
        bad[4] = 0xFF; bad[5] = 0xFF
        cases.append(self._case(C, "Connect AR block version 0xFF.0xFF",
                                 _rpc_bind(cid) + _rpc_request(_OP_CONNECT,
                                                                bytes(bad), cid)))

        cid = c()
        cases.append(self._case(C, "Connect truncated payload (6 bytes)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT,
                                                b'\x01\x01\x00\x04\x01\x00', cid)))

        cid = c()
        cases.append(self._case(C, "Connect empty payload",
                                 _rpc_bind(cid) + _rpc_request(_OP_CONNECT, b'', cid)))

        cid = c()
        cases.append(self._case(C, "Connect random junk payload (32 bytes)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_CONNECT, bytes(range(32)), cid)))

        return cases

    # ------------------------------------------------------------------
    # Category: record_rw
    # ------------------------------------------------------------------

    def _gen_record_rw(self):
        C = CATEGORY_RECORD_RW
        cases = []
        c = self._cid

        for index, name in [
            (0xF000, "I&M0 (manufacturer info)"),
            (0xF001, "I&M1 (installation)"),
            (0xF002, "I&M2 (date)"),
            (0xF003, "I&M3 (descriptor)"),
            (0xF004, "I&M4 (signature)"),
            (0xF020, "system log"),
            (0xF040, "PROFIsafe parameter"),
            (0x0000, "index=0x0000"),
            (0xFFFF, "index=0xFFFF"),
        ]:
            cid = c()
            cases.append(self._case(C, f"Record Read {name}",
                                     _rpc_bind(cid)
                                     + _rpc_request(_OP_READ, _pnio_read(index=index), cid)))

        cid = c()
        cases.append(self._case(C, "Record Read slot=0xFFFF subslot=0xFFFF",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_READ,
                                                _pnio_read(slot=0xFFFF, subslot=0xFFFF,
                                                            index=0xF000), cid)))

        cid = c()
        cases.append(self._case(C, "Record Write I&M1 (index 0xF001) 54 bytes blank",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_WRITE,
                                                _pnio_write(index=0xF001,
                                                            data=b'\x00' * 54), cid)))

        cid = c()
        cases.append(self._case(C, "Record Write I&M0 (read-only, expect error)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_WRITE,
                                                _pnio_write(index=0xF000,
                                                            data=b'\x00' * 32), cid)))

        cid = c()
        cases.append(self._case(C, "Record Write index=0xF001 zero-length data",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_WRITE,
                                                _pnio_write(index=0xF001, data=b''), cid)))

        cid = c()
        cases.append(self._case(C, "Record Write index=0xFFFF (unknown)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_WRITE,
                                                _pnio_write(index=0xFFFF,
                                                            data=b'\xDE\xAD\xBE\xEF'), cid)))

        cid = c()
        cases.append(self._case(C, "Record Write index=0xF001 0xFFFF bytes (oversize)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_WRITE,
                                                _pnio_write(index=0xF001,
                                                            data=b'\xAA' * 0xFFFF), cid)))

        cid = c()
        cases.append(self._case(C, "Record Read API=1 (non-zero API)",
                                 _rpc_bind(cid)
                                 + _rpc_request(_OP_READ,
                                                _pnio_read(api=1, index=0xF000), cid)))

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
            print(f"\r[profinet] {i}/{total}  {case_id}  {desc[:55]}",
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

        # DCP: generate but skip send without raw socket
        if category in self._DCP_CATS and not _HAS_SCAPY:
            result.anomaly         = None
            result.crash_indicator = False
            result.duration_ms     = 0.0
            return result

        t0 = time.monotonic()
        try:
            pdus = _split_pdus(payload)
            last_call_id: Optional[int] = None
            data: Optional[bytes] = None

            for pdu in pdus:
                if len(pdu) >= 16:
                    last_call_id = struct.unpack_from('<I', pdu, 12)[0]
                self._sock.sendto(pdu, self._remote)
                data = self._recv_response()

            result.duration_ms = (time.monotonic() - t0) * 1000

            if data is None:
                result.anomaly         = ANOMALY_TIMEOUT
                result.crash_indicator = True
            else:
                result.response = data
                self._classify_response(data, result, last_call_id)

        except OSError:
            result.anomaly         = ANOMALY_CONNECTION_RESET
            result.crash_indicator = True
            result.duration_ms     = (time.monotonic() - t0) * 1000

        return result

    def _classify_response(self, resp: bytes, result: FuzzResult,
                           expected_call_id: Optional[int] = None) -> None:
        if len(resp) < 16:
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        ptype   = resp[2]
        call_id = struct.unpack_from('<I', resp, 12)[0]

        if ptype == _PTYPE_FAULT:
            result.anomaly         = ANOMALY_EXCEPTION
            result.crash_indicator = False
            return

        if ptype not in (_PTYPE_BIND_ACK, _PTYPE_RESPONSE):
            result.anomaly         = ANOMALY_UNEXPECTED_DATA
            result.crash_indicator = True
            return

        if (expected_call_id is not None
                and result.category not in self._DCP_CATS
                and call_id != expected_call_id):
            result.anomaly         = ANOMALY_MALFORMED_RESPONSE
            result.crash_indicator = True
            return

        # BindACK: check context result at offset 28 (p_results[0])
        if ptype == _PTYPE_BIND_ACK and len(resp) >= 30:
            ctx_result = struct.unpack_from('<H', resp, 28)[0]
            if ctx_result != 0:
                result.anomaly         = ANOMALY_EXCEPTION
                result.crash_indicator = False
        # Normal response (anomaly stays None, crash stays False)
