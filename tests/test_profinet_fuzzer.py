"""Unit tests for the PROFINET fuzzer — generator phase, no network."""

import socket
import struct

import pytest

from protocols.profinet.fuzzer import (
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_DCP_CONFIGURATION,
    CATEGORY_DCP_DISCOVERY,
    CATEGORY_PNIO_CONNECT,
    CATEGORY_RECORD_RW,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    ProfinetFuzzer,
    _PNIO_CM_UUID,
    _NDR_UUID,
    _OP_CONNECT,
    _OP_READ,
    _OP_WRITE,
    _PTYPE_BIND,
    _PTYPE_BIND_ACK,
    _PTYPE_REQUEST,
    _PTYPE_RESPONSE,
    _PTYPE_FAULT,
    _DCP_FRAME_IDENTIFY,
    _DCP_SVC_IDENTIFY,
    _TEST_AR_UUID,
    _rpc_bind,
    _rpc_request,
    _rpc_header,
    _split_pdus,
    _dcp_frame,
    _dcp_block,
    _pnio_connect,
    _pnio_read,
    _pnio_write,
)
from core.base_module import Device

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _device():
    return Device(ip="127.0.0.1", port=34965, protocol="profinet")


def _fuzzer():
    return ProfinetFuzzer(target=_device(), logger=None, delay=0)


# ---------------------------------------------------------------------------
# Frame builder tests
# ---------------------------------------------------------------------------

class TestRpcHeader:
    def test_length(self):
        assert len(_rpc_header(0x0F, 1, 72)) == 16

    def test_version(self):
        h = _rpc_header(0x0F, 1, 72)
        assert h[0] == 0x04
        assert h[1] == 0x00

    def test_ptype_field(self):
        h = _rpc_header(0x0B, 1, 24)
        assert h[2] == 0x0B

    def test_pfc_flags(self):
        h = _rpc_header(0x0F, 1, 72)
        assert h[3] == 0x03

    def test_data_repr_le(self):
        h = _rpc_header(0x0F, 1, 72)
        assert h[4] == 0x10  # little-endian marker

    def test_frag_len_field(self):
        h = _rpc_header(0x0F, 1, 72)
        assert struct.unpack_from('<H', h, 8)[0] == 72

    def test_call_id_field(self):
        h = _rpc_header(0x0F, 42, 72)
        assert struct.unpack_from('<I', h, 12)[0] == 42


class TestRpcBind:
    def test_length(self):
        assert len(_rpc_bind(1)) == 72

    def test_ptype_is_bind(self):
        assert _rpc_bind(1)[2] == _PTYPE_BIND

    def test_uuid_embedded(self):
        b = _rpc_bind(1)
        assert b[32:48] == _PNIO_CM_UUID

    def test_ndr_uuid_embedded(self):
        b = _rpc_bind(1)
        assert b[52:68] == _NDR_UUID

    def test_call_id(self):
        b = _rpc_bind(7)
        assert struct.unpack_from('<I', b, 12)[0] == 7

    def test_bad_uuid_accepted(self):
        b = _rpc_bind(1, uuid=bytes(16))
        assert b[32:48] == bytes(16)


class TestRpcRequest:
    def test_ptype_is_request(self):
        r = _rpc_request(_OP_READ, b'\x00' * 8, 1)
        assert r[2] == _PTYPE_REQUEST

    def test_op_num_field(self):
        for op in (_OP_CONNECT, _OP_READ, _OP_WRITE):
            r = _rpc_request(op, b'', 1)
            assert struct.unpack_from('<H', r, 22)[0] == op

    def test_alloc_hint_equals_payload_len(self):
        payload = b'\xAB' * 32
        r = _rpc_request(_OP_READ, payload, 1)
        assert struct.unpack_from('<I', r, 16)[0] == 32

    def test_payload_appended(self):
        payload = b'\x01\x02\x03\x04'
        r = _rpc_request(_OP_READ, payload, 1)
        assert r[24:28] == payload


class TestSplitPdus:
    def test_single_bind(self):
        b = _rpc_bind(1)
        pdus = _split_pdus(b)
        assert len(pdus) == 1
        assert pdus[0] == b

    def test_bind_plus_request(self):
        b = _rpc_bind(1)
        r = _rpc_request(_OP_READ, _pnio_read(), 1)
        combined = b + r
        pdus = _split_pdus(combined)
        assert len(pdus) == 2
        assert pdus[0] == b
        assert pdus[1] == r

    def test_empty_payload(self):
        pdus = _split_pdus(b'')
        assert pdus == [b'']

    def test_short_payload_no_crash(self):
        pdus = _split_pdus(b'\x04\x00')
        assert len(pdus) == 1

    def test_corrupt_frag_len_falls_back(self):
        bad = bytearray(_rpc_bind(1))
        struct.pack_into('<H', bad, 8, 0xFFFF)
        pdus = _split_pdus(bytes(bad))
        assert len(pdus) == 1


class TestDcpFrame:
    def test_frame_id_big_endian(self):
        f = _dcp_frame(frame_id=0xFEFC)
        assert struct.unpack('!H', f[0:2])[0] == 0xFEFC

    def test_service_id(self):
        f = _dcp_frame(svc_id=0x05)
        assert f[2] == 0x05

    def test_service_type(self):
        f = _dcp_frame(svc_type=0x00)
        assert f[3] == 0x00

    def test_xid_big_endian(self):
        f = _dcp_frame(xid=0xDEADBEEF)
        assert struct.unpack('!I', f[4:8])[0] == 0xDEADBEEF

    def test_dcp_data_length_matches_blocks(self):
        blocks = _dcp_block(0xFF, 0xFF, b'')
        f = _dcp_frame(blocks=blocks)
        dcp_data_len = struct.unpack('!H', f[10:12])[0]
        assert dcp_data_len == len(blocks)

    def test_blocks_appended(self):
        blocks = b'\xDE\xAD\xBE\xEF'
        f = _dcp_frame(blocks=blocks)
        assert f[12:16] == blocks


class TestDcpBlock:
    def test_length(self):
        b = _dcp_block(0xFF, 0xFF, b'')
        assert len(b) == 4  # option(1)+suboption(1)+len(2)

    def test_option_suboption(self):
        b = _dcp_block(0x02, 0x01, b'\x00\x00')
        assert b[0] == 0x02
        assert b[1] == 0x01

    def test_block_length_field(self):
        data = b'\x01\x02\x03\x04'
        b = _dcp_block(0x01, 0x01, data)
        assert struct.unpack('!H', b[2:4])[0] == 4

    def test_odd_data_padded(self):
        data = b'\x01\x02\x03'
        b = _dcp_block(0x02, 0x02, data)
        assert len(b) % 2 == 0
        assert len(b) == 8  # 2+2+3+1pad

    def test_even_data_not_padded(self):
        data = b'\x01\x02'
        b = _dcp_block(0x02, 0x02, data)
        assert len(b) == 6  # 2+2+2, no pad


class TestPnioConnect:
    def test_block_type(self):
        c = _pnio_connect()
        assert struct.unpack('!H', c[0:2])[0] == 0x0101

    def test_version(self):
        c = _pnio_connect()
        assert c[4] == 0x01
        assert c[5] == 0x00

    def test_ar_type_embedded(self):
        c = _pnio_connect(ar_type=0x0002)
        assert struct.unpack('!H', c[6:8])[0] == 0x0002

    def test_station_name_in_payload(self):
        c = _pnio_connect(station_name=b"testdev")
        assert b"testdev" in c


class TestPnioRead:
    def test_block_type(self):
        r = _pnio_read()
        assert struct.unpack('!H', r[0:2])[0] == 0x0027

    def test_index_field(self):
        r = _pnio_read(index=0xF001)
        assert struct.unpack('!H', r[34:36])[0] == 0xF001

    def test_ar_uuid_embedded(self):
        r = _pnio_read()
        assert r[8:24] == _TEST_AR_UUID


# ---------------------------------------------------------------------------
# Generate cases tests
# ---------------------------------------------------------------------------

class TestGenerateCases:
    def test_all_categories_generated(self):
        f = _fuzzer()
        cases = f.generate_cases()
        cats = {c[1] for c in cases}
        assert cats == set(ProfinetFuzzer.FUZZ_CATEGORIES)

    def test_minimum_case_count(self):
        f = _fuzzer()
        cases = f.generate_cases()
        assert len(cases) >= 140

    def test_unique_case_ids(self):
        f = _fuzzer()
        cases = f.generate_cases()
        ids = [c[0] for c in cases]
        assert len(ids) == len(set(ids))

    def test_payloads_are_bytes(self):
        f = _fuzzer()
        for case_id, cat, desc, payload in f.generate_cases():
            assert isinstance(payload, bytes), f"{case_id}: payload not bytes"

    def test_descriptions_nonempty(self):
        f = _fuzzer()
        for case_id, cat, desc, payload in f.generate_cases():
            assert len(desc) > 0, f"{case_id}: empty description"

    def test_category_filter(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_BOUNDARY])
        assert len(cases) >= 10
        assert all(c[1] == CATEGORY_BOUNDARY for c in cases)

    def test_category_filter_dcp(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_DCP_DISCOVERY])
        assert len(cases) >= 15
        assert all(c[1] == CATEGORY_DCP_DISCOVERY for c in cases)

    def test_case_ids_have_protocol_prefix(self):
        f = _fuzzer()
        cases = f.generate_cases()
        for case_id, _, _, _ in cases:
            assert case_id.startswith("profinet-"), f"Bad prefix: {case_id}"


class TestBoundaryCategory:
    def test_boundary_has_bind_cases(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_BOUNDARY])
        bind_cases = [c for c in cases if _rpc_bind.__doc__ and
                      len(c[3]) >= 72]
        assert len(bind_cases) >= 1

    def test_boundary_has_read_cases(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_BOUNDARY])
        read_cases = [c for c in cases if "Read" in c[2]]
        assert len(read_cases) >= 4

    def test_boundary_has_connect_case(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_BOUNDARY])
        conn_cases = [c for c in cases if "Connect" in c[2]]
        assert len(conn_cases) >= 1


class TestBinaryCorruptionCategory:
    def test_has_uuid_corruption_cases(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_BINARY_CORRUPTION])
        uuid_cases = [c for c in cases if "UUID" in c[2]]
        assert len(uuid_cases) >= 2

    def test_has_empty_payload_case(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_BINARY_CORRUPTION])
        empty = [c for c in cases if c[3] == b'']
        assert len(empty) >= 1

    def test_count(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_BINARY_CORRUPTION])
        assert len(cases) >= 25


class TestDcpDiscoveryCategory:
    def test_identify_all_case_exists(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_DCP_DISCOVERY])
        identify_all = [c for c in cases if "Identify All" in c[2]]
        assert len(identify_all) >= 1

    def test_dcp_payload_starts_with_frame_id(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_DCP_DISCOVERY])
        for cid, cat, desc, payload in cases:
            if len(payload) >= 2:
                frame_id = struct.unpack('!H', payload[0:2])[0]
                assert frame_id in (0xFEFC, 0xFEFD, 0xFEFF, 0xFE00), \
                    f"{cid}: unexpected FrameID 0x{frame_id:04X}"

    def test_max_station_name_case_exists(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_DCP_DISCOVERY])
        max_cases = [c for c in cases if "max" in c[2] or "240" in c[2]]
        assert len(max_cases) >= 1


class TestStateMachineCategory:
    def test_has_no_bind_cases(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_STATE_MACHINE])
        # At least one case that tests connect without bind
        no_bind = [c for c in cases if "without" in c[2].lower()
                   or "no prior" in c[2].lower()]
        assert len(no_bind) >= 1

    def test_count(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_STATE_MACHINE])
        assert len(cases) >= 10


class TestSequenceCategory:
    def test_mismatch_case_exists(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_SEQUENCE])
        mismatch = [c for c in cases if "mismatch" in c[2].lower()]
        assert len(mismatch) >= 1

    def test_count(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_SEQUENCE])
        assert len(cases) >= 10


class TestPnioConnectCategory:
    def test_ar_type_variants_covered(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_PNIO_CONNECT])
        ar_cases = [c for c in cases if "AR type" in c[2]]
        assert len(ar_cases) >= 4

    def test_count(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_PNIO_CONNECT])
        assert len(cases) >= 15


class TestRecordRwCategory:
    def test_im_indices_covered(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_RECORD_RW])
        for im in ["I&M0", "I&M1", "I&M4"]:
            found = [c for c in cases if im in c[2]]
            assert len(found) >= 1, f"Missing {im} case"

    def test_write_cases_exist(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_RECORD_RW])
        write_cases = [c for c in cases if "Write" in c[2]]
        assert len(write_cases) >= 3

    def test_count(self):
        f = _fuzzer()
        cases = f.generate_cases([CATEGORY_RECORD_RW])
        assert len(cases) >= 15


# ---------------------------------------------------------------------------
# ProfinetFuzzer class attributes
# ---------------------------------------------------------------------------

class TestFuzzerClass:
    def test_protocol_name(self):
        assert ProfinetFuzzer.PROTOCOL_NAME == "profinet"

    def test_default_port(self):
        assert ProfinetFuzzer.DEFAULT_PORT == 34964

    def test_fuzz_categories_count(self):
        assert len(ProfinetFuzzer.FUZZ_CATEGORIES) == 8

    def test_all_standard_cats_present(self):
        cats = ProfinetFuzzer.FUZZ_CATEGORIES
        assert CATEGORY_BOUNDARY in cats
        assert CATEGORY_BINARY_CORRUPTION in cats
        assert CATEGORY_STATE_MACHINE in cats
        assert CATEGORY_SEQUENCE in cats

    def test_all_protocol_cats_present(self):
        cats = ProfinetFuzzer.FUZZ_CATEGORIES
        assert CATEGORY_DCP_DISCOVERY in cats
        assert CATEGORY_DCP_CONFIGURATION in cats
        assert CATEGORY_PNIO_CONNECT in cats
        assert CATEGORY_RECORD_RW in cats

    def test_connect_creates_udp_socket(self):
        f = _fuzzer()
        f.connect()
        assert f._sock is not None
        assert f._sock.type == socket.SOCK_DGRAM
        f.close()

    def test_close_clears_socket(self):
        f = _fuzzer()
        f.connect()
        f.close()
        assert f._sock is None

    def test_double_close_safe(self):
        f = _fuzzer()
        f.connect()
        f.close()
        f.close()  # should not raise

    def test_fuzz_without_connect_raises(self):
        f = _fuzzer()
        with pytest.raises(RuntimeError):
            f.fuzz()
