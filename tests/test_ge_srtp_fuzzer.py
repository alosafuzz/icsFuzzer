"""GE SRTP fuzzer generator and unit tests — no live target required."""

import struct

import pytest

from protocols.ge_srtp.fuzzer import (
    GeSrtpFuzzer,
    _srtp_header,
    _init_pkt,
    _read_req,
    _write_req,
    _status_req,
    _get_info_req,
    _PKT_INIT,
    _PKT_INIT_ACK,
    _PKT_REQ,
    _PKT_REQ_ACK,
    _MSG_SHORT,
    _MSG_SHORT_ACK,
    _MSG_SHORT_ERR,
    _MSG_EXTENDED,
    _MSG_EXTENDED_ACK,
    SVC_STATUS,
    SVC_READ_SYS_MEM,
    SVC_WRITE_SYS_MEM,
    SVC_SET_PLC_RUN,
    SVC_GET_INFO,
    SVC_GET_TIME,
    SVC_GET_FAULT,
    SVC_PROG_STORE,
    SVC_TOGGLE_FORCE,
    SEG_R,
    SEG_I,
    SEG_Q,
    SEG_AI,
    SEG_AQ,
    SEG_M,
    CATEGORY_SERVICE_SWEEP,
    CATEGORY_MEM_SWEEP,
    CATEGORY_EXTENDED_MSG,
    CATEGORY_MAILBOX,
    CATEGORY_DANGEROUS,
    _MBOX_SRC_DEFAULT,
    _MBOX_DST_DEFAULT,
    _SAFE_READ_SVCS,
    _ALL_SEGS,
)
from core.base_module import (
    ANOMALY_EXCEPTION,
    ANOMALY_MALFORMED_RESPONSE,
    ANOMALY_TIMEOUT,
    ANOMALY_CONNECTION_RESET,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
)


@pytest.fixture
def device():
    return Device(ip="127.0.0.1", port=18246, protocol="ge_srtp")


@pytest.fixture
def fuzzer(device):
    return GeSrtpFuzzer(target=device, logger=None, delay=0)


@pytest.fixture
def dangerous_fuzzer(device):
    return GeSrtpFuzzer(target=device, logger=None, delay=0, dangerous=True)


# ---------------------------------------------------------------------------
# TestSrtpHeaderBuilder
# ---------------------------------------------------------------------------

class TestSrtpHeaderBuilder:
    def test_header_length_always_56(self):
        assert len(_srtp_header()) == 56

    def test_pkt_type_default_req(self):
        h = _srtp_header()
        pkt_type = struct.unpack_from('<H', h, 0)[0]
        assert pkt_type == _PKT_REQ

    def test_pkt_type_init(self):
        h = _srtp_header(pkt_type=_PKT_INIT)
        pkt_type = struct.unpack_from('<H', h, 0)[0]
        assert pkt_type == _PKT_INIT

    def test_index_little_endian(self):
        h = _srtp_header(index=0x0102)
        idx = struct.unpack_from('<H', h, 2)[0]
        assert idx == 0x0102

    def test_payload_size_offset(self):
        h = _srtp_header(payload_size=42)
        sz = struct.unpack_from('<H', h, 4)[0]
        assert sz == 42

    def test_reserved_bytes_zeros(self):
        h = _srtp_header()
        # bytes 6-25 = 20 reserved bytes
        assert h[6:26] == b'\x00' * 20

    def test_msg_seq_at_offset_29(self):
        h = _srtp_header(msg_seq=0x42)
        assert h[29] == 0x42

    def test_msg_type_at_offset_30(self):
        h = _srtp_header(msg_type=_MSG_SHORT)
        assert h[30] == _MSG_SHORT

    def test_mbox_src_little_endian(self):
        h = _srtp_header(mbox_src=0xDEADBEEF)
        v = struct.unpack_from('<I', h, 32)[0]
        assert v == 0xDEADBEEF

    def test_mbox_dst_little_endian(self):
        h = _srtp_header(mbox_dst=0xCAFEBABE)
        v = struct.unpack_from('<I', h, 36)[0]
        assert v == 0xCAFEBABE

    def test_pkt_num_at_offset_40(self):
        h = _srtp_header(pkt_num=3)
        assert h[40] == 3

    def test_total_pkt_num_at_offset_41(self):
        h = _srtp_header(total_pkt_num=7)
        assert h[41] == 7

    def test_svc_req_code_at_offset_42(self):
        h = _srtp_header(svc_req_code=SVC_READ_SYS_MEM)
        assert h[42] == SVC_READ_SYS_MEM

    def test_seg_selector_at_offset_43(self):
        h = _srtp_header(seg_selector=SEG_I)
        assert h[43] == SEG_I

    def test_target_index_little_endian(self):
        h = _srtp_header(target_index=0x1234)
        v = struct.unpack_from('<H', h, 44)[0]
        assert v == 0x1234

    def test_target_count_little_endian(self):
        h = _srtp_header(target_count=0xABCD)
        v = struct.unpack_from('<H', h, 46)[0]
        assert v == 0xABCD

    def test_data_at_offset_48(self):
        h = _srtp_header(data=b'\x11\x22\x33\x44\x55\x66')
        assert h[48:54] == b'\x11\x22\x33\x44\x55\x66'

    def test_data_padded_if_short(self):
        h = _srtp_header(data=b'\xFF')
        # First byte is 0xFF, rest padded with 0x00
        assert h[48] == 0xFF
        assert h[49:54] == b'\x00' * 5

    def test_tail_two_zeros(self):
        h = _srtp_header()
        assert h[54:56] == b'\x00\x00'

    def test_init_pkt_all_zeros(self):
        p = _init_pkt()
        assert len(p) == 56
        assert p == b'\x00' * 56
        # pkt_type = 0x0000 = INIT
        pkt_type = struct.unpack_from('<H', p, 0)[0]
        assert pkt_type == _PKT_INIT

    def test_read_req_pkt_type(self):
        p = _read_req(SVC_READ_SYS_MEM, SEG_R, 1, 1, 1)
        assert struct.unpack_from('<H', p, 0)[0] == _PKT_REQ

    def test_read_req_service_code(self):
        p = _read_req(SVC_READ_SYS_MEM, SEG_R, 1, 1, 1)
        assert p[42] == SVC_READ_SYS_MEM

    def test_read_req_seg_selector(self):
        p = _read_req(SVC_READ_SYS_MEM, SEG_AI, 1, 1, 1)
        assert p[43] == SEG_AI

    def test_write_req_payload_size(self):
        p = _write_req(SVC_WRITE_SYS_MEM, SEG_R, 1, 1, b'\xFF\xFF', 1)
        sz = struct.unpack_from('<H', p, 4)[0]
        assert sz == 2

    def test_status_req_svc_code(self):
        p = _status_req(1)
        assert p[42] == SVC_STATUS

    def test_get_info_req_svc_code(self):
        p = _get_info_req(1)
        assert p[42] == SVC_GET_INFO

    def test_default_mbox_src(self):
        p = _status_req(1)
        v = struct.unpack_from('<I', p, 32)[0]
        assert v == _MBOX_SRC_DEFAULT

    def test_default_mbox_dst(self):
        p = _status_req(1)
        v = struct.unpack_from('<I', p, 36)[0]
        assert v == _MBOX_DST_DEFAULT


# ---------------------------------------------------------------------------
# TestGenerateCases
# ---------------------------------------------------------------------------

class TestGenerateCases:
    def test_all_standard_categories_present(self, fuzzer):
        cases = fuzzer.generate_cases()
        cats  = {c[1] for c in cases}
        assert CATEGORY_BOUNDARY          in cats
        assert CATEGORY_BINARY_CORRUPTION in cats
        assert CATEGORY_STATE_MACHINE     in cats
        assert CATEGORY_SEQUENCE          in cats
        assert CATEGORY_SERVICE_SWEEP     in cats
        assert CATEGORY_MEM_SWEEP         in cats
        assert CATEGORY_EXTENDED_MSG      in cats
        assert CATEGORY_MAILBOX           in cats

    def test_dangerous_excluded_by_default(self, fuzzer):
        cases = fuzzer.generate_cases()
        cats  = {c[1] for c in cases}
        assert CATEGORY_DANGEROUS not in cats

    def test_dangerous_included_when_flag_set(self, dangerous_fuzzer):
        cases = dangerous_fuzzer.generate_cases([CATEGORY_DANGEROUS])
        assert len(cases) > 0
        assert all(c[1] == CATEGORY_DANGEROUS for c in cases)

    def test_minimum_case_count(self, fuzzer):
        # service_sweep alone = len(_SAFE_READ_SVCS) * len(_ALL_SEGS) + gaps ≈ 100+
        assert len(fuzzer.generate_cases()) >= 500

    def test_unique_case_ids(self, fuzzer):
        cases = fuzzer.generate_cases()
        ids   = [c[0] for c in cases]
        assert len(ids) == len(set(ids))

    def test_case_ids_prefixed(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert all(c[0].startswith("ge_srtp-") for c in cases)

    def test_all_payloads_bytes(self, fuzzer):
        for case_id, _, _, payload in fuzzer.generate_cases():
            assert isinstance(payload, bytes), f"{case_id}: not bytes"

    def test_subset_category(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        assert all(c[1] == CATEGORY_BOUNDARY for c in cases)

    def test_generate_no_connection_needed(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert len(cases) > 0


# ---------------------------------------------------------------------------
# TestBoundaryCategory
# ---------------------------------------------------------------------------

class TestBoundaryCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_BOUNDARY])) >= 20

    def test_status_present(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("status" in d.lower() or "STATUS" in d for d in descs)

    def test_get_info_present(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("GET_INFO" in d or "info" in d.lower() for d in descs)

    def test_read_sys_mem_multiple_segs(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("%R Register" in d or "Register" in d for d in descs)
        assert any("%AI" in d or "Analog Input" in d for d in descs)

    def test_index_boundary_zero(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("index=0" in d for d in descs)

    def test_index_boundary_max(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("0xFFFF" in d for d in descs)

    def test_count_boundary_zero(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("count=0" in d for d in descs)

    def test_count_boundary_max(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("0xFFFF" in d for d in descs)

    def test_payload_size_0xffff(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BOUNDARY])]
        assert any("0xFFFF" in d and "payload_size" in d for d in descs)

    def test_all_payloads_56_bytes(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        for case_id, _, _, payload in cases:
            assert len(payload) == 56, f"{case_id}: expected 56 bytes, got {len(payload)}"


# ---------------------------------------------------------------------------
# TestBinaryCorruptionCategory
# ---------------------------------------------------------------------------

class TestBinaryCorruptionCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])) >= 70

    def test_empty_payload(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        assert any(c[3] == b'' for c in cases)

    def test_all_zero_56_bytes(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        assert any(c[3] == b'\x00' * 56 for c in cases)

    def test_all_ff_56_bytes(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        assert any(c[3] == b'\xFF' * 56 for c in cases)

    def test_truncated_at_all_positions(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])]
        assert any("truncated at byte 1" in d for d in descs)
        assert any("truncated at byte 55" in d for d in descs)

    def test_wrong_pkt_type(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])]
        assert any("pkt_type" in d for d in descs)

    def test_bit_flip_cases(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])]
        assert any("bit-flip" in d for d in descs)


# ---------------------------------------------------------------------------
# TestStateMachineCategory
# ---------------------------------------------------------------------------

class TestStateMachineCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_STATE_MACHINE])) >= 12

    def test_second_init(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("INIT" in d and "established" in d for d in descs)

    def test_init_ack_from_client(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("INIT_ACK" in d and "client" in d for d in descs)

    def test_req_ack_from_client(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("REQ_ACK" in d and "client" in d for d in descs)

    def test_unknown_pkt_type(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("unknown pkt_type" in d for d in descs)

    def test_extended_msg_type(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("EXTENDED" in d or "0x80" in d for d in descs)

    def test_second_init_payload_is_all_zeros(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        second_init = next(c for c in cases if "Second INIT" in c[2])
        assert second_init[3] == b'\x00' * 56

    def test_msg_seq_boundary(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_STATE_MACHINE])]
        assert any("msg_seq=0x00" in d or "msg_seq=0x" in d for d in descs)


# ---------------------------------------------------------------------------
# TestSequenceCategory
# ---------------------------------------------------------------------------

class TestSequenceCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_SEQUENCE])) >= 15

    def test_repeated_status(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_SEQUENCE])]
        assert sum(1 for d in descs if "Rapid status" in d) >= 3

    def test_different_memory_types(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_SEQUENCE])]
        assert any("%R" in d for d in descs)
        assert any("%I" in d or "Discrete" in d for d in descs)

    def test_index_cycling(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_SEQUENCE])]
        assert any("0x0000" in d for d in descs)
        assert any("0xFFFF" in d for d in descs)

    def test_pkt_index_cycling(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_SEQUENCE])]
        assert any("pkt_index=0x0000" in d for d in descs)
        assert any("pkt_index=0xFFFF" in d for d in descs)


# ---------------------------------------------------------------------------
# TestServiceSweepCategory
# ---------------------------------------------------------------------------

class TestServiceSweepCategory:
    def test_case_count(self, fuzzer):
        # At minimum: documented combos + undocumented 0x00-0x4F + high-range samples
        assert len(fuzzer.generate_cases([CATEGORY_SERVICE_SWEEP])) >= 100

    def test_documented_svcs_present(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_SERVICE_SWEEP])]
        assert any("0x04" in d and "documented" in d for d in descs)
        assert any("0x00" in d and "documented" in d for d in descs)

    def test_undocumented_gaps_covered(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_SERVICE_SWEEP])]
        assert any("UNDOCUMENTED" in d for d in descs)
        # Code 0x01 is one of the known gaps
        assert any("0x01" in d and "UNDOCUMENTED" in d for d in descs)

    def test_high_range_covered(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_SERVICE_SWEEP])]
        assert any("0x50" in d or "0x58" in d or "high-range" in d for d in descs)

    def test_all_documented_segs_per_svc(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SERVICE_SWEEP])
        # Each documented read service should be paired with at least one of each seg type
        svc_segs = [(c[3][42], c[3][43]) for c in cases if len(c[3]) == 56]
        svc_set = {(svc, seg) for svc, seg in svc_segs}
        # Check that READ_SYS_MEM + SEG_R is covered
        assert (SVC_READ_SYS_MEM, SEG_R) in svc_set


# ---------------------------------------------------------------------------
# TestMemSweepCategory
# ---------------------------------------------------------------------------

class TestMemSweepCategory:
    def test_case_count(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_MEM_SWEEP])
        assert len(cases) == 256   # 0x00-0xFF = 256 values

    def test_all_byte_values_covered(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_MEM_SWEEP])
        segs  = {c[3][43] for c in cases if len(c[3]) == 56}
        assert segs == set(range(256))

    def test_documented_segs_labeled(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_MEM_SWEEP])]
        assert any("documented" in d and "0x08" in d for d in descs)

    def test_undocumented_segs_labeled(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_MEM_SWEEP])]
        assert any("UNDOCUMENTED" in d for d in descs)

    def test_svc_code_is_read_sys_mem(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_MEM_SWEEP])
        for c in cases:
            assert c[3][42] == SVC_READ_SYS_MEM, \
                f"Expected READ_SYS_MEM (0x04) at byte 42, got 0x{c[3][42]:02X}"


# ---------------------------------------------------------------------------
# TestExtendedMsgCategory
# ---------------------------------------------------------------------------

class TestExtendedMsgCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_EXTENDED_MSG])) >= 10

    def test_extended_msg_type(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_EXTENDED_MSG])
        ext_cases = [c for c in cases if len(c[3]) == 56 and c[3][30] == _MSG_EXTENDED]
        assert ext_cases

    def test_pkt_num_gt_total(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_EXTENDED_MSG])]
        assert any("pkt_num > total" in d or "pkt_num=3 total=1" in d for d in descs)

    def test_pkt_num_zero(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_EXTENDED_MSG])]
        assert any("pkt_num=0" in d for d in descs)

    def test_total_zero(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_EXTENDED_MSG])]
        assert any("total=0" in d for d in descs)

    def test_unknown_msg_types(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_EXTENDED_MSG])]
        assert any("0x00" in d and "unknown" in d.lower() for d in descs)
        assert any("0xFF" in d and "unknown" in d.lower() for d in descs)


# ---------------------------------------------------------------------------
# TestMailboxCategory
# ---------------------------------------------------------------------------

class TestMailboxCategory:
    def test_case_count(self, fuzzer):
        assert len(fuzzer.generate_cases([CATEGORY_MAILBOX])) >= 10

    def test_mbox_dst_zero(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_MAILBOX])]
        assert any("mbox_dst=0x00000000" in d for d in descs)

    def test_mbox_dst_all_ones(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_MAILBOX])]
        assert any("0xFFFFFFFF" in d and "mbox_dst" in d for d in descs)

    def test_mbox_src_zero(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_MAILBOX])]
        assert any("mbox_src=0x00000000" in d for d in descs)

    def test_mbox_src_all_ones(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_MAILBOX])]
        assert any("0xFFFFFFFF" in d and "mbox_src" in d for d in descs)

    def test_routing_loop_case(self, fuzzer):
        descs = [c[2] for c in fuzzer.generate_cases([CATEGORY_MAILBOX])]
        assert any("routing loop" in d for d in descs)

    def test_mbox_dst_payload_is_correct(self, fuzzer):
        cases  = fuzzer.generate_cases([CATEGORY_MAILBOX])
        # Find the zero-dst case and check the bytes
        zero   = next(c for c in cases if "mbox_dst=0x00000000" in c[2])
        mbox_dst = struct.unpack_from('<I', zero[3], 36)[0]
        assert mbox_dst == 0x00000000


# ---------------------------------------------------------------------------
# TestDangerousCategory
# ---------------------------------------------------------------------------

class TestDangerousCategory:
    def test_excluded_from_normal_generate(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert all(c[1] != CATEGORY_DANGEROUS for c in cases)

    def test_included_with_dangerous_flag(self, dangerous_fuzzer):
        cases = dangerous_fuzzer.generate_cases([CATEGORY_DANGEROUS])
        assert len(cases) > 0

    def test_set_plc_run_stop(self, dangerous_fuzzer):
        descs = [c[2] for c in dangerous_fuzzer.generate_cases([CATEGORY_DANGEROUS])]
        assert any("HALTS PLC" in d or "stop" in d.lower() for d in descs)

    def test_set_plc_run_start(self, dangerous_fuzzer):
        descs = [c[2] for c in dangerous_fuzzer.generate_cases([CATEGORY_DANGEROUS])]
        assert any("STARTS PLC" in d or "start" in d.lower() for d in descs)

    def test_write_sys_mem_present(self, dangerous_fuzzer):
        descs = [c[2] for c in dangerous_fuzzer.generate_cases([CATEGORY_DANGEROUS])]
        assert any("WRITE_SYS_MEM" in d for d in descs)

    def test_toggle_force_present(self, dangerous_fuzzer):
        descs = [c[2] for c in dangerous_fuzzer.generate_cases([CATEGORY_DANGEROUS])]
        assert any("TOGGLE_FORCE" in d or "force" in d.lower() for d in descs)

    def test_stop_plc_payload_check(self, dangerous_fuzzer):
        cases = dangerous_fuzzer.generate_cases([CATEGORY_DANGEROUS])
        stop  = next(c for c in cases if "HALTS PLC" in c[2])
        # svc_req_code at byte 42 should be SET_PLC_RUN (0x23)
        assert stop[3][42] == SVC_SET_PLC_RUN


# ---------------------------------------------------------------------------
# TestHardwareGate
# ---------------------------------------------------------------------------

class TestHardwareGate:
    def test_fuzz_raises_without_connect(self, device):
        f = GeSrtpFuzzer(target=device, logger=None, delay=0)
        with pytest.raises(RuntimeError, match="connect"):
            f.fuzz()

    def test_replay_raises_without_connect(self, device):
        f = GeSrtpFuzzer(target=device, logger=None, delay=0)
        with pytest.raises(RuntimeError, match="connect"):
            f.replay_payload(_status_req(1))

    def test_close_safe_when_not_connected(self, device):
        f = GeSrtpFuzzer(target=device, logger=None, delay=0)
        f.close()   # should not raise

    def test_generate_cases_no_connection_needed(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert len(cases) > 0

    def test_double_close_safe(self, device):
        f = GeSrtpFuzzer(target=device, logger=None, delay=0)
        f.close()
        f.close()


# ---------------------------------------------------------------------------
# TestClassifyResponse
# ---------------------------------------------------------------------------

class TestClassifyResponse:
    def _mk_result(self):
        from core.base_module import FuzzResult
        r = FuzzResult(case_id="x", protocol="ge_srtp",
                       target="127.0.0.1:18246",
                       category=CATEGORY_BOUNDARY,
                       description="test",
                       payload=b'')
        return r

    def _valid_ack(self, msg_type=_MSG_SHORT_ACK) -> bytes:
        """Build a minimal valid 56-byte REQ_ACK."""
        hdr  = struct.pack('<H', _PKT_REQ_ACK)
        hdr += struct.pack('<H', 1)   # index
        hdr += struct.pack('<H', 0)   # payload_size
        hdr += b'\x00' * 20          # reserved
        hdr += b'\x00' * 3           # timestamp
        hdr += bytes([1])            # msg_seq
        hdr += bytes([msg_type])     # msg_type
        hdr += b'\x00' * 26         # rest
        return hdr

    def test_valid_short_ack_no_anomaly(self, fuzzer):
        r = self._mk_result()
        fuzzer._classify_response(self._valid_ack(_MSG_SHORT_ACK), r)
        assert r.anomaly is None

    def test_valid_extended_ack_no_anomaly(self, fuzzer):
        r = self._mk_result()
        fuzzer._classify_response(self._valid_ack(_MSG_EXTENDED_ACK), r)
        assert r.anomaly is None

    def test_short_err_is_exception(self, fuzzer):
        r = self._mk_result()
        fuzzer._classify_response(self._valid_ack(_MSG_SHORT_ERR), r)
        assert r.anomaly == ANOMALY_EXCEPTION
        assert not r.crash_indicator

    def test_wrong_pkt_type_malformed(self, fuzzer):
        r = self._mk_result()
        data = struct.pack('<H', 0x0099) + b'\x00' * 54
        fuzzer._classify_response(data, r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert r.crash_indicator

    def test_too_short_malformed(self, fuzzer):
        r = self._mk_result()
        fuzzer._classify_response(b'\x03\x00\x00\x00', r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert r.crash_indicator

    def test_unknown_msg_type_malformed(self, fuzzer):
        r = self._mk_result()
        ack = self._valid_ack(0xAB)   # unknown msg_type
        fuzzer._classify_response(ack, r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert r.crash_indicator

    def test_init_ack_as_response_malformed(self, fuzzer):
        r = self._mk_result()
        # INIT_ACK (0x0001) as response to our REQ
        data = struct.pack('<H', _PKT_INIT_ACK) + b'\x00' * 54
        fuzzer._classify_response(data, r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE
