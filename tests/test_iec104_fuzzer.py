"""Generator-phase tests for Iec104Fuzzer (no live target required)."""

import struct

import pytest

from core.base_module import (
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    CATEGORY_TIMESTAMP,
    Device,
)
from protocols.iec104.fuzzer import (
    COT_ACTIVATION,
    TYPEID_C_IC_NA_1,
    Iec104Fuzzer,
    _CF1_STARTDT_ACT,
    _CF1_STOPDT_ACT,
    _CF1_TESTFR_ACT,
    _asdu,
    _gi,
    _i_frame,
    _ioa,
    _s_frame,
    _u_frame,
)


@pytest.fixture
def fuzzer():
    target = Device(ip="127.0.0.1", port=2405, protocol="iec104")
    return Iec104Fuzzer(target=target, logger=None)


# ---------------------------------------------------------------------------
# Wire-level builder unit tests
# ---------------------------------------------------------------------------

class TestWireBuilders:
    def test_u_frame_startdt_act(self):
        frame = _u_frame(_CF1_STARTDT_ACT)
        assert frame == bytes([0x68, 4, 0x07, 0x00, 0x00, 0x00])

    def test_u_frame_testfr_act(self):
        frame = _u_frame(_CF1_TESTFR_ACT)
        assert frame == bytes([0x68, 4, 0x43, 0x00, 0x00, 0x00])

    def test_s_frame_rsn_zero(self):
        frame = _s_frame(0)
        assert frame[0] == 0x68
        assert frame[1] == 4
        assert frame[2] == 0x01   # CF1 S-frame marker
        assert frame[3] == 0x00   # CF2
        assert frame[4] == 0x00   # RSN low (0 << 1 = 0)
        assert frame[5] == 0x00   # RSN high

    def test_s_frame_rsn_encoded(self):
        frame = _s_frame(5)
        rsn = struct.unpack("<H", frame[4:6])[0]
        assert rsn == (5 << 1)   # RSN stored shifted left

    def test_i_frame_ssn_rsn_encoded(self):
        gi_asdu = _asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1, _ioa(0) + b"\x14")
        frame = _i_frame(gi_asdu, ssn=3, rsn=7)
        assert frame[0] == 0x68
        assert frame[2] & 0x01 == 0   # I-frame: CF1 bit 0 = 0
        ssn = struct.unpack("<H", frame[2:4])[0] >> 1
        rsn = struct.unpack("<H", frame[4:6])[0] >> 1
        assert ssn == 3
        assert rsn == 7

    def test_i_frame_length_field(self):
        asdu = _asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1, _ioa(0) + b"\x14")
        frame = _i_frame(asdu)
        assert frame[1] == 4 + len(asdu)

    def test_asdu_structure(self):
        obj = _ioa(1) + b"\x14"  # IOA + QOI
        asdu = _asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1, obj)
        assert asdu[0] == TYPEID_C_IC_NA_1    # TypeID
        assert asdu[1] == 0x01                 # VSQ: 1 obj, SQ=0
        assert asdu[2] == COT_ACTIVATION       # COT low
        assert asdu[3] == 0x00                 # OA
        ca = struct.unpack("<H", asdu[4:6])[0]
        assert ca == 1                         # CA=1
        assert asdu[6:9] == _ioa(1)            # IOA
        assert asdu[9] == 0x14                 # QOI=20

    def test_ioa_encoding(self):
        assert _ioa(0) == b"\x00\x00\x00"
        assert _ioa(1) == b"\x01\x00\x00"
        assert _ioa(0xFFFFFF) == b"\xFF\xFF\xFF"
        assert _ioa(0x010203) == b"\x03\x02\x01"

    def test_gi_frame_is_valid_i_frame(self):
        frame = _gi()
        assert frame[0] == 0x68
        assert frame[2] & 0x01 == 0   # I-frame
        type_id = frame[6]
        assert type_id == TYPEID_C_IC_NA_1

    def test_ssn_max(self):
        asdu = _asdu(TYPEID_C_IC_NA_1, 1, COT_ACTIVATION, 1, _ioa(0) + b"\x14")
        frame = _i_frame(asdu, ssn=0x7FFF)
        cf12 = struct.unpack("<H", frame[2:4])[0]
        assert cf12 == 0xFFFE   # 0x7FFF << 1

    def test_u_frame_stopdt(self):
        frame = _u_frame(_CF1_STOPDT_ACT)
        assert frame == bytes([0x68, 4, 0x13, 0x00, 0x00, 0x00])


# ---------------------------------------------------------------------------
# generate_cases — structure tests
# ---------------------------------------------------------------------------

class TestGenerateCases:
    def test_returns_list_of_tuples(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert isinstance(cases, list)
        assert len(cases) > 0
        for item in cases:
            assert len(item) == 4
            case_id, category, description, payload = item
            assert case_id.startswith("iec104-")
            assert isinstance(category, str)
            assert isinstance(description, str)
            assert isinstance(payload, bytes)

    def test_all_categories_produced(self, fuzzer):
        cases = fuzzer.generate_cases()
        cats = {c[1] for c in cases}
        for expected_cat in fuzzer.FUZZ_CATEGORIES:
            assert expected_cat in cats, f"No cases generated for category: {expected_cat}"

    def test_case_ids_unique(self, fuzzer):
        cases = fuzzer.generate_cases()
        ids = [c[0] for c in cases]
        assert len(ids) == len(set(ids))

    def test_category_filter(self, fuzzer):
        cases = fuzzer.generate_cases(categories=["boundary"])
        assert all(c[1] == CATEGORY_BOUNDARY for c in cases)
        assert len(cases) > 0

    def test_type_id_exhaustion_256_cases(self, fuzzer):
        cases = fuzzer.generate_cases(categories=["type_id_exhaustion"])
        assert len(cases) == 256

    def test_cot_exhaustion_64_cases(self, fuzzer):
        cases = fuzzer.generate_cases(categories=["cot_exhaustion"])
        assert len(cases) == 64

    def test_all_cot_values_covered(self, fuzzer):
        cases = fuzzer.generate_cases(categories=["cot_exhaustion"])
        # Each case ASDU[2] low 6 bits should match the loop index
        for i, (_, _, desc, payload) in enumerate(cases):
            assert str(i) in desc   # description contains the COT value

    def test_type_id_exhaustion_all_typeids(self, fuzzer):
        cases = fuzzer.generate_cases(categories=["type_id_exhaustion"])
        type_ids = set()
        for _, _, _, payload in cases:
            # TypeID is at byte 6 (start + length + CF1-CF4 + TypeID)
            if len(payload) > 6:
                type_ids.add(payload[6])
        assert len(type_ids) == 256

    def test_total_case_count(self, fuzzer):
        cases = fuzzer.generate_cases()
        # We should have at least 500 cases for comprehensive coverage
        assert len(cases) >= 500


# ---------------------------------------------------------------------------
# Category-specific payload structure tests
# ---------------------------------------------------------------------------

class TestBoundaryCategory:
    def test_all_payloads_non_empty(self, fuzzer):
        cases = fuzzer.generate_cases(categories=[CATEGORY_BOUNDARY])
        for _, _, _, payload in cases:
            assert len(payload) > 0

    def test_valid_apci_structure(self, fuzzer):
        cases = fuzzer.generate_cases(categories=[CATEGORY_BOUNDARY])
        for _, _, desc, payload in cases:
            if len(payload) >= 2 and payload[0] == 0x68:
                # length field should match actual payload (for non-truncation tests)
                if "Truncated" not in desc and "length=" not in desc:
                    assert payload[1] == len(payload) - 2, (
                        f"Length mismatch in {desc}: declared {payload[1]}, actual {len(payload)-2}"
                    )

    def test_u_frames_present(self, fuzzer):
        cases = fuzzer.generate_cases(categories=[CATEGORY_BOUNDARY])
        u_frame_descs = [desc for _, _, desc, _ in cases if "U-frame" in desc]
        assert len(u_frame_descs) >= 3

    def test_s_frames_present(self, fuzzer):
        cases = fuzzer.generate_cases(categories=[CATEGORY_BOUNDARY])
        s_payloads = [p for _, _, desc, p in cases if "S-frame" in desc]
        assert len(s_payloads) > 0
        for p in s_payloads:
            assert p[0] == 0x68
            assert p[2] & 0x03 == 0x01   # S-frame marker


class TestBinaryCorruption:
    def test_wrong_start_byte_variants(self, fuzzer):
        cases = fuzzer.generate_cases(categories=[CATEGORY_BINARY_CORRUPTION])
        wrong_start = [p for _, _, desc, p in cases if "Wrong start byte" in desc]
        assert len(wrong_start) >= 4
        for p in wrong_start:
            assert p[0] != 0x68

    def test_empty_payload_present(self, fuzzer):
        cases = fuzzer.generate_cases(categories=[CATEGORY_BINARY_CORRUPTION])
        empty = [p for _, _, desc, p in cases if "Empty payload" in desc]
        assert len(empty) == 1
        assert empty[0] == b""

    def test_truncated_apdu_variants(self, fuzzer):
        cases = fuzzer.generate_cases(categories=[CATEGORY_BINARY_CORRUPTION])
        truncated = [p for _, _, desc, p in cases if "Truncated APDU" in desc]
        assert len(truncated) >= 5


class TestSequenceNumber:
    def test_ssn_rsn_values_in_payload(self, fuzzer):
        cases = fuzzer.generate_cases(categories=[CATEGORY_SEQUENCE])
        assert len(cases) >= 12

    def test_max_ssn_encoded(self, fuzzer):
        cases = fuzzer.generate_cases(categories=[CATEGORY_SEQUENCE])
        max_ssn_cases = [p for _, _, desc, p in cases if "SSN=0x7FFF" in desc]
        assert len(max_ssn_cases) > 0
        for p in max_ssn_cases:
            if len(p) >= 4 and p[0] == 0x68:
                cf12 = struct.unpack("<H", p[2:4])[0]
                ssn  = cf12 >> 1
                assert ssn == 0x7FFF


class TestStateMachine:
    def test_wrong_direction_u_frames(self, fuzzer):
        cases = fuzzer.generate_cases(categories=[CATEGORY_STATE_MACHINE])
        con_frames = [desc for _, _, desc, _ in cases if "CON" in desc]
        assert len(con_frames) >= 3


class TestGiTiming:
    def test_all_qoi_variants(self, fuzzer):
        cases = fuzzer.generate_cases(categories=["gi_timing"])
        qoi_cases = [desc for _, _, desc, _ in cases if "QOI=" in desc]
        assert len(qoi_cases) >= 4

    def test_broadcast_ca_present(self, fuzzer):
        cases = fuzzer.generate_cases(categories=["gi_timing"])
        broadcast = [p for _, _, desc, p in cases if "CA=0xFFFF" in desc]
        assert len(broadcast) >= 1

    def test_rapid_gi_burst(self, fuzzer):
        cases = fuzzer.generate_cases(categories=["gi_timing"])
        burst = [p for _, _, desc, p in cases if "burst" in desc and "GI" in desc]
        assert len(burst) >= 1
        # Multi-APDU payload should be longer than a single GI
        for p in burst:
            assert len(p) > 16


class TestCommandFlood:
    def test_float_nan_present(self, fuzzer):
        cases = fuzzer.generate_cases(categories=["command_flood"])
        nan_cases = [p for _, _, desc, p in cases if "NaN" in desc]
        assert len(nan_cases) >= 1
        for p in nan_cases:
            # Extract float bytes from payload (after APCI + ASDU header + IOA)
            if len(p) >= 6 + 6 + 3:  # APCI + ASDU_hdr + IOA
                f_bytes = p[6 + 6 + 3: 6 + 6 + 3 + 4]
                if len(f_bytes) == 4:
                    import math
                    val = struct.unpack("<f", f_bytes)[0]
                    assert math.isnan(val)

    def test_float_inf_present(self, fuzzer):
        cases = fuzzer.generate_cases(categories=["command_flood"])
        inf_cases = [p for _, _, desc, p in cases if "+Inf" in desc or "-Inf" in desc]
        assert len(inf_cases) >= 2

    def test_single_command_variants(self, fuzzer):
        cases = fuzzer.generate_cases(categories=["command_flood"])
        sc_cases = [c for c in cases if "single command" in c[2]]
        assert len(sc_cases) >= 4


# ---------------------------------------------------------------------------
# _count_apdus
# ---------------------------------------------------------------------------

class TestCountApdus:
    def test_single_apdu(self, fuzzer):
        frame = _u_frame(_CF1_STARTDT_ACT)
        assert Iec104Fuzzer._count_apdus(frame) == 1

    def test_two_apdus(self, fuzzer):
        frame = _gi() + _u_frame(_CF1_TESTFR_ACT)
        assert Iec104Fuzzer._count_apdus(frame) == 2

    def test_three_apdus(self, fuzzer):
        frame = _gi() * 3
        assert Iec104Fuzzer._count_apdus(frame) == 3

    def test_empty_payload(self, fuzzer):
        assert Iec104Fuzzer._count_apdus(b"") == 1  # max(0, 1) = 1

    def test_invalid_start_byte(self, fuzzer):
        assert Iec104Fuzzer._count_apdus(b"\x00\x04\x00\x00\x00\x00") == 1

    def test_truncated_apdu_not_counted(self, fuzzer):
        gi = _gi()
        # Only the first byte — incomplete
        assert Iec104Fuzzer._count_apdus(gi[:1]) == 1  # max(0,1)


# ---------------------------------------------------------------------------
# Hardware gate — fuzz() and connect() without a live target
# ---------------------------------------------------------------------------

class TestHardwareGate:
    def test_fuzz_raises_without_connect(self, fuzzer):
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.fuzz()

    def test_connect_refused(self):
        target = Device(ip="127.0.0.1", port=65535, protocol="iec104")
        f = Iec104Fuzzer(target=target, logger=None)
        with pytest.raises(OSError):
            f.connect(target)

    def test_replay_raises_without_connect(self, fuzzer):
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.replay_payload(b"\x68\x04\x07\x00\x00\x00")

    def test_close_without_connect_does_not_raise(self, fuzzer):
        fuzzer.close()   # should be silent
        assert fuzzer._sock is None

    def test_double_close_silent(self, fuzzer):
        fuzzer.close()
        fuzzer.close()

    def test_discover_raises_not_implemented(self, fuzzer):
        with pytest.raises(NotImplementedError):
            fuzzer.discover("eth0")
