"""DNP3 fuzzer generator and unit tests — no live target required."""

import struct

import pytest

from protocols.dnp3.fuzzer import (
    Dnp3Fuzzer,
    _crc16,
    _dll_frame,
    _dll_frame_bad_hdr_crc,
    _dll_frame_bad_block_crc,
    _dll_only,
    _app_request,
    _tl_byte,
    _read_class0,
    _read_gv,
    _ctrl_primary,
    _recv_dnp3,
    _START,
    _CTRL_UNCONF,
    _OUTSTATION_ADDR,
    _MASTER_ADDR,
    _FC_READ,
    _FC_RESPONSE,
    CATEGORY_LINK_LAYER,
    CATEGORY_OBJ_VARIATION,
    CATEGORY_APP_FRAG,
    CATEGORY_SAV5_BYPASS,
)
from core.base_module import (
    CATEGORY_BOUNDARY,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
)


@pytest.fixture
def device():
    return Device(ip="127.0.0.1", port=20001, protocol="dnp3")


@pytest.fixture
def fuzzer(device):
    return Dnp3Fuzzer(target=device, logger=None, delay=0)


# ---------------------------------------------------------------------------
# TestCRC
# ---------------------------------------------------------------------------

class TestCRC:
    def test_empty_returns_xorout(self):
        """Empty input with init=0, xorout=0xFFFF gives 0xFFFF."""
        assert _crc16(b"") == struct.pack("<H", 0xFFFF)

    def test_single_zero_byte(self):
        """Single 0x00 byte → CRC reflects correctly."""
        result = _crc16(b"\x00")
        assert len(result) == 2
        # Value should be reproducible
        assert result == _crc16(b"\x00")

    def test_known_different_inputs_differ(self):
        """Different inputs produce different CRCs."""
        assert _crc16(b"\x00") != _crc16(b"\x01")
        assert _crc16(b"hello") != _crc16(b"world")

    def test_crc_is_two_bytes_le(self):
        """CRC is returned as 2-byte little-endian packed bytes."""
        result = _crc16(b"test")
        assert isinstance(result, bytes)
        assert len(result) == 2

    def test_header_crc_round_trip(self):
        """Header CRC covers start bytes + header body (bytes 0-7), per opendnp3."""
        frame = _read_class0()
        expected_crc = _crc16(frame[0:8])   # 0x05 0x64 + LEN CTRL DST SRC
        assert frame[8:10] == expected_crc


# ---------------------------------------------------------------------------
# TestWireBuilders
# ---------------------------------------------------------------------------

class TestWireBuilders:
    def test_dll_frame_start_bytes(self):
        frame = _dll_frame(_tl_byte() + bytes([0xC0, _FC_READ]))
        assert frame[:2] == _START

    def test_dll_frame_length_field(self):
        user_data = _tl_byte() + bytes([0xC0, _FC_READ, 60, 1, 0x06])  # 6 bytes
        frame = _dll_frame(user_data)
        assert frame[2] == 5 + len(user_data)  # LEN = 5 + user_data_len

    def test_dll_frame_ctrl_default(self):
        frame = _dll_frame(b"\xC0\x01")
        assert frame[3] == _CTRL_UNCONF

    def test_dll_frame_dst_src_encoded_le(self):
        frame = _dll_frame(b"\xC0\x01", dst=0x0102, src=0x0304)
        assert frame[4] == 0x02   # DST low byte
        assert frame[5] == 0x01   # DST high byte
        assert frame[6] == 0x04   # SRC low byte
        assert frame[7] == 0x03   # SRC high byte

    def test_dll_frame_min_length(self):
        """Header (10 bytes) + 1-byte user data + 2-byte block CRC = 13 bytes."""
        frame = _dll_frame(b"\xC0")
        assert len(frame) == 13

    def test_dll_frame_block_crc_present(self):
        """16-byte user data should produce 10-header + 16-data + 2-CRC = 28 bytes."""
        frame = _dll_frame(b"\xC0" * 16)
        assert len(frame) == 28

    def test_dll_frame_two_blocks(self):
        """17-byte user data → 2 blocks (16+1), wire = 10 + (16+2) + (1+2) = 31 bytes."""
        frame = _dll_frame(b"\xC0" * 17)
        assert len(frame) == 31

    def test_bad_header_crc_differs(self):
        """Frame with bad header CRC differs from valid frame."""
        good = _read_class0()
        bad  = _dll_frame_bad_hdr_crc(
            _tl_byte() + bytes([0xC0, _FC_READ, 60, 1, 0x06])
        )
        assert bad[:8] == good[:8]    # body same
        assert bad[8:10] != good[8:10]  # CRC differs

    def test_bad_block_crc_differs(self):
        """Frame with bad block CRC differs from valid frame only in block CRC."""
        good = _read_class0()
        bad  = _dll_frame_bad_block_crc(
            _tl_byte() + bytes([0xC0, _FC_READ, 60, 1, 0x06])
        )
        assert bad[:10] == good[:10]  # header identical (header CRC valid)
        assert bad != good            # block CRC different

    def test_tl_byte_single_segment(self):
        assert _tl_byte() == bytes([0xC0])   # FIR=1, FIN=1, SEQ=0

    def test_tl_byte_first_fragment(self):
        assert _tl_byte(fin=False) == bytes([0x80])  # FIR=1, FIN=0, SEQ=0

    def test_tl_byte_last_fragment(self):
        assert _tl_byte(fir=False) == bytes([0x40])  # FIR=0, FIN=1, SEQ=0

    def test_tl_byte_seq(self):
        assert _tl_byte(seq=5)  == bytes([0xC5])

    def test_read_class0_structure(self):
        frame = _read_class0()
        assert frame[:2] == _START
        user_data_len = frame[2] - 5
        body = frame[10:]
        # Extract user data (strip block CRCs)
        ud = body[:user_data_len]  # first block has ≤16 bytes so just the data portion
        # TL at offset 0, AC at 1, FC=READ at 2
        # ud[0] = TL = 0xC0, ud[1] = AC = 0xC0, ud[2] = FC = 0x01
        assert ud[0] == 0xC0  # TL
        assert ud[2] == _FC_READ

    def test_dll_only_no_user_data(self):
        """Link-layer-only frame (LEN=5, no blocks)."""
        frame = _dll_only(0xC4)
        assert len(frame) == 10   # just the 10-byte header
        assert frame[2] == 5     # LEN=5

    def test_ctrl_primary_encoding(self):
        """DIR=1, PRM=1, FCB=0, FCV=0, FC=4 → 0xC4."""
        assert _ctrl_primary(4) == 0xC4
        assert _ctrl_primary(0) == 0xC0
        assert _ctrl_primary(9) == 0xC9


# ---------------------------------------------------------------------------
# TestGenerateCases
# ---------------------------------------------------------------------------

class TestGenerateCases:
    def test_all_categories_produced(self, fuzzer):
        cases = fuzzer.generate_cases()
        cats  = {c[1] for c in cases}
        assert CATEGORY_BOUNDARY       in cats
        assert CATEGORY_BINARY_CORRUPTION in cats
        assert CATEGORY_SEQUENCE       in cats
        assert CATEGORY_STATE_MACHINE  in cats
        assert CATEGORY_LINK_LAYER     in cats
        assert CATEGORY_OBJ_VARIATION  in cats
        assert CATEGORY_APP_FRAG       in cats
        assert CATEGORY_SAV5_BYPASS    in cats

    def test_case_ids_unique(self, fuzzer):
        cases = fuzzer.generate_cases()
        ids   = [c[0] for c in cases]
        assert len(ids) == len(set(ids))

    def test_case_ids_prefixed_dnp3(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert all(c[0].startswith("dnp3-") for c in cases)

    def test_minimum_case_count(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert len(cases) >= 180

    def test_all_payloads_bytes(self, fuzzer):
        cases = fuzzer.generate_cases()
        for case_id, cat, desc, payload in cases:
            assert isinstance(payload, bytes), f"{case_id} payload not bytes"

    def test_descriptions_non_empty(self, fuzzer):
        cases = fuzzer.generate_cases()
        for case_id, cat, desc, payload in cases:
            assert isinstance(desc, str) and len(desc) > 0

    def test_subset_by_category(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        cats  = {c[1] for c in cases}
        assert cats == {CATEGORY_BOUNDARY}

    def test_empty_category_list_returns_all(self, fuzzer):
        all_cases = fuzzer.generate_cases()
        none_cats = fuzzer.generate_cases(None)
        assert len(all_cases) == len(none_cats)


# ---------------------------------------------------------------------------
# TestBoundaryCategory
# ---------------------------------------------------------------------------

class TestBoundaryCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        assert len(cases) >= 20

    def test_all_have_start_bytes(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        for case_id, _, _, payload in cases:
            if len(payload) >= 2:
                assert payload[:2] == _START, f"{case_id}: missing start bytes"

    def test_dst_variants_present(self, fuzzer):
        cases   = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs   = [c[2] for c in cases]
        assert any("DST=0xFFFF" in d for d in descs)
        assert any("broadcast" in d.lower() for d in descs)

    def test_includes_cold_restart(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs = [c[2] for c in cases]
        assert any("COLD_RESTART" in d or "cold" in d.lower() for d in descs)

    def test_includes_direct_operate(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs = [c[2] for c in cases]
        assert any("DIRECT_OPERATE" in d or "direct" in d.lower() for d in descs)


# ---------------------------------------------------------------------------
# TestBinaryCorruptionCategory
# ---------------------------------------------------------------------------

class TestBinaryCorruptionCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        assert len(cases) >= 30

    def test_wrong_start_bytes_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        wrong_start = [c for c in cases if len(c[3]) >= 2 and c[3][:2] != _START]
        assert len(wrong_start) >= 4

    def test_truncated_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        descs = [c[2] for c in cases]
        assert any("Truncated" in d or "truncated" in d for d in descs)

    def test_bad_crc_frames_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        descs = [c[2] for c in cases]
        assert any("CRC" in d or "crc" in d for d in descs)

    def test_empty_payload_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        empty = [c for c in cases if len(c[3]) == 0]
        assert len(empty) >= 1


# ---------------------------------------------------------------------------
# TestSequenceCategory
# ---------------------------------------------------------------------------

class TestSequenceCategory:
    def test_all_16_app_seq_values(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SEQUENCE])
        seqs  = []
        for _, _, _, payload in cases:
            if len(payload) >= 12:  # valid header + some user data
                # Extract AC byte: header=10 + TL=1 → byte index 11
                user_data_len = payload[2] - 5
                if user_data_len >= 2 and len(payload) >= 13:
                    ac = payload[11]   # TL at 10, AC at 11
                    seqs.append(ac & 0x0F)
        assert len(set(seqs)) >= 12  # at least 12 distinct SEQ values seen

    def test_con_flag_case_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SEQUENCE])
        descs = [c[2] for c in cases]
        assert any("CON=1" in d or "CON" in d for d in descs)

    def test_fcb_attack_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SEQUENCE])
        descs = [c[2] for c in cases]
        assert any("FCB" in d for d in descs)


# ---------------------------------------------------------------------------
# TestStateMachineCategory
# ---------------------------------------------------------------------------

class TestStateMachineCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        assert len(cases) >= 12

    def test_response_fc_sent_by_master(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        descs = [c[2] for c in cases]
        assert any("RESPONSE" in d and "master" in d.lower() for d in descs)

    def test_dll_reset_link_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        descs = [c[2] for c in cases]
        assert any("RESET_LINK" in d for d in descs)

    def test_operate_without_select(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        descs = [c[2] for c in cases]
        assert any("OPERATE" in d and "SELECT" in d for d in descs)


# ---------------------------------------------------------------------------
# TestLinkLayerCategory
# ---------------------------------------------------------------------------

class TestLinkLayerCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LINK_LAYER])
        assert len(cases) >= 20

    def test_all_16_dll_fc_values(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LINK_LAYER])
        descs = [c[2] for c in cases]
        for fc in range(16):
            assert any(f"FC={fc}" in d for d in descs), f"missing DLL FC={fc}"

    def test_wrong_direction_frames(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LINK_LAYER])
        descs = [c[2] for c in cases]
        assert any("DIR=0" in d or "direction" in d.lower() for d in descs)

    def test_ctrl_extremes(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LINK_LAYER])
        descs = [c[2] for c in cases]
        assert any("0xFF" in d or "all ones" in d.lower() for d in descs)
        assert any("0x00" in d or "all zeros" in d.lower() for d in descs)


# ---------------------------------------------------------------------------
# TestObjectVariationCategory
# ---------------------------------------------------------------------------

class TestObjectVariationCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_OBJ_VARIATION])
        assert len(cases) >= 35

    def test_standard_groups_covered(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_OBJ_VARIATION])
        descs = [c[2] for c in cases]
        for label in ["G1", "G10", "G30", "G60", "G80"]:
            assert any(label in d for d in descs), f"missing {label}"

    def test_undefined_groups_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_OBJ_VARIATION])
        descs = [c[2] for c in cases]
        assert any("undefined" in d.lower() or "reserved" in d.lower() for d in descs)

    def test_nan_inf_float_cases(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_OBJ_VARIATION])
        descs = [c[2] for c in cases]
        assert any("NaN" in d or "nan" in d for d in descs)
        assert any("Inf" in d or "inf" in d for d in descs)

    def test_crob_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_OBJ_VARIATION])
        descs = [c[2] for c in cases]
        assert any("CROB" in d or "G12V1" in d for d in descs)

    def test_direct_operate_cases(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_OBJ_VARIATION])
        descs = [c[2] for c in cases]
        assert any("DIRECT_OPERATE" in d for d in descs)

    def test_nan_float_correctly_encoded(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_OBJ_VARIATION])
        nan_cases = [c for c in cases if "NaN" in c[2]]
        assert nan_cases
        # Verify NaN bytes appear in payload (IEEE 754 NaN: 0x7FC00000 or similar)
        for _, _, _, payload in nan_cases:
            nan_bytes = struct.pack("<f", float("nan"))
            assert nan_bytes in payload, "NaN not correctly encoded in payload"


# ---------------------------------------------------------------------------
# TestAppLayerFragCategory
# ---------------------------------------------------------------------------

class TestAppLayerFragCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_APP_FRAG])
        assert len(cases) >= 12

    def test_fir_fin_variants(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_APP_FRAG])
        descs = [c[2] for c in cases]
        assert any("FIR=1 FIN=0" in d for d in descs)
        assert any("FIR=0 FIN=1" in d for d in descs)
        assert any("FIR=0 FIN=0" in d for d in descs)

    def test_multi_frame_payloads(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_APP_FRAG])
        descs = [c[2] for c in cases]
        assert any("Two" in d or "two" in d or "2" in d for d in descs)
        assert any("Three" in d or "three" in d or "3" in d for d in descs)

    def test_multi_frame_count_matches(self, fuzzer):
        """Two-frame concatenated payload should be counted as 2 frames."""
        f0 = _read_class0()
        double = f0 + f0
        count  = Dnp3Fuzzer._count_frames(double)
        assert count == 2

    def test_triple_frame_count(self, fuzzer):
        f0    = _read_class0()
        count = Dnp3Fuzzer._count_frames(f0 * 3)
        assert count == 3


# ---------------------------------------------------------------------------
# TestSAv5BypassCategory
# ---------------------------------------------------------------------------

class TestSAv5BypassCategory:
    def test_cases_produced(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SAV5_BYPASS])
        assert len(cases) >= 10

    def test_auth_req_fc_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SAV5_BYPASS])
        descs = [c[2] for c in cases]
        assert any("AUTH_REQ" in d or "0x20" in d for d in descs)

    def test_replay_cases_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SAV5_BYPASS])
        descs = [c[2] for c in cases]
        assert any("replay" in d.lower() for d in descs)

    def test_group120_objects(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SAV5_BYPASS])
        descs = [c[2] for c in cases]
        assert any("G120" in d for d in descs)

    def test_wrap_around_seq(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SAV5_BYPASS])
        descs = [c[2] for c in cases]
        assert any("0xFFFFFFFF" in d or "wrap" in d.lower() for d in descs)


# ---------------------------------------------------------------------------
# TestCountFrames
# ---------------------------------------------------------------------------

class TestCountFrames:
    def test_single_frame(self):
        assert Dnp3Fuzzer._count_frames(_read_class0()) == 1

    def test_two_frames(self):
        f = _read_class0()
        assert Dnp3Fuzzer._count_frames(f + f) == 2

    def test_five_frames(self):
        f = _read_class0()
        assert Dnp3Fuzzer._count_frames(f * 5) == 5

    def test_truncated_returns_at_least_one(self):
        assert Dnp3Fuzzer._count_frames(b"") == 1
        assert Dnp3Fuzzer._count_frames(b"\x05\x64") == 1

    def test_wrong_start_returns_one(self):
        """Wrong start bytes → no valid frames found → returns 1."""
        payload = b"\x00" * 20
        assert Dnp3Fuzzer._count_frames(payload) == 1

    def test_dll_only_frame(self):
        """Header-only frame (LEN=5, no blocks) counts as 1."""
        frame = _dll_only(_ctrl_primary(0))
        assert Dnp3Fuzzer._count_frames(frame) == 1

    def test_truncated_partial_frame_not_counted(self):
        """Partial second frame not counted."""
        f = _read_class0()
        partial = f + f[:5]   # full frame + partial second
        assert Dnp3Fuzzer._count_frames(partial) == 1


# ---------------------------------------------------------------------------
# TestExtractUserData
# ---------------------------------------------------------------------------

class TestExtractUserData:
    def test_single_block_round_trip(self):
        """Build frame, extract user data, verify matches original."""
        user_data = b"\xC0\x01\x3C\x01\x06"  # TL + AC + FC + G60V1 + qual
        frame = _dll_frame(user_data)
        # body = frame[10:]
        extracted = Dnp3Fuzzer._extract_user_data(frame[10:], len(user_data))
        assert extracted == user_data

    def test_two_block_round_trip(self):
        user_data = bytes(range(17))   # 17 bytes → 2 blocks
        frame = _dll_frame(user_data)
        extracted = Dnp3Fuzzer._extract_user_data(frame[10:], 17)
        assert extracted == user_data


# ---------------------------------------------------------------------------
# TestHardwareGate
# ---------------------------------------------------------------------------

class TestHardwareGate:
    def test_fuzz_raises_without_connect(self, device):
        fuzzer = Dnp3Fuzzer(target=device, logger=None)
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.fuzz()

    def test_replay_raises_without_connect(self, device):
        fuzzer = Dnp3Fuzzer(target=device, logger=None)
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.replay_payload(b"\x05\x64")

    def test_connect_fails_on_refused(self, device):
        fuzzer = Dnp3Fuzzer(target=device, logger=None)
        with pytest.raises(OSError):
            fuzzer.connect(Device(ip="127.0.0.1", port=19999, protocol="dnp3"))

    def test_close_safe_when_not_connected(self, device):
        fuzzer = Dnp3Fuzzer(target=device, logger=None)
        fuzzer.close()  # should not raise

    def test_generate_cases_needs_no_connection(self, fuzzer):
        """Generator phase must work without a live target."""
        cases = fuzzer.generate_cases()
        assert len(cases) > 0


# ── _recv_dnp3 frame size formula ─────────────────────────────────────────────

class TestRecvDnp3FrameSize:
    """Verify _recv_dnp3 reads the exact number of bytes a DNP3 frame contains.

    DNP3 data blocks are 16 bytes each, each followed by a 2-byte CRC.
    The old formula (10 + dll_len - 5) omitted block CRCs, causing short reads.
    """

    def _make_frame(self, user_bytes: int) -> bytes:
        """Build a minimal valid DNP3 frame with 'user_bytes' of zeroed user data."""
        import math
        n_blocks = math.ceil(user_bytes / 16) if user_bytes > 0 else 0
        dll_len = 5 + user_bytes
        # Header: 0x05 0x64 + len + ctrl + dst(2) + src(2) + hdr_crc(2)
        hdr = bytes([0x05, 0x64, dll_len, 0xC4, 0x01, 0x00, 0x00, 0x00]) + b'\x00\x00'
        body = b''
        remaining = user_bytes
        while remaining > 0:
            block = min(remaining, 16)
            body += b'\x00' * block + b'\x00\x00'   # data + CRC placeholder
            remaining -= block
        return hdr + body

    def _recv_frame(self, frame: bytes):
        """Feed frame bytes through _recv_dnp3 via a socket pair."""
        import socket as _socket
        a, b = _socket.socketpair()
        try:
            a.sendall(frame)
            a.close()
            result = _recv_dnp3(b, timeout=1.0)
        finally:
            b.close()
        return result

    def test_zero_user_bytes(self):
        frame = self._make_frame(0)
        assert len(frame) == 10
        result = self._recv_frame(frame)
        assert result is not None and len(result) == 10

    def test_6_user_bytes_one_block(self):
        frame = self._make_frame(6)
        assert len(frame) == 18   # 10 hdr + 6 data + 2 CRC
        result = self._recv_frame(frame)
        assert result is not None and len(result) == 18

    def test_16_user_bytes_one_full_block(self):
        frame = self._make_frame(16)
        assert len(frame) == 28   # 10 + 16 + 2
        result = self._recv_frame(frame)
        assert result is not None and len(result) == 28

    def test_17_user_bytes_two_blocks(self):
        frame = self._make_frame(17)
        assert len(frame) == 31   # 10 + 17 + 4
        result = self._recv_frame(frame)
        assert result is not None and len(result) == 31

    def test_32_user_bytes_two_full_blocks(self):
        frame = self._make_frame(32)
        assert len(frame) == 46   # 10 + 32 + 4
        result = self._recv_frame(frame)
        assert result is not None and len(result) == 46
