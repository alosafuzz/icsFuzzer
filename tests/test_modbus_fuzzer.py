"""Unit tests for ModbusFuzzer generators — no hardware required."""

import struct
import tempfile
import os
import pytest

from core.base_module import (
    CATEGORY_BOUNDARY,
    CATEGORY_INJECTION,
    CATEGORY_STATE_MACHINE,
    CATEGORY_SEQUENCE,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_AUTH,
    Device,
    INJECTION_STRINGS,
)
from protocols.modbus.fuzzer import (
    ModbusFuzzer,
    FC_READ_HOLDING_REGS,
    FC_WRITE_SINGLE_COIL,
    FC_WRITE_SINGLE_REG,
    FC_WRITE_MULTIPLE_REGS,
    FC_WRITE_MULTIPLE_COILS,
    COIL_ON,
    COIL_OFF,
    _GAP_CODES,
    _USER_DEFINED_CODES,
    _EXCEPTION_SPACE,
)


@pytest.fixture
def device():
    return Device(ip="127.0.0.1", port=502, protocol="modbus")


@pytest.fixture
def fuzzer(device):
    return ModbusFuzzer(target=device, logger=None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_mbap(frame: bytes):
    """Return (tid, proto_id, length, unit_id, pdu) from an ADU."""
    assert len(frame) >= 7, f"Frame too short: {len(frame)} bytes"
    tid, proto_id, length, unit_id = struct.unpack(">HHHB", frame[:7])
    pdu = frame[7:]
    return tid, proto_id, length, unit_id, pdu


def is_valid_mbap_structure(frame: bytes) -> bool:
    """Verify a frame has a parseable 7-byte MBAP header."""
    return len(frame) >= 7


# ---------------------------------------------------------------------------
# MBAP helper methods
# ---------------------------------------------------------------------------

class TestMbapHelpers:
    def test_mbap_structure(self, fuzzer):
        pdu = b"\x03\x00\x00\x00\x01"
        frame = fuzzer._mbap(pdu, unit_id=0xFF, tid=0x0001)
        tid, proto_id, length, unit_id, payload = parse_mbap(frame)
        assert tid == 0x0001
        assert proto_id == 0x0000
        assert length == 1 + len(pdu)
        assert unit_id == 0xFF
        assert payload == pdu

    def test_mbap_length_field_equals_unit_id_plus_pdu(self, fuzzer):
        pdu = b"\x03\x00\x00\x00\x05"
        frame = fuzzer._mbap(pdu)
        _, _, length, _, _ = parse_mbap(frame)
        assert length == 1 + len(pdu)

    def test_mbap_raw_explicit_fields(self, fuzzer):
        pdu = b"\x03\x00\x00\x00\x01"
        frame = fuzzer._mbap_raw(0xDEAD, 0x0001, 99, 0x01, pdu)
        tid, proto_id, length, unit_id, payload = parse_mbap(frame)
        assert tid == 0xDEAD
        assert proto_id == 0x0001
        assert length == 99
        assert unit_id == 0x01
        assert payload == pdu

    def test_pdu_read_structure(self):
        pdu = ModbusFuzzer._pdu_read(FC_READ_HOLDING_REGS, 0x0010, 0x0005)
        assert pdu[0] == FC_READ_HOLDING_REGS
        start, qty = struct.unpack(">HH", pdu[1:])
        assert start == 0x0010
        assert qty == 0x0005

    def test_pdu_write_single_coil(self):
        pdu = ModbusFuzzer._pdu_write_single_coil(0x0001, COIL_ON)
        assert pdu[0] == FC_WRITE_SINGLE_COIL
        addr, val = struct.unpack(">HH", pdu[1:])
        assert addr == 0x0001
        assert val == COIL_ON

    def test_pdu_write_multiple_regs(self):
        pdu = ModbusFuzzer._pdu_write_multiple_regs(0x0000, [0xDEAD, 0xBEEF])
        assert pdu[0] == FC_WRITE_MULTIPLE_REGS
        _, qty, byte_count = struct.unpack(">HHB", pdu[1:6])
        assert qty == 2
        assert byte_count == 4
        vals = struct.unpack(">HH", pdu[6:])
        assert vals == (0xDEAD, 0xBEEF)


# ---------------------------------------------------------------------------
# --unit-id flag: unit_id constructor param + _mbap() default
# ---------------------------------------------------------------------------

class TestUnitId:
    def test_unit_id_default_is_one(self, device):
        # No unit_id arg → default must be 0x01, not 0xFF.
        # Verified via _mbap() (no explicit uid) and a generator that never
        # sets uid itself (invalid_function_codes uses self._mbap() throughout).
        fuzzer = ModbusFuzzer(target=device, logger=None)
        frame = fuzzer._mbap(b"\x03\x00\x00\x00\x01")
        assert frame[6] == 0x01, f"_mbap() default uid: expected 0x01, got 0x{frame[6]:02X}"

        for desc, payload in fuzzer._generate_invalid_function_codes():
            # _mbap_raw cases don't exist in this generator; every frame uses _mbap()
            assert len(payload) >= 7, f"Short frame: {desc}"
            assert payload[6] == 0x01, (
                f"invalid_function_codes uid: expected 0x01, got 0x{payload[6]:02X} in '{desc}'"
            )

    def test_unit_id_override(self, device):
        # unit_id=0xFF wires through _mbap() and into generated payloads.
        fuzzer = ModbusFuzzer(target=device, logger=None, unit_id=0xFF)
        frame = fuzzer._mbap(b"\x03\x00\x00\x00\x01")
        assert frame[6] == 0xFF, f"_mbap() uid: expected 0xFF, got 0x{frame[6]:02X}"

        for desc, payload in fuzzer._generate_invalid_function_codes():
            assert len(payload) >= 7, f"Short frame: {desc}"
            assert payload[6] == 0xFF, (
                f"invalid_function_codes uid: expected 0xFF, got 0x{payload[6]:02X} in '{desc}'"
            )

    def test_unit_id_cli_flag(self, device):
        # Mirrors the CLI kwarg wiring: inspect.signature detects unit_id in __init__
        # and passes args.unit_id to the constructor. Verified at the constructor level
        # (subprocess --dry-run would add no signal beyond what we assert here).
        import inspect
        sig = inspect.signature(ModbusFuzzer.__init__)
        assert "unit_id" in sig.parameters, "ModbusFuzzer.__init__ must accept unit_id"
        assert sig.parameters["unit_id"].default == 0x01, "unit_id default must be 0x01"

        fuzzer = ModbusFuzzer(target=device, logger=None, unit_id=5)
        assert fuzzer._unit_id == 5
        # Every injection case (no explicit uid in generator) must carry uid=5
        for desc, payload in fuzzer._generate_injection():
            assert len(payload) >= 7, f"Short frame: {desc}"
            assert payload[6] == 5, (
                f"injection uid: expected 5, got {payload[6]} in '{desc}'"
            )

    def test_auth_category_ignores_unit_id(self, device):
        # auth sweeps all 256 UIDs explicitly; unit_id must not collapse them to one value.
        fuzzer = ModbusFuzzer(target=device, logger=None, unit_id=5)
        sweep = [
            payload for desc, payload in fuzzer._generate_auth()
            if "unit ID sweep" in desc and len(payload) >= 7
        ]
        assert len(sweep) == 256, f"Expected 256 UID sweep cases, got {len(sweep)}"
        uids = {p[6] for p in sweep}
        assert uids == set(range(0x100)), (
            f"Auth sweep must cover all 256 UIDs; missing: "
            f"{sorted(set(range(0x100)) - uids)[:5]}"
        )

    def test_broadcast_abuse_preserves_uid(self, device):
        # broadcast_abuse sets uid explicitly per case; unit_id must not override them.
        fuzzer = ModbusFuzzer(target=device, logger=None, unit_id=5)
        cases = fuzzer._generate_broadcast_abuse()
        uids = {payload[6] for _, payload in cases if len(payload) >= 7}
        assert 0x00 in uids, "broadcast UID=0x00 must be present"
        assert 0xFF in uids, "broadcast UID=0xFF must be present"
        assert len(uids) > 1, (
            "broadcast_abuse must produce multiple UIDs; unit_id=5 must not override all"
        )


# ---------------------------------------------------------------------------
# generate_cases() — hardware-free entry point
# ---------------------------------------------------------------------------

class TestGenerateCases:
    def test_returns_list_of_tuples(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        assert isinstance(cases, list)
        assert len(cases) > 0
        for item in cases:
            assert len(item) == 4
            case_id, category, description, payload = item
            assert isinstance(case_id, str)
            assert isinstance(category, str)
            assert isinstance(description, str)
            assert isinstance(payload, bytes)

    def test_case_ids_are_unique(self, fuzzer):
        cases = fuzzer.generate_cases()
        ids = [c[0] for c in cases]
        assert len(ids) == len(set(ids))

    def test_case_ids_follow_naming_convention(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        for case_id, *_ in cases:
            assert case_id.startswith("modbus-")

    def test_all_categories_produce_cases(self, fuzzer):
        for category in ModbusFuzzer.FUZZ_CATEGORIES:
            cases = fuzzer.generate_cases([category])
            assert len(cases) > 0, f"No cases generated for category: {category}"

    def test_category_filter_respected(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        assert all(c[1] == CATEGORY_BOUNDARY for c in cases)

    def test_all_payloads_are_bytes(self, fuzzer):
        cases = fuzzer.generate_cases()
        for _, _, _, payload in cases:
            assert isinstance(payload, bytes)
            assert len(payload) > 0

    def test_total_case_count_is_substantial(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert len(cases) > 500, f"Expected >500 cases, got {len(cases)}"


# ---------------------------------------------------------------------------
# _generate_boundary
# ---------------------------------------------------------------------------

class TestGenerateBoundary:
    def test_returns_nonempty_list(self, fuzzer):
        cases = fuzzer._generate_boundary()
        assert len(cases) > 0

    def test_all_frames_have_valid_mbap(self, fuzzer):
        for desc, payload in fuzzer._generate_boundary():
            assert is_valid_mbap_structure(payload), f"Short frame in: {desc}"

    def test_fc03_qty_zero_present(self, fuzzer):
        cases = fuzzer._generate_boundary()
        descs = [d for d, _ in cases]
        assert any("qty=0" in d and "FC03" in d for d in descs)

    def test_fc03_qty_125_present(self, fuzzer):
        cases = fuzzer._generate_boundary()
        descs = [d for d, _ in cases]
        assert any("qty=125" in d and "FC03" in d for d in descs)

    def test_fc03_qty_126_present(self, fuzzer):
        cases = fuzzer._generate_boundary()
        descs = [d for d, _ in cases]
        assert any("qty=126" in d for d in descs)

    def test_fc05_invalid_coil_values_present(self, fuzzer):
        cases = fuzzer._generate_boundary()
        descs = [d for d, _ in cases]
        assert any("0x0001" in d for d in descs)
        assert any("0x00FF" in d for d in descs)
        assert any("0xFFFE" in d for d in descs)

    def test_fc05_valid_coil_values_present(self, fuzzer):
        cases = fuzzer._generate_boundary()
        descs = [d for d, _ in cases]
        assert any("0xFF00" in d for d in descs)
        assert any("0x0000" in d for d in descs)

    def test_mbap_length_boundary_cases_present(self, fuzzer):
        cases = fuzzer._generate_boundary()
        descs = [d for d, _ in cases]
        assert any("MBAP Length boundary" in d for d in descs)

    def test_fc10_byte_count_mismatch_present(self, fuzzer):
        cases = fuzzer._generate_boundary()
        descs = [d for d, _ in cases]
        assert any("byte_count" in d.lower() or "byte count" in d.lower() for d in descs)

    def test_address_ceiling_cases_present(self, fuzzer):
        cases = fuzzer._generate_boundary()
        descs = [d for d, _ in cases]
        assert any("0xFFFF" in d for d in descs)


# ---------------------------------------------------------------------------
# _generate_injection
# ---------------------------------------------------------------------------

class TestGenerateInjection:
    def test_produces_cases_for_each_builtin_payload(self, fuzzer):
        cases = fuzzer._generate_injection()
        # Each built-in payload appears at least once (FC10 + FC06 = 2 per payload)
        assert len(cases) >= len(INJECTION_STRINGS)

    def test_fc10_write_function_code(self, fuzzer):
        cases = fuzzer._generate_injection()
        fc10_cases = [(d, p) for d, p in cases if "FC10" in d]
        assert len(fc10_cases) > 0
        for _, payload in fc10_cases:
            assert len(payload) >= 7
            pdu = payload[7:]
            assert pdu[0] == FC_WRITE_MULTIPLE_REGS

    def test_fc06_write_function_code(self, fuzzer):
        cases = fuzzer._generate_injection()
        fc06_cases = [(d, p) for d, p in cases if "FC06" in d]
        assert len(fc06_cases) > 0
        for _, payload in fc06_cases:
            pdu = payload[7:]
            assert pdu[0] == FC_WRITE_SINGLE_REG

    def test_injection_file_extends_payloads(self, device):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("CUSTOM_PAYLOAD_1\n")
            f.write("CUSTOM_PAYLOAD_2\n")
            f.write("\n")  # blank line should be skipped
            tmpfile = f.name
        try:
            fuzzer = ModbusFuzzer(target=device, logger=None, injection_file=tmpfile)
            cases = fuzzer._generate_injection()
            descs = [d for d, _ in cases]
            assert any("CUSTOM_PAYLOAD_1" in d for d in descs)
            assert any("CUSTOM_PAYLOAD_2" in d for d in descs)
        finally:
            os.unlink(tmpfile)

    def test_injection_file_blank_lines_skipped(self, device):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n\n\nONLY_ONE_PAYLOAD\n\n")
            tmpfile = f.name
        try:
            fuzzer_with_file = ModbusFuzzer(target=device, logger=None, injection_file=tmpfile)
            base_fuzzer = ModbusFuzzer(target=device, logger=None)
            extra = len(fuzzer_with_file._injection_payloads) - len(base_fuzzer._injection_payloads)
            assert extra == 1
        finally:
            os.unlink(tmpfile)

    def test_payload_truncated_to_register_limit(self, fuzzer):
        # FC10 max is 123 registers = 246 bytes; very long payloads must be truncated
        cases = fuzzer._generate_injection()
        for desc, payload in cases:
            if "FC10" in desc:
                pdu = payload[7:]
                byte_count = pdu[5]
                assert byte_count <= 246


# ---------------------------------------------------------------------------
# _generate_state_machine
# ---------------------------------------------------------------------------

class TestGenerateStateMachine:
    def test_returns_nonempty_list(self, fuzzer):
        assert len(fuzzer._generate_state_machine()) > 0

    def test_proto_id_nonzero_cases_present(self, fuzzer):
        cases = fuzzer._generate_state_machine()
        descs = [d for d, _ in cases]
        assert any("Protocol ID" in d for d in descs)

    def test_starvation_case_present(self, fuzzer):
        cases = fuzzer._generate_state_machine()
        descs = [d for d, _ in cases]
        assert any("starvation" in d.lower() for d in descs)

    def test_truncation_case_present(self, fuzzer):
        cases = fuzzer._generate_state_machine()
        descs = [d for d, _ in cases]
        assert any("truncation" in d.lower() for d in descs)

    def test_duplicate_tid_case_present(self, fuzzer):
        cases = fuzzer._generate_state_machine()
        descs = [d for d, _ in cases]
        assert any("duplicate" in d.lower() and "tid" in d.lower() for d in descs)

    def test_exception_space_as_request_present(self, fuzzer):
        cases = fuzzer._generate_state_machine()
        descs = [d for d, _ in cases]
        assert any("exception space" in d.lower() for d in descs)

    def test_proto_id_nonzero_frames_have_correct_field(self, fuzzer):
        cases = fuzzer._generate_state_machine()
        for desc, payload in cases:
            if "Protocol ID=0x0001" in desc:
                _, proto_id, _, _, _ = parse_mbap(payload[:7 + 5])
                assert proto_id == 0x0001


# ---------------------------------------------------------------------------
# _generate_sequence
# ---------------------------------------------------------------------------

class TestGenerateSequence:
    def test_returns_nonempty_list(self, fuzzer):
        assert len(fuzzer._generate_sequence()) > 0

    def test_pipelined_reads_present(self, fuzzer):
        cases = fuzzer._generate_sequence()
        descs = [d for d, _ in cases]
        assert any("pipelined" in d.lower() for d in descs)

    def test_tid_wraparound_present(self, fuzzer):
        cases = fuzzer._generate_sequence()
        descs = [d for d, _ in cases]
        assert any("wraparound" in d.lower() for d in descs)

    def test_fc23_atomic_case_present(self, fuzzer):
        cases = fuzzer._generate_sequence()
        descs = [d for d, _ in cases]
        assert any("FC23" in d for d in descs)

    def test_byte_count_mismatch_cases_present(self, fuzzer):
        cases = fuzzer._generate_sequence()
        descs = [d for d, _ in cases]
        assert any("byte_count mismatch" in d for d in descs)

    def test_pipelined_payload_contains_multiple_adus(self, fuzzer):
        cases = fuzzer._generate_sequence()
        for desc, payload in cases:
            if "5 pipelined" in desc:
                # Each ADU is 12 bytes (7 MBAP + 5 PDU); 5 × 12 = 60 bytes
                assert len(payload) == 60


# ---------------------------------------------------------------------------
# _generate_binary_corruption
# ---------------------------------------------------------------------------

class TestGenerateBinaryCorruption:
    def test_returns_nonempty_list(self, fuzzer):
        assert len(fuzzer._generate_binary_corruption()) > 0

    def test_bit_flip_cases_cover_all_bits(self, fuzzer):
        cases = fuzzer._generate_binary_corruption()
        flip_cases = [(d, p) for d, p in cases if "Bit flip" in d]
        # 12-byte base frame × 8 bits = 96 bit-flip cases
        assert len(flip_cases) == 12 * 8

    def test_truncation_cases_cover_all_lengths(self, fuzzer):
        cases = fuzzer._generate_binary_corruption()
        trunc_cases = [d for d, _ in cases if "Truncation" in d]
        # Truncations from 1 to 11 bytes (base is 12 bytes, so 11 cases)
        assert len(trunc_cases) == 11

    def test_byte_sub_cases_present(self, fuzzer):
        cases = fuzzer._generate_binary_corruption()
        sub_cases = [d for d, _ in cases if "Byte sub" in d]
        # 12 bytes × 3 values (0x00, 0xFF, 0xAA) = 36 cases
        assert len(sub_cases) == 36

    def test_byte_swap_cases_present(self, fuzzer):
        cases = fuzzer._generate_binary_corruption()
        swap_cases = [d for d, _ in cases if "Byte swap" in d]
        # 11 adjacent pairs in 12-byte frame
        assert len(swap_cases) == 11

    def test_bit_flip_produces_correct_mutation(self, fuzzer):
        cases = fuzzer._generate_binary_corruption()
        # Find the first bit-flip case (byte[0] bit 0)
        for desc, payload in cases:
            if "Bit flip byte[0] bit 0" in desc:
                # The original frame has TID=0x0001 at bytes 0-1
                # Flipping bit 0 of byte 0 (0x00) → 0x01
                assert payload[0] in (0x00 ^ 1, 0x01)
                break


# ---------------------------------------------------------------------------
# _generate_auth
# ---------------------------------------------------------------------------

class TestGenerateAuth:
    def test_returns_nonempty_list(self, fuzzer):
        assert len(fuzzer._generate_auth()) > 0

    def test_unit_id_sweep_covers_all_256_values(self, fuzzer):
        cases = fuzzer._generate_auth()
        sweep_cases = [(d, p) for d, p in cases if "unit ID sweep" in d]
        assert len(sweep_cases) == 256

    def test_sweep_covers_broadcast_uid(self, fuzzer):
        cases = fuzzer._generate_auth()
        descs = [d for d, _ in cases]
        assert any("UID=0x00" in d for d in descs)

    def test_sweep_covers_reserved_uid(self, fuzzer):
        cases = fuzzer._generate_auth()
        descs = [d for d, _ in cases]
        assert any("UID=0xFF" in d for d in descs)

    def test_reserved_uid_write_commands_present(self, fuzzer):
        cases = fuzzer._generate_auth()
        descs = [d for d, _ in cases]
        assert any("FC06 write to reserved" in d for d in descs)

    def test_tid_probes_present(self, fuzzer):
        cases = fuzzer._generate_auth()
        descs = [d for d, _ in cases]
        assert any("transaction ID probe" in d for d in descs)

    def test_unit_id_field_set_correctly_in_sweep(self, fuzzer):
        cases = fuzzer._generate_auth()
        for uid in [0x00, 0x01, 0xF7, 0xFF]:
            for desc, payload in cases:
                if f"UID=0x{uid:02X}" in desc and "unit ID sweep" in desc:
                    _, _, _, frame_uid, _ = parse_mbap(payload)
                    assert frame_uid == uid
                    break


# ---------------------------------------------------------------------------
# _generate_invalid_function_codes
# ---------------------------------------------------------------------------

class TestGenerateInvalidFunctionCodes:
    def test_returns_nonempty_list(self, fuzzer):
        assert len(fuzzer._generate_invalid_function_codes()) > 0

    def test_gap_codes_all_covered(self, fuzzer):
        cases = fuzzer._generate_invalid_function_codes()
        for fc in _GAP_CODES:
            assert any(f"0x{fc:02X}" in d for d, _ in cases), f"Gap code 0x{fc:02X} not covered"

    def test_user_defined_codes_all_covered(self, fuzzer):
        cases = fuzzer._generate_invalid_function_codes()
        for fc in _USER_DEFINED_CODES:
            assert any(f"0x{fc:02X}" in d for d, _ in cases), f"User-defined 0x{fc:02X} not covered"

    def test_exception_space_all_covered(self, fuzzer):
        cases = fuzzer._generate_invalid_function_codes()
        for fc in _EXCEPTION_SPACE:
            assert any(f"0x{fc:02X}" in d for d, _ in cases), f"Exception-space 0x{fc:02X} not covered"

    def test_null_function_code_present(self, fuzzer):
        cases = fuzzer._generate_invalid_function_codes()
        # FC 0x00 is a gap code
        assert any("0x00" in d for d, _ in cases)

    def test_function_code_set_correctly_in_frame(self, fuzzer):
        cases = fuzzer._generate_invalid_function_codes()
        for desc, payload in cases:
            if "0x09" in desc and "no data" in desc:
                pdu = payload[7:]
                assert pdu[0] == 0x09
                break


# ---------------------------------------------------------------------------
# _generate_broadcast_abuse
# ---------------------------------------------------------------------------

class TestGenerateBroadcastAbuse:
    def test_returns_nonempty_list(self, fuzzer):
        assert len(fuzzer._generate_broadcast_abuse()) > 0

    def test_uid_zero_write_cases_present(self, fuzzer):
        cases = fuzzer._generate_broadcast_abuse()
        descs = [d for d, _ in cases]
        assert any("UID=0x00" in d and "Write" in d for d in descs)

    def test_uid_ff_write_cases_present(self, fuzzer):
        cases = fuzzer._generate_broadcast_abuse()
        descs = [d for d, _ in cases]
        assert any("UID=0xFF" in d and "Write" in d for d in descs)

    def test_reserved_uid_write_cases_present(self, fuzzer):
        cases = fuzzer._generate_broadcast_abuse()
        descs = [d for d, _ in cases]
        assert any("serial reserved" in d and "Write" in d for d in descs)

    def test_broadcast_read_case_present(self, fuzzer):
        cases = fuzzer._generate_broadcast_abuse()
        descs = [d for d, _ in cases]
        assert any("read" in d.lower() and "no response" in d.lower() for d in descs)

    def test_uid_zero_set_correctly_in_frame(self, fuzzer):
        cases = fuzzer._generate_broadcast_abuse()
        for desc, payload in cases:
            if "UID=0x00" in desc and "FC06" in desc:
                _, _, _, unit_id, _ = parse_mbap(payload)
                assert unit_id == 0x00
                break

    def test_all_write_fcs_covered_for_broadcast(self, fuzzer):
        cases = fuzzer._generate_broadcast_abuse()
        descs = " ".join(d for d, _ in cases)
        assert "FC05" in descs
        assert "FC06" in descs
        assert "FC0F" in descs
        assert "FC10" in descs


# ---------------------------------------------------------------------------
# _generate_coil_aliasing
# ---------------------------------------------------------------------------

class TestGenerateCoilAliasing:
    def test_returns_nonempty_list(self, fuzzer):
        assert len(fuzzer._generate_coil_aliasing()) > 0

    def test_write_then_read_different_type_present(self, fuzzer):
        cases = fuzzer._generate_coil_aliasing()
        descs = [d for d, _ in cases]
        assert any("FC05" in d and "FC03" in d for d in descs)

    def test_boundary_address_cases_present(self, fuzzer):
        cases = fuzzer._generate_coil_aliasing()
        descs = [d for d, _ in cases]
        assert any("0x0010" in d for d in descs)

    def test_multi_coil_write_with_reg_read_present(self, fuzzer):
        cases = fuzzer._generate_coil_aliasing()
        descs = [d for d, _ in cases]
        assert any("1968 coils" in d for d in descs)

    def test_paired_frames_are_two_adus(self, fuzzer):
        cases = fuzzer._generate_coil_aliasing()
        for desc, payload in cases:
            if "→" in desc:
                # Should contain two ADUs: each at least 7+1 = 8 bytes
                assert len(payload) >= 16, f"Payload too short for two ADUs in: {desc}"


# ---------------------------------------------------------------------------
# fuzz() raises NotImplementedError (hardware gate preserved)
# ---------------------------------------------------------------------------

class TestFuzzHardwareGate:
    def test_fuzz_raises_without_connect(self, fuzzer):
        # fuzz() requires connect() — RuntimeError before any case is sent
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.fuzz()

    def test_generate_cases_does_not_raise(self, fuzzer):
        # generate_cases() must work without hardware
        cases = fuzzer.generate_cases()
        assert len(cases) > 0

    def test_connect_refused_without_server(self):
        # Connecting to a port with nothing listening raises OSError
        target = Device(ip="127.0.0.1", port=65535, protocol="modbus")
        f = ModbusFuzzer(target=target, logger=None)
        try:
            with pytest.raises(OSError):
                f.connect(target)
        finally:
            f.close()

    def test_replay_raises_without_connect(self, fuzzer):
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.replay_payload(b"\x00\x01\x00\x00\x00\x06\xFF\x03\x00\x00\x00\x01")

    def test_discover_raises_not_implemented(self, fuzzer):
        with pytest.raises(NotImplementedError):
            fuzzer.discover("eth0")

    def test_close_does_not_raise(self, fuzzer):
        fuzzer.close()  # no socket open; must not raise
        assert fuzzer._sock is None


# ---------------------------------------------------------------------------
# _GAP_CODES correctness
# ---------------------------------------------------------------------------

class TestGapCodes:
    def test_assigned_public_not_in_gap_codes(self):
        from protocols.modbus.fuzzer import _ASSIGNED_PUBLIC
        for fc in _GAP_CODES:
            assert fc not in _ASSIGNED_PUBLIC, f"Assigned FC 0x{fc:02X} wrongly in _GAP_CODES"

    def test_gap_codes_not_in_exception_space(self):
        for fc in _GAP_CODES:
            assert fc < 0x80, f"FC 0x{fc:02X} is in exception space but listed as gap"

    def test_gap_codes_not_in_user_defined(self):
        for fc in _GAP_CODES:
            assert fc not in _USER_DEFINED_CODES, f"FC 0x{fc:02X} is user-defined but in gap codes"
