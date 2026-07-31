"""Unit tests for protocols/fins/fuzzer.py — no network required."""

import struct
import pytest

from protocols.fins.fuzzer import (
    AREA_CIO_BIT, AREA_CIO_WORD, AREA_COUNTER_PV, AREA_DM_BIT,
    AREA_DM_WORD, AREA_EM0_WORD, AREA_HR_WORD, AREA_TIMER_PV,
    CATEGORY_BINARY_CORRUPTION, CATEGORY_BOUNDARY,
    CATEGORY_COMMAND_SWEEP, CATEGORY_CPU_CONTROL,
    CATEGORY_MEMORY_READ, CATEGORY_MEMORY_WRITE,
    CATEGORY_SEQUENCE, CATEGORY_STATE_MACHINE,
    FinsFuzzer,
    _ICF_COMMAND, _ICF_RESPONSE,
    _MRC_CPU_RUN, _MRC_CPU_STOP, _MRC_MEMORY_READ, _MRC_MEMORY_WRITE,
    _SRC_CPU_RUN, _SRC_CPU_STOP, _SRC_MEMORY_READ, _SRC_MEMORY_WRITE,
    _fins_ctrl_data, _fins_fill, _fins_header, _fins_read, _fins_reset,
    _fins_run, _fins_status, _fins_stop, _fins_write,
)
from core.base_module import Device


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _NullLogger:
    def log(self, result): pass


def _make_fuzzer():
    dev = Device(ip="127.0.0.1", port=9610, protocol="fins")
    return FinsFuzzer(target=dev, logger=_NullLogger())


# ---------------------------------------------------------------------------
# _fins_header
# ---------------------------------------------------------------------------

class TestFinsHeader:
    def test_length(self):
        assert len(_fins_header()) == 12

    def test_icf_command_default(self):
        h = _fins_header()
        assert h[0] == _ICF_COMMAND

    def test_rsv_zero(self):
        h = _fins_header()
        assert h[1] == 0x00

    def test_gct_default(self):
        h = _fins_header()
        assert h[2] == 0x02

    def test_dna_zero(self):
        h = _fins_header()
        assert h[3] == 0x00

    def test_da1_encoded(self):
        h = _fins_header(da1=0x42)
        assert h[4] == 0x42

    def test_da2_zero(self):
        h = _fins_header()
        assert h[5] == 0x00

    def test_sna_zero(self):
        h = _fins_header()
        assert h[6] == 0x00

    def test_sa1_default(self):
        h = _fins_header(sa1=0x01)
        assert h[7] == 0x01

    def test_sid_encoded(self):
        h = _fins_header(sid=0xAB)
        assert h[9] == 0xAB

    def test_mrc_encoded(self):
        h = _fins_header(mrc=0x04)
        assert h[10] == 0x04

    def test_src_encoded(self):
        h = _fins_header(src=0x02)
        assert h[11] == 0x02


# ---------------------------------------------------------------------------
# _fins_read
# ---------------------------------------------------------------------------

class TestFinsRead:
    def test_total_length(self):
        # 12 header + 6 data = 18
        assert len(_fins_read()) == 18

    def test_mrc_is_read(self):
        p = _fins_read()
        assert p[10] == _MRC_MEMORY_READ

    def test_src_is_read(self):
        p = _fins_read()
        assert p[11] == _SRC_MEMORY_READ

    def test_area_encoded(self):
        p = _fins_read(area=AREA_DM_WORD)
        assert p[12] == AREA_DM_WORD

    def test_address_encoded_be(self):
        p = _fins_read(address=0x1234)
        assert struct.unpack_from('!H', p, 13)[0] == 0x1234

    def test_bit_encoded(self):
        p = _fins_read(bit=7)
        assert p[15] == 7

    def test_count_encoded(self):
        p = _fins_read(count=100)
        assert struct.unpack_from('!H', p, 16)[0] == 100

    def test_sid_encoded(self):
        p = _fins_read(sid=0x55)
        assert p[9] == 0x55


# ---------------------------------------------------------------------------
# _fins_write
# ---------------------------------------------------------------------------

class TestFinsWrite:
    def test_mrc_is_write(self):
        p = _fins_write(data=b'\x00\x00')
        assert p[10] == _MRC_MEMORY_WRITE

    def test_src_is_write(self):
        p = _fins_write(data=b'\x00\x00')
        assert p[11] == _SRC_MEMORY_WRITE

    def test_area_encoded(self):
        p = _fins_write(area=AREA_HR_WORD, data=b'\x00\x00')
        assert p[12] == AREA_HR_WORD

    def test_data_appended(self):
        p = _fins_write(data=b'\xAB\xCD')
        assert p[-2:] == b'\xAB\xCD'

    def test_count_encoded(self):
        p = _fins_write(count=5, data=b'\x00' * 10)
        assert struct.unpack_from('!H', p, 16)[0] == 5

    def test_empty_data(self):
        p = _fins_write(count=0, data=b'')
        assert len(p) == 18   # 12 header + 6 address data, no payload data


# ---------------------------------------------------------------------------
# _fins_run / stop / reset
# ---------------------------------------------------------------------------

class TestCpuCommands:
    def test_run_mrc(self):
        p = _fins_run()
        assert p[10] == _MRC_CPU_RUN

    def test_run_src(self):
        p = _fins_run()
        assert p[11] == _SRC_CPU_RUN

    def test_stop_mrc(self):
        p = _fins_stop()
        assert p[10] == _MRC_CPU_STOP

    def test_stop_src(self):
        p = _fins_stop()
        assert p[11] == _SRC_CPU_STOP

    def test_stop_is_12_bytes(self):
        assert len(_fins_stop()) == 12

    def test_reset_is_12_bytes(self):
        assert len(_fins_reset()) == 12

    def test_status_is_12_bytes(self):
        assert len(_fins_status()) == 12

    def test_ctrl_data_is_12_bytes(self):
        assert len(_fins_ctrl_data()) == 12


# ---------------------------------------------------------------------------
# _fins_fill
# ---------------------------------------------------------------------------

class TestFinsFill:
    def test_mrc(self):
        p = _fins_fill()
        assert p[10] == 0x01   # MRC_MEMORY_FILL

    def test_src(self):
        p = _fins_fill()
        assert p[11] == 0x03   # SRC_MEMORY_FILL

    def test_fill_data_appended(self):
        p = _fins_fill(fill_data=b'\xDE\xAD')
        assert b'\xDE\xAD' in p


# ---------------------------------------------------------------------------
# FinsFuzzer.generate_cases — category counts and structure
# ---------------------------------------------------------------------------

class TestGenerateCases:
    def setup_method(self):
        self.f = _make_fuzzer()

    def _collect(self, cat):
        return self.f.generate_cases([cat])

    def test_boundary_generates_cases(self):
        assert len(self._collect(CATEGORY_BOUNDARY)) >= 10

    def test_binary_corruption_generates_cases(self):
        assert len(self._collect(CATEGORY_BINARY_CORRUPTION)) >= 20

    def test_sequence_generates_cases(self):
        assert len(self._collect(CATEGORY_SEQUENCE)) >= 10

    def test_state_machine_generates_cases(self):
        assert len(self._collect(CATEGORY_STATE_MACHINE)) >= 8

    def test_memory_read_generates_cases(self):
        assert len(self._collect(CATEGORY_MEMORY_READ)) >= 15

    def test_memory_write_generates_cases(self):
        assert len(self._collect(CATEGORY_MEMORY_WRITE)) >= 10

    def test_cpu_control_generates_cases(self):
        assert len(self._collect(CATEGORY_CPU_CONTROL)) >= 5

    def test_command_sweep_generates_cases(self):
        assert len(self._collect(CATEGORY_COMMAND_SWEEP)) >= 15

    def test_all_categories_total(self):
        assert len(self.f.generate_cases()) >= 100

    def test_case_tuple_shape(self):
        for case in self._collect(CATEGORY_BOUNDARY):
            assert len(case) == 4
            case_id, cat, desc, payload = case
            assert isinstance(case_id, str)
            assert isinstance(cat, str)
            assert isinstance(desc, str)
            assert isinstance(payload, bytes)

    def test_case_ids_unique(self):
        cases = self.f.generate_cases()
        ids = [c[0] for c in cases]
        assert len(ids) == len(set(ids))

    def test_empty_payload_in_corruption(self):
        cases = self._collect(CATEGORY_BINARY_CORRUPTION)
        payloads = [c[3] for c in cases]
        assert b'' in payloads

    def test_all_areas_in_read(self):
        cases = self._collect(CATEGORY_MEMORY_READ)
        payloads = b''.join(c[3] for c in cases)
        for area in (AREA_CIO_WORD, AREA_DM_WORD, AREA_HR_WORD, AREA_TIMER_PV):
            assert bytes([area]) in payloads

    def test_write_includes_all_writable_areas(self):
        cases = self._collect(CATEGORY_MEMORY_WRITE)
        payloads = b''.join(c[3] for c in cases)
        for area in (AREA_CIO_WORD, AREA_DM_WORD, AREA_HR_WORD):
            assert bytes([area]) in payloads

    def test_cpu_control_includes_stop(self):
        cases = self._collect(CATEGORY_CPU_CONTROL)
        descs = [c[2] for c in cases]
        assert any("Stop" in d for d in descs)

    def test_cpu_control_includes_run(self):
        cases = self._collect(CATEGORY_CPU_CONTROL)
        descs = [c[2] for c in cases]
        assert any("Run" in d for d in descs)

    def test_command_sweep_includes_unknown_mrc(self):
        cases = self._collect(CATEGORY_COMMAND_SWEEP)
        descs = [c[2] for c in cases]
        assert any("Reserved" in d or "unknown" in d.lower() for d in descs)

    def test_boundary_includes_sid_extremes(self):
        cases = self._collect(CATEGORY_BOUNDARY)
        descs = [c[2] for c in cases]
        assert any("SID=0" in d for d in descs)
        assert any("SID=0xFF" in d or "SID=255" in d for d in descs)

    def test_category_labels_correct(self):
        for cat in FinsFuzzer.FUZZ_CATEGORIES:
            for case in self._collect(cat):
                assert case[1] == cat

    def test_single_category_filter(self):
        boundary = self.f.generate_cases([CATEGORY_BOUNDARY])
        all_cases = self.f.generate_cases()
        assert len(boundary) < len(all_cases)

    def test_icf_response_in_state_machine(self):
        cases = self._collect(CATEGORY_STATE_MACHINE)
        payloads = [c[3] for c in cases]
        # At least one case has ICF=0xC0
        assert any(p and p[0] == _ICF_RESPONSE for p in payloads if p)
