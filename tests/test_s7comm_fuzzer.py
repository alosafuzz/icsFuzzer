"""Unit tests for protocols/s7comm/fuzzer.py — no network required."""

import struct
import pytest

from protocols.s7comm.fuzzer import (
    AREA_DB, AREA_FLAGS, AREA_INPUTS, AREA_LOCAL, AREA_OUTPUTS,
    CATEGORY_BINARY_CORRUPTION, CATEGORY_BOUNDARY,
    CATEGORY_CPU_CONTROL, CATEGORY_PDU_NEGOTIATION,
    CATEGORY_READ_WRITE, CATEGORY_SEQUENCE, CATEGORY_STATE_MACHINE,
    CATEGORY_SZL_READ,
    S7commFuzzer,
    _COTP_CC, _COTP_CR, _COTP_DT,
    _FC_PI_SERVICE, _FC_PLC_STOP, _FC_READ_VAR, _FC_SETUP_COMM, _FC_WRITE_VAR,
    _ROSCTR_ACK, _ROSCTR_ACK_DATA, _ROSCTR_JOB, _ROSCTR_USERDATA,
    _cotp_cr, _cotp_dt, _s7_header, _s7_pkt, _s7_pi_service, _s7_plc_stop,
    _s7_read_var, _s7_setup_comm, _s7_szl_read, _s7_write_var, _tpkt,
)
from core.base_module import Device


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _NullLogger:
    def log(self, result): pass


def _make_fuzzer():
    dev = Device(ip="127.0.0.1", port=10200, protocol="s7comm")
    return S7commFuzzer(target=dev, logger=_NullLogger())


def _s7_body_offset():
    """TPKT(4) + COTP-DT(3) = 7; S7 body starts at index 7."""
    return 7


# ---------------------------------------------------------------------------
# _tpkt
# ---------------------------------------------------------------------------

class TestTpkt:
    def test_version_byte(self):
        p = _tpkt(b'\x01\x02')
        assert p[0] == 0x03

    def test_reserved_byte(self):
        p = _tpkt(b'\x01')
        assert p[1] == 0x00

    def test_length_encoding(self):
        payload = b'\xAA' * 10
        p = _tpkt(payload)
        assert struct.unpack('!H', p[2:4])[0] == 14  # 4 + 10

    def test_empty_payload_length(self):
        p = _tpkt(b'')
        assert struct.unpack('!H', p[2:4])[0] == 4

    def test_payload_preserved(self):
        payload = b'\x11\x22\x33'
        p = _tpkt(payload)
        assert p[4:] == payload


# ---------------------------------------------------------------------------
# _cotp_dt
# ---------------------------------------------------------------------------

class TestCotpDt:
    def test_li(self):
        p = _cotp_dt(b'\x32')
        assert p[0] == 0x02   # LI = length indicator

    def test_ptype(self):
        p = _cotp_dt(b'\x00')
        assert p[1] == _COTP_DT  # 0xF0

    def test_tpdu_nr(self):
        p = _cotp_dt(b'\x00')
        assert p[2] == 0x80   # end-of-TSDU bit set

    def test_payload_appended(self):
        p = _cotp_dt(b'\xAB\xCD')
        assert p[3:] == b'\xAB\xCD'


# ---------------------------------------------------------------------------
# _cotp_cr
# ---------------------------------------------------------------------------

class TestCotpCr:
    def test_tpkt_prefix(self):
        p = _cotp_cr()
        assert p[0] == 0x03  # TPKT version

    def test_ptype_is_cr(self):
        p = _cotp_cr()
        assert p[5] == _COTP_CR  # 0xE0

    def test_default_src_tsap(self):
        p = _cotp_cr(src_tsap=0x0100)
        # C1 tag at byte 14, length=2, value at bytes 16-17
        assert struct.unpack('!H', p[16:18])[0] == 0x0100

    def test_default_dst_tsap(self):
        p = _cotp_cr(dst_tsap=0x0200)
        assert struct.unpack('!H', p[20:22])[0] == 0x0200

    def test_tpkt_length_matches(self):
        p = _cotp_cr()
        assert struct.unpack('!H', p[2:4])[0] == len(p)


# ---------------------------------------------------------------------------
# _s7_header
# ---------------------------------------------------------------------------

class TestS7Header:
    def test_magic_byte(self):
        h = _s7_header()
        assert h[0] == 0x32

    def test_rosctr_job(self):
        h = _s7_header(rosctr=_ROSCTR_JOB)
        assert h[1] == _ROSCTR_JOB

    def test_rosctr_userdata(self):
        h = _s7_header(rosctr=_ROSCTR_USERDATA)
        assert h[1] == _ROSCTR_USERDATA

    def test_pdu_ref_encoding(self):
        h = _s7_header(pdu_ref=0x1234)
        assert struct.unpack('!H', h[4:6])[0] == 0x1234

    def test_param_len_encoding(self):
        h = _s7_header(param_len=8)
        assert struct.unpack('!H', h[6:8])[0] == 8

    def test_data_len_encoding(self):
        h = _s7_header(data_len=4)
        assert struct.unpack('!H', h[8:10])[0] == 4

    def test_always_10_bytes(self):
        assert len(_s7_header()) == 10


# ---------------------------------------------------------------------------
# _s7_setup_comm
# ---------------------------------------------------------------------------

class TestS7SetupComm:
    def test_is_tpkt_framed(self):
        p = _s7_setup_comm()
        assert p[0] == 0x03

    def test_rosctr_is_job(self):
        p = _s7_setup_comm()
        assert p[_s7_body_offset() + 1] == _ROSCTR_JOB

    def test_function_code(self):
        p = _s7_setup_comm()
        param_start = _s7_body_offset() + 10
        assert p[param_start] == _FC_SETUP_COMM

    def test_pdu_len_encoded(self):
        p = _s7_setup_comm(pdu_len=960)
        param_start = _s7_body_offset() + 10
        pdu_len = struct.unpack('!H', p[param_start + 6: param_start + 8])[0]
        assert pdu_len == 960

    def test_max_amq_encoded(self):
        p = _s7_setup_comm(max_amq=5)
        param_start = _s7_body_offset() + 10
        max_amq_c = struct.unpack('!H', p[param_start + 2: param_start + 4])[0]
        max_amq_s = struct.unpack('!H', p[param_start + 4: param_start + 6])[0]
        assert max_amq_c == 5
        assert max_amq_s == 5


# ---------------------------------------------------------------------------
# _s7_read_var
# ---------------------------------------------------------------------------

class TestS7ReadVar:
    def test_is_tpkt_framed(self):
        p = _s7_read_var()
        assert p[0] == 0x03

    def test_function_code(self):
        p = _s7_read_var()
        param_start = _s7_body_offset() + 10
        assert p[param_start] == _FC_READ_VAR

    def test_num_items(self):
        p = _s7_read_var()
        param_start = _s7_body_offset() + 10
        assert p[param_start + 1] == 0x01

    def test_area_db(self):
        p = _s7_read_var(area=AREA_DB, db_num=1)
        # item at param_start+2; area at offset 8 into item
        item_start = _s7_body_offset() + 10 + 2
        assert p[item_start + 8] == AREA_DB

    def test_db_num_encoded(self):
        p = _s7_read_var(area=AREA_DB, db_num=42)
        item_start = _s7_body_offset() + 10 + 2
        db_num = struct.unpack('!H', p[item_start + 6: item_start + 8])[0]
        assert db_num == 42

    def test_address_shift(self):
        # address=5 → stored as 5<<3 = 40 = 0x000028 in 3B BE
        p = _s7_read_var(address=5)
        item_start = _s7_body_offset() + 10 + 2
        raw = struct.unpack('!I', bytes([0]) + p[item_start + 9: item_start + 12])[0]
        assert raw == 5 << 3

    def test_count_encoded(self):
        p = _s7_read_var(count=100)
        item_start = _s7_body_offset() + 10 + 2
        count = struct.unpack('!H', p[item_start + 4: item_start + 6])[0]
        assert count == 100

    def test_transport_size(self):
        p = _s7_read_var(transport_size=0x06)
        item_start = _s7_body_offset() + 10 + 2
        assert p[item_start + 3] == 0x06


# ---------------------------------------------------------------------------
# _s7_write_var
# ---------------------------------------------------------------------------

class TestS7WriteVar:
    def test_function_code(self):
        p = _s7_write_var(data=b'\x00\x00')
        param_start = _s7_body_offset() + 10
        assert p[param_start] == _FC_WRITE_VAR

    def test_data_embedded(self):
        p = _s7_write_var(area=AREA_DB, db_num=1, count=1, data=b'\xAB\xCD')
        assert b'\xAB\xCD' in p

    def test_data_len_in_header(self):
        p = _s7_write_var(area=AREA_DB, db_num=1, count=1, data=b'\x00' * 4)
        # data_len in S7 header at body_offset+8
        bo = _s7_body_offset()
        data_len = struct.unpack('!H', p[bo + 8: bo + 10])[0]
        # data section = 0x00 + 0x04 + 2B bits_count + 4B data = 8
        assert data_len == 8


# ---------------------------------------------------------------------------
# _s7_szl_read
# ---------------------------------------------------------------------------

class TestS7SzlRead:
    def test_rosctr_is_userdata(self):
        p = _s7_szl_read()
        assert p[_s7_body_offset() + 1] == _ROSCTR_USERDATA

    def test_szl_id_in_data(self):
        p = _s7_szl_read(szl_id=0x0111)
        # szl_id is in the data section, packed BE
        assert struct.pack('!H', 0x0111) in p

    def test_szl_index_in_data(self):
        p = _s7_szl_read(szl_id=0x0011, szl_index=0x0002)
        assert struct.pack('!H', 0x0002) in p


# ---------------------------------------------------------------------------
# _s7_plc_stop
# ---------------------------------------------------------------------------

class TestS7PlcStop:
    def test_function_code(self):
        p = _s7_plc_stop()
        param_start = _s7_body_offset() + 10
        assert p[param_start] == _FC_PLC_STOP


# ---------------------------------------------------------------------------
# _s7_pi_service
# ---------------------------------------------------------------------------

class TestS7PiService:
    def test_function_code(self):
        p = _s7_pi_service(b'_INSE')
        param_start = _s7_body_offset() + 10
        assert p[param_start] == _FC_PI_SERVICE

    def test_pi_name_embedded(self):
        p = _s7_pi_service(b'_INSE')
        assert b'_INSE' in p

    def test_empty_pi_name(self):
        p = _s7_pi_service(b'')
        assert len(p) > 0

    def test_long_pi_name(self):
        p = _s7_pi_service(b'A' * 50)
        assert b'A' * 50 in p


# ---------------------------------------------------------------------------
# S7commFuzzer.generate_cases — category counts and structure
# ---------------------------------------------------------------------------

class TestGenerateCases:
    def setup_method(self):
        self.f = _make_fuzzer()

    def _collect(self, cat):
        return self.f.generate_cases([cat])

    def test_boundary_generates_cases(self):
        cases = self._collect(CATEGORY_BOUNDARY)
        assert len(cases) >= 10

    def test_binary_corruption_generates_cases(self):
        cases = self._collect(CATEGORY_BINARY_CORRUPTION)
        assert len(cases) >= 20

    def test_state_machine_generates_cases(self):
        cases = self._collect(CATEGORY_STATE_MACHINE)
        assert len(cases) >= 8

    def test_sequence_generates_cases(self):
        cases = self._collect(CATEGORY_SEQUENCE)
        assert len(cases) >= 10

    def test_pdu_negotiation_generates_cases(self):
        cases = self._collect(CATEGORY_PDU_NEGOTIATION)
        assert len(cases) >= 10

    def test_read_write_generates_cases(self):
        cases = self._collect(CATEGORY_READ_WRITE)
        assert len(cases) >= 15

    def test_szl_read_generates_cases(self):
        cases = self._collect(CATEGORY_SZL_READ)
        assert len(cases) >= 10

    def test_cpu_control_generates_cases(self):
        cases = self._collect(CATEGORY_CPU_CONTROL)
        assert len(cases) >= 8

    def test_all_categories_total(self):
        cases = self.f.generate_cases()
        assert len(cases) >= 100

    def test_case_tuple_shape(self):
        cases = self._collect(CATEGORY_BOUNDARY)
        for case in cases:
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

    def test_category_labels_correct(self):
        for cat in S7commFuzzer.FUZZ_CATEGORIES:
            cases = self._collect(cat)
            for case in cases:
                assert case[1] == cat

    def test_empty_payload_case_exists(self):
        cases = self._collect(CATEGORY_BINARY_CORRUPTION)
        payloads = [c[3] for c in cases]
        assert b'' in payloads

    def test_setup_comm_payload_present(self):
        cases = self._collect(CATEGORY_BOUNDARY)
        descs = [c[2] for c in cases]
        assert any("Setup Communication" in d for d in descs)

    def test_szl_id_0x0011_present(self):
        cases = self._collect(CATEGORY_SZL_READ)
        payloads = [c[3] for c in cases]
        id_bytes = struct.pack('!H', 0x0011)
        assert any(id_bytes in p for p in payloads)

    def test_plc_stop_in_cpu_control(self):
        cases = self._collect(CATEGORY_CPU_CONTROL)
        descs = [c[2] for c in cases]
        assert any("Stop" in d for d in descs)

    def test_pi_service_in_cpu_control(self):
        cases = self._collect(CATEGORY_CPU_CONTROL)
        descs = [c[2] for c in cases]
        assert any("PI service" in d for d in descs)

    def test_all_areas_in_read_write(self):
        cases = self._collect(CATEGORY_READ_WRITE)
        payloads = b''.join(c[3] for c in cases)
        for area in (AREA_INPUTS, AREA_OUTPUTS, AREA_FLAGS, AREA_DB):
            assert area.to_bytes(1, 'big') in payloads

    def test_unknown_szl_ids_present(self):
        cases = self._collect(CATEGORY_SZL_READ)
        descs = [c[2] for c in cases]
        assert any("unknown" in d for d in descs)

    def test_single_category_filter(self):
        boundary = self.f.generate_cases([CATEGORY_BOUNDARY])
        all_cats  = self.f.generate_cases()
        assert len(boundary) < len(all_cats)

    def test_pdu_ref_wraps_in_sequence(self):
        cases = self._collect(CATEGORY_SEQUENCE)
        descs = [c[2] for c in cases]
        assert any("0xFFFF" in d for d in descs)

    def test_binary_corruption_includes_truncated(self):
        cases = self._collect(CATEGORY_BINARY_CORRUPTION)
        descs = [c[2] for c in cases]
        assert any("truncated" in d for d in descs)
