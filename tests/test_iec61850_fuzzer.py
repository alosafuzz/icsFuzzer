"""Unit tests for IEC 61850 fuzzer — wire builders, BER helpers, generate_cases.

All tests run offline (no network). Protocol helpers are exercised directly.
"""

import struct

import pytest

from protocols.iec61850.fuzzer import (
    ACSE_AARQ,
    CATEGORY_ADDR,
    CATEGORY_ASN1,
    CATEGORY_FRAG,
    CATEGORY_SERVICE_SWEEP,
    COTP_CR,
    Iec61850Fuzzer,
    _ACSE_AARQ,
    _ACSE_AARE,
    _COTP_CC,
    _COTP_CR,
    _COTP_DR,
    _COTP_DT,
    _MMS_CONFIRMED_ERR,
    _MMS_CONFIRMED_REQ,
    _MMS_CONFIRMED_RSP,
    _SVC_GETNAMELIST,
    _SVC_IDENTIFY,
    _SVC_READ,
    _SVC_WRITE,
    _ber,
    _ber_len,
    _extract_mms_pdu,
    _mms_getnamelist,
    _mms_identify,
    _mms_read,
    _mms_svc_sweep,
    _mms_write,
    _tpkt,
    _vis,
)
from core.base_module import (
    ANOMALY_CONNECTION_RESET,
    ANOMALY_EXCEPTION,
    ANOMALY_MALFORMED_RESPONSE,
    ANOMALY_TIMEOUT,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
)


# ── BER helper tests ──────────────────────────────────────────────────────────

class TestBerLen:
    def test_short_form_zero(self):
        assert _ber_len(0) == bytes([0x00])

    def test_short_form_max(self):
        assert _ber_len(0x7F) == bytes([0x7F])

    def test_long_form_one_byte(self):
        b = _ber_len(0x80)
        assert b == bytes([0x81, 0x80])

    def test_long_form_one_byte_max(self):
        b = _ber_len(0xFF)
        assert b == bytes([0x81, 0xFF])

    def test_long_form_two_byte(self):
        b = _ber_len(0x100)
        assert b == bytes([0x82, 0x01, 0x00])

    def test_long_form_two_byte_max(self):
        b = _ber_len(0xFFFF)
        assert b == bytes([0x82, 0xFF, 0xFF])


class TestBer:
    def test_primitive_empty(self):
        b = _ber(0x02, b'')
        assert b == bytes([0x02, 0x00])

    def test_primitive_one_byte(self):
        b = _ber(0x02, bytes([0x01]))
        assert b == bytes([0x02, 0x01, 0x01])

    def test_constructed_small(self):
        body = bytes([0x01, 0x02, 0x03])
        b = _ber(0xA0, body)
        assert b[0] == 0xA0
        assert b[1] == 0x03
        assert b[2:] == body

    def test_long_body_length_encoding(self):
        body = bytes(200)
        b = _ber(0x04, body)
        assert b[0] == 0x04
        assert b[1] == 0x81
        assert b[2] == 200
        assert b[3:] == body


class TestVisStr:
    def test_ascii(self):
        b = _vis("AB")
        assert b[0] == 0x1A
        assert b[1] == 0x02
        assert b[2:] == b"AB"

    def test_bytes_input(self):
        b = _vis(b"\xFF\xFE")
        assert b[0] == 0x1A
        assert b[1] == 0x02


# ── TPKT framing ─────────────────────────────────────────────────────────────

class TestTpkt:
    def test_empty_payload(self):
        b = _tpkt(b'')
        assert b[0] == 0x03   # version
        assert b[1] == 0x00   # reserved
        total = struct.unpack('!H', b[2:4])[0]
        # 4 TPKT + 3 COTP DT + 4 session DATA SPDU + presentation overhead
        assert total == len(b)
        assert total > 7

    def test_cotp_dt_bytes(self):
        b = _tpkt(b"x")
        assert b[4] == 0x02   # COTP LI = 2
        assert b[5] == 0xF0   # COTP DT
        assert b[6] == 0x80   # EOT = 1

    def test_length_field_matches(self):
        payload = bytes(100)
        b = _tpkt(payload)
        claimed = struct.unpack('!H', b[2:4])[0]
        assert claimed == len(b)

    def test_payload_preserved(self):
        payload = bytes(range(16))
        b = _tpkt(payload)
        # Payload is wrapped in session DATA SPDU + presentation; use helper to extract
        assert _extract_mms_pdu(b) == payload


# ── Connection byte sequences ─────────────────────────────────────────────────

class TestCoTPCR:
    def test_length_22(self):
        assert len(COTP_CR) == 22

    def test_tpkt_version(self):
        assert COTP_CR[0] == 0x03

    def test_cotp_pdu_type_cr(self):
        assert COTP_CR[5] == 0xE0

    def test_tpkt_length_field(self):
        total = struct.unpack('!H', COTP_CR[2:4])[0]
        assert total == 22


class TestACSE_AARQ:
    def test_total_length(self):
        # Full session CN + presentation CP + ACSE AARQ captured from libiec61850 client
        assert len(ACSE_AARQ) == 187

    def test_tpkt_version(self):
        assert ACSE_AARQ[0] == 0x03

    def test_cotp_dt_type(self):
        assert ACSE_AARQ[5] == 0xF0

    def test_acse_tag_is_aarq(self):
        # AARQ (0x60) is inside the session+presentation wrapper, not at byte 7
        assert 0x60 in ACSE_AARQ

    def test_tpkt_length_matches(self):
        claimed = struct.unpack('!H', ACSE_AARQ[2:4])[0]
        assert claimed == len(ACSE_AARQ)

    def test_contains_mms_abstract_syntax_oid(self):
        # OID 1.0.9506.2.1 = 28 CA 22 02 01
        assert bytes([0x28, 0xCA, 0x22, 0x02, 0x01]) in ACSE_AARQ

    def test_contains_user_information_tag(self):
        assert 0xBE in ACSE_AARQ

    def test_session_connect_spdu(self):
        # Byte 7 = Session CONNECT SPDU type (13 = 0x0d)
        assert ACSE_AARQ[7] == 0x0d


# ── MMS PDU builders ──────────────────────────────────────────────────────────

class TestMmsGetNameList:
    def test_returns_bytes(self):
        b = _mms_getnamelist(1, 9)
        assert isinstance(b, bytes)

    def test_tpkt_framing(self):
        b = _mms_getnamelist(1, 9)
        assert b[0] == 0x03
        claimed = struct.unpack('!H', b[2:4])[0]
        assert claimed == len(b)

    def test_mms_confirmed_req_tag(self):
        b = _mms_getnamelist(1, 9)
        assert _extract_mms_pdu(b)[0] == 0xA0

    def test_getnamelist_service_tag(self):
        b = _mms_getnamelist(1, 9)
        assert _SVC_GETNAMELIST in b

    def test_vmd_specific_null_present(self):
        b = _mms_getnamelist(1, 9)
        assert bytes([0x80, 0x00]) in b

    def test_domain_specific_scope(self):
        b = _mms_getnamelist(1, 9, b"TESTDOMAIN")
        assert b"TESTDOMAIN" in b
        assert bytes([0x81]) in b   # domainSpecific identifier tag

    def test_object_class_byte(self):
        for c in range(12):
            b = _mms_getnamelist(1, c)
            # object class value must appear in the payload
            assert bytes([c]) in b

    def test_invoke_id_range(self):
        for i in [0, 1, 127, 128, 255]:
            b = _mms_getnamelist(i, 9)
            assert bytes([i & 0xFF]) in b


class TestMmsIdentify:
    def test_returns_bytes(self):
        assert isinstance(_mms_identify(1), bytes)

    def test_identify_service_tag(self):
        b = _mms_identify(1)
        assert _SVC_IDENTIFY in b

    def test_empty_service_body(self):
        b = _mms_identify(1)
        # A2 00 (identify + length=0) must appear
        assert bytes([0xA2, 0x00]) in b

    def test_tpkt_length_consistent(self):
        b = _mms_identify(2)
        claimed = struct.unpack('!H', b[2:4])[0]
        assert claimed == len(b)


class TestMmsRead:
    def test_returns_bytes(self):
        b = _mms_read(1, b"D", b"I")
        assert isinstance(b, bytes)

    def test_read_service_tag(self):
        b = _mms_read(1, b"DOM", b"ITEM")
        assert _SVC_READ in b

    def test_domain_and_item_in_payload(self):
        b = _mms_read(1, b"ICS_FUZZER_TARGET", b"LLN0$DC$NamPlt")
        assert b"ICS_FUZZER_TARGET" in b
        assert b"LLN0$DC$NamPlt" in b

    def test_vis_tag_present(self):
        b = _mms_read(1, b"D", b"I")
        assert 0x1A in b   # VisibleString tag

    def test_tpkt_length_consistent(self):
        b = _mms_read(3, b"DOM", b"ITEM")
        claimed = struct.unpack('!H', b[2:4])[0]
        assert claimed == len(b)


class TestMmsWrite:
    def test_returns_bytes(self):
        b = _mms_write(1, b"D", b"I", b"\x01")
        assert isinstance(b, bytes)

    def test_write_service_tag(self):
        b = _mms_write(1, b"D", b"I", b"\x01")
        assert _SVC_WRITE in b

    def test_value_in_payload(self):
        val = bytes([0xDE, 0xAD])
        b   = _mms_write(1, b"D", b"I", val)
        assert val in b


class TestMmsSvcSweep:
    def test_arbitrary_tag(self):
        for tag in range(0xA0, 0xC0):
            b = _mms_svc_sweep(1, tag)
            assert _extract_mms_pdu(b)[0] == 0xA0   # outer confirmedRequest
            assert bytes([tag, 0x00]) in b            # sweep tag + empty body

    def test_tpkt_consistent(self):
        b = _mms_svc_sweep(1, 0xB3)
        claimed = struct.unpack('!H', b[2:4])[0]
        assert claimed == len(b)


# ── Fuzzer class ──────────────────────────────────────────────────────────────

@pytest.fixture
def fuzzer():
    dev = Device("127.0.0.1", 10200, "iec61850")
    f   = Iec61850Fuzzer(target=dev, logger=None, delay=0)
    return f


class TestFuzzCategories:
    def test_all_categories_present(self, fuzzer):
        cats = fuzzer.FUZZ_CATEGORIES
        assert CATEGORY_BOUNDARY in cats
        assert CATEGORY_BINARY_CORRUPTION in cats
        assert CATEGORY_SEQUENCE in cats
        assert CATEGORY_STATE_MACHINE in cats
        assert CATEGORY_SERVICE_SWEEP in cats
        assert CATEGORY_ASN1 in cats
        assert CATEGORY_FRAG in cats
        assert CATEGORY_ADDR in cats

    def test_generate_cases_returns_list(self, fuzzer):
        cases = fuzzer.generate_cases()
        assert isinstance(cases, list)
        assert len(cases) > 0

    def test_case_tuple_structure(self, fuzzer):
        cases = fuzzer.generate_cases()
        cid, cat, desc, payload = cases[0]
        assert isinstance(cid, str)
        assert isinstance(cat, str)
        assert isinstance(desc, str)
        assert isinstance(payload, bytes)

    def test_all_payloads_are_bytes(self, fuzzer):
        for _, _, _, payload in fuzzer.generate_cases():
            assert isinstance(payload, bytes), "all payloads must be bytes"

    def test_no_empty_descriptions(self, fuzzer):
        for _, _, desc, _ in fuzzer.generate_cases():
            assert len(desc) > 0

    def test_unique_case_ids(self, fuzzer):
        ids = [cid for cid, _, _, _ in fuzzer.generate_cases()]
        assert len(ids) == len(set(ids))


class TestBoundaryCategory:
    def test_has_cases(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        assert len(cases) > 0

    def test_all_object_classes_covered(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs = [d for _, _, d, _ in cases]
        for c in range(12):
            assert any(f"({c})" in d or f"objectClass=" in d for d in descs), \
                f"object class {c} not found in boundary cases"

    def test_identify_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs = [d for _, _, d, _ in cases]
        assert any("Identify" in d for d in descs)

    def test_read_requests_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs = [d for _, _, d, _ in cases]
        assert any("Read" in d for d in descs)

    def test_write_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        descs = [d for _, _, d, _ in cases]
        assert any("Write" in d for d in descs)


class TestBinaryCorruptionCategory:
    def test_has_cases(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        assert len(cases) >= 20

    def test_flip_tpkt_version_is_invalid(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        for _, _, desc, payload in cases:
            if "TPKT version byte" in desc:
                assert payload[0] != 0x03   # flipped from 0x03

    def test_zero_fill_acse_body(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        descs = [d for _, _, d, _ in cases]
        assert any("Zero-fill ACSE" in d for d in descs)

    def test_insert_filler_bytes(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        descs = [d for _, _, d, _ in cases]
        assert any("Insert" in d for d in descs)


class TestSequenceCategory:
    def test_has_cases(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SEQUENCE])
        assert len(cases) >= 10

    def test_cotp_cr_mid_session_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SEQUENCE])
        descs = [d for _, _, d, _ in cases]
        assert any("COTP CR again" in d or "re-connect" in d for d in descs)

    def test_pipelined_pair_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SEQUENCE])
        descs = [d for _, _, d, _ in cases]
        assert any("back-to-back" in d or "pipelined" in d for d in descs)


class TestStateMachineCategory:
    def test_has_cases(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        assert len(cases) >= 8

    def test_bad_tpkt_versions_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        descs = [d for _, _, d, _ in cases]
        assert any("TPKT version" in d for d in descs)

    def test_bad_oid_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_STATE_MACHINE])
        descs = [d for _, _, d, _ in cases]
        assert any("OID" in d for d in descs)


class TestServiceSweepCategory:
    def test_has_cases(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SERVICE_SWEEP])
        assert len(cases) >= 32

    def test_covers_a0_to_bf(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SERVICE_SWEEP])
        descs = [d for _, _, d, _ in cases]
        for tag in range(0xA0, 0xC0):
            assert any(f"0x{tag:02X}" in d for d in descs), \
                f"tag 0x{tag:02X} not swept"

    def test_confirmed_req_outer_tag(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_SERVICE_SWEEP])
        for _, _, _, payload in cases:
            mms = _extract_mms_pdu(payload)
            if mms:
                assert mms[0] == 0xA0   # outer confirmedRequestPDU


class TestAsn1BerCorruptionCategory:
    def test_has_cases(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_ASN1])
        assert len(cases) >= 12

    def test_indefinite_length_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_ASN1])
        descs = [d for _, _, d, _ in cases]
        assert any("indefinite" in d for d in descs)

    def test_long_form_length_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_ASN1])
        descs = [d for _, _, d, _ in cases]
        assert any("long-form" in d for d in descs)

    def test_overflow_cases_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_ASN1])
        descs = [d for _, _, d, _ in cases]
        assert any("overflow" in d for d in descs)

    def test_zero_length_confirmed_req_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_ASN1])
        descs = [d for _, _, d, _ in cases]
        assert any("length=0" in d for d in descs)


class TestFragmentationCategory:
    def test_has_cases(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_FRAG])
        assert len(cases) >= 9

    def test_claimed_len_exceeds_data(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_FRAG])
        for _, _, desc, payload in cases:
            if "claimed_len+1" in desc:
                claimed = struct.unpack('!H', payload[2:4])[0]
                assert claimed > len(payload)   # claimed > actual

    def test_length_zero_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_FRAG])
        descs = [d for _, _, d, _ in cases]
        assert any("length=0" in d for d in descs)

    def test_max_uint16_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_FRAG])
        descs = [d for _, _, d, _ in cases]
        assert any("65535" in d or "0xFFFF" in d for d in descs)


class TestAddressSweepCategory:
    def test_has_cases(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_ADDR])
        assert len(cases) >= 15

    def test_empty_domain_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_ADDR])
        descs = [d for _, _, d, _ in cases]
        assert any("empty" in d or "domain=b''" in d for d in descs)

    def test_path_traversal_domain(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_ADDR])
        payloads = [p for _, _, _, p in cases]
        assert any(b"../../../" in p for p in payloads)

    def test_overlong_domain(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_ADDR])
        payloads = [p for _, _, _, p in cases]
        assert any(b"A" * 64 in p for p in payloads)

    def test_continue_after_present(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_ADDR])
        descs = [d for _, _, d, _ in cases]
        assert any("continueAfter" in d for d in descs)


# ── Classify response ─────────────────────────────────────────────────────────

class TestClassifyResponse:
    @pytest.fixture
    def f(self, fuzzer):
        return fuzzer

    def test_none_is_timeout(self, f):
        anomaly, crash = f._classify_response(None)
        assert anomaly == ANOMALY_TIMEOUT
        assert crash is True

    def test_empty_bytes_is_reset(self, f):
        anomaly, crash = f._classify_response(b'')
        assert anomaly == ANOMALY_CONNECTION_RESET
        assert crash is True

    def test_short_bytes_is_malformed(self, f):
        anomaly, crash = f._classify_response(bytes([0x03, 0x00, 0x00]))
        assert anomaly == ANOMALY_MALFORMED_RESPONSE
        assert crash is True

    def test_bad_tpkt_version_is_malformed(self, f):
        payload = bytes([0x01, 0x00, 0x00, 0x08, 0x02, 0xF0, 0x80, 0xA1])
        anomaly, crash = f._classify_response(payload)
        assert anomaly == ANOMALY_MALFORMED_RESPONSE

    def test_length_mismatch_is_malformed(self, f):
        # claim length=20 but actual=8
        payload = bytes([0x03, 0x00, 0x00, 0x14, 0x02, 0xF0, 0x80, 0xA1])
        anomaly, crash = f._classify_response(payload)
        assert anomaly == ANOMALY_MALFORMED_RESPONSE
        assert crash is True

    def test_confirmed_response_is_clean(self, f):
        # valid TPKT: length = 8, COTP DT, MMS confirmedResponsePDU (A1)
        payload = bytes([0x03, 0x00, 0x00, 0x08, 0x02, 0xF0, 0x80, 0xA1])
        anomaly, crash = f._classify_response(payload)
        assert anomaly is None
        assert crash is False

    def test_confirmed_error_is_exception(self, f):
        payload = bytes([0x03, 0x00, 0x00, 0x08, 0x02, 0xF0, 0x80, 0xA2])
        anomaly, crash = f._classify_response(payload)
        assert anomaly == ANOMALY_EXCEPTION
        assert crash is False

    def test_cotp_dr_is_connection_reset(self, f):
        payload = bytes([0x03, 0x00, 0x00, 0x08, 0x02, 0x80, 0x80, 0x00])
        anomaly, crash = f._classify_response(payload)
        assert anomaly == ANOMALY_CONNECTION_RESET
        assert crash is True

    def test_unknown_mms_tag_is_malformed(self, f):
        # MMS tag 0xFF is not a known PDU type
        payload = bytes([0x03, 0x00, 0x00, 0x08, 0x02, 0xF0, 0x80, 0xFF])
        anomaly, crash = f._classify_response(payload)
        assert anomaly == ANOMALY_MALFORMED_RESPONSE
        assert crash is True


# ── connect() guard ───────────────────────────────────────────────────────────

class TestConnectGuard:
    def test_fuzz_without_connect_raises(self, fuzzer):
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.fuzz()

    def test_close_without_connect_is_safe(self, fuzzer):
        fuzzer.close()   # must not raise

    def test_generate_cases_offline(self, fuzzer):
        # generate_cases must work without a live connection
        cases = fuzzer.generate_cases()
        assert len(cases) > 0
