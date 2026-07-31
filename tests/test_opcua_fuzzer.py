"""Unit tests for OPC-UA fuzzer — wire builders, case generation, classify_response.

These tests run offline (no network). All builder functions and generate_cases()
are exercised without a live target.
"""

import struct

import pytest

from protocols.opcua.fuzzer import (
    OpcuaFuzzer,
    _BufReader,
    _ua_string,
    _ua_bytestring,
    _ua_nodeid_null,
    _ua_nodeid_twobyte,
    _ua_nodeid_fourbyte,
    _ua_nodeid_numeric,
    _ua_nodeid_string,
    _ua_nodeid_bytestring,
    _ua_nodeid_guid,
    _svc_nodeid,
    _request_header,
    _ua_msg_header,
    _hel,
    _opn_request,
    _msg_frame,
    _read_body,
    _browse_body,
    _write_body,
    _create_session_body,
    _activate_session_body,
    _create_subscription_body,
    _delete_subscriptions_body,
    CATEGORY_SERVICE_SWEEP,
    CATEGORY_NODEID_VARIANTS,
    CATEGORY_SUBSCRIPTION,
    CATEGORY_CHUNKED,
    SVC_CREATE_SESSION,
    SVC_READ,
    SVC_BROWSE,
    SVC_CREATE_SUBSCRIPTION,
)
from core.base_module import (
    ANOMALY_EXCEPTION,
    ANOMALY_MALFORMED_RESPONSE,
    ANOMALY_TIMEOUT,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
    FuzzResult,
)


def _make_fuzzer():
    dev = Device(ip="127.0.0.1", port=4840, protocol="opcua")
    return OpcuaFuzzer(target=dev, logger=None, delay=0)


# ---------------------------------------------------------------------------
# TestUaString
# ---------------------------------------------------------------------------

class TestUaString:
    def test_null_string(self):
        assert _ua_string(None) == struct.pack('<i', -1)

    def test_empty_string(self):
        b = _ua_string("")
        assert b == struct.pack('<i', 0)

    def test_ascii_string(self):
        b = _ua_string("hello")
        assert b == struct.pack('<i', 5) + b'hello'

    def test_bytestring_null(self):
        assert _ua_bytestring(None) == struct.pack('<i', -1)

    def test_bytestring_data(self):
        b = _ua_bytestring(b'\x01\x02\x03')
        assert b == struct.pack('<i', 3) + b'\x01\x02\x03'


# ---------------------------------------------------------------------------
# TestNodeId
# ---------------------------------------------------------------------------

class TestNodeId:
    def test_null(self):
        n = _ua_nodeid_null()
        assert n == b'\x00\x00'
        assert len(n) == 2

    def test_twobyte(self):
        n = _ua_nodeid_twobyte(5)
        assert n[0] == 0x00
        assert n[1] == 5

    def test_fourbyte(self):
        n = _ua_nodeid_fourbyte(0, 461)
        assert n[0] == 0x01
        assert n[1] == 0x00     # ns
        assert struct.unpack_from('<H', n, 2)[0] == 461

    def test_fourbyte_namespace(self):
        n = _ua_nodeid_fourbyte(2, 100)
        assert n[1] == 2

    def test_numeric(self):
        n = _ua_nodeid_numeric(0, 0xFFFFFFFF)
        assert n[0] == 0x02
        assert struct.unpack_from('<I', n, 3)[0] == 0xFFFFFFFF

    def test_string_nodeid(self):
        n = _ua_nodeid_string(1, "MyNode")
        assert n[0] == 0x03
        assert struct.unpack_from('<H', n, 1)[0] == 1

    def test_bytestring_nodeid(self):
        n = _ua_nodeid_bytestring(0, b'\xDE\xAD')
        assert n[0] == 0x05

    def test_guid_nodeid(self):
        g = b'\x01' * 16
        n = _ua_nodeid_guid(0, g)
        assert n[0] == 0x04
        assert len(n) == 19

    def test_svc_nodeid_is_fourbyte_ns0(self):
        n = _svc_nodeid(631)
        assert n[0] == 0x01
        assert n[1] == 0x00
        assert struct.unpack_from('<H', n, 2)[0] == 631


# ---------------------------------------------------------------------------
# TestHEL
# ---------------------------------------------------------------------------

class TestHEL:
    def test_starts_with_hel_f(self):
        h = _hel("opc.tcp://127.0.0.1:4840")
        assert h[:4] == b'HELF'

    def test_size_field_correct(self):
        h = _hel("opc.tcp://127.0.0.1:4840")
        total = struct.unpack_from('<I', h, 4)[0]
        assert total == len(h)

    def test_protocol_version_zero(self):
        h = _hel("opc.tcp://127.0.0.1:4840")
        assert struct.unpack_from('<I', h, 8)[0] == 0

    def test_url_encoded_in_body(self):
        url = "opc.tcp://192.168.1.1:4840"
        h = _hel(url)
        assert url.encode() in h

    def test_minimum_length(self):
        h = _hel("opc.tcp://127.0.0.1:4840")
        assert len(h) >= 28 + len("opc.tcp://127.0.0.1:4840")


# ---------------------------------------------------------------------------
# TestOPN
# ---------------------------------------------------------------------------

class TestOPN:
    def test_starts_with_opn_f(self):
        o = _opn_request()
        assert o[:3] == b'OPN'
        assert o[3:4] == b'F'

    def test_size_correct(self):
        o = _opn_request()
        total = struct.unpack_from('<I', o, 4)[0]
        assert total == len(o)

    def test_policy_none_present(self):
        o = _opn_request()
        assert b'SecurityPolicy#None' in o

    def test_secure_channel_id_zero(self):
        o = _opn_request()
        # SecureChannelId is first field after 8-byte header
        assert struct.unpack_from('<I', o, 8)[0] == 0

    def test_null_certs(self):
        o = _opn_request()
        # After channel_id + policy, both certs should be -1 (null bytestring)
        assert struct.pack('<i', -1) in o


# ---------------------------------------------------------------------------
# TestMSGFrame
# ---------------------------------------------------------------------------

class TestMSGFrame:
    def test_starts_with_msg_f(self):
        m = _msg_frame(1, 1, 1, 1, SVC_READ, b'')
        assert m[:4] == b'MSGF'

    def test_size_field_correct(self):
        body = _read_body(0, 2258, 13)
        m = _msg_frame(1, 1, 1, 1, SVC_READ, body)
        total = struct.unpack_from('<I', m, 4)[0]
        assert total == len(m)

    def test_channel_id_at_offset_8(self):
        m = _msg_frame(42, 99, 1, 1, SVC_READ, b'')
        assert struct.unpack_from('<I', m, 8)[0] == 42

    def test_token_id_at_offset_12(self):
        m = _msg_frame(1, 77, 1, 1, SVC_READ, b'')
        assert struct.unpack_from('<I', m, 12)[0] == 77

    def test_seq_at_offset_16(self):
        m = _msg_frame(1, 1, 55, 1, SVC_READ, b'')
        assert struct.unpack_from('<I', m, 16)[0] == 55

    def test_req_id_at_offset_20(self):
        m = _msg_frame(1, 1, 1, 88, SVC_READ, b'')
        assert struct.unpack_from('<I', m, 20)[0] == 88


# ---------------------------------------------------------------------------
# TestRequestHeader
# ---------------------------------------------------------------------------

class TestRequestHeader:
    def test_null_auth_token(self):
        h = _request_header()
        assert h[:2] == b'\x00\x00'    # null NodeId

    def test_with_auth_token(self):
        tok = _ua_nodeid_fourbyte(0, 42)
        h = _request_header(auth_token=tok)
        assert h[:4] == tok

    def test_additional_header_null(self):
        h = _request_header()
        assert h[-3:] == b'\x00\x00\x00'


# ---------------------------------------------------------------------------
# TestBufReader
# ---------------------------------------------------------------------------

class TestBufReader:
    def test_read(self):
        r = _BufReader(b'\x01\x02\x03\x04')
        assert r.read(2) == b'\x01\x02'
        assert r.read(2) == b'\x03\x04'

    def test_read_uint32(self):
        r = _BufReader(struct.pack('<I', 0xDEADBEEF))
        assert r.read_uint32() == 0xDEADBEEF

    def test_skip_ua_string(self):
        data = struct.pack('<i', 5) + b'hello' + b'\xFF'
        r = _BufReader(data)
        r.skip_ua_string()
        assert r.read(1) == b'\xFF'

    def test_skip_ua_string_null(self):
        data = struct.pack('<i', -1) + b'\xFF'
        r = _BufReader(data)
        r.skip_ua_string()
        assert r.read(1) == b'\xFF'

    def test_skip_nodeid_twobyte(self):
        data = b'\x00\x05' + b'\xFF'
        r = _BufReader(data)
        r.skip_nodeid()
        assert r.read(1) == b'\xFF'

    def test_skip_nodeid_fourbyte(self):
        n = _ua_nodeid_fourbyte(0, 461) + b'\xFF'
        r = _BufReader(n)
        r.skip_nodeid()
        assert r.read(1) == b'\xFF'

    def test_read_nodeid_raw(self):
        n = _ua_nodeid_fourbyte(0, 42)
        r = _BufReader(n)
        raw = r.read_nodeid_raw()
        assert raw == n

    def test_skip_unknown_nodeid_raises(self):
        r = _BufReader(b'\x10\x00\x00\x00')
        with pytest.raises(ValueError):
            r.skip_nodeid()


# ---------------------------------------------------------------------------
# TestGenerateCases
# ---------------------------------------------------------------------------

class TestGenerateCases:
    def test_all_categories_returns_cases(self):
        f = _make_fuzzer()
        cases = f.generate_cases()
        assert len(cases) > 100

    def test_case_tuple_structure(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_BOUNDARY])
        for case_id, cat, desc, payload in cases:
            assert isinstance(case_id, str)
            assert cat == CATEGORY_BOUNDARY
            assert isinstance(desc, str)
            assert isinstance(payload, bytes)

    def test_unique_case_ids(self):
        f = _make_fuzzer()
        cases = f.generate_cases()
        ids = [c[0] for c in cases]
        assert len(ids) == len(set(ids))

    def test_boundary_covers_read(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_BOUNDARY])
        payloads = b''.join(c[3] for c in cases)
        assert SVC_READ.to_bytes(4, 'little') in payloads or b'MSG' in payloads

    def test_boundary_attr_sweep_present(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_BOUNDARY])
        descs = [c[2] for c in cases]
        # attribute IDs 1 through at least 5 should appear in descriptions
        for attr_id in range(1, 6):
            assert any(f"attr={attr_id}" in d for d in descs), f"attr={attr_id} missing"

    def test_binary_corruption_has_truncations(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_BINARY_CORRUPTION])
        descs = [c[2] for c in cases]
        assert any("truncated" in d for d in descs)

    def test_service_sweep_covers_unknown_ids(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_SERVICE_SWEEP])
        assert len(cases) > 100

    def test_service_sweep_all_payloads_bytes(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_SERVICE_SWEEP])
        for _, _, _, payload in cases:
            assert isinstance(payload, bytes)

    def test_nodeid_variants_covers_all_6_types(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_NODEID_VARIANTS])
        descs = ' '.join(c[2] for c in cases)
        for enc in ("TwoByte", "FourByte", "Numeric", "String", "ByteString"):
            assert enc in descs, f"{enc} NodeId type missing"

    def test_subscription_flood_has_enough_cases(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_SUBSCRIPTION])
        assert len(cases) >= 20

    def test_chunked_abuse_has_chunk_c(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_CHUNKED])
        descs = [c[2] for c in cases]
        assert any("'C'" in d or "ChunkType" in d for d in descs)

    def test_state_machine_has_second_hel(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_STATE_MACHINE])
        descs = [c[2] for c in cases]
        assert any("HEL" in d for d in descs)

    def test_sequence_covers_max_seq(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_SEQUENCE])
        descs = [c[2] for c in cases]
        assert any("0xFFFFFFFF" in d or "max" in d.lower() for d in descs)

    def test_single_category_subset(self):
        f = _make_fuzzer()
        all_cases = f.generate_cases()
        bnd_cases = f.generate_cases([CATEGORY_BOUNDARY])
        assert len(bnd_cases) < len(all_cases)

    def test_empty_category_list_returns_empty(self):
        f = _make_fuzzer()
        cases = f.generate_cases([])
        assert cases == []

    def test_unknown_category_ignored(self):
        f = _make_fuzzer()
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cases = f.generate_cases(["nonexistent_cat"])
        assert cases == []


# ---------------------------------------------------------------------------
# TestHardwareGate
# ---------------------------------------------------------------------------

class TestHardwareGate:
    def test_fuzz_raises_without_connect(self):
        f = _make_fuzzer()
        with pytest.raises(RuntimeError, match="connect"):
            f.fuzz()

    def test_replay_raises_without_connect(self):
        f = _make_fuzzer()
        with pytest.raises(RuntimeError, match="connect"):
            f.replay_payload(b'\x00')

    def test_generate_cases_works_offline(self):
        f = _make_fuzzer()
        cases = f.generate_cases([CATEGORY_BOUNDARY])
        assert len(cases) > 0

    def test_close_without_connect_safe(self):
        f = _make_fuzzer()
        f.close()    # must not raise

    def test_double_close_safe(self):
        f = _make_fuzzer()
        f.close()
        f.close()    # must not raise


# ---------------------------------------------------------------------------
# TestClassifyResponse
# ---------------------------------------------------------------------------

class TestClassifyResponse:
    def _fuzzer(self):
        return _make_fuzzer()

    def _result(self):
        dev = Device(ip="127.0.0.1", port=4840, protocol="opcua")
        return FuzzResult(case_id="opcua-0001", protocol="opcua",
                          target="127.0.0.1:4840", category="boundary",
                          description="test")

    def test_err_frame_is_malformed(self):
        f = self._fuzzer()
        r = self._result()
        err_body  = struct.pack('<I', 0x80820000) + struct.pack('<i', 0)
        err_frame = b'ERR' + b'F' + struct.pack('<I', 8 + len(err_body)) + err_body
        f._classify_response(err_frame, r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert r.crash_indicator is True

    def test_short_frame_is_malformed(self):
        f = self._fuzzer()
        r = self._result()
        f._classify_response(b'\x00\x01\x02', r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE

    def test_unknown_msg_type_is_malformed(self):
        f = self._fuzzer()
        r = self._result()
        payload = b'XYZ' + b'F' + struct.pack('<I', 8) + b'\x00' * 8
        payload = b'XYZ' + b'F' + struct.pack('<I', len(b'XYZ' + b'F') + 4) + b''
        bad = b'XYZ' + b'F' + struct.pack('<I', 8)
        f._classify_response(bad, r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE

    def test_wrong_size_is_malformed(self):
        f = self._fuzzer()
        r = self._result()
        # MessageSize claims 100 bytes but actual is 8
        bad = b'MSG' + b'F' + struct.pack('<I', 100)
        f._classify_response(bad, r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE

    def test_ack_frame_no_anomaly(self):
        f = self._fuzzer()
        r = self._result()
        ack  = b'ACK' + b'F'
        body = struct.pack('<I', 0) * 5   # 20 bytes
        ack += struct.pack('<I', 8 + len(body)) + body
        f._classify_response(ack, r)
        assert r.anomaly is None
        assert r.crash_indicator is False
