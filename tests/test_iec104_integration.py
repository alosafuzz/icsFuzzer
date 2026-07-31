"""Integration tests for Iec104Fuzzer send/receive path.

Spins up an inline IEC 104 responder on a free loopback port so the full
send loop, STARTDT handshake, anomaly classification, and JSONL logging can
be exercised without a physical RTU/IED.
"""

import json
import socket
import struct
import threading

import pytest

from core.base_module import (
    ANOMALY_EXCEPTION,
    ANOMALY_MALFORMED_RESPONSE,
    Device,
    FuzzResult,
)
from protocols.iec104.fuzzer import (
    COT_ACTIVATION,
    TYPEID_C_IC_NA_1,
    Iec104Fuzzer,
    _CF1_STARTDT_ACT,
    _CF1_TESTFR_ACT,
    _CF1_TESTFR_CON,
    _gi,
    _i_frame,
    _asdu,
    _ioa,
    _u_frame,
)


# ---------------------------------------------------------------------------
# Inline responder fixture
# ---------------------------------------------------------------------------

class _NoopSidecar:
    def log(self, *args, **kwargs):
        pass


def _handle_conn(conn, addr):
    from scripts.iec104_responder import handle_client
    handle_client(conn, addr, sidecar=_NoopSidecar(), verbose=False)


@pytest.fixture(scope="module")
def iec104_server():
    """IEC 104 responder on a free loopback port. Module-scoped for speed."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(20)
    host, port = srv.getsockname()
    stop = threading.Event()

    def _accept():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, addr = srv.accept()
                threading.Thread(target=_handle_conn, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue

    threading.Thread(target=_accept, daemon=True).start()
    yield host, port
    stop.set()
    srv.close()


@pytest.fixture
def connected_fuzzer(iec104_server):
    host, port = iec104_server
    target = Device(ip=host, port=port, protocol="iec104")
    f = Iec104Fuzzer(target=target, logger=None, delay=0)
    f.connect(target)
    yield f
    f.close()


# ---------------------------------------------------------------------------
# STARTDT handshake
# ---------------------------------------------------------------------------

class TestHandshake:
    def test_connect_establishes_startdt(self, iec104_server):
        host, port = iec104_server
        target = Device(ip=host, port=port, protocol="iec104")
        f = Iec104Fuzzer(target=target, logger=None, delay=0)
        f.connect(target)
        assert f._sock is not None
        assert f._ssn == 0
        f.close()
        assert f._sock is None

    def test_double_close_silent(self, iec104_server):
        host, port = iec104_server
        target = Device(ip=host, port=port, protocol="iec104")
        f = Iec104Fuzzer(target=target, logger=None)
        f.connect(target)
        f.close()
        f.close()

    def test_close_without_connect(self):
        target = Device(ip="127.0.0.1", port=2405, protocol="iec104")
        f = Iec104Fuzzer(target=target, logger=None)
        f.close()   # must not raise


# ---------------------------------------------------------------------------
# _send_case — I-frame round-trip
# ---------------------------------------------------------------------------

class TestSendCase:
    def test_gi_returns_exception_anomaly(self, connected_fuzzer):
        result = connected_fuzzer._send_case(
            "t-001", "gi_timing", "GI round-trip", _gi()
        )
        assert result.anomaly == ANOMALY_EXCEPTION
        assert result.crash_indicator is False

    def test_exception_response_decoded(self, connected_fuzzer):
        result = connected_fuzzer._send_case(
            "t-002", "gi_timing", "GI exception decode", _gi()
        )
        assert result.response_decoded is not None
        assert "cot" in result.response_decoded
        assert result.response_decoded["cot"] == 44  # COT_UNKNOWN_TI

    def test_result_fields_populated(self, connected_fuzzer):
        result = connected_fuzzer._send_case(
            "t-003", "gi_timing", "Field check", _gi()
        )
        assert result.case_id == "t-003"
        assert result.protocol == "iec104"
        assert result.category == "gi_timing"
        assert result.payload == _gi()
        assert result.response is not None
        assert result.duration_ms is not None and result.duration_ms >= 0

    def test_testfr_returns_no_anomaly(self, connected_fuzzer):
        result = connected_fuzzer._send_case(
            "t-004", "boundary", "TESTFR_ACT", _u_frame(_CF1_TESTFR_ACT)
        )
        # TESTFR_CON is expected — no anomaly
        assert result.anomaly is None
        assert result.crash_indicator is False

    def test_s_frame_returns_no_anomaly(self, connected_fuzzer):
        from protocols.iec104.fuzzer import _s_frame
        result = connected_fuzzer._send_case(
            "t-005", "boundary", "S-frame RSN=0", _s_frame(0)
        )
        # S-frame gets no response from the responder; expect timeout or no-response
        # The responder ignores S-frames — the result will be a timeout
        assert result.anomaly is not None  # timeout or no_response, not an error

    def test_malformed_start_byte_triggers_reconnect(self, connected_fuzzer):
        bad = bytearray(_gi())
        bad[0] = 0x00
        result = connected_fuzzer._send_case(
            "t-006", ANOMALY_MALFORMED_RESPONSE, "bad start byte", bytes(bad)
        )
        # Responder closes on bad start byte → connection reset or timeout
        assert result.crash_indicator is True

    def test_ssn_increments_after_i_frame(self, connected_fuzzer):
        ssn_before = connected_fuzzer._ssn
        connected_fuzzer._send_case("t-007", "gi_timing", "SSN inc", _gi())
        assert connected_fuzzer._ssn == (ssn_before + 1) & 0x7FFF

    def test_ssn_not_incremented_for_u_frame(self, connected_fuzzer):
        ssn_before = connected_fuzzer._ssn
        connected_fuzzer._send_case(
            "t-008", "boundary", "TESTFR no SSN inc",
            _u_frame(_CF1_TESTFR_ACT)
        )
        assert connected_fuzzer._ssn == ssn_before  # U-frame: no SSN change


# ---------------------------------------------------------------------------
# Response classification
# ---------------------------------------------------------------------------

class TestClassifyResponse:
    def test_malformed_start_byte(self, connected_fuzzer):
        payload = _gi()
        fake_resp = bytes([0x00, 0x0E]) + bytes(12)
        result = FuzzResult("x", "iec104", "t", "test", "bad start")
        connected_fuzzer._classify_response(payload, fake_resp, result)
        assert result.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert result.crash_indicator is True

    def test_length_mismatch(self, connected_fuzzer):
        payload = _gi()
        # Declare length=14 but only provide 6 bytes total (2 header + 4 body)
        fake_resp = bytes([0x68, 14]) + bytes(4)
        result = FuzzResult("x", "iec104", "t", "test", "len mismatch")
        connected_fuzzer._classify_response(payload, fake_resp, result)
        assert result.anomaly == ANOMALY_MALFORMED_RESPONSE

    def test_exception_cot_classified(self, connected_fuzzer):
        payload = _gi()
        # Build a valid I-frame exception response (COT=44)
        asdu = bytes([TYPEID_C_IC_NA_1, 0x01, 44, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
        resp = bytes([0x68, 4 + len(asdu)]) + bytes(4) + asdu
        result = FuzzResult("x", "iec104", "t", "test", "exception")
        connected_fuzzer._classify_response(payload, resp, result)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert result.crash_indicator is False

    def test_s_frame_response_no_anomaly(self, connected_fuzzer):
        payload = _gi()
        resp = bytes([0x68, 4, 0x01, 0x00, 0x00, 0x00])  # S-frame
        result = FuzzResult("x", "iec104", "t", "test", "s-frame")
        connected_fuzzer._classify_response(payload, resp, result)
        assert result.anomaly is None
        assert result.crash_indicator is False


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

class TestReplay:
    def test_replay_returns_bytes(self, connected_fuzzer):
        response = connected_fuzzer.replay_payload(_gi())
        assert isinstance(response, bytes)
        assert len(response) >= 6

    def test_replay_without_connect_raises(self):
        target = Device(ip="127.0.0.1", port=2405, protocol="iec104")
        f = Iec104Fuzzer(target=target, logger=None)
        with pytest.raises(RuntimeError, match="connect"):
            f.replay_payload(_gi())


# ---------------------------------------------------------------------------
# Full generate → send loop
# ---------------------------------------------------------------------------

class TestFuzzLoop:
    def test_boundary_category_end_to_end(self, connected_fuzzer):
        cases = connected_fuzzer.generate_cases(["boundary"])
        results = [
            connected_fuzzer._send_case(cid, cat, desc, payload)
            for cid, cat, desc, payload in cases
        ]
        assert len(results) == len(cases)
        for r in results:
            assert r.response is not None or r.anomaly is not None

    def test_gi_timing_end_to_end(self, connected_fuzzer):
        cases = connected_fuzzer.generate_cases(["gi_timing"])
        results = [
            connected_fuzzer._send_case(cid, cat, desc, payload)
            for cid, cat, desc, payload in cases
        ]
        assert len(results) > 0
        exception_results = [r for r in results if r.anomaly == ANOMALY_EXCEPTION]
        assert len(exception_results) > 0

    def test_logger_integration(self, iec104_server, tmp_path):
        from core.logger import FuzzLogger
        host, port = iec104_server
        target = Device(ip=host, port=port, protocol="iec104")
        with FuzzLogger(str(tmp_path / "out")) as logger:
            f = Iec104Fuzzer(target=target, logger=logger, delay=0)
            f.connect(target)
            f._send_case("iec-log-001", "gi_timing", "GI log test", _gi())
            f.close()

        log_files = list((tmp_path / "out").glob("*.jsonl"))
        assert len(log_files) == 1
        records = [
            json.loads(line)
            for line in log_files[0].read_text().splitlines()
            if line.strip()
        ]
        fuzz_records = [r for r in records if r.get("id")]
        assert len(fuzz_records) == 1
        rec = fuzz_records[0]
        assert rec["id"]       == "iec-log-001"
        assert rec["protocol"] == "iec104"
        assert rec["anomaly"]  == ANOMALY_EXCEPTION
        assert rec["payload_hex"] is not None
        assert rec["response_hex"] is not None
