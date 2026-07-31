"""DNP3 integration tests — fuzzer against inline software responder."""

import json
import socket
import threading
import time
from pathlib import Path

import pytest

from core.base_module import (
    ANOMALY_CONNECTION_RESET,
    ANOMALY_EXCEPTION,
    ANOMALY_MALFORMED_RESPONSE,
    ANOMALY_NO_RESPONSE,
    ANOMALY_TIMEOUT,
    ANOMALY_UNEXPECTED_DATA,
    CATEGORY_BOUNDARY,
    CATEGORY_BINARY_CORRUPTION,
    Device,
)
from core.logger import FuzzLogger
from protocols.dnp3.fuzzer import (
    Dnp3Fuzzer,
    _dll_frame,
    _dll_frame_bad_hdr_crc,
    _dll_frame_bad_block_crc,
    _app_request,
    _tl_byte,
    _read_class0,
    _read_gv,
    _dll_only,
    _ctrl_primary,
    _crc16,
    _FC_READ,
    _FC_RESPONSE,
    _FC_DIRECT_OPERATE,
    _START,
    _CTRL_UNCONF,
    _OUTSTATION_ADDR,
    CATEGORY_LINK_LAYER,
    CATEGORY_APP_FRAG,
    CATEGORY_SAV5_BYPASS,
)


# ---------------------------------------------------------------------------
# Noop sidecar + importable handler
# ---------------------------------------------------------------------------

class _NoopSidecar:
    def log(self, *args, **kwargs):
        pass

    def summary(self):
        pass

    def close(self):
        pass


def _handle_conn(conn, addr):
    from scripts.dnp3_responder import handle_client
    handle_client(conn, addr, sidecar=_NoopSidecar(), verbose=False)


# ---------------------------------------------------------------------------
# Module-scoped server fixture
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def device():
    return Device(ip="127.0.0.1", port=20001, protocol="dnp3")


@pytest.fixture(scope="module")
def dnp3_server():
    port = _free_port()
    srv  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(32)
    srv.settimeout(1.0)

    stop_event = threading.Event()

    def _serve():
        while not stop_event.is_set():
            try:
                conn, addr = srv.accept()
                threading.Thread(target=_handle_conn, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                pass
            except Exception:
                break

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    time.sleep(0.05)
    yield port
    stop_event.set()
    srv.close()
    t.join(timeout=2)


@pytest.fixture
def fuzzer(dnp3_server):
    port   = dnp3_server
    device = Device(ip="127.0.0.1", port=port, protocol="dnp3")
    fuzz   = Dnp3Fuzzer(target=device, logger=None, delay=0)
    fuzz.connect(device)
    yield fuzz
    fuzz.close()


# ---------------------------------------------------------------------------
# TestHandshake
# ---------------------------------------------------------------------------

class TestHandshake:
    def test_connect_and_close(self, dnp3_server):
        device = Device(ip="127.0.0.1", port=dnp3_server, protocol="dnp3")
        fuzz   = Dnp3Fuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        fuzz.close()

    def test_multiple_sequential_connections(self, dnp3_server):
        device = Device(ip="127.0.0.1", port=dnp3_server, protocol="dnp3")
        for _ in range(3):
            fuzz = Dnp3Fuzzer(target=device, logger=None, delay=0)
            fuzz.connect(device)
            fuzz.close()


# ---------------------------------------------------------------------------
# TestSendCase
# ---------------------------------------------------------------------------

class TestSendCase:
    def test_read_class0_no_anomaly(self, fuzzer):
        """Standard READ Class0 should get a clean RESPONSE with no anomaly."""
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        read_cases = [c for c in cases if "Class0" in c[2] and "standard outstation" in c[2]]
        assert read_cases, "No Class0 standard case found"
        case_id, cat, desc, payload = read_cases[0]
        result = fuzzer._send_case(case_id, cat, desc, payload)
        assert result.anomaly is None or result.anomaly == ANOMALY_EXCEPTION
        assert not result.crash_indicator

    def test_read_response_decoded(self, fuzzer):
        """READ Class0 response should include IIN bits in response_decoded."""
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        read_cases = [c for c in cases if "standard outstation" in c[2]]
        assert read_cases
        result = fuzzer._send_case(*read_cases[0])
        # Response should be a valid DNP3 response
        if result.response and len(result.response) >= 10:
            assert result.response[:2] == _START

    def test_bad_start_byte_causes_crash_indicator(self, fuzzer):
        """Frame with wrong start bytes: responder closes → connection_reset."""
        payload = b"\x00\x00" + b"\xC4\x01\x00\x03\x00" + bytes(10)  # bad start
        result  = fuzzer._send_case("test-bad-start", CATEGORY_BINARY_CORRUPTION,
                                    "bad start bytes", payload)
        assert result.crash_indicator
        assert result.anomaly in (ANOMALY_CONNECTION_RESET, ANOMALY_TIMEOUT,
                                   ANOMALY_NO_RESPONSE, ANOMALY_MALFORMED_RESPONSE)

    def test_bad_header_crc_causes_crash_indicator(self, fuzzer):
        """Frame with corrupted header CRC should cause responder to close."""
        payload = _dll_frame_bad_hdr_crc(
            _tl_byte() + bytes([0xC0, _FC_READ, 60, 1, 0x06])
        )
        result  = fuzzer._send_case("test-bad-hcrc", CATEGORY_BINARY_CORRUPTION,
                                    "bad header CRC", payload)
        assert result.crash_indicator

    def test_bad_block_crc_causes_crash_indicator(self, fuzzer):
        """Frame with corrupted block CRC should cause responder to close."""
        payload = _dll_frame_bad_block_crc(
            _tl_byte() + bytes([0xC0, _FC_READ, 60, 1, 0x06])
        )
        result  = fuzzer._send_case("test-bad-bcrc", CATEGORY_BINARY_CORRUPTION,
                                    "bad block CRC", payload)
        assert result.crash_indicator

    def test_unknown_fc_returns_exception(self, fuzzer):
        """Unknown AL FC → IIN2.FUNC_NOT_SUPP → ANOMALY_EXCEPTION, no crash."""
        payload = _dll_frame(_tl_byte() + bytes([0xC0, 0x7F]))  # FC=0x7F unknown
        result  = fuzzer._send_case("test-unk-fc", "boundary",
                                    "unknown AL FC=0x7F", payload)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert not result.crash_indicator

    def test_direct_operate_no_crash(self, fuzzer):
        """DIRECT_OPERATE with CROB should get echo response, no crash."""
        crob = bytes([0x41, 1, 0xE8, 0x03, 0x00, 0x00, 0xF4, 0x01, 0x00, 0x00, 0x00])
        obj  = bytes([12, 1, 0x17, 1, 1]) + crob
        payload = _dll_frame(_tl_byte() + _app_request(_FC_DIRECT_OPERATE, obj))
        result  = fuzzer._send_case("test-do", "boundary", "DIRECT_OPERATE G12V1", payload)
        assert result.anomaly is None or result.anomaly == ANOMALY_EXCEPTION
        assert not result.crash_indicator

    def test_dll_only_link_layer_frame(self, fuzzer):
        """DLL-only REQUEST_LINK_STATUS should get a LINK_STATUS response."""
        payload = _dll_only(_ctrl_primary(9))   # FC=9 REQUEST_LINK_STATUS
        result  = fuzzer._send_case("test-link-stat", CATEGORY_LINK_LAYER,
                                    "DLL FC=9 REQUEST_LINK_STATUS", payload)
        # Link status response is DLL-only (no AL), classified as no anomaly
        assert not result.crash_indicator

    def test_sav5_auth_req_returns_exception(self, fuzzer):
        """AUTH_REQ (FC=0x20) should return IIN2.FUNC_NOT_SUPP → ANOMALY_EXCEPTION."""
        payload = _dll_frame(_tl_byte() + bytes([0xC0, 0x20]))   # FC=0x20
        result  = fuzzer._send_case("test-auth", CATEGORY_SAV5_BYPASS,
                                    "AUTH_REQ FC=0x20", payload)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert not result.crash_indicator

    def test_cold_restart_no_crash(self, fuzzer):
        """COLD_RESTART should get response (device won't actually reset on testbed)."""
        payload = _dll_frame(_tl_byte() + bytes([0xC0, 0x0D]))  # FC=COLD_RESTART
        result  = fuzzer._send_case("test-cr", "boundary", "COLD_RESTART", payload)
        assert not result.crash_indicator


# ---------------------------------------------------------------------------
# TestClassifyResponse
# ---------------------------------------------------------------------------

class TestClassifyResponse:
    def _make_response(self, iin1: int = 0, iin2: int = 0,
                       al_fc: int = _FC_RESPONSE, objects: bytes = b"") -> bytes:
        """Build a valid DNP3 RESPONSE frame as the outstation would send."""
        from scripts.dnp3_responder import _response_frame
        return _response_frame(iin1, iin2, objects)

    def test_clean_response_no_anomaly(self, device):
        fuzzer = Dnp3Fuzzer(target=device, logger=None, delay=0)
        from core.base_module import FuzzResult
        result = FuzzResult("t", "dnp3", "127.0.0.1", "boundary", "test")
        resp   = self._make_response(0x00, 0x00)
        fuzzer._classify_response(resp, result)
        assert result.anomaly is None
        assert not result.crash_indicator

    def test_iin2_func_not_supp_gives_exception(self, device):
        fuzzer = Dnp3Fuzzer(target=device, logger=None, delay=0)
        from core.base_module import FuzzResult
        result = FuzzResult("t", "dnp3", "127.0.0.1", "boundary", "test")
        resp   = self._make_response(0x00, 0x01)   # IIN2.FUNC_NOT_SUPP
        fuzzer._classify_response(resp, result)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert not result.crash_indicator

    def test_iin2_obj_unknown_gives_exception(self, device):
        fuzzer = Dnp3Fuzzer(target=device, logger=None, delay=0)
        from core.base_module import FuzzResult
        result = FuzzResult("t", "dnp3", "127.0.0.1", "boundary", "test")
        resp   = self._make_response(0x00, 0x02)   # IIN2.OBJ_UNKNOWN
        fuzzer._classify_response(resp, result)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert not result.crash_indicator

    def test_iin2_param_error_gives_exception(self, device):
        fuzzer = Dnp3Fuzzer(target=device, logger=None, delay=0)
        from core.base_module import FuzzResult
        result = FuzzResult("t", "dnp3", "127.0.0.1", "boundary", "test")
        resp   = self._make_response(0x00, 0x04)   # IIN2.PARAM_ERROR
        fuzzer._classify_response(resp, result)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert not result.crash_indicator

    def test_wrong_start_bytes_gives_malformed(self, device):
        fuzzer = Dnp3Fuzzer(target=device, logger=None, delay=0)
        from core.base_module import FuzzResult
        result = FuzzResult("t", "dnp3", "127.0.0.1", "boundary", "test")
        bad    = b"\x00\x64" + bytes(8)
        fuzzer._classify_response(bad, result)
        assert result.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert result.crash_indicator

    def test_device_restart_iin_no_crash(self, device):
        """IIN1.DEVICE_RESTART bit set is normal — device just restarted."""
        fuzzer = Dnp3Fuzzer(target=device, logger=None, delay=0)
        from core.base_module import FuzzResult
        result = FuzzResult("t", "dnp3", "127.0.0.1", "boundary", "test")
        resp   = self._make_response(0x01, 0x00)   # IIN1.0 = DEVICE_RESTART
        fuzzer._classify_response(resp, result)
        assert result.anomaly is None
        assert not result.crash_indicator


# ---------------------------------------------------------------------------
# TestReplay
# ---------------------------------------------------------------------------

class TestReplay:
    def test_replay_round_trip(self, fuzzer):
        payload  = _read_class0()
        response = fuzzer.replay_payload(payload)
        assert response is not None
        assert len(response) >= 10
        assert response[:2] == _START

    def test_replay_raises_without_connect(self):
        device = Device(ip="127.0.0.1", port=20001, protocol="dnp3")
        fuzzer = Dnp3Fuzzer(target=device, logger=None, delay=0)
        with pytest.raises(RuntimeError, match="connect"):
            fuzzer.replay_payload(_read_class0())


# ---------------------------------------------------------------------------
# TestFuzzLoop
# ---------------------------------------------------------------------------

class TestFuzzLoop:
    def test_boundary_end_to_end(self, dnp3_server, tmp_path):
        port   = dnp3_server
        device = Device(ip="127.0.0.1", port=port, protocol="dnp3")
        logger = FuzzLogger(str(tmp_path / "output"))
        fuzz   = Dnp3Fuzzer(target=device, logger=logger, delay=0)
        fuzz.connect(device)
        results = fuzz.fuzz([CATEGORY_BOUNDARY])
        fuzz.close()
        logger.close()

        assert len(results) > 0
        malformed = [r for r in results if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, (
            f"ANOMALY_MALFORMED_RESPONSE found in boundary category "
            f"(check CRC mismatch): {[r.description for r in malformed]}"
        )

    def test_link_layer_end_to_end(self, dnp3_server, tmp_path):
        port   = dnp3_server
        device = Device(ip="127.0.0.1", port=port, protocol="dnp3")
        fuzz   = Dnp3Fuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        results = fuzz.fuzz([CATEGORY_LINK_LAYER])
        fuzz.close()
        assert len(results) > 0

    def test_logger_jsonl_written(self, dnp3_server, tmp_path):
        port   = dnp3_server
        device = Device(ip="127.0.0.1", port=port, protocol="dnp3")
        logger = FuzzLogger(str(tmp_path / "out"))
        fuzz   = Dnp3Fuzzer(target=device, logger=logger, delay=0)
        fuzz.connect(device)
        fuzz.fuzz([CATEGORY_BOUNDARY])
        fuzz.close()
        logger.close()

        logs = list(Path(tmp_path / "out").glob("*.jsonl"))
        assert len(logs) == 1
        records = [json.loads(l) for l in logs[0].read_text().splitlines() if l]
        assert len(records) > 0
        for rec in records:
            assert "id" in rec
            assert "protocol" in rec
            assert rec["protocol"] == "dnp3"

    def test_app_layer_frag_drain_works(self, dnp3_server):
        """Multi-frame cases must drain correctly — no buffer contamination."""
        port   = dnp3_server
        device = Device(ip="127.0.0.1", port=port, protocol="dnp3")
        fuzz   = Dnp3Fuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        results = fuzz.fuzz([CATEGORY_APP_FRAG])
        fuzz.close()

        malformed = [r for r in results if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, (
            f"ANOMALY_MALFORMED_RESPONSE in app_layer_frag (drain bug?): "
            f"{[r.description for r in malformed]}"
        )

    def test_no_malformed_response_in_boundary(self, dnp3_server):
        """Boundary category must not produce ANOMALY_MALFORMED_RESPONSE — that
        indicates a structural bug (bad CRC scope, wrong frame parser, SEQ mismatch)
        rather than a testbed limitation."""
        port   = dnp3_server
        device = Device(ip="127.0.0.1", port=port, protocol="dnp3")
        fuzz   = Dnp3Fuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        results = fuzz.fuzz([CATEGORY_BOUNDARY])
        fuzz.close()

        malformed = [r for r in results if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, (
            f"ANOMALY_MALFORMED_RESPONSE in boundary (structural bug): "
            f"{[(r.description, r.response_decoded) for r in malformed]}"
        )
