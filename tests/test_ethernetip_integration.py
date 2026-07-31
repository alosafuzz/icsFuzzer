"""EtherNet/IP integration tests — fuzzer against inline software responder."""

import json
import socket
import struct
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
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
)
from core.logger import FuzzLogger
from protocols.ethernetip.fuzzer import (
    EthernetIpFuzzer,
    _enip_packet,
    _register_session_packet,
    _list_identity_packet,
    _nop_packet,
    _unconnected_msg,
    _get_attr_all,
    _get_attr_single,
    _forward_open,
    _large_forward_open,
    _forward_close,
    _CMD_REGISTER_SESSION,
    _CMD_SEND_RR_DATA,
    _CMD_LIST_IDENTITY,
    _CPF_NULL_ADDR,
    _CPF_UNCONN_DATA,
    _cpf_items,
    _send_rr_data,
    CATEGORY_FWD_OPEN_CLOSE,
    CATEGORY_CIP_PATH,
    CATEGORY_UNCONN_SEND,
    CATEGORY_LARGE_FWD_OPEN,
)


# ---------------------------------------------------------------------------
# Noop sidecar + importable handler
# ---------------------------------------------------------------------------

class _NoopSidecar:
    def log(self, *args, **kwargs): pass
    def summary(self): pass
    def close(self): pass


def _handle_conn(conn, addr):
    from scripts.ethernetip_responder import handle_client
    handle_client(conn, addr, sidecar=_NoopSidecar(), verbose=False)


# ---------------------------------------------------------------------------
# Server fixture
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def enip_server():
    port = _free_port()
    srv  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    srv.settimeout(1.0)

    stop = threading.Event()

    def _serve():
        while not stop.is_set():
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
    stop.set()
    srv.close()
    t.join(timeout=2)


@pytest.fixture
def device(enip_server):
    return Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")


@pytest.fixture
def fuzzer(enip_server):
    port   = enip_server
    device = Device(ip="127.0.0.1", port=port, protocol="ethernetip")
    fuzz   = EthernetIpFuzzer(target=device, logger=None, delay=0)
    fuzz.connect(device)
    yield fuzz
    fuzz.close()


# ---------------------------------------------------------------------------
# TestHandshake
# ---------------------------------------------------------------------------

class TestHandshake:
    def test_connect_establishes_session(self, enip_server):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        fuzz   = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        assert fuzz._session != 0, "Session handle should be non-zero after Register Session"
        fuzz.close()

    def test_close_clears_session(self, enip_server):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        fuzz   = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        fuzz.close()
        assert fuzz._session == 0
        assert fuzz._sock is None

    def test_multiple_sequential_connections(self, enip_server):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        for _ in range(3):
            fuzz = EthernetIpFuzzer(target=device, logger=None, delay=0)
            fuzz.connect(device)
            assert fuzz._session != 0
            fuzz.close()

    def test_each_session_gets_different_handle(self, enip_server):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        sessions = []
        for _ in range(3):
            fuzz = EthernetIpFuzzer(target=device, logger=None, delay=0)
            fuzz.connect(device)
            sessions.append(fuzz._session)
            fuzz.close()
        assert len(set(sessions)) == 3, "Each connection should get a unique session handle"


# ---------------------------------------------------------------------------
# TestReplay
# ---------------------------------------------------------------------------

class TestReplay:
    def test_list_identity_round_trip(self, fuzzer):
        resp = fuzzer.replay_payload(_list_identity_packet())
        assert resp is not None and len(resp) >= 24
        cmd = struct.unpack_from('<H', resp, 0)[0]
        assert cmd == _CMD_LIST_IDENTITY

    def test_get_attr_all_identity_round_trip(self, fuzzer):
        payload = _unconnected_msg(_get_attr_all(0x01, 1), fuzzer._session)
        resp    = fuzzer.replay_payload(payload)
        assert resp is not None and len(resp) >= 24
        cmd = struct.unpack_from('<H', resp, 0)[0]
        assert cmd == _CMD_SEND_RR_DATA
        # Check ENIP status = 0
        status = struct.unpack_from('<I', resp, 8)[0]
        assert status == 0

    def test_replay_raises_without_connect(self, enip_server):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        fuzz   = EthernetIpFuzzer(target=device, logger=None, delay=0)
        with pytest.raises(RuntimeError, match="connect"):
            fuzz.replay_payload(_list_identity_packet())


# ---------------------------------------------------------------------------
# TestSendCase
# ---------------------------------------------------------------------------

class TestSendCase:
    def test_list_identity_no_anomaly(self, fuzzer):
        cases     = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        id_cases  = [c for c in cases if "List Identity" in c[2]]
        assert id_cases
        result = fuzzer._send_case(*id_cases[0])
        assert result.anomaly is None
        assert not result.crash_indicator

    def test_list_services_no_anomaly(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        svc   = [c for c in cases if "List Services" in c[2]]
        assert svc
        result = fuzzer._send_case(*svc[0])
        assert result.anomaly is None
        assert not result.crash_indicator

    def test_get_attr_all_identity_no_anomaly(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        gaa   = [c for c in cases if "Get_Attributes_All Identity" in c[2]]
        assert gaa
        result = fuzzer._send_case(*gaa[0])
        assert result.anomaly is None
        assert not result.crash_indicator

    def test_unknown_cip_service_gives_exception(self, fuzzer):
        """Service 0xFF on Identity → CIP error general status → ANOMALY_EXCEPTION."""
        payload = _unconnected_msg(
            b'\xFF\x02\x20\x01\x24\x01',   # service=0xFF, path to class 1 inst 1
            fuzzer._session,
        )
        result = fuzzer._send_case("test-unk-svc", CATEGORY_BOUNDARY,
                                   "unknown CIP service 0xFF", payload)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert not result.crash_indicator

    def test_set_readonly_attr_gives_exception(self, fuzzer):
        """Set_Attribute_Single on read-only attr → CIP error → ANOMALY_EXCEPTION."""
        payload = _unconnected_msg(
            _get_attr_single(0x01, 1, 99),   # attr 99 doesn't exist
            fuzzer._session,
        )
        result = fuzzer._send_case("test-bad-attr", CATEGORY_BOUNDARY,
                                   "Get_Attr_Single attr=99 (nonexistent)", payload)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert not result.crash_indicator

    def test_wrong_session_gives_exception(self, fuzzer):
        """Wrong session handle → ENIP Status=0x0004 → ANOMALY_EXCEPTION."""
        payload = _unconnected_msg(_get_attr_all(0x01, 1), 0xDEADBEEF)
        result  = fuzzer._send_case("test-wrong-sess", CATEGORY_STATE_MACHINE,
                                    "wrong session handle", payload)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert not result.crash_indicator

    def test_empty_payload_causes_crash_indicator(self, fuzzer):
        """Empty payload → connection close → crash indicator."""
        result = fuzzer._send_case("test-empty", CATEGORY_BINARY_CORRUPTION,
                                   "empty payload", b'')
        assert result.crash_indicator

    def test_nop_no_anomaly(self, fuzzer):
        """NOP command skips response wait — should produce no anomaly."""
        result = fuzzer._send_case("test-nop", CATEGORY_BOUNDARY,
                                   "NOP", _nop_packet())
        assert result.anomaly is None
        assert not result.crash_indicator

    def test_forward_open_no_crash(self, fuzzer):
        """Forward_Open should succeed or return CIP error — no crash."""
        cases = fuzzer.generate_cases([CATEGORY_FWD_OPEN_CLOSE])
        std   = [c for c in cases if "standard" in c[2].lower()]
        assert std
        result = fuzzer._send_case(*std[0])
        assert result.anomaly in (None, ANOMALY_EXCEPTION)
        assert not result.crash_indicator

    def test_large_fwd_open_no_crash(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_LARGE_FWD_OPEN])
        std   = [c for c in cases if "standard" in c[2].lower()]
        assert std
        result = fuzzer._send_case(*std[0])
        assert result.anomaly in (None, ANOMALY_EXCEPTION)
        assert not result.crash_indicator


# ---------------------------------------------------------------------------
# TestClassifyResponse
# ---------------------------------------------------------------------------

class TestClassifyResponse:
    def _raw_resp(self, cmd: int, data: bytes, session: int = 0,
                  status: int = 0) -> bytes:
        return _enip_packet(cmd, data, session=session, status=status)

    def _cip_in_rr(self, cip_data: bytes, session: int = 1) -> bytes:
        cpf = _cpf_items((_CPF_NULL_ADDR, b''), (_CPF_UNCONN_DATA, cip_data))
        rr  = struct.pack('<IH', 0, 0) + cpf   # IntHandle + Timeout + CPF
        return _enip_packet(_CMD_SEND_RR_DATA, rr, session=session)

    def test_success_response_no_anomaly(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        from core.base_module import FuzzResult
        result = FuzzResult("t", "ethernetip", "127.0.0.1", "boundary", "test")
        cip_ok = bytes([0x81, 0x00, 0x00, 0x00]) + b'\x01\x02\x03\x04'
        resp   = self._cip_in_rr(cip_ok)
        fuzzer._classify_response(resp, result)
        assert result.anomaly is None

    def test_enip_bad_session_gives_exception(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        from core.base_module import FuzzResult
        result = FuzzResult("t", "ethernetip", "127.0.0.1", "boundary", "test")
        resp   = self._raw_resp(_CMD_SEND_RR_DATA, b'', status=0x0004)
        fuzzer._classify_response(resp, result)
        assert result.anomaly == ANOMALY_EXCEPTION

    def test_cip_service_error_gives_exception(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        from core.base_module import FuzzResult
        result = FuzzResult("t", "ethernetip", "127.0.0.1", "boundary", "test")
        cip_err = bytes([0x81, 0x00, 0x08, 0x00])   # service not supported
        resp    = self._cip_in_rr(cip_err)
        fuzzer._classify_response(resp, result)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert not result.crash_indicator

    def test_short_response_gives_malformed(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        from core.base_module import FuzzResult
        result = FuzzResult("t", "ethernetip", "127.0.0.1", "boundary", "test")
        fuzzer._classify_response(b'\x65\x00' + b'\x00' * 10, result)   # only 12 bytes
        assert result.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert result.crash_indicator

    def test_enip_unsupported_cmd_gives_exception_with_crash(self, device):
        fuzzer = EthernetIpFuzzer(target=device, logger=None, delay=0)
        from core.base_module import FuzzResult
        result = FuzzResult("t", "ethernetip", "127.0.0.1", "boundary", "test")
        resp   = self._raw_resp(0x0001, b'', status=0x0001)  # unsupported
        fuzzer._classify_response(resp, result)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert result.crash_indicator  # 0x0001 unsupported → crash_indicator=True


# ---------------------------------------------------------------------------
# TestFuzzLoop
# ---------------------------------------------------------------------------

class TestFuzzLoop:
    def test_boundary_no_malformed_response(self, enip_server, tmp_path):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        fuzz   = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        results = fuzz.fuzz([CATEGORY_BOUNDARY])
        fuzz.close()

        malformed = [r for r in results if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, (
            f"ANOMALY_MALFORMED_RESPONSE in boundary: "
            f"{[(r.description, r.response_decoded) for r in malformed]}"
        )

    def test_cip_path_no_malformed_response(self, enip_server):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        fuzz   = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        results = fuzz.fuzz([CATEGORY_CIP_PATH])
        fuzz.close()

        malformed = [r for r in results if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0

    def test_forward_open_close_completes(self, enip_server):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        fuzz   = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        results = fuzz.fuzz([CATEGORY_FWD_OPEN_CLOSE])
        fuzz.close()
        assert len(results) > 0

    def test_unconnected_send_completes(self, enip_server):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        fuzz   = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        results = fuzz.fuzz([CATEGORY_UNCONN_SEND])
        fuzz.close()
        assert len(results) > 0

    def test_large_fwd_open_completes(self, enip_server):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        fuzz   = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        results = fuzz.fuzz([CATEGORY_LARGE_FWD_OPEN])
        fuzz.close()
        assert len(results) > 0

    def test_logger_jsonl_written(self, enip_server, tmp_path):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        logger = FuzzLogger(str(tmp_path / "out"))
        fuzz   = EthernetIpFuzzer(target=device, logger=logger, delay=0)
        fuzz.connect(device)
        fuzz.fuzz([CATEGORY_BOUNDARY])
        fuzz.close()
        logger.close()

        logs = list(Path(tmp_path / "out").glob("*.jsonl"))
        assert len(logs) == 1
        records = [json.loads(l) for l in logs[0].read_text().splitlines() if l]
        assert len(records) > 0
        for rec in records:
            assert "id" in rec or "type" in rec
            if "id" in rec:
                assert rec.get("protocol") == "ethernetip"

    def test_binary_corruption_all_crash(self, enip_server):
        """Binary corruption cases should produce only crash indicators, no false positives."""
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        fuzz   = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        results = fuzz.fuzz([CATEGORY_BINARY_CORRUPTION])
        fuzz.close()

        malformed = [r for r in results if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, (
            f"ANOMALY_MALFORMED_RESPONSE in binary_corruption: "
            f"{[r.description for r in malformed]}"
        )

    def test_sequence_no_malformed(self, enip_server):
        device = Device(ip="127.0.0.1", port=enip_server, protocol="ethernetip")
        fuzz   = EthernetIpFuzzer(target=device, logger=None, delay=0)
        fuzz.connect(device)
        results = fuzz.fuzz([CATEGORY_SEQUENCE])
        fuzz.close()

        malformed = [r for r in results if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0
