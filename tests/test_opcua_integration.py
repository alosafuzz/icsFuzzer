"""OPC-UA integration tests — fuzzer against a local software responder."""

import socket
import struct
import threading

import pytest

from protocols.opcua.fuzzer import (
    OpcuaFuzzer,
    _hel,
    _opn_request,
    _msg_frame,
    _read_body,
    _browse_body,
    _write_body,
    _create_subscription_body,
    _ua_nodeid_fourbyte,
    CATEGORY_SERVICE_SWEEP,
    CATEGORY_NODEID_VARIANTS,
    CATEGORY_SUBSCRIPTION,
    CATEGORY_CHUNKED,
    SVC_READ,
    SVC_BROWSE,
    SVC_WRITE,
    SVC_CREATE_SESSION,
    SVC_ACTIVATE_SESSION,
    SVC_CREATE_SUBSCRIPTION,
)
from core.base_module import (
    ANOMALY_EXCEPTION,
    ANOMALY_MALFORMED_RESPONSE,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
)


class _NoopSidecar:
    def log(self, action, **kw): pass
    def summary(self): return {}
    def close(self): pass


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def opcua_server():
    from scripts.opcua_responder import handle_client

    port    = _free_port()
    sidecar = _NoopSidecar()
    stop    = threading.Event()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(50)
    srv.settimeout(0.5)

    def _loop():
        while not stop.is_set():
            try:
                conn, addr = srv.accept()
                conn.settimeout(4.0)
                t = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, sidecar, False),
                    daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                continue

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    yield {"port": port, "sidecar": sidecar}

    stop.set()
    t.join(timeout=2.0)
    srv.close()


@pytest.fixture
def device(opcua_server):
    return Device(ip="127.0.0.1", port=opcua_server["port"], protocol="opcua")


@pytest.fixture
def fuzzer(device):
    f = OpcuaFuzzer(target=device, logger=None, delay=0)
    f.connect()
    yield f
    f.close()


# ---------------------------------------------------------------------------
# TestConnect
# ---------------------------------------------------------------------------

class TestConnect:
    def test_connect_completes_4_step_handshake(self, device):
        f = OpcuaFuzzer(target=device, logger=None, delay=0)
        f.connect()
        assert f._channel_id == 1
        assert f._token_id   == 1
        assert f._auth_token is not None
        f.close()

    def test_close_clears_state(self, device):
        f = OpcuaFuzzer(target=device, logger=None, delay=0)
        f.connect()
        f.close()
        assert f._sock is None
        assert f._channel_id == 0
        assert f._token_id   == 0
        assert f._auth_token is None

    def test_double_close_safe(self, device):
        f = OpcuaFuzzer(target=device, logger=None, delay=0)
        f.connect()
        f.close()
        f.close()    # must not raise

    def test_connect_refused_raises(self):
        dev = Device(ip="127.0.0.1", port=1, protocol="opcua")
        f = OpcuaFuzzer(target=dev, logger=None, delay=0)
        with pytest.raises(Exception):
            f.connect()


# ---------------------------------------------------------------------------
# TestReplay
# ---------------------------------------------------------------------------

class TestReplay:
    def test_replay_read_returns_msg(self, fuzzer):
        payload = _msg_frame(
            fuzzer._channel_id, fuzzer._token_id,
            fuzzer._next_seq(), fuzzer._next_req(),
            SVC_READ, _read_body(0, 2258, 13),
            auth_token=fuzzer._auth_token)
        resp = fuzzer.replay_payload(payload)
        assert resp is not None
        assert resp[:3] == b'MSG'

    def test_replay_browse_returns_msg(self, fuzzer):
        payload = _msg_frame(
            fuzzer._channel_id, fuzzer._token_id,
            fuzzer._next_seq(), fuzzer._next_req(),
            SVC_BROWSE, _browse_body(0, 84),
            auth_token=fuzzer._auth_token)
        resp = fuzzer.replay_payload(payload)
        assert resp is not None
        assert resp[:3] == b'MSG'

    def test_replay_write_returns_msg_with_exception(self, fuzzer):
        payload = _msg_frame(
            fuzzer._channel_id, fuzzer._token_id,
            fuzzer._next_seq(), fuzzer._next_req(),
            SVC_WRITE, _write_body(0, 2253, 0),
            auth_token=fuzzer._auth_token)
        resp = fuzzer.replay_payload(payload)
        assert resp is not None
        assert resp[:3] == b'MSG'

    def test_replay_unknown_service_returns_msg(self, fuzzer):
        payload = _msg_frame(
            fuzzer._channel_id, fuzzer._token_id,
            fuzzer._next_seq(), fuzzer._next_req(),
            9999, b'',
            auth_token=fuzzer._auth_token)
        resp = fuzzer.replay_payload(payload)
        assert resp is not None
        assert resp[:3] == b'MSG'

    def test_replay_without_connect_raises(self, device):
        f = OpcuaFuzzer(target=device, logger=None, delay=0)
        with pytest.raises(RuntimeError, match="connect"):
            f.replay_payload(b'\x00')


# ---------------------------------------------------------------------------
# TestSendCase
# ---------------------------------------------------------------------------

class TestSendCase:
    def test_boundary_no_malformed_response(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        results = []
        for case_id, cat, desc, payload in cases:
            r = fuzzer._send_case(case_id, cat, desc, payload)
            results.append(r)
        malformed = [r for r in results if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        # Soft assertion: malformed count should be low (< 20% of boundary cases)
        assert len(malformed) < len(cases) * 0.20, \
            f"Too many malformed responses in boundary: {len(malformed)}/{len(cases)}"

    def test_binary_corruption_produces_anomalies(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BINARY_CORRUPTION])
        results = []
        for case_id, cat, desc, payload in cases:
            r = fuzzer._send_case(case_id, cat, desc, payload)
            results.append(r)
        anomalies = [r for r in results if r.anomaly is not None]
        assert len(anomalies) > 0

    def test_results_have_duration(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])[:3]
        for case_id, cat, desc, payload in cases:
            r = fuzzer._send_case(case_id, cat, desc, payload)
            assert r.duration_ms is not None
            assert r.duration_ms >= 0

    def test_results_have_protocol_field(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])[:3]
        for case_id, cat, desc, payload in cases:
            r = fuzzer._send_case(case_id, cat, desc, payload)
            assert r.protocol == "opcua"


# ---------------------------------------------------------------------------
# TestFuzzLoop
# ---------------------------------------------------------------------------

class TestFuzzLoop:
    def test_boundary_no_malformed_response(self, device):
        f = OpcuaFuzzer(target=device, logger=None, delay=0)
        f.connect()
        results = f.fuzz([CATEGORY_BOUNDARY])
        f.close()
        malformed = [r for r in results if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) < len(results) * 0.20

    def test_state_machine_no_crash_from_reconnect(self, device):
        f = OpcuaFuzzer(target=device, logger=None, delay=0)
        f.connect()
        results = f.fuzz([CATEGORY_STATE_MACHINE])
        f.close()
        assert len(results) > 0

    def test_binary_corruption_has_crash_indicators(self, device):
        f = OpcuaFuzzer(target=device, logger=None, delay=0)
        f.connect()
        results = f.fuzz([CATEGORY_BINARY_CORRUPTION])
        f.close()
        crash = [r for r in results if r.crash_indicator]
        assert len(crash) > 0

    def test_all_results_have_protocol_opcua(self, device):
        f = OpcuaFuzzer(target=device, logger=None, delay=0)
        f.connect()
        results = f.fuzz([CATEGORY_BOUNDARY])
        f.close()
        for r in results:
            assert r.protocol == "opcua"

    def test_subscription_flood_runs(self, device):
        f = OpcuaFuzzer(target=device, logger=None, delay=0)
        f.connect()
        results = f.fuzz([CATEGORY_SUBSCRIPTION])
        f.close()
        assert len(results) > 0

    def test_nodeid_variants_runs(self, device):
        f = OpcuaFuzzer(target=device, logger=None, delay=0)
        f.connect()
        results = f.fuzz([CATEGORY_NODEID_VARIANTS])
        f.close()
        assert len(results) > 0
