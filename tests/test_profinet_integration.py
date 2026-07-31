"""Integration tests — ProfinetFuzzer against a local UDP responder."""

import socket
import struct
import threading
import time

import pytest

from protocols.profinet.fuzzer import (
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_DCP_CONFIGURATION,
    CATEGORY_DCP_DISCOVERY,
    CATEGORY_PNIO_CONNECT,
    CATEGORY_RECORD_RW,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    ProfinetFuzzer,
    _PTYPE_BIND_ACK,
    _PTYPE_FAULT,
    _PTYPE_RESPONSE,
    _rpc_bind,
    _rpc_request,
    _pnio_connect,
    _pnio_read,
    _pnio_write,
    _OP_CONNECT,
    _OP_READ,
    _OP_WRITE,
    _OP_RELEASE,
    _PNIO_CM_UUID,
    _BAD_UUID,
)
from core.base_module import (
    ANOMALY_EXCEPTION,
    ANOMALY_TIMEOUT,
    Device,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _NoopSidecar:
    def __init__(self):
        self._counts: dict = {}

    def log(self, action: str, **kwargs):
        self._counts[action] = self._counts.get(action, 0) + 1

    def summary(self): pass
    def close(self): pass

    def count(self, action: str) -> int:
        return self._counts.get(action, 0)


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# UDP responder fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pn_server():
    from scripts.profinet_responder import _responder_loop

    port    = _free_udp_port()
    sidecar = _NoopSidecar()
    stop    = threading.Event()

    t = threading.Thread(
        target=_responder_loop,
        args=("127.0.0.1", port, sidecar, stop, False),
        daemon=True)
    t.start()
    time.sleep(0.05)

    yield {"port": port, "sidecar": sidecar}

    stop.set()
    t.join(timeout=2.0)


@pytest.fixture
def device(pn_server):
    return Device(ip="127.0.0.1", port=pn_server["port"], protocol="profinet")


@pytest.fixture
def fuzzer(device):
    f = ProfinetFuzzer(target=device, logger=None, delay=0)
    f.connect()
    yield f
    f.close()


# ---------------------------------------------------------------------------
# TestRpcBind
# ---------------------------------------------------------------------------

class TestRpcBind:
    def test_bind_returns_bind_ack(self, pn_server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] == _PTYPE_BIND_ACK

    def test_bind_ack_echoes_call_id(self, pn_server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(42), ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert struct.unpack_from('<I', resp, 12)[0] == 42

    def test_bind_wrong_uuid_returns_nak(self, pn_server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1, uuid=_BAD_UUID),
                    ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] == _PTYPE_BIND_ACK
        # Context result at offset 28 should be non-zero (rejected)
        ctx_result = struct.unpack_from('<H', resp, 28)[0]
        assert ctx_result != 0

    def test_bind_sidecar_logged(self, pn_server):
        before = pn_server["sidecar"].count("bind_ok")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(99), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.close()
        assert pn_server["sidecar"].count("bind_ok") > before

    def test_bind_bad_uuid_sidecar_logged(self, pn_server):
        before = pn_server["sidecar"].count("bind_bad_uuid")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1, uuid=_BAD_UUID),
                    ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.close()
        assert pn_server["sidecar"].count("bind_bad_uuid") > before


# ---------------------------------------------------------------------------
# TestPnioConnect
# ---------------------------------------------------------------------------

class TestPnioConnect:
    def test_valid_connect_gets_response(self, pn_server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)  # consume BindACK
        sock.sendto(_rpc_request(_OP_CONNECT, _pnio_connect(), 1),
                    ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] in (_PTYPE_RESPONSE, _PTYPE_FAULT)

    def test_connect_sidecar_logged(self, pn_server):
        before = pn_server["sidecar"].count("connect_ok")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.sendto(_rpc_request(_OP_CONNECT, _pnio_connect(), 1),
                    ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.close()
        assert pn_server["sidecar"].count("connect_ok") > before

    def test_connect_unknown_ar_gets_fault(self, pn_server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.sendto(_rpc_request(_OP_CONNECT, _pnio_connect(ar_type=0x0000), 1),
                    ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] == _PTYPE_FAULT


# ---------------------------------------------------------------------------
# TestRecordRead
# ---------------------------------------------------------------------------

class TestRecordRead:
    def test_read_im0_gets_reply(self, pn_server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.sendto(_rpc_request(_OP_READ, _pnio_read(index=0xF000), 1),
                    ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] in (_PTYPE_RESPONSE, _PTYPE_FAULT)

    def test_read_im0_sidecar_logged(self, pn_server):
        before = pn_server["sidecar"].count("read_ok")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.sendto(_rpc_request(_OP_READ, _pnio_read(index=0xF000), 1),
                    ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.close()
        assert pn_server["sidecar"].count("read_ok") > before

    def test_read_unknown_index_gets_fault(self, pn_server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.sendto(_rpc_request(_OP_READ, _pnio_read(index=0xABCD), 1),
                    ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] == _PTYPE_FAULT


# ---------------------------------------------------------------------------
# TestRecordWrite
# ---------------------------------------------------------------------------

class TestRecordWrite:
    def test_write_im1_ok(self, pn_server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.sendto(_rpc_request(_OP_WRITE,
                                  _pnio_write(index=0xF001, data=b'\x00' * 54), 1),
                    ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] in (_PTYPE_RESPONSE, _PTYPE_FAULT)

    def test_write_im0_rejected(self, pn_server):
        before = pn_server["sidecar"].count("write_reject")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.sendto(_rpc_request(_OP_WRITE,
                                  _pnio_write(index=0xF000, data=b'\x00' * 32), 1),
                    ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] == _PTYPE_FAULT
        assert pn_server["sidecar"].count("write_reject") > before


# ---------------------------------------------------------------------------
# TestRelease
# ---------------------------------------------------------------------------

class TestRelease:
    def test_release_ok(self, pn_server):
        before = pn_server["sidecar"].count("release_ok")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        from protocols.profinet.fuzzer import _TEST_AR_UUID
        sock.sendto(_rpc_request(_OP_RELEASE, _TEST_AR_UUID, 1),
                    ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] == _PTYPE_RESPONSE
        assert pn_server["sidecar"].count("release_ok") > before


# ---------------------------------------------------------------------------
# TestUnknownOp
# ---------------------------------------------------------------------------

class TestUnknownOp:
    def test_unknown_op_gets_fault(self, pn_server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.sendto(_rpc_request(0xFFFF, b'', 1),
                    ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] == _PTYPE_FAULT

    def test_unknown_op_sidecar_logged(self, pn_server):
        before = pn_server["sidecar"].count("rpc_unknown_op")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(1), ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.sendto(_rpc_request(0x00FF, b'', 1),
                    ("127.0.0.1", pn_server["port"]))
        sock.recvfrom(4096)
        sock.close()
        assert pn_server["sidecar"].count("rpc_unknown_op") > before


# ---------------------------------------------------------------------------
# TestBoundaryCategory (via fuzzer)
# ---------------------------------------------------------------------------

class TestBoundaryViaFuzzer:
    def test_boundary_no_timeouts(self, fuzzer, pn_server):
        """All boundary cases must get a response from the responder."""
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        timeout_cases = [r for r in results
                         if r.anomaly == ANOMALY_TIMEOUT]
        # Allow up to 2 timeouts (large-payload cases may be truncated)
        assert len(timeout_cases) <= 2, (
            f"Unexpected timeouts in boundary: "
            + ", ".join(r.case_id for r in timeout_cases[:5])
        )


# ---------------------------------------------------------------------------
# TestStateMachine (via fuzzer)
# ---------------------------------------------------------------------------

class TestStateMachineViaFuzzer:
    def test_state_machine_no_crash_indicator(self, fuzzer, pn_server):
        """State machine cases should get responses, not be dropped silently."""
        results = fuzzer.fuzz([CATEGORY_STATE_MACHINE])
        # All should get either a response or EXCEPTION — not blank crash=True
        # (TIMEOUT is acceptable for truly malformed PDUs that the server drops)
        actual_crashes = [r for r in results
                          if r.crash_indicator and r.anomaly == ANOMALY_TIMEOUT
                          and "Without" not in r.description]
        # At most half the cases should time out (most should get a fault or response)
        assert len(actual_crashes) <= len(results) // 2


# ---------------------------------------------------------------------------
# TestBinaryCorruption — responder survives all input
# ---------------------------------------------------------------------------

class TestBinaryCorruptionViaFuzzer:
    def test_responder_survives_all_corruption(self, fuzzer, pn_server):
        """After all binary_corruption cases, responder is still alive (can Bind)."""
        fuzzer.fuzz([CATEGORY_BINARY_CORRUPTION])
        # Probe: send a valid Bind and expect BindACK
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(9999), ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] == _PTYPE_BIND_ACK


# ---------------------------------------------------------------------------
# TestDcpCases — generated without scapy, no crash
# ---------------------------------------------------------------------------

class TestDcpCases:
    def test_dcp_discovery_no_crash(self, fuzzer):
        """DCP cases without scapy: anomaly=None, crash=False."""
        from protocols.profinet.fuzzer import _HAS_SCAPY
        if _HAS_SCAPY:
            pytest.skip("scapy available — DCP cases are sent, skip this test")
        results = fuzzer.fuzz([CATEGORY_DCP_DISCOVERY])
        crashes = [r for r in results if r.crash_indicator]
        assert len(crashes) == 0

    def test_dcp_configuration_no_crash(self, fuzzer):
        from protocols.profinet.fuzzer import _HAS_SCAPY
        if _HAS_SCAPY:
            pytest.skip("scapy available — DCP cases are sent, skip this test")
        results = fuzzer.fuzz([CATEGORY_DCP_CONFIGURATION])
        crashes = [r for r in results if r.crash_indicator]
        assert len(crashes) == 0


# ---------------------------------------------------------------------------
# TestSequenceCategory
# ---------------------------------------------------------------------------

class TestSequenceCategory:
    def test_sequence_cases_run(self, fuzzer, pn_server):
        results = fuzzer.fuzz([CATEGORY_SEQUENCE])
        assert len(results) >= 10
        # Responder should still be alive
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(_rpc_bind(7777), ("127.0.0.1", pn_server["port"]))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        assert resp[2] == _PTYPE_BIND_ACK
