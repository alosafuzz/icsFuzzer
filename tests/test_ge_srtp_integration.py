"""GE SRTP integration tests — fuzzer against a local TCP responder."""

import socket
import struct
import threading
import time
from typing import Optional

import pytest

from protocols.ge_srtp.fuzzer import (
    GeSrtpFuzzer,
    _init_pkt,
    _read_req,
    _status_req,
    _get_info_req,
    _write_req,
    _srtp_header,
    _PKT_INIT,
    _PKT_INIT_ACK,
    _PKT_REQ,
    _PKT_REQ_ACK,
    _MSG_SHORT_ACK,
    _MSG_SHORT_ERR,
    SVC_STATUS,
    SVC_READ_SYS_MEM,
    SVC_WRITE_SYS_MEM,
    SVC_SET_PLC_RUN,
    SVC_GET_INFO,
    SVC_GET_TIME,
    SVC_GET_FAULT,
    SEG_R,
    SEG_I,
    SEG_AI,
    CATEGORY_SERVICE_SWEEP,
    CATEGORY_MEM_SWEEP,
    CATEGORY_EXTENDED_MSG,
    CATEGORY_MAILBOX,
)
from core.base_module import (
    ANOMALY_EXCEPTION,
    ANOMALY_MALFORMED_RESPONSE,
    ANOMALY_TIMEOUT,
    ANOMALY_CONNECTION_RESET,
    CATEGORY_BINARY_CORRUPTION,
    CATEGORY_BOUNDARY,
    CATEGORY_SEQUENCE,
    CATEGORY_STATE_MACHINE,
    Device,
)


# ---------------------------------------------------------------------------
# _NoopSidecar
# ---------------------------------------------------------------------------

class _NoopSidecar:
    def log(self, action: str, **kwargs): pass
    def summary(self): pass
    def close(self): pass


# ---------------------------------------------------------------------------
# TCP responder fixture
# ---------------------------------------------------------------------------

def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def srtp_server():
    from scripts.ge_srtp_responder import handle_client

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
                conn.settimeout(3.0)
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
def device(srtp_server):
    return Device(ip="127.0.0.1", port=srtp_server["port"], protocol="ge_srtp")


@pytest.fixture
def fuzzer(device):
    f = GeSrtpFuzzer(target=device, logger=None, delay=0)
    f.connect()
    yield f
    f.close()


# ---------------------------------------------------------------------------
# TestConnect
# ---------------------------------------------------------------------------

class TestConnect:
    def test_connect_completes_handshake(self, device):
        f = GeSrtpFuzzer(target=device, logger=None, delay=0)
        f.connect()
        assert f._sock is not None
        f.close()

    def test_close_clears_socket(self, device):
        f = GeSrtpFuzzer(target=device, logger=None, delay=0)
        f.connect()
        f.close()
        assert f._sock is None

    def test_double_close_safe(self, device):
        f = GeSrtpFuzzer(target=device, logger=None, delay=0)
        f.connect()
        f.close()
        f.close()

    def test_handshake_fails_on_closed_port(self, device):
        f = GeSrtpFuzzer(target=Device(ip="127.0.0.1", port=19997, protocol="ge_srtp"),
                         logger=None, delay=0)
        with pytest.raises((ConnectionError, ConnectionRefusedError, OSError)):
            f.connect()
        f.close()


# ---------------------------------------------------------------------------
# TestReplay
# ---------------------------------------------------------------------------

class TestReplay:
    def test_status_req_returns_56_bytes(self, fuzzer):
        resp = fuzzer.replay_payload(_status_req(1))
        assert resp is not None
        assert len(resp) >= 56

    def test_status_req_ack_pkt_type(self, fuzzer):
        resp = fuzzer.replay_payload(_status_req(1))
        pkt_type = struct.unpack_from('<H', resp, 0)[0]
        assert pkt_type == _PKT_REQ_ACK

    def test_get_info_returns_data(self, fuzzer):
        resp = fuzzer.replay_payload(_get_info_req(1))
        assert resp is not None
        assert len(resp) > 56   # includes info payload

    def test_read_sys_mem_r_ok(self, fuzzer):
        resp = fuzzer.replay_payload(_read_req(SVC_READ_SYS_MEM, SEG_R, 1, 1, 2))
        assert resp is not None
        pkt_type = struct.unpack_from('<H', resp, 0)[0]
        assert pkt_type == _PKT_REQ_ACK
        assert resp[30] == _MSG_SHORT_ACK

    def test_read_sys_mem_unknown_seg_error(self, fuzzer):
        resp = fuzzer.replay_payload(_read_req(SVC_READ_SYS_MEM, 0x01, 1, 1, 3))
        assert resp is not None
        assert resp[30] == _MSG_SHORT_ERR

    def test_write_sys_mem_rejected(self, fuzzer):
        resp = fuzzer.replay_payload(_write_req(SVC_WRITE_SYS_MEM, SEG_R, 1, 1,
                                                b'\xFF\xFF', 4))
        assert resp is not None
        assert resp[30] == _MSG_SHORT_ERR

    def test_set_plc_run_rejected(self, fuzzer):
        resp = fuzzer.replay_payload(_write_req(SVC_SET_PLC_RUN, SEG_R, 0, 1,
                                                b'\x01\x00', 5))
        assert resp is not None
        assert resp[30] == _MSG_SHORT_ERR

    def test_unknown_svc_error(self, fuzzer):
        pkt = _srtp_header(pkt_type=_PKT_REQ, svc_req_code=0xF0,
                           seg_selector=SEG_R, target_index=0, target_count=0)
        resp = fuzzer.replay_payload(pkt)
        assert resp is not None
        assert resp[30] == _MSG_SHORT_ERR

    def test_replay_raises_without_connect(self, device):
        f = GeSrtpFuzzer(target=device, logger=None, delay=0)
        with pytest.raises(RuntimeError, match="connect"):
            f.replay_payload(_status_req(1))


# ---------------------------------------------------------------------------
# TestSendCase
# ---------------------------------------------------------------------------

class TestSendCase:
    def test_status_no_anomaly(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        case  = next(c for c in cases if "SHORT_STATUS" in c[2] or "status" in c[2].lower())
        result = fuzzer._send_case(*case)
        assert result.anomaly is None
        assert not result.crash_indicator

    def test_get_info_no_anomaly(self, fuzzer):
        cases  = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        case   = next(c for c in cases if "GET_INFO" in c[2])
        result = fuzzer._send_case(*case)
        assert result.anomaly is None

    def test_read_sys_mem_no_anomaly(self, fuzzer):
        cases  = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        case   = next(c for c in cases if "READ_SYS_MEM" in c[2] and "%R" in c[2])
        result = fuzzer._send_case(*case)
        assert result.anomaly is None

    def test_send_case_has_duration(self, fuzzer):
        cases  = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        result = fuzzer._send_case(*cases[0])
        assert result.duration_ms >= 0

    def test_write_rejected_is_exception(self, fuzzer):
        payload = _write_req(SVC_WRITE_SYS_MEM, SEG_R, 1, 1, b'\xFF\xFF', 1)
        result  = fuzzer._send_case("t-write", CATEGORY_BOUNDARY, "write test", payload)
        assert result.anomaly == ANOMALY_EXCEPTION


# ---------------------------------------------------------------------------
# TestClassifyResponse
# ---------------------------------------------------------------------------

class TestClassifyResponse:
    def _mk_result(self):
        from core.base_module import FuzzResult
        r = FuzzResult(case_id="x", protocol="ge_srtp",
                       target="127.0.0.1:18246",
                       category=CATEGORY_BOUNDARY,
                       description="test",
                       payload=b'')
        return r

    def _valid_ack(self, msg_type=_MSG_SHORT_ACK) -> bytes:
        hdr  = struct.pack('<H', _PKT_REQ_ACK)
        hdr += struct.pack('<H', 1)
        hdr += struct.pack('<H', 0)
        hdr += b'\x00' * 20
        hdr += b'\x00\x00\x00'
        hdr += bytes([1])
        hdr += bytes([msg_type])
        hdr += b'\x00' * 26
        return hdr

    def test_short_ack_no_anomaly(self, fuzzer):
        r = self._mk_result()
        fuzzer._classify_response(self._valid_ack(_MSG_SHORT_ACK), r)
        assert r.anomaly is None

    def test_short_err_is_exception(self, fuzzer):
        r = self._mk_result()
        fuzzer._classify_response(self._valid_ack(_MSG_SHORT_ERR), r)
        assert r.anomaly == ANOMALY_EXCEPTION
        assert not r.crash_indicator

    def test_wrong_pkt_type_malformed(self, fuzzer):
        r = self._mk_result()
        data = struct.pack('<H', 0x0099) + b'\x00' * 54
        fuzzer._classify_response(data, r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert r.crash_indicator

    def test_too_short_malformed(self, fuzzer):
        r = self._mk_result()
        fuzzer._classify_response(b'\x03\x00', r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE


# ---------------------------------------------------------------------------
# TestFuzzLoop
# ---------------------------------------------------------------------------

class TestFuzzLoop:
    def test_boundary_no_malformed_response(self, fuzzer):
        results  = fuzzer.fuzz([CATEGORY_BOUNDARY])
        malformed = [r for r in results
                     if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, \
            [f"{r.description}: {r.anomaly}" for r in malformed]

    def test_sequence_no_malformed_response(self, fuzzer):
        results  = fuzzer.fuzz([CATEGORY_SEQUENCE])
        malformed = [r for r in results
                     if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, \
            [f"{r.description}: {r.anomaly}" for r in malformed]

    def test_state_machine_no_malformed_response(self, fuzzer):
        results  = fuzzer.fuzz([CATEGORY_STATE_MACHINE])
        malformed = [r for r in results
                     if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, \
            [f"{r.description}: {r.anomaly}" for r in malformed]

    def test_mailbox_no_malformed_response(self, fuzzer):
        results  = fuzzer.fuzz([CATEGORY_MAILBOX])
        malformed = [r for r in results
                     if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, \
            [f"{r.description}: {r.anomaly}" for r in malformed]

    def test_extended_msg_no_malformed_response(self, fuzzer):
        results  = fuzzer.fuzz([CATEGORY_EXTENDED_MSG])
        malformed = [r for r in results
                     if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, \
            [f"{r.description}: {r.anomaly}" for r in malformed]

    def test_binary_corruption_has_anomalies(self, fuzzer):
        results = fuzzer.fuzz([CATEGORY_BINARY_CORRUPTION])
        bad = [r for r in results if r.crash_indicator or r.anomaly is not None]
        assert len(bad) > 0

    def test_all_results_have_protocol(self, fuzzer):
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        assert all(r.protocol == "ge_srtp" for r in results)

    def test_fuzz_returns_all_results(self, fuzzer):
        cases   = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        assert len(results) == len(cases)
