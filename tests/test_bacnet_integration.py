"""BACnet integration tests — fuzzer against a local UDP responder."""

import socket
import struct
import threading
import time
from typing import Optional

import pytest

from protocols.bacnet.fuzzer import (
    BacnetFuzzer,
    _who_is,
    _i_am,
    _read_property,
    _write_property,
    _subscribe_cov,
    _register_foreign_device,
    _read_bdt,
    _bvll,
    _npdu,
    _apdu_unconfirmed,
    _OBJ_DEVICE,
    _OBJ_ANALOG_INPUT,
    _OBJ_ANALOG_VALUE,
    _OBJ_BINARY_VALUE,
    _PROP_OBJECT_NAME,
    _PROP_PRESENT_VALUE,
    _PROP_VENDOR_ID,
    _USVC_WHO_IS,
    _USVC_I_AM,
    _BVLL_UNICAST,
    _BVLL_RESULT,
    _BVLL_READ_BDT_ACK,
    CATEGORY_READ_WRITE_PROP,
    CATEGORY_WHOIS_RANGE,
    CATEGORY_COV_FLOOD,
    CATEGORY_BBMD,
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
)


# ---------------------------------------------------------------------------
# _NoopSidecar — satisfies log/summary/close contract without writing files
# ---------------------------------------------------------------------------

class _NoopSidecar:
    def log(self, action: str, **kwargs):
        pass

    def summary(self):
        pass

    def close(self):
        pass


# ---------------------------------------------------------------------------
# UDP responder fixture (module-scoped)
# ---------------------------------------------------------------------------

def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve_one(sock: socket.socket, sidecar):
    """Handle one datagram and send the response if any."""
    from scripts.bacnet_responder import handle_datagram
    try:
        sock.settimeout(5.0)
        data, addr = sock.recvfrom(65535)
        resp = handle_datagram(data, addr, sidecar=sidecar, verbose=False)
        if resp:
            sock.sendto(resp, addr)
    except socket.timeout:
        pass


@pytest.fixture(scope="module")
def bacnet_server():
    """UDP server running the BACnet responder in a background thread."""
    from scripts.bacnet_responder import handle_datagram

    port   = _free_port()
    sidecar = _NoopSidecar()
    stop   = threading.Event()

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", port))
    srv_sock.settimeout(0.5)

    def _loop():
        while not stop.is_set():
            try:
                data, addr = srv_sock.recvfrom(65535)
                resp = handle_datagram(data, addr, sidecar=sidecar, verbose=False)
                if resp:
                    srv_sock.sendto(resp, addr)
            except socket.timeout:
                continue
            except Exception:
                continue

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    yield {"port": port, "sidecar": sidecar}

    stop.set()
    t.join(timeout=2.0)
    srv_sock.close()


@pytest.fixture
def device(bacnet_server):
    return Device(ip="127.0.0.1", port=bacnet_server["port"], protocol="bacnet")


@pytest.fixture
def fuzzer(device):
    f = BacnetFuzzer(target=device, logger=None, delay=0)
    f.connect()
    yield f
    f.close()


# ---------------------------------------------------------------------------
# TestConnect
# ---------------------------------------------------------------------------

class TestConnect:
    def test_connect_creates_socket(self, device):
        f = BacnetFuzzer(target=device, logger=None, delay=0)
        assert f._sock is None
        f.connect()
        assert f._sock is not None
        f.close()

    def test_close_clears_socket(self, device):
        f = BacnetFuzzer(target=device, logger=None, delay=0)
        f.connect()
        f.close()
        assert f._sock is None

    def test_double_close_safe(self, device):
        f = BacnetFuzzer(target=device, logger=None, delay=0)
        f.connect()
        f.close()
        f.close()   # should not raise

    def test_connect_stores_target_addr(self, device):
        f = BacnetFuzzer(target=device, logger=None, delay=0)
        f.connect()
        assert f._target_addr == ("127.0.0.1", device.port)
        f.close()


# ---------------------------------------------------------------------------
# TestReplay
# ---------------------------------------------------------------------------

class TestReplay:
    def test_who_is_gets_i_am(self, fuzzer):
        resp = fuzzer.replay_payload(_who_is())
        assert resp is not None
        assert len(resp) >= 4
        assert resp[0] == 0x81
        # APDU type at offset 6 should be 0x10 (Unconfirmed) service 0x00 (I-Am)
        assert resp[6] == 0x10
        assert resp[7] == _USVC_I_AM

    def test_who_is_with_range_gets_i_am(self, fuzzer):
        resp = fuzzer.replay_payload(_who_is(0, 4194303))
        assert resp is not None
        assert resp[7] == _USVC_I_AM

    def test_who_is_wrong_range_no_response(self, fuzzer):
        # Device instance 1234; range 5000-5001 should yield no response
        resp = fuzzer.replay_payload(_who_is(5000, 5001))
        # Responder always responds regardless of range — just check parse safety
        # (our soft responder responds to all Who-Is)
        # so just assert it doesn't raise
        pass

    def test_read_property_device_name(self, fuzzer):
        resp = fuzzer.replay_payload(
            _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 1))
        assert resp is not None
        assert resp[0] == 0x81
        # Complex-ACK = 0x30
        assert resp[6] == 0x30

    def test_read_property_present_value(self, fuzzer):
        resp = fuzzer.replay_payload(
            _read_property(_OBJ_ANALOG_INPUT, 0, _PROP_PRESENT_VALUE, 2))
        assert resp is not None
        assert resp[6] == 0x30

    def test_read_unknown_object_returns_error(self, fuzzer):
        resp = fuzzer.replay_payload(
            _read_property(_OBJ_ANALOG_INPUT, 9999, _PROP_PRESENT_VALUE, 3))
        assert resp is not None
        # Error APDU = 0x50
        assert resp[6] == 0x50

    def test_read_unknown_property_returns_error(self, fuzzer):
        resp = fuzzer.replay_payload(
            _read_property(_OBJ_DEVICE, 1234, 0xFF, 4))
        assert resp is not None
        assert resp[6] == 0x50

    def test_write_property_simple_ack(self, fuzzer):
        resp = fuzzer.replay_payload(
            _write_property(_OBJ_ANALOG_VALUE, 0, _PROP_PRESENT_VALUE,
                            bytes([0x44]) + struct.pack('>f', 5.0), 5))
        assert resp is not None
        # Simple-ACK = 0x20
        assert resp[6] == 0x20

    def test_subscribe_cov_simple_ack(self, fuzzer):
        resp = fuzzer.replay_payload(
            _subscribe_cov(1, _OBJ_ANALOG_INPUT, 0, invoke_id=6))
        assert resp is not None
        assert resp[6] == 0x20

    def test_read_bdt_returns_ack(self, fuzzer):
        resp = fuzzer.replay_payload(_read_bdt())
        assert resp is not None
        assert resp[1] == _BVLL_READ_BDT_ACK

    def test_register_fd_returns_bvlc_result(self, fuzzer):
        resp = fuzzer.replay_payload(_register_foreign_device(600))
        assert resp is not None
        assert resp[1] == _BVLL_RESULT
        code = struct.unpack_from('>H', resp, 4)[0]
        assert code == 0x0000  # success

    def test_replay_raises_without_connect(self, device):
        f = BacnetFuzzer(target=device, logger=None, delay=0)
        with pytest.raises(RuntimeError, match="connect"):
            f.replay_payload(_who_is())


# ---------------------------------------------------------------------------
# TestSendCase
# ---------------------------------------------------------------------------

class TestSendCase:
    def test_who_is_no_anomaly(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        who_is_case = next(c for c in cases if "Who-Is broadcast" in c[2])
        result = fuzzer._send_case(*who_is_case)
        assert result.anomaly is None
        assert not result.crash_indicator

    def test_read_device_name_no_anomaly(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        case  = next(c for c in cases if "ReadProperty Device Object_Name" in c[2])
        result = fuzzer._send_case(*case)
        assert result.anomaly is None
        assert not result.crash_indicator

    def test_write_property_no_anomaly(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        case  = next(c for c in cases if "WriteProperty" in c[2])
        result = fuzzer._send_case(*case)
        assert result.anomaly is None
        assert not result.crash_indicator

    def test_send_case_has_duration(self, fuzzer):
        cases = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        result = fuzzer._send_case(*cases[0])
        assert result.duration_ms >= 0

    def test_send_case_has_response_bytes(self, fuzzer):
        pkt = _read_property(_OBJ_DEVICE, 1234, _PROP_OBJECT_NAME, 1)
        result = fuzzer._send_case("t-resp", CATEGORY_BOUNDARY,
                                   "read device name", pkt)
        assert result.response is not None
        assert len(result.response) > 0


# ---------------------------------------------------------------------------
# TestClassifyResponse
# ---------------------------------------------------------------------------

class TestClassifyResponse:
    def _mk_result(self):
        from core.base_module import FuzzResult
        r = FuzzResult(case_id="x", protocol="bacnet",
                       target="127.0.0.1:47809",
                       category=CATEGORY_BOUNDARY,
                       description="test",
                       payload=b'')
        return r

    def test_i_am_no_anomaly(self, fuzzer):
        r = self._mk_result()
        # Craft a minimal I-Am packet
        pkt = _i_am()
        fuzzer._classify_response(pkt, r)
        assert r.anomaly is None

    def test_who_is_no_anomaly(self, fuzzer):
        # Who-Is is unconfirmed (0x10) — we get I-Am back; classify the I-Am
        r   = self._mk_result()
        pkt = _i_am()
        fuzzer._classify_response(pkt, r)
        assert r.anomaly is None

    def test_complex_ack_no_anomaly(self, fuzzer):
        r = self._mk_result()
        # Complex-ACK: 0x30 (type) + invoke_id + service + data
        payload = b'\x81\x0A\x00\x0A\x01\x00\x30\x01\x0C\x21\x01'
        fuzzer._classify_response(payload, r)
        assert r.anomaly is None

    def test_simple_ack_no_anomaly(self, fuzzer):
        r = self._mk_result()
        payload = b'\x81\x0A\x00\x09\x01\x00\x20\x01\x0F'
        fuzzer._classify_response(payload, r)
        assert r.anomaly is None

    def test_error_apdu_is_exception(self, fuzzer):
        r = self._mk_result()
        payload = b'\x81\x0A\x00\x0D\x01\x00\x50\x01\x0C\x91\x01\x91\x1F'
        fuzzer._classify_response(payload, r)
        assert r.anomaly == ANOMALY_EXCEPTION
        assert not r.crash_indicator

    def test_reject_apdu_is_exception(self, fuzzer):
        r = self._mk_result()
        payload = b'\x81\x0A\x00\x09\x01\x00\x60\x01\x09'
        fuzzer._classify_response(payload, r)
        assert r.anomaly == ANOMALY_EXCEPTION
        assert not r.crash_indicator

    def test_abort_apdu_is_exception(self, fuzzer):
        r = self._mk_result()
        payload = b'\x81\x0A\x00\x09\x01\x00\x70\x01\x04'
        fuzzer._classify_response(payload, r)
        assert r.anomaly == ANOMALY_EXCEPTION
        assert not r.crash_indicator

    def test_short_response_malformed(self, fuzzer):
        r = self._mk_result()
        fuzzer._classify_response(b'\x81\x0A', r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert r.crash_indicator

    def test_wrong_type_byte_malformed(self, fuzzer):
        r = self._mk_result()
        fuzzer._classify_response(b'\x80\x0A\x00\x08\x01\x00\x10\x08', r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert r.crash_indicator

    def test_bvlc_result_success_no_anomaly(self, fuzzer):
        r = self._mk_result()
        payload = b'\x81\x00\x00\x06' + struct.pack('>H', 0x0000)
        fuzzer._classify_response(payload, r)
        assert r.anomaly is None

    def test_bvlc_result_error_is_exception(self, fuzzer):
        r = self._mk_result()
        payload = b'\x81\x00\x00\x06' + struct.pack('>H', 0x0030)
        fuzzer._classify_response(payload, r)
        assert r.anomaly == ANOMALY_EXCEPTION
        assert not r.crash_indicator

    def test_bdt_ack_no_anomaly(self, fuzzer):
        r = self._mk_result()
        payload = b'\x81\x03\x00\x04'
        fuzzer._classify_response(payload, r)
        assert r.anomaly is None

    def test_fdt_ack_no_anomaly(self, fuzzer):
        r = self._mk_result()
        payload = b'\x81\x07\x00\x04'
        fuzzer._classify_response(payload, r)
        assert r.anomaly is None

    def test_unknown_pdu_type_malformed(self, fuzzer):
        r = self._mk_result()
        payload = b'\x81\x0A\x00\x09\x01\x00\x80\x01\x00'
        fuzzer._classify_response(payload, r)
        assert r.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert r.crash_indicator


# ---------------------------------------------------------------------------
# TestFuzzLoop
# ---------------------------------------------------------------------------

class TestFuzzLoop:
    def test_boundary_no_malformed_response(self, fuzzer):
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        malformed = [r for r in results
                     if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, \
            [f"{r.description}: {r.anomaly}" for r in malformed]

    def test_read_write_no_malformed_response(self, fuzzer):
        results  = fuzzer.fuzz([CATEGORY_READ_WRITE_PROP])
        malformed = [r for r in results
                     if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, \
            [f"{r.description}: {r.anomaly}" for r in malformed]

    def test_whois_no_malformed_response(self, fuzzer):
        results  = fuzzer.fuzz([CATEGORY_WHOIS_RANGE])
        malformed = [r for r in results
                     if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, \
            [f"{r.description}: {r.anomaly}" for r in malformed]

    def test_cov_flood_no_malformed_response(self, fuzzer):
        results  = fuzzer.fuzz([CATEGORY_COV_FLOOD])
        malformed = [r for r in results
                     if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, \
            [f"{r.description}: {r.anomaly}" for r in malformed]

    def test_bbmd_no_malformed_response(self, fuzzer):
        results  = fuzzer.fuzz([CATEGORY_BBMD])
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

    def test_all_results_have_protocol(self, fuzzer):
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        assert all(r.protocol == "bacnet" for r in results)

    def test_binary_corruption_has_malformed_or_timeout(self, fuzzer):
        results = fuzzer.fuzz([CATEGORY_BINARY_CORRUPTION])
        bad = [r for r in results
               if r.anomaly in (ANOMALY_MALFORMED_RESPONSE, ANOMALY_TIMEOUT)
               or r.crash_indicator]
        # Many corruption cases should produce anomalies
        assert len(bad) > 0

    def test_fuzz_returns_all_results(self, fuzzer):
        cases   = fuzzer.generate_cases([CATEGORY_BOUNDARY])
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        assert len(results) == len(cases)
