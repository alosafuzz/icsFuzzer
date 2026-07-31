"""Integration tests for IEC 61850 fuzzer against the software responder.

The responder runs in-process on port 10291 (ephemeral, avoids conflicts).
Tests verify the full TPKT/COTP/ACSE/MMS connect + fuzz loop.
"""

import socket
import struct
import threading
import time

import pytest

from protocols.iec61850.fuzzer import (
    ACSE_AARQ,
    CATEGORY_ADDR,
    CATEGORY_ASN1,
    CATEGORY_FRAG,
    CATEGORY_SERVICE_SWEEP,
    COTP_CR,
    Iec61850Fuzzer,
    _ACSE_AARE,
    _MMS_CONFIRMED_RSP,
    _mms_getnamelist,
    _mms_identify,
    _recv_tpkt,
    _tpkt,
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

# Import responder internals for the in-process server
from scripts.iec61850_responder import handle_client


# ── Inline responder fixture ──────────────────────────────────────────────────

class _RespServer:
    """Minimal single-threaded TCP server running iec61850_responder.handle_client."""

    def __init__(self, port: int):
        self.port   = port
        self._srv   = None
        self._thread = None
        self.actions = []

    def _fake_sc(self, action, **kw):
        self.actions.append((action, kw))

    def _serve(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.settimeout(1.0)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(5)
        while self._running:
            try:
                conn, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, False, None),
                daemon=True,
            )
            t.start()

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        time.sleep(0.15)   # give server time to bind

    def stop(self):
        self._running = False
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass


_PORT = 10291


@pytest.fixture(scope="module")
def responder():
    srv = _RespServer(_PORT)
    srv.start()
    yield srv
    srv.stop()


@pytest.fixture
def fuzzer(responder):
    dev = Device("127.0.0.1", _PORT, "iec61850")
    f   = Iec61850Fuzzer(target=dev, logger=None, delay=0)
    yield f
    f.close()


# ── Handshake tests ───────────────────────────────────────────────────────────

class TestHandshake:
    def test_cotp_cr_cc(self, responder):
        s = socket.socket()
        s.settimeout(5.0)
        s.connect(("127.0.0.1", _PORT))
        s.sendall(COTP_CR)
        cc = _recv_tpkt(s, 3.0)
        assert cc is not None and cc != b''
        assert cc[5] == 0xD0   # COTP CC
        s.close()

    def test_acse_aarq_aare(self, responder):
        s = socket.socket()
        s.settimeout(5.0)
        s.connect(("127.0.0.1", _PORT))
        s.sendall(COTP_CR)
        _recv_tpkt(s, 3.0)        # consume CC
        s.sendall(ACSE_AARQ)
        aare = _recv_tpkt(s, 3.0)
        assert aare is not None and aare != b''
        assert aare[7] == 0x61    # AARE tag
        s.close()

    def test_fuzzer_connect(self, fuzzer):
        fuzzer.connect()
        assert fuzzer._sock is not None

    def test_double_close_safe(self, fuzzer):
        fuzzer.connect()
        fuzzer.close()
        fuzzer.close()   # must not raise


# ── GetNameList ───────────────────────────────────────────────────────────────

class TestGetNameList:
    def test_getnamelist_domain_class(self, fuzzer):
        fuzzer.connect()
        pdu  = _mms_getnamelist(1, 9)
        resp = fuzzer._raw_send_recv(pdu, timeout=3.0)
        assert resp is not None
        assert len(resp) >= 8
        assert resp[7] == _MMS_CONFIRMED_RSP
        assert b"ICS_FUZZER_TARGET" in resp
        fuzzer.close()

    def test_getnamelist_domain_specific(self, fuzzer):
        fuzzer.connect()
        pdu  = _mms_getnamelist(2, 9, b"ICS_FUZZER_TARGET")
        resp = fuzzer._raw_send_recv(pdu, timeout=3.0)
        assert resp is not None
        assert resp[7] == _MMS_CONFIRMED_RSP
        fuzzer.close()

    def test_getnamelist_tpkt_length_valid(self, fuzzer):
        fuzzer.connect()
        pdu  = _mms_getnamelist(1, 9)
        resp = fuzzer._raw_send_recv(pdu, timeout=3.0)
        if resp and len(resp) >= 4:
            claimed = struct.unpack('!H', resp[2:4])[0]
            assert claimed == len(resp)
        fuzzer.close()


# ── Identify ──────────────────────────────────────────────────────────────────

class TestIdentify:
    def test_identify_response(self, fuzzer):
        fuzzer.connect()
        pdu  = _mms_identify(1)
        resp = fuzzer._raw_send_recv(pdu, timeout=3.0)
        assert resp is not None
        assert resp[7] == _MMS_CONFIRMED_RSP
        assert b"icsFuzzer-sw" in resp
        fuzzer.close()

    def test_identify_contains_version(self, fuzzer):
        fuzzer.connect()
        pdu  = _mms_identify(1)
        resp = fuzzer._raw_send_recv(pdu, timeout=3.0)
        assert b"1.0" in resp
        fuzzer.close()


# ── Fuzz category quick-runs ──────────────────────────────────────────────────

class TestBoundaryFuzz:
    def test_boundary_runs_without_exception(self, fuzzer):
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        assert len(results) > 0
        fuzzer.close()

    def test_boundary_has_no_malformed_on_clean_responder(self, fuzzer):
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        malformed = [r for r in results
                     if r.anomaly == ANOMALY_MALFORMED_RESPONSE]
        assert len(malformed) == 0, \
            f"Unexpected malformed responses: {[r.description for r in malformed]}"
        fuzzer.close()


class TestServiceSweepFuzz:
    def test_sweep_runs(self, fuzzer):
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_SERVICE_SWEEP])
        assert len(results) >= 32
        fuzzer.close()

    def test_sweep_returns_exception_or_reset(self, fuzzer):
        """Unknown services must return error or reset — not clean."""
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_SERVICE_SWEEP])
        non_clean = [r for r in results if r.anomaly is not None]
        assert len(non_clean) >= len(results) // 2, \
            "Expected most sweep cases to produce anomalies"
        fuzzer.close()


class TestBinaryCorruptionFuzz:
    def test_binary_corruption_runs(self, fuzzer):
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_BINARY_CORRUPTION])
        assert len(results) > 0
        fuzzer.close()

    def test_crash_indicators_produce_anomaly(self, fuzzer):
        """Crash-indicator results must carry a non-None anomaly code."""
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_BINARY_CORRUPTION])
        crash_results = [r for r in results if r.crash_indicator]
        for r in crash_results:
            assert r.anomaly is not None, \
                f"crash_indicator=True but anomaly=None for: {r.description}"
        fuzzer.close()


class TestFragmentationFuzz:
    def test_fragmentation_runs(self, fuzzer):
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_FRAG])
        assert len(results) > 0
        fuzzer.close()


class TestAsn1CorruptionFuzz:
    def test_asn1_runs(self, fuzzer):
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_ASN1])
        assert len(results) > 0
        fuzzer.close()


class TestAddressSweepFuzz:
    def test_addr_sweep_runs(self, fuzzer):
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_ADDR])
        assert len(results) > 0
        fuzzer.close()


# ── FuzzResult structure ───────────────────────────────────────────────────────

class TestResultStructure:
    def test_result_fields(self, fuzzer):
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        r = results[0]
        assert hasattr(r, "case_id")
        assert hasattr(r, "protocol")
        assert hasattr(r, "category")
        assert hasattr(r, "description")
        assert hasattr(r, "payload")
        assert hasattr(r, "response")
        assert hasattr(r, "anomaly")
        assert hasattr(r, "crash_indicator")
        assert hasattr(r, "duration_ms")
        fuzzer.close()

    def test_protocol_name(self, fuzzer):
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        for r in results:
            assert r.protocol == "iec61850"
        fuzzer.close()

    def test_target_field(self, fuzzer):
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        for r in results:
            assert "127.0.0.1" in r.target
        fuzzer.close()

    def test_duration_positive(self, fuzzer):
        fuzzer.connect()
        results = fuzzer.fuzz([CATEGORY_BOUNDARY])
        for r in results:
            assert r.duration_ms >= 0
        fuzzer.close()
