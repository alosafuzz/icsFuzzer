"""Integration tests for ModbusFuzzer send/receive path.

Spins up an inline Modbus responder on a free loopback port so the full
send loop, anomaly classification, JSONL logging, and replay path can be
exercised without a physical PLC.
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
from protocols.modbus.fuzzer import ModbusFuzzer

# ---------------------------------------------------------------------------
# Inline Modbus responder (mirrors scripts/modbus_responder.py core logic)
# ---------------------------------------------------------------------------

_ASSIGNED_PUBLIC = frozenset([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x2B,
])


def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


class _NoopSidecar:
    """Drop-in sidecar that discards all log entries — used in integration tests."""
    def log(self, *args, **kwargs):
        pass


def _handle_conn(conn, addr):
    """Thin wrapper so integration tests don't need to import scripts/."""
    from scripts.modbus_responder import handle_client
    handle_client(conn, addr, sidecar=_NoopSidecar(), verbose=False)


@pytest.fixture(scope="module")
def modbus_server():
    """Modbus responder on a free loopback port. Module-scoped for speed."""
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
def connected_fuzzer(modbus_server):
    host, port = modbus_server
    target = Device(ip=host, port=port, protocol="modbus")
    f = ModbusFuzzer(target=target, logger=None, delay=0)
    f.connect(target)
    yield f
    f.close()


# ---------------------------------------------------------------------------
# Connect / close lifecycle
# ---------------------------------------------------------------------------

class TestConnectClose:
    def test_connect_and_close(self, modbus_server):
        host, port = modbus_server
        target = Device(ip=host, port=port, protocol="modbus")
        f = ModbusFuzzer(target=target, logger=None)
        f.connect(target)
        assert f._sock is not None
        f.close()
        assert f._sock is None

    def test_double_close_does_not_raise(self, modbus_server):
        host, port = modbus_server
        target = Device(ip=host, port=port, protocol="modbus")
        f = ModbusFuzzer(target=target, logger=None)
        f.connect(target)
        f.close()
        f.close()  # second close must be silent

    def test_close_without_connect(self):
        target = Device(ip="127.0.0.1", port=502, protocol="modbus")
        f = ModbusFuzzer(target=target, logger=None)
        f.close()  # must not raise


# ---------------------------------------------------------------------------
# _send_case — response classification
# ---------------------------------------------------------------------------

class TestSendCase:
    def _frame(self, fc, tid=1):
        pdu = struct.pack(">BHH", fc, 0x0000, 0x0001)
        return struct.pack(">HHHB", tid, 0, 1 + len(pdu), 0xFF) + pdu

    def test_assigned_fc_returns_exception_anomaly(self, connected_fuzzer):
        frame = self._frame(0x03)  # FC03 Read Holding Regs
        result = connected_fuzzer._send_case("mb-i-001", "boundary", "FC03", frame)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert result.crash_indicator is False

    def test_unassigned_fc_returns_exception_anomaly(self, connected_fuzzer):
        pdu = bytes([0x41])  # user-defined FC
        frame = struct.pack(">HHHB", 2, 0, 1 + len(pdu), 0xFF) + pdu
        result = connected_fuzzer._send_case("mb-i-002", "invalid_function_codes", "FC 0x41", frame)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert result.crash_indicator is False

    def test_result_fields_populated(self, connected_fuzzer):
        frame = self._frame(0x01, tid=42)
        result = connected_fuzzer._send_case("mb-i-003", "boundary", "FC01", frame)
        assert result.case_id == "mb-i-003"
        assert result.protocol == "modbus"
        assert result.category == "boundary"
        assert result.payload == frame
        assert result.response is not None
        assert result.duration_ms is not None and result.duration_ms >= 0

    def test_exception_response_decoded(self, connected_fuzzer):
        frame = self._frame(0x03, tid=10)
        result = connected_fuzzer._send_case("mb-i-004", "boundary", "FC03", frame)
        assert result.anomaly == ANOMALY_EXCEPTION
        assert result.response_decoded is not None
        assert "exception_fc" in result.response_decoded
        assert "exception_code" in result.response_decoded

    def test_tid_mismatch_flagged_as_malformed(self, connected_fuzzer):
        # Directly call _classify_response with a mismatched TID in the response
        payload = struct.pack(">HHHB", 0x1234, 0, 6, 0xFF) + b"\x03\x00\x00\x00\x01"
        fake_response = struct.pack(">HHHB", 0xFFFF, 0, 2, 0xFF) + bytes([0x83, 0x02])
        result = FuzzResult(
            case_id="mb-i-005", protocol="modbus",
            target="127.0.0.1:502", category="test", description="tid mismatch",
        )
        connected_fuzzer._classify_response(payload, fake_response, result)
        assert result.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert result.crash_indicator is True

    def test_bad_proto_id_flagged_as_malformed(self, connected_fuzzer):
        payload = struct.pack(">HHHB", 1, 0, 6, 0xFF) + b"\x03\x00\x00\x00\x01"
        # Build a response with protocol ID = 0x0001 (invalid)
        fake_response = struct.pack(">HHHB", 1, 0x0001, 2, 0xFF) + bytes([0x83, 0x02])
        result = FuzzResult(
            case_id="mb-i-006", protocol="modbus",
            target="127.0.0.1:502", category="test", description="bad proto_id",
        )
        connected_fuzzer._classify_response(payload, fake_response, result)
        assert result.anomaly == ANOMALY_MALFORMED_RESPONSE
        assert result.crash_indicator is True


# ---------------------------------------------------------------------------
# replay_payload
# ---------------------------------------------------------------------------

class TestReplay:
    def test_replay_returns_response_bytes(self, connected_fuzzer):
        pdu = struct.pack(">BHH", 0x03, 0x0000, 0x0001)
        frame = struct.pack(">HHHB", 1, 0, 1 + len(pdu), 0xFF) + pdu
        response = connected_fuzzer.replay_payload(frame)
        assert isinstance(response, bytes)
        assert len(response) >= 7

    def test_replay_without_connect_raises(self):
        target = Device(ip="127.0.0.1", port=502, protocol="modbus")
        f = ModbusFuzzer(target=target, logger=None)
        with pytest.raises(RuntimeError, match="connect"):
            f.replay_payload(b"\x00\x01\x00\x00\x00\x06\xFF\x03\x00\x00\x00\x01")


# ---------------------------------------------------------------------------
# Full generate → send loop
# ---------------------------------------------------------------------------

class TestFuzzLoop:
    def test_boundary_category_end_to_end(self, connected_fuzzer):
        cases = connected_fuzzer.generate_cases(["boundary"])
        results = [connected_fuzzer._send_case(cid, cat, desc, payload)
                   for cid, cat, desc, payload in cases]
        assert len(results) == 69
        # Every result should have a response or an anomaly — none should be bare
        for r in results:
            assert r.response is not None or r.anomaly is not None

    def test_logger_integration(self, modbus_server, tmp_path):
        from core.logger import FuzzLogger
        host, port = modbus_server
        target = Device(ip=host, port=port, protocol="modbus")
        with FuzzLogger(str(tmp_path / "out")) as logger:
            f = ModbusFuzzer(target=target, logger=logger, delay=0)
            f.connect(target)
            pdu = struct.pack(">BHH", 0x03, 0x0000, 0x0001)
            frame = struct.pack(">HHHB", 1, 0, 1 + len(pdu), 0xFF) + pdu
            f._send_case("mb-log-001", "boundary", "FC03 read", frame)
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
        assert rec["id"] == "mb-log-001"
        assert rec["protocol"] == "modbus"
        assert rec["anomaly"] == ANOMALY_EXCEPTION
        assert rec["payload_hex"] is not None
        assert rec["response_hex"] is not None
