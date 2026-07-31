"""Integration tests for FINS fuzzer + software responder.

Spins up scripts.fins_responder._responder_loop on a free UDP port,
then exercises the fuzzer against it.
"""

import socket
import struct
import threading
import time
import pytest

from scripts.fins_responder import _responder_loop
from protocols.fins.fuzzer import (
    AREA_CIO_WORD, AREA_DM_WORD, AREA_HR_WORD,
    AREA_TIMER_PV, AREA_COUNTER_PV, AREA_EM0_WORD,
    CATEGORY_BOUNDARY, CATEGORY_BINARY_CORRUPTION,
    CATEGORY_MEMORY_READ, CATEGORY_MEMORY_WRITE,
    CATEGORY_CPU_CONTROL, CATEGORY_COMMAND_SWEEP,
    CATEGORY_STATE_MACHINE, CATEGORY_SEQUENCE,
    FinsFuzzer,
    _fins_read, _fins_write, _fins_run, _fins_stop, _fins_reset,
    _fins_status, _fins_ctrl_data,
)
from core.base_module import ANOMALY_TIMEOUT, ANOMALY_EXCEPTION, Device


# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

class _RecordingSidecar:
    def __init__(self):
        self._log = []
        self._lock = threading.Lock()

    def log(self, action, **kwargs):
        with self._lock:
            self._log.append({"action": action, **kwargs})

    def actions(self):
        with self._lock:
            return [e["action"] for e in self._log]

    def count(self, action):
        return self.actions().count(action)

    def clear(self):
        with self._lock:
            self._log.clear()


class _NullLogger:
    def log(self, result): pass


def _free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def fins_server():
    sidecar = _RecordingSidecar()
    port    = _free_udp_port()
    stop    = threading.Event()
    t = threading.Thread(
        target=_responder_loop,
        args=("127.0.0.1", port, sidecar, stop, False),
        daemon=True,
    )
    t.start()
    time.sleep(0.05)
    yield {"port": port, "sidecar": sidecar}
    stop.set()
    t.join(timeout=2.0)


def _send_recv(port, pkt, timeout=3.0):
    """Fire-and-forget single UDP exchange."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(pkt, ("127.0.0.1", port))
        try:
            data, _ = s.recvfrom(2048)
            return data
        except socket.timeout:
            return None


def _fuzzer(port):
    dev = Device(ip="127.0.0.1", port=port, protocol="fins")
    f = FinsFuzzer(target=dev, logger=_NullLogger())
    f.connect()
    return f


# ---------------------------------------------------------------------------
# Basic protocol handling
# ---------------------------------------------------------------------------

class TestBasicExchange:
    def test_status_gets_response(self, fins_server):
        resp = _send_recv(fins_server["port"], _fins_status(sid=1))
        assert resp is not None
        assert len(resp) >= 14

    def test_response_icf_is_set(self, fins_server):
        resp = _send_recv(fins_server["port"], _fins_status(sid=1))
        assert resp and (resp[0] & 0xC0) == 0xC0

    def test_response_sid_echoed(self, fins_server):
        resp = _send_recv(fins_server["port"], _fins_status(sid=0x42))
        assert resp and resp[9] == 0x42

    def test_response_mrc_echoed(self, fins_server):
        pkt  = _fins_status(sid=1)   # MRC=0x06
        resp = _send_recv(fins_server["port"], pkt)
        assert resp and resp[10] == 0x06

    def test_response_src_echoed(self, fins_server):
        pkt  = _fins_status(sid=1)   # SRC=0x01
        resp = _send_recv(fins_server["port"], pkt)
        assert resp and resp[11] == 0x01

    def test_end_code_ok_for_status(self, fins_server):
        resp = _send_recv(fins_server["port"], _fins_status(sid=1))
        assert resp and resp[12:14] == b'\x00\x00'

    def test_status_ok_logged(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        _send_recv(fins_server["port"], _fins_status(sid=1))
        time.sleep(0.05)
        assert "status_ok" in sidecar.actions()


# ---------------------------------------------------------------------------
# Memory Read
# ---------------------------------------------------------------------------

class TestMemoryRead:
    def test_cio_read_ok(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"],
                          _fins_read(area=AREA_CIO_WORD, address=0, count=1, sid=1))
        time.sleep(0.05)
        assert resp is not None
        assert resp[12:14] == b'\x00\x00'
        assert "read_ok" in sidecar.actions()

    def test_dm_read_ok(self, fins_server):
        resp = _send_recv(fins_server["port"],
                          _fins_read(area=AREA_DM_WORD, address=0, count=1, sid=1))
        assert resp and resp[12:14] == b'\x00\x00'

    def test_hr_read_ok(self, fins_server):
        resp = _send_recv(fins_server["port"],
                          _fins_read(area=AREA_HR_WORD, address=0, count=1, sid=1))
        assert resp and resp[12:14] == b'\x00\x00'

    def test_timer_pv_read_ok(self, fins_server):
        resp = _send_recv(fins_server["port"],
                          _fins_read(area=AREA_TIMER_PV, address=0, count=1, sid=1))
        assert resp and resp[12:14] == b'\x00\x00'

    def test_unknown_area_returns_error(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"],
                          _fins_read(area=0xFF, address=0, count=1, sid=1))
        time.sleep(0.05)
        assert resp is not None
        assert resp[12:14] != b'\x00\x00'
        assert "read_bad_area" in sidecar.actions()

    def test_address_too_large_returns_error(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"],
                          _fins_read(area=AREA_CIO_WORD, address=0x8000, count=1, sid=1))
        time.sleep(0.05)
        assert resp and resp[12:14] != b'\x00\x00'
        assert "read_bad_address" in sidecar.actions()

    def test_count_zero_returns_error(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"],
                          _fins_read(area=AREA_CIO_WORD, address=0, count=0, sid=1))
        time.sleep(0.05)
        assert resp and resp[12:14] != b'\x00\x00'
        assert "read_bad_count" in sidecar.actions()

    def test_read_returns_stub_data(self, fins_server):
        resp = _send_recv(fins_server["port"],
                          _fins_read(area=AREA_CIO_WORD, address=0, count=4, sid=1))
        # 14 header+end_code + 8 data bytes (4 words * 2 bytes)
        assert resp and len(resp) >= 22


# ---------------------------------------------------------------------------
# Memory Write
# ---------------------------------------------------------------------------

class TestMemoryWrite:
    def test_dm_write_ok(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"],
                          _fins_write(area=AREA_DM_WORD, address=0,
                                      count=1, data=b'\x00\x00', sid=1))
        time.sleep(0.05)
        assert resp and resp[12:14] == b'\x00\x00'
        assert "write_ok" in sidecar.actions()

    def test_timer_pv_write_rejected(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"],
                          _fins_write(area=AREA_TIMER_PV, address=0,
                                      count=1, data=b'\x00\x01', sid=1))
        time.sleep(0.05)
        assert resp and resp[12:14] != b'\x00\x00'
        assert "write_reject" in sidecar.actions()

    def test_unknown_area_write_bad(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"],
                          _fins_write(area=0x00, address=0,
                                      count=1, data=b'\xDE\xAD', sid=1))
        time.sleep(0.05)
        assert resp and resp[12:14] != b'\x00\x00'
        assert "write_bad_area" in sidecar.actions()


# ---------------------------------------------------------------------------
# CPU Control
# ---------------------------------------------------------------------------

class TestCpuControl:
    def test_run_rejected(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"], _fins_run(sid=1))
        time.sleep(0.05)
        assert resp and resp[12:14] != b'\x00\x00'
        assert "run_reject" in sidecar.actions()

    def test_stop_rejected(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"], _fins_stop(sid=1))
        time.sleep(0.05)
        assert resp and resp[12:14] != b'\x00\x00'
        assert "stop_reject" in sidecar.actions()

    def test_reset_rejected(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"], _fins_reset(sid=1))
        time.sleep(0.05)
        assert resp and resp[12:14] != b'\x00\x00'
        assert "reset_reject" in sidecar.actions()

    def test_clock_read_ok(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        from protocols.fins.fuzzer import _fins_clock_read
        resp = _send_recv(fins_server["port"], _fins_clock_read(sid=1))
        time.sleep(0.05)
        assert resp and resp[12:14] == b'\x00\x00'
        assert "clock_ok" in sidecar.actions()

    def test_ctrl_data_ok(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"], _fins_ctrl_data(sid=1))
        time.sleep(0.05)
        assert resp and resp[12:14] == b'\x00\x00'
        assert "ctrl_data_ok" in sidecar.actions()


# ---------------------------------------------------------------------------
# Unknown commands
# ---------------------------------------------------------------------------

class TestUnknownCommands:
    def test_unknown_mrc_returns_error(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        from protocols.fins.fuzzer import _fins_header
        pkt  = _fins_header(mrc=0xAA, src=0xBB, sid=1)
        resp = _send_recv(fins_server["port"], pkt)
        time.sleep(0.05)
        assert resp and resp[12:14] != b'\x00\x00'
        assert "cmd_unknown" in sidecar.actions()

    def test_malformed_short_packet_logged(self, fins_server):
        sidecar = fins_server["sidecar"]
        sidecar.clear()
        resp = _send_recv(fins_server["port"], b'\x80\x00\x02')
        time.sleep(0.1)
        assert "cmd_malformed" in sidecar.actions()


# ---------------------------------------------------------------------------
# Fuzzer via FuzzModule.fuzz()
# ---------------------------------------------------------------------------

class TestBoundaryViaFuzzer:
    def test_boundary_no_timeouts(self, fins_server):
        f = _fuzzer(fins_server["port"])
        results = f.fuzz([CATEGORY_BOUNDARY])
        f.close()
        timeouts = [r for r in results if r.anomaly == ANOMALY_TIMEOUT]
        assert len(timeouts) == 0

    def test_memory_read_no_timeouts(self, fins_server):
        f = _fuzzer(fins_server["port"])
        results = f.fuzz([CATEGORY_MEMORY_READ])
        f.close()
        timeouts = [r for r in results if r.anomaly == ANOMALY_TIMEOUT]
        assert len(timeouts) == 0

    def test_memory_write_no_timeouts(self, fins_server):
        f = _fuzzer(fins_server["port"])
        results = f.fuzz([CATEGORY_MEMORY_WRITE])
        f.close()
        timeouts = [r for r in results if r.anomaly == ANOMALY_TIMEOUT]
        assert len(timeouts) == 0


class TestBinaryCorruptionViaFuzzer:
    def test_responder_survives_corruption(self, fins_server):
        """After all corruption cases, responder must still respond."""
        f = _fuzzer(fins_server["port"])
        f.fuzz([CATEGORY_BINARY_CORRUPTION])
        # Verify responder is still alive
        resp = f.replay_payload(_fins_status(sid=0x01))
        f.close()
        assert resp is not None
        assert len(resp) >= 14

    def test_command_sweep_all_get_responses(self, fins_server):
        f = _fuzzer(fins_server["port"])
        results = f.fuzz([CATEGORY_COMMAND_SWEEP])
        f.close()
        timeouts = [r for r in results if r.anomaly == ANOMALY_TIMEOUT]
        assert len(timeouts) == 0


class TestCpuControlViaFuzzer:
    def test_cpu_control_all_rejected_not_timeout(self, fins_server):
        f = _fuzzer(fins_server["port"])
        results = f.fuzz([CATEGORY_CPU_CONTROL])
        f.close()
        timeouts = [r for r in results if r.anomaly == ANOMALY_TIMEOUT]
        assert len(timeouts) == 0
