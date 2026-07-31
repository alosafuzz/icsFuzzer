"""Integration tests for S7comm fuzzer + software responder.

Spins up scripts.s7comm_responder._server_loop on a free TCP port,
then exercises the fuzzer against it.
"""

import socket
import struct
import threading
import time
import pytest

from scripts.s7comm_responder import _server_loop
from protocols.s7comm.fuzzer import (
    AREA_DB, AREA_INPUTS, AREA_OUTPUTS, AREA_FLAGS,
    CATEGORY_BOUNDARY, CATEGORY_BINARY_CORRUPTION,
    CATEGORY_PDU_NEGOTIATION, CATEGORY_READ_WRITE,
    CATEGORY_SZL_READ, CATEGORY_CPU_CONTROL,
    CATEGORY_STATE_MACHINE, CATEGORY_SEQUENCE,
    S7commFuzzer,
    _COTP_CC, _COTP_CR, _COTP_DT,
    _ROSCTR_ACK_DATA, _ROSCTR_USERDATA,
    _cotp_cr, _s7_setup_comm, _s7_read_var, _s7_write_var,
    _s7_szl_read, _s7_plc_stop, _s7_pi_service, _s7_pkt, _s7_header, _tpkt,
)
from core.base_module import (
    ANOMALY_TIMEOUT, ANOMALY_CONNECTION_RESET, ANOMALY_MALFORMED_RESPONSE,
    Device, FuzzResult,
)


# ---------------------------------------------------------------------------
# Shared test infrastructure
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

    def latest(self):
        with self._lock:
            return self._log[-1] if self._log else None

    def clear(self):
        with self._lock:
            self._log.clear()


class _NullLogger:
    def log(self, result): pass


def _free_tcp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def s7_server():
    sidecar = _RecordingSidecar()
    port    = _free_tcp_port()
    stop    = threading.Event()
    t = threading.Thread(
        target=_server_loop,
        args=("127.0.0.1", port, sidecar, stop, False),
        daemon=True,
    )
    t.start()
    time.sleep(0.05)
    yield {"port": port, "sidecar": sidecar}
    stop.set()
    t.join(timeout=2.0)


def _raw_client(port, timeout=3.0):
    """Return a connected raw TCP socket (not yet through S7 handshake)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(("127.0.0.1", port))
    return s


def _recv_tpkt(s):
    hdr = s.recv(4)
    if not hdr or len(hdr) < 4:
        return hdr
    total = struct.unpack('!H', hdr[2:4])[0]
    if total <= 4:
        return hdr
    rest = b''
    while len(rest) < total - 4:
        chunk = s.recv(total - 4 - len(rest))
        if not chunk:
            break
        rest += chunk
    return hdr + rest


def _do_cotp_handshake(s):
    """Send COTP CR and receive CC. Return CC bytes."""
    s.sendall(_cotp_cr(0x0100, 0x0200))
    cc = _recv_tpkt(s)
    return cc


def _do_s7_connect(s):
    """Full COTP + Setup Communication handshake. Return setup_comm response."""
    cc = _do_cotp_handshake(s)
    s.sendall(_s7_setup_comm(pdu_ref=1))
    resp = _recv_tpkt(s)
    return cc, resp


def _fuzzer(port):
    dev = Device(ip="127.0.0.1", port=port, protocol="s7comm")
    return S7commFuzzer(target=dev, logger=_NullLogger())


# ---------------------------------------------------------------------------
# COTP handshake
# ---------------------------------------------------------------------------

class TestCotp:
    def test_cr_receives_cc(self, s7_server):
        port = s7_server["port"]
        with _raw_client(port) as s:
            cc = _do_cotp_handshake(s)
            assert cc and len(cc) >= 6
            assert cc[5] == _COTP_CC

    def test_cc_tpkt_framed(self, s7_server):
        port = s7_server["port"]
        with _raw_client(port) as s:
            cc = _do_cotp_handshake(s)
            assert cc[0] == 0x03  # TPKT version

    def test_cotp_ok_logged(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_cotp_handshake(s)
        time.sleep(0.05)
        assert "cotp_ok" in sidecar.actions()

    def test_malformed_ptype_logs_cotp_bad(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        # Send a TPKT where the COTP PTYPE byte is wrong (use DT instead of CR)
        bad_cr = bytearray(_cotp_cr())
        bad_cr[5] = _COTP_DT  # wrong PTYPE
        with _raw_client(port) as s:
            s.sendall(bytes(bad_cr))
            time.sleep(0.1)
        assert "cotp_bad" in sidecar.actions()


# ---------------------------------------------------------------------------
# Setup Communication
# ---------------------------------------------------------------------------

class TestSetupComm:
    def test_setup_comm_ack_data(self, s7_server):
        port = s7_server["port"]
        with _raw_client(port) as s:
            _, resp = _do_s7_connect(s)
            assert resp and len(resp) >= 9
            assert resp[8] == _ROSCTR_ACK_DATA

    def test_setup_comm_response_has_pdu_len(self, s7_server):
        port = s7_server["port"]
        with _raw_client(port) as s:
            _, resp = _do_s7_connect(s)
            # FC is at param start = TPKT(4)+COTP(3)+S7hdr(12) = 19
            # For Ack_Data, header is 12B → param starts at 7+12=19
            param_start = 19
            assert resp[param_start] == 0xF0  # FC_SETUP_COMM

    def test_setup_comm_ok_logged(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
        time.sleep(0.05)
        assert "setup_comm_ok" in sidecar.actions()

    def test_fuzzer_connect_succeeds(self, s7_server):
        f = _fuzzer(s7_server["port"])
        f.connect()
        f.close()


# ---------------------------------------------------------------------------
# Read Variable
# ---------------------------------------------------------------------------

class TestReadVar:
    def test_read_db1_ok(self, s7_server):
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            s.sendall(_s7_read_var(area=AREA_DB, db_num=1, address=0, count=1, pdu_ref=2))
            resp = _recv_tpkt(s)
        assert resp and len(resp) >= 9
        assert resp[8] == _ROSCTR_ACK_DATA

    def test_read_db1_sidecar_logged(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            s.sendall(_s7_read_var(area=AREA_DB, db_num=1, address=0, count=1, pdu_ref=2))
            _recv_tpkt(s)
        time.sleep(0.05)
        assert "read_ok" in sidecar.actions()

    def test_read_db0_logs_bad_db(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            s.sendall(_s7_read_var(area=AREA_DB, db_num=0, address=0, count=1, pdu_ref=2))
            _recv_tpkt(s)
        time.sleep(0.05)
        assert "read_bad_db" in sidecar.actions()

    def test_read_unknown_area_logs_bad_area(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            s.sendall(_s7_read_var(area=0xFF, db_num=0, address=0, count=1, pdu_ref=2))
            _recv_tpkt(s)
        time.sleep(0.05)
        assert "read_bad_area" in sidecar.actions()

    def test_read_address_too_large_logs_bad_address(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            # address=0x8000 > 0x7FFF → bad_address
            s.sendall(_s7_read_var(area=AREA_DB, db_num=1, address=0x8000,
                                   count=1, pdu_ref=2))
            _recv_tpkt(s)
        time.sleep(0.05)
        assert "read_bad_address" in sidecar.actions()


# ---------------------------------------------------------------------------
# Write Variable
# ---------------------------------------------------------------------------

class TestWriteVar:
    def test_write_db1_ok(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            s.sendall(_s7_write_var(area=AREA_DB, db_num=1, address=0,
                                    count=1, data=b'\x00\x00', pdu_ref=2))
            resp = _recv_tpkt(s)
        time.sleep(0.05)
        assert "write_ok" in sidecar.actions()
        assert resp and resp[8] == _ROSCTR_ACK_DATA

    def test_write_inputs_rejected(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            s.sendall(_s7_write_var(area=AREA_INPUTS, db_num=0, address=0,
                                    count=1, data=b'\xFF', pdu_ref=2))
            _recv_tpkt(s)
        time.sleep(0.05)
        assert "write_reject" in sidecar.actions()


# ---------------------------------------------------------------------------
# SZL Read
# ---------------------------------------------------------------------------

class TestSzlRead:
    def test_szl_known_ok(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            s.sendall(_s7_szl_read(szl_id=0x0011, pdu_ref=2))
            resp = _recv_tpkt(s)
        time.sleep(0.05)
        assert "szl_ok" in sidecar.actions()
        assert resp and resp[8] == _ROSCTR_ACK_DATA

    def test_szl_unknown_id_logged(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            s.sendall(_s7_szl_read(szl_id=0xDEAD, pdu_ref=2))
            _recv_tpkt(s)
        time.sleep(0.05)
        assert "szl_unknown_id" in sidecar.actions()

    @pytest.mark.parametrize("szl_id", [0x0011, 0x001C, 0x0111, 0x0112, 0x0424])
    def test_all_known_szl_ids_return_data(self, s7_server, szl_id):
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            s.sendall(_s7_szl_read(szl_id=szl_id, pdu_ref=2))
            resp = _recv_tpkt(s)
        assert resp and len(resp) >= 14


# ---------------------------------------------------------------------------
# CPU Control
# ---------------------------------------------------------------------------

class TestCpuControl:
    def test_plc_stop_rejected(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            s.sendall(_s7_plc_stop(pdu_ref=2))
            _recv_tpkt(s)
        time.sleep(0.05)
        assert "cpu_control_reject" in sidecar.actions()

    def test_pi_service_rejected(self, s7_server):
        sidecar = s7_server["sidecar"]
        sidecar.clear()
        port = s7_server["port"]
        with _raw_client(port) as s:
            _do_s7_connect(s)
            s.sendall(_s7_pi_service(b'_INSE', pdu_ref=2))
            _recv_tpkt(s)
        time.sleep(0.05)
        assert "cpu_control_reject" in sidecar.actions()


# ---------------------------------------------------------------------------
# Fuzzer via FuzzModule.fuzz()
# ---------------------------------------------------------------------------

class TestBoundaryViaFuzzer:
    def test_boundary_no_connection_reset(self, s7_server):
        f = _fuzzer(s7_server["port"])
        f.connect()
        results = f.fuzz([CATEGORY_BOUNDARY])
        f.close()
        crash = [r for r in results
                 if r.anomaly == ANOMALY_CONNECTION_RESET and
                    r.category == CATEGORY_BOUNDARY]
        # Allow at most one connection reset for boundary cases
        assert len(crash) <= 1

    def test_pdu_negotiation_all_respond(self, s7_server):
        f = _fuzzer(s7_server["port"])
        f.connect()
        results = f.fuzz([CATEGORY_PDU_NEGOTIATION])
        f.close()
        no_resp = [r for r in results if r.response is None and r.anomaly == ANOMALY_TIMEOUT]
        assert len(no_resp) == 0

    def test_read_write_no_timeout(self, s7_server):
        f = _fuzzer(s7_server["port"])
        f.connect()
        results = f.fuzz([CATEGORY_READ_WRITE])
        f.close()
        timeouts = [r for r in results if r.anomaly == ANOMALY_TIMEOUT]
        assert len(timeouts) == 0


class TestBinaryCorruptionViaFuzzer:
    def test_responder_survives_corruption(self, s7_server):
        """Responder must still respond to a valid request after all corruption cases."""
        f = _fuzzer(s7_server["port"])
        f.connect()
        f.fuzz([CATEGORY_BINARY_CORRUPTION])
        # After corruption, responder should still be alive
        f._reconnect()
        # Send a valid request and expect a response
        f._sock.sendall(_s7_read_var(area=AREA_DB, db_num=1, address=0,
                                     count=1, pdu_ref=99))
        resp = f._recv_response()
        f.close()
        assert resp is not None


class TestStateMachineViaFuzzer:
    def test_state_machine_responder_survives(self, s7_server):
        """Responder must remain alive after all state-machine cases."""
        f = _fuzzer(s7_server["port"])
        f.connect()
        f.fuzz([CATEGORY_STATE_MACHINE])
        # After state-machine abuse, reconnect and send a valid read
        f._reconnect()
        f._sock.sendall(_s7_read_var(area=AREA_DB, db_num=1, address=0,
                                     count=1, pdu_ref=99))
        resp = f._recv_response()
        f.close()
        assert resp is not None


class TestSzlReadViaFuzzer:
    def test_szl_read_no_unexpected_crash(self, s7_server):
        f = _fuzzer(s7_server["port"])
        f.connect()
        results = f.fuzz([CATEGORY_SZL_READ])
        f.close()
        timeouts = [r for r in results if r.anomaly == ANOMALY_TIMEOUT]
        assert len(timeouts) == 0

    def test_szl_read_known_ids_return_ack_data(self, s7_server):
        port = s7_server["port"]
        for szl_id in (0x0011, 0x001C, 0x0111):
            with _raw_client(port) as s:
                _do_s7_connect(s)
                s.sendall(_s7_szl_read(szl_id=szl_id, pdu_ref=2))
                resp = _recv_tpkt(s)
            assert resp and resp[8] in (_ROSCTR_ACK_DATA, _ROSCTR_USERDATA), \
                f"SZL 0x{szl_id:04X} got ROSCTR=0x{resp[8]:02X}"
