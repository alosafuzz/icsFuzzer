"""Core framework unit tests."""

import json
import tempfile
from pathlib import Path

import pytest

from core.base_module import (
    STANDARD_CATEGORIES,
    INJECTION_STRINGS,
    Device,
    FuzzResult,
    FuzzModule,
    ANOMALY_TIMEOUT,
)
from core.logger import FuzzLogger
from core.reporter import FuzzReporter


class _StubFuzzer(FuzzModule):
    """Minimal concrete implementation for testing FuzzModule interface."""

    PROTOCOL_NAME = "stub"
    DEFAULT_PORT = 9999
    FUZZ_CATEGORIES = STANDARD_CATEGORIES[:]

    def discover(self, interface, timeout=30):
        return []

    def connect(self, target):
        pass

    def fuzz(self, categories=None):
        cats = self._resolve_categories(categories)
        results = []
        for cat in cats:
            r = FuzzResult(
                case_id=self._next_id(),
                protocol=self.PROTOCOL_NAME,
                target=f"{self.target.ip}:{self.target.port}",
                category=cat,
                description=f"stub case for {cat}",
                payload=b"\x00\x01\x02",
            )
            results.append(r)
        return results

    def close(self):
        pass


@pytest.fixture
def device():
    return Device(ip="127.0.0.1", port=9999, protocol="stub")


@pytest.fixture
def tmp_output(tmp_path):
    return str(tmp_path / "output")


class TestDevice:
    def test_str(self, device):
        assert "127.0.0.1" in str(device)
        assert "STUB" in str(device)

    def test_defaults(self, device):
        assert device.device_type == "unknown"
        assert device.metadata == {}


class TestFuzzModule:
    def test_resolve_all_categories(self, device):
        fuzzer = _StubFuzzer(target=device, logger=None)
        assert fuzzer._resolve_categories(None) == STANDARD_CATEGORIES

    def test_resolve_subset(self, device):
        fuzzer = _StubFuzzer(target=device, logger=None)
        cats = fuzzer._resolve_categories(["boundary", "injection"])
        assert cats == ["boundary", "injection"]

    def test_resolve_invalid_warns(self, device):
        fuzzer = _StubFuzzer(target=device, logger=None)
        with pytest.warns(UserWarning, match="invalid_cat"):
            cats = fuzzer._resolve_categories(["boundary", "invalid_cat"])
        assert cats == ["boundary"]

    def test_case_id_increments(self, device):
        fuzzer = _StubFuzzer(target=device, logger=None)
        id1 = fuzzer._next_id()
        id2 = fuzzer._next_id()
        assert id1 == "stub-0001"
        assert id2 == "stub-0002"

    def test_fuzz_returns_results(self, device):
        fuzzer = _StubFuzzer(target=device, logger=None)
        results = fuzzer.fuzz()
        assert len(results) == len(STANDARD_CATEGORIES)
        for r in results:
            assert isinstance(r, FuzzResult)


class TestFuzzLogger:
    def test_creates_jsonl(self, tmp_output, device):
        logger = FuzzLogger(tmp_output)
        r = FuzzResult(
            case_id="stub-0001",
            protocol="stub",
            target="127.0.0.1:9999",
            category="boundary",
            description="test case",
            payload=b"\xff\x00",
            response=b"\x01",
            anomaly=ANOMALY_TIMEOUT,
            crash_indicator=True,
        )
        logger.log(r)
        logger.close()

        logs = list(Path(tmp_output).glob("*.jsonl"))
        assert len(logs) == 1
        records = [json.loads(line) for line in logs[0].read_text().splitlines() if line]
        assert len(records) == 1
        rec = records[0]
        assert rec["id"] == "stub-0001"
        assert rec["protocol"] == "stub"
        assert rec["anomaly"] == ANOMALY_TIMEOUT
        assert rec["crash_indicator"] is True
        assert rec["payload_hex"] == "ff00"

    def test_stats_tracking(self, tmp_output, device):
        logger = FuzzLogger(tmp_output)
        logger.log(FuzzResult("a", "stub", "t", "boundary", "d", anomaly=None, crash_indicator=False))
        logger.log(FuzzResult("b", "stub", "t", "boundary", "d", anomaly=ANOMALY_TIMEOUT, crash_indicator=True))
        stats = logger.stats()
        logger.close()
        assert stats["total_cases"] == 2
        assert stats["anomalies"] == 1
        assert stats["crash_indicators"] == 1

    def test_log_info(self, tmp_output):
        logger = FuzzLogger(tmp_output)
        logger.log_info("test message")
        logger.close()
        logs = list(Path(tmp_output).glob("*.jsonl"))
        records = [json.loads(l) for l in logs[0].read_text().splitlines() if l]
        assert records[0]["type"] == "info"
        assert records[0]["message"] == "test message"


class TestFuzzReporter:
    def test_no_log(self, tmp_output, capsys):
        reporter = FuzzReporter(tmp_output)
        reporter.summarize()
        out = capsys.readouterr().out
        assert "No log file found" in out

    def test_summarize(self, tmp_output):
        logger = FuzzLogger(tmp_output)
        logger.log(FuzzResult("a", "modbus", "1.1.1.1:502", "boundary", "d"))
        logger.log(FuzzResult("b", "opcua", "1.1.1.2:4840", "injection", "d", anomaly=ANOMALY_TIMEOUT))
        logger.log(FuzzResult("c", "modbus", "1.1.1.1:502", "binary_corruption", "d", crash_indicator=True))
        logger.close()

        reporter = FuzzReporter(tmp_output)
        reporter.summarize()  # should not raise


class TestInjectionStrings:
    def test_non_empty(self):
        assert len(INJECTION_STRINGS) > 10

    def test_contains_sqli(self):
        assert any("SELECT" in s or "DROP" in s for s in INJECTION_STRINGS)

    def test_contains_format_string(self):
        assert any("%n" in s or "%x" in s for s in INJECTION_STRINGS)


class TestProtocolStubs:
    """Verify all 8 protocol modules load and declare required attributes."""

    @pytest.mark.parametrize("proto,cls_name", [
        ("modbus",     "ModbusFuzzer"),
        ("opcua",      "OpcuaFuzzer"),
        ("iec104",     "Iec104Fuzzer"),
        ("ethernetip", "EthernetIpFuzzer"),
        ("bacnet",     "BacnetFuzzer"),
        ("dnp3",       "Dnp3Fuzzer"),
        ("iec61850",   "Iec61850Fuzzer"),
        ("ge_srtp",    "GeSrtpFuzzer"),
    ])
    def test_module_loads(self, proto, cls_name):
        import importlib
        mod = importlib.import_module(f"protocols.{proto}.fuzzer")
        cls = getattr(mod, cls_name)
        assert issubclass(cls, FuzzModule)
        assert cls.PROTOCOL_NAME
        assert cls.DEFAULT_PORT > 0
        assert len(cls.FUZZ_CATEGORIES) > 0

    # All protocol modules now raise RuntimeError (not NotImplementedError) when
    # fuzz() is called without connect(). test_stub_raises_not_implemented is
    # retired — IEC 61850 was the last remaining stub and is now fully implemented.
