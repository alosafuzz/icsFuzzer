"""Structured JSONL logger for fuzz cases and anomalies."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from core.base_module import FuzzResult


class FuzzLogger:
    """Writes one JSONL record per fuzz case. Mirrors sparkplugFuzzer log format
    with added protocol and crash_indicator fields."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.log_path = self.output_dir / f"icsFuzzer-{ts}.jsonl"
        self._file = open(self.log_path, "w", encoding="utf-8")
        self._total = 0
        self._anomalies = 0
        self._crashes = 0
        print(f"[log] Writing to {self.log_path}")

    def log(self, result: FuzzResult) -> None:
        record = {
            "id": result.case_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": result.protocol,
            "target": result.target,
            "category": result.category,
            "description": result.description,
            "payload_hex": result.payload.hex() if result.payload else None,
            "response_hex": result.response.hex() if result.response else None,
            "response_decoded": result.response_decoded,
            "duration_ms": result.duration_ms,
            "anomaly": result.anomaly,
            "crash_indicator": result.crash_indicator,
        }
        self._file.write(json.dumps(record) + "\n")
        self._file.flush()
        self._total += 1
        if result.anomaly:
            self._anomalies += 1
        if result.crash_indicator:
            self._crashes += 1
            print(
                f"  [!] CRASH INDICATOR: {result.case_id} — {result.description}"
            )

    def log_info(self, message: str) -> None:
        """Log a freeform informational message as a sentinel record."""
        record = {
            "type": "info",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message,
        }
        self._file.write(json.dumps(record) + "\n")
        self._file.flush()

    def stats(self) -> dict:
        return {
            "total_cases": self._total,
            "anomalies": self._anomalies,
            "crash_indicators": self._crashes,
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._file.closed:
            self.close()
        return False

    def close(self) -> None:
        self._file.close()
        stats = self.stats()
        print(
            f"[log] Session complete — "
            f"{stats['total_cases']} cases, "
            f"{stats['anomalies']} anomalies, "
            f"{stats['crash_indicators']} crash indicators"
        )
        print(f"[log] Log: {self.log_path}")
