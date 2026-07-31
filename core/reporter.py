"""Offline reporter: reads JSONL output and generates a summary + crash triage."""

import json
import os
from collections import defaultdict
from pathlib import Path


class FuzzReporter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)

    def _latest_log(self) -> Path | None:
        logs = sorted(self.output_dir.glob("icsFuzzer-*.jsonl"), reverse=True)
        return logs[0] if logs else None

    def summarize(self, log_path: Path = None) -> None:
        path = log_path or self._latest_log()
        if not path or not path.exists():
            print("[report] No log file found.")
            return

        records = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        fuzz_records = [r for r in records if r.get("id") and not r.get("type")]
        if not fuzz_records:
            print("[report] No fuzz records found in log.")
            return

        total = len(fuzz_records)
        anomalies = [r for r in fuzz_records if r.get("anomaly")]
        crashes = [r for r in fuzz_records if r.get("crash_indicator")]

        by_protocol = defaultdict(int)
        by_category = defaultdict(int)
        by_anomaly = defaultdict(int)

        for r in fuzz_records:
            by_protocol[r.get("protocol", "unknown")] += 1
            by_category[r.get("category", "unknown")] += 1
            if r.get("anomaly"):
                by_anomaly[r["anomaly"]] += 1

        print("\n" + "=" * 60)
        print(" icsFuzzer — Session Report")
        print("=" * 60)
        print(f"  Log file:          {path.name}")
        print(f"  Total cases:       {total}")
        print(f"  Anomalies:         {len(anomalies)} ({len(anomalies)/total*100:.1f}%)")
        print(f"  Crash indicators:  {len(crashes)}")

        if by_protocol:
            print("\n  By Protocol:")
            for proto, count in sorted(by_protocol.items()):
                print(f"    {proto:<14} {count}")

        if by_category:
            print("\n  By Category:")
            for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
                print(f"    {cat:<22} {count}")

        if by_anomaly:
            print("\n  Anomaly Breakdown:")
            for atype, count in sorted(by_anomaly.items(), key=lambda x: -x[1]):
                print(f"    {atype:<28} {count}")

        if crashes:
            print("\n  Crash Indicators (triage):")
            print(f"  {'ID':<20} {'Protocol':<12} {'Category':<20} Description")
            print("  " + "-" * 80)
            for r in crashes:
                print(
                    f"  {r['id']:<20} {r.get('protocol','?'):<12} "
                    f"{r.get('category','?'):<20} {r.get('description','?')[:50]}"
                )
            print(f"\n  Replay a case: python icsFuzzer.py --replay <ID>")

        print("=" * 60 + "\n")
