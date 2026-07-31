# icsFuzzer — proof-of-concept scripts

Standalone reproductions for issues found with icsFuzzer. Each is stdlib-only and takes a
target as an argument.

> **Authorized use only.** These scripts send traffic that can hang or crash a device. Run
> them only against systems you own or are explicitly authorized to test.

## What's here

This directory contains reproductions **only for issues that are already fixed**, plus a
non-weaponized robustness checker. Dedicated proof-of-concept exploits for unpatched issues —
including findings whose upstream projects are unmaintained — are intentionally withheld to
avoid handing out a ready-to-run exploit while no fix exists. They will be added once a fix or
advisory is available.

| Script | Issue | Status |
|---|---|---|
| `pymodbus_exception_repro.py` | pymodbus returns a hardcoded function code and `transaction_id=0` for undecodable function codes | Fixed upstream ([pymodbus#2990](https://github.com/pymodbus-dev/pymodbus/issues/2990)) |
| `modbus_tcp_dos_check.py` | Modbus-TCP robustness checker across two server libraries; detects known hang/exhaustion behaviors (`--safe-only` for non-destructive probes) | Detector; per-check disclosure status in the file header |

## Usage

```bash
# pymodbus: spins up a local pymodbus server and shows the fixed/wrong response
python3 pymodbus_exception_repro.py

# Modbus robustness checker, non-destructive probes only
python3 modbus_tcp_dos_check.py --target 192.168.1.100 --safe-only
```

Exit code `1` indicates the issue reproduced/was detected; `0` indicates it did not.

## Reporting new findings

If you reproduce or extend one of these, or find something new, please follow the
coordinated-disclosure guidance in [../SECURITY.md](../SECURITY.md).
