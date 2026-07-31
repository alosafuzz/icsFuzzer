#!/usr/bin/env python3
"""icsFuzzer - Modular ICS/OT Protocol Security Assessment Tool"""

import argparse
import importlib
import inspect
import sys
import time
from pathlib import Path

from core.base_module import Device, FuzzModule
from core.logger import FuzzLogger
from core.reporter import FuzzReporter

VERSION = "0.1"

SUPPORTED_PROTOCOLS = [
    "modbus",
    "opcua",
    "iec104",
    "ethernetip",
    "bacnet",
    "dnp3",
    "iec61850",
    "ge_srtp",
    "profinet",
    "s7comm",
    "fins",
]

PROTOCOL_PORTS = {
    "modbus":    502,
    "dnp3":      20000,
    "opcua":     4840,
    "ethernetip":44818,
    "iec61850":  102,
    "bacnet":    47808,
    "iec104":    2404,
    "ge_srtp":   18245,
    "profinet":  34964,
    "s7comm":    102,
    "fins":      9600,
}

# EtherType for GOOSE (IEC 61850 L2 multicast)
GOOSE_ETHERTYPE = 0x88B8

BANNER = r"""
    _           ______
   (_)_________/ ____/_  __________  ___  _____
  / // ___/ __/ /_  / / / /_  /_  / / _ \/ ___/
 / // /__(__  ) __/ / /_/ / / /_/ //  __/ /
/_/ \___/____/_/    \__,_/ /___/___/\___/_/

  Modular ICS/OT Protocol Security Assessment Tool
  Version {version}
""".format(version=VERSION)

WARNING_BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║                      *** CRITICAL WARNING ***                        ║
║                                                                      ║
║  icsFuzzer sends malformed and out-of-specification packets to       ║
║  industrial control system devices. Fuzzing live OT/ICS systems      ║
║  can cause:                                                          ║
║                                                                      ║
║    •  Unexpected device reboots, hangs, or firmware crashes          ║
║    •  Loss of process visibility or remote control capability        ║
║    •  Disruption to physical processes or equipment                  ║
║    •  Interference with safety instrumented systems (SIS)            ║
║    •  Network congestion on bandwidth-limited OT segments            ║
║                                                                      ║
║  ONLY use against systems you have EXPLICIT WRITTEN AUTHORIZATION    ║
║  to test. ALWAYS coordinate with plant/facility operators before     ║
║  running. NEVER target production systems without approval.          ║
║                                                                      ║
║  By proceeding you confirm you have authorization to test the        ║
║  specified targets and accept full responsibility for any impact.    ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def print_banner():
    print(BANNER)


def print_warning():
    print(WARNING_BANNER)


def confirm_targets(targets: list[Device], yes: bool) -> bool:
    """Display discovered/specified targets and require explicit confirmation
    before fuzzing begins. Returns True to proceed, False to abort."""
    print("\n[targets] The following hosts will be fuzzed:")
    for t in targets:
        print(f"    {t.protocol.upper():<12} {t.ip}:{t.port}  ({t.device_type})")

    if yes:
        print("\n[--yes] Skipping confirmation prompt.\n")
        return True

    print()
    try:
        answer = input("Proceed with fuzzing? [y/N] ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n[abort] Cancelled by user.")
        return False

    if answer != "y":
        print("[abort] Cancelled by user.")
        return False

    return True


def load_protocol_module(name: str) -> type[FuzzModule]:
    """Dynamically load a protocol fuzzer module by name."""
    try:
        mod = importlib.import_module(f"protocols.{name}.fuzzer")
        cls_name = f"{name.capitalize()}Fuzzer"
        # Handle multi-word class names
        class_map = {
            "modbus":    "ModbusFuzzer",
            "dnp3":      "Dnp3Fuzzer",
            "opcua":     "OpcuaFuzzer",
            "ethernetip":"EthernetIpFuzzer",
            "iec61850":  "Iec61850Fuzzer",
            "bacnet":    "BacnetFuzzer",
            "iec104":    "Iec104Fuzzer",
            "ge_srtp":   "GeSrtpFuzzer",
            "profinet":  "ProfinetFuzzer",
            "s7comm":    "S7commFuzzer",
            "fins":      "FinsFuzzer",
        }
        cls = getattr(mod, class_map[name])
        return cls
    except ImportError as e:
        print(f"[error] Protocol module '{name}' could not be loaded: {e}")
        sys.exit(1)
    except AttributeError:
        print(f"[error] Protocol module '{name}' does not export the expected class.")
        sys.exit(1)


def detect_protocols_from_seeds(seeds: list) -> list[str]:
    """Infer which protocols were observed in pcap/sniff seeds."""
    detected = set()
    for pkt in seeds:
        tcp = pkt.getlayer("TCP")
        udp = pkt.getlayer("UDP")
        # Check both src and dst ports so server responses identify protocols too
        port_vals: set[int] = set()
        if tcp:
            port_vals.update({tcp.dport, tcp.sport})
        elif udp:
            port_vals.update({udp.dport, udp.sport})
        for port_val in port_vals:
            for proto, port in PROTOCOL_PORTS.items():
                if port_val == port:
                    detected.add(proto)
        # EtherType fingerprinting for GOOSE (L2 multicast, no IP layer)
        ether = pkt.getlayer("Ether")
        if ether and ether.type == GOOSE_ETHERTYPE:
            detected.add("iec61850")
    return sorted(detected)


def run_auto_mode(args) -> tuple[list, list, list]:
    """Detect protocols via pcap or sniff. Returns (targets, seeds, edges).

    edges is a list of (src_addr, dst_addr, protocol) tuples for topology mapping.
    IEC 61850 GOOSE devices are tracked as MAC-addressed Device entries (no IP).
    """
    from core.capture import CaptureEngine
    capture = CaptureEngine()

    if args.pcap:
        print(f"[auto] Loading pcap: {args.pcap}")
        seeds = capture.load_pcap(args.pcap)
    else:
        print(f"[auto] Sniffing on {args.sniff} for {args.duration}s ...")
        seeds = capture.sniff(args.sniff, args.duration)

    detected_protocols = detect_protocols_from_seeds(seeds)

    if not detected_protocols:
        print("[auto] No recognized ICS protocols detected in traffic. Exiting.")
        sys.exit(0)

    print(f"\n[auto] Detected protocols: {', '.join(p.upper() for p in detected_protocols)}")

    targets = []
    edges = []
    for proto in detected_protocols:
        proto_seeds = [s for s in seeds if _seed_matches_proto(s, proto)]
        pairs = _extract_hosts(proto_seeds, proto)
        for src, dst in pairs:
            edges.append((src, dst, proto))

        if proto == "iec61850":
            # GOOSE is L2-only — create MAC-addressed Device entries, not IP targets
            seen_macs = set()
            for src, dst in pairs:
                for mac in (src, dst):
                    if mac not in seen_macs:
                        seen_macs.add(mac)
                        targets.append(Device(
                            ip="",
                            port=0,
                            protocol=proto,
                            device_type="discovered",
                            mac=mac,
                        ))
            continue

        seen_ips = set()
        for src, dst in pairs:
            for ip in (src, dst):
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    targets.append(Device(
                        ip=ip,
                        port=PROTOCOL_PORTS[proto],
                        protocol=proto,
                        device_type="discovered",
                    ))

    return targets, seeds, edges


def _seed_matches_proto(pkt, proto: str) -> bool:
    if proto == "iec61850":
        ether = pkt.getlayer("Ether")
        return bool(ether and ether.type == GOOSE_ETHERTYPE)
    port = PROTOCOL_PORTS.get(proto)
    tcp = pkt.getlayer("TCP")
    if tcp:
        return tcp.dport == port or tcp.sport == port
    udp = pkt.getlayer("UDP")
    if udp:
        return udp.dport == port or udp.sport == port
    return False


def _extract_hosts(seeds: list, proto: str) -> list[tuple[str, str]]:
    """Return (src, dst) address pairs observed for a protocol.

    Returns IP addresses for TCP/UDP protocols, MAC addresses for GOOSE (L2).
    """
    seen: set[tuple] = set()
    pairs: list[tuple[str, str]] = []
    for pkt in seeds:
        if proto == "iec61850":
            ether = pkt.getlayer("Ether")
            if not ether:
                continue
            src, dst = ether.src, ether.dst
        else:
            ip = pkt.getlayer("IP")
            if not ip:
                continue
            src, dst = ip.src, ip.dst
        key = (src, dst)
        if key not in seen:
            seen.add(key)
            pairs.append((src, dst))
    return pairs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="icsFuzzer",
        description="icsFuzzer — Modular ICS/OT Protocol Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  icsfuzzer.py --protocol modbus --target 192.168.1.10
  icsfuzzer.py --protocol auto --sniff eth0 --duration 60 --yes
  icsfuzzer.py --protocol auto --pcap capture.pcap
  icsfuzzer.py --protocol opcua --target 192.168.1.20:4840 --categories boundary,injection
  icsfuzzer.py --setup
        """,
    )

    parser.add_argument(
        "--protocol",
        choices=SUPPORTED_PROTOCOLS + ["auto"],
        default="auto",
        metavar="PROTOCOL",
        help=(
            f"Protocol to fuzz: {{{', '.join(SUPPORTED_PROTOCOLS)}, auto}}. "
            "'auto' detects protocols from --pcap or --sniff traffic."
        ),
    )
    parser.add_argument(
        "--target",
        metavar="HOST[:PORT]",
        help="Target host (and optional port). Overrides default port for the protocol.",
    )
    parser.add_argument(
        "--sniff",
        metavar="IFACE",
        help="Network interface for live packet capture (auto/discovery mode). Requires root/CAP_NET_RAW.",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Duration in seconds for live sniff (default: 60).",
    )
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        help="Path to a .pcap file to ingest as fuzzing seeds.",
    )
    parser.add_argument(
        "--categories",
        metavar="CAT1,CAT2,...",
        help=(
            "Comma-separated list of fuzz categories to run. "
            "Omit to run all categories for the protocol."
        ),
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        metavar="SECONDS",
        help="Delay between fuzz cases in seconds (default: 0.1). Increase for sensitive targets.",
    )
    parser.add_argument(
        "--output",
        default="output",
        metavar="DIR",
        help="Output directory for JSONL logs and reports (default: ./output).",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip interactive confirmation prompt before fuzzing.",
    )
    parser.add_argument(
        "--replay",
        metavar="CASE_ID",
        help="Replay a single fuzz case by ID from a previous run's JSONL log.",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Install protocol library dependencies and exit.",
    )
    parser.add_argument(
        "--list-protocols",
        action="store_true",
        help="List available protocol modules and their status.",
    )
    parser.add_argument(
        "--no-viz",
        action="store_true",
        help="Skip interactive HTML topology generation after auto-mode discovery.",
    )
    parser.add_argument(
        "--replay-all-crashes",
        action="store_true",
        help="Replay all cases with crash_indicator=true from the latest log and exit.",
    )
    parser.add_argument(
        "--injection-file",
        metavar="FILE",
        help=(
            "Path to a file of additional injection strings, one per line. "
            "Merged into the injection fuzz category. "
            "Example: --injection-file payloads/hmi-injection.txt"
        ),
    )
    parser.add_argument(
        "--unit-id",
        type=lambda x: int(x, 0),
        default=0x01,
        metavar="UID",
        help=(
            "Modbus unit identifier byte for generated MBAP frames (default: 0x01). "
            "Use 0x01 for ESP-IDF and most TCP slaves. "
            "Categories that sweep UIDs (auth, broadcast_abuse) ignore this flag. "
            "Example: --unit-id 0x01"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Generate all fuzz cases and export payloads to a TSV file without sending. "
            "No live target or hardware required. Writes to --output directory."
        ),
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        metavar="PPS",
        help=(
            "Maximum send rate in packets per second (e.g., 10.0). "
            "Overrides --delay. Use for rate-sensitive targets."
        ),
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        help=(
            "List all fuzz categories for the specified protocol (with case counts) and exit. "
            "Requires --protocol. No target or connection needed."
        ),
    )
    parser.add_argument(
        "--fingerprint",
        action="store_true",
        help=(
            "Fingerprint each target before fuzzing. Default mode is active (sends one "
            "benign identity probe per protocol). Results are printed and stored in the "
            "Device object for inclusion in the HTML topology report."
        ),
    )
    parser.add_argument(
        "--fingerprint-passive",
        action="store_true",
        help=(
            "Passive fingerprint only — reads the OS ARP cache and performs OUI vendor "
            "lookup. Sends zero packets. Implied by --fingerprint in high-risk OT "
            "environments where even a single extra packet is unacceptable."
        ),
    )

    return parser


def run_setup():
    """Run the dependency setup script."""
    setup_script = Path(__file__).parent / "setup.sh"
    if not setup_script.exists():
        print("[error] setup.sh not found.")
        sys.exit(1)
    import subprocess
    result = subprocess.run(["bash", str(setup_script)], check=False)
    sys.exit(result.returncode)


def list_protocols():
    """Print protocol module status."""
    print(f"\n{'Protocol':<14} {'Default Port':<14} {'Status'}")
    print("-" * 42)
    for proto in SUPPORTED_PROTOCOLS:
        port = PROTOCOL_PORTS.get(proto, "N/A")
        try:
            importlib.import_module(f"protocols.{proto}.fuzzer")
            status = "available"
        except ImportError:
            status = "not installed"
        except NotImplementedError:
            status = "stub (pending)"
        print(f"  {proto:<12} {str(port):<14} {status}")
    print()


def parse_target(target_str: str, protocol: str) -> Device:
    """Parse 'host', 'host:port', or '[::1]:port' (IPv6) into a Device."""
    default_port = PROTOCOL_PORTS.get(protocol, 0)
    if target_str.startswith("["):
        # IPv6 bracket notation: [::1]:502 or [::1]
        bracket_end = target_str.find("]")
        ip = target_str[1:bracket_end] if bracket_end != -1 else target_str[1:]
        port = default_port
        if bracket_end != -1 and len(target_str) > bracket_end + 2 and target_str[bracket_end + 1] == ":":
            port = int(target_str[bracket_end + 2:])
        return Device(ip=ip, port=port, protocol=protocol)
    if target_str.count(":") == 1:
        # IPv4 or hostname with explicit port: 192.168.1.10:502
        ip, port_str = target_str.rsplit(":", 1)
        return Device(ip=ip, port=int(port_str), protocol=protocol)
    # Plain hostname, IPv4, or bare IPv6 (no port)
    return Device(ip=target_str, port=default_port, protocol=protocol)


def replay_case(case_id: str, output_dir: str) -> None:
    """Find a fuzz case by ID in the latest JSONL log and replay its payload."""
    import json as _json

    log_dir = Path(output_dir)
    logs = sorted(log_dir.glob("icsFuzzer-*.jsonl"), reverse=True)
    if not logs:
        print(f"[replay] No log files found in {output_dir}")
        sys.exit(1)

    record = None
    for log_path in logs:
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = _json.loads(line)
                    if r.get("id") == case_id:
                        record = r
                        break
                except _json.JSONDecodeError:
                    continue
        if record:
            break

    if not record:
        print(f"[replay] Case '{case_id}' not found in any log under {output_dir}")
        sys.exit(1)

    print(f"[replay] {record['id']}  protocol={record['protocol'].upper()}  target={record['target']}")
    print(f"[replay] category={record['category']}  anomaly={record.get('anomaly')}  crash={record.get('crash_indicator')}")
    print(f"[replay] payload={record.get('payload_hex')}")

    if not record.get("payload_hex"):
        print("[replay] No payload recorded — nothing to send.")
        sys.exit(0)

    payload = bytes.fromhex(record["payload_hex"])
    target = parse_target(record["target"], record["protocol"])
    FuzzerClass = load_protocol_module(record["protocol"])
    fuzzer = FuzzerClass(target=target, logger=None, delay=0)
    try:
        fuzzer.connect(target)
        response = fuzzer.replay_payload(payload)
        print(f"[replay] Response: {response.hex() if response else 'none'}")
    except NotImplementedError:
        print(f"[replay] {record['protocol'].upper()} replay not yet implemented.")
    finally:
        try:
            fuzzer.close()
        except Exception:
            pass


def replay_all_crashes(output_dir: str) -> None:
    """Replay every crash-indicator case from the latest JSONL log."""
    import json as _json

    log_dir = Path(output_dir)
    logs = sorted(log_dir.glob("icsFuzzer-*.jsonl"), reverse=True)
    if not logs:
        print(f"[replay] No log files found in {output_dir}")
        sys.exit(1)

    log_path = logs[0]
    print(f"[replay] Scanning {log_path.name} for crash indicators ...")

    crash_records = []
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = _json.loads(line)
                if r.get("crash_indicator") and r.get("payload_hex"):
                    crash_records.append(r)
            except _json.JSONDecodeError:
                continue

    if not crash_records:
        print("[replay] No crash indicators with payloads found in latest log.")
        return

    print(f"[replay] {len(crash_records)} crash case(s) to replay.\n")

    for i, record in enumerate(crash_records, 1):
        print(f"[replay] [{i}/{len(crash_records)}] {record['id']}  "
              f"{record['protocol'].upper()}  {record['target']}")
        payload = bytes.fromhex(record["payload_hex"])
        target = parse_target(record["target"], record["protocol"])
        FuzzerClass = load_protocol_module(record["protocol"])
        fuzzer = FuzzerClass(target=target, logger=None, delay=0)
        try:
            fuzzer.connect(target)
            response = fuzzer.replay_payload(payload)
            print(f"  response: {response.hex() if response else 'none'}")
        except NotImplementedError:
            print(f"  {record['protocol'].upper()} replay not yet implemented.")
        except KeyboardInterrupt:
            print("\n[abort] Replay interrupted by user.")
            break
        finally:
            try:
                fuzzer.close()
            except Exception:
                pass


def list_categories(protocol: str) -> None:
    """Print fuzz categories and case counts for a protocol, then exit."""
    FuzzerClass = load_protocol_module(protocol)
    default_port = PROTOCOL_PORTS.get(protocol, 0)
    target = Device(ip="127.0.0.1", port=default_port, protocol=protocol)
    fuzzer = FuzzerClass(target=target, logger=None, delay=0)
    cases = fuzzer.generate_cases()
    counts: dict[str, int] = {}
    for _, cat, _, _ in cases:
        counts[cat] = counts.get(cat, 0) + 1
    print(f"\nCategories for {protocol}  ({len(cases)} total cases):\n")
    for cat, n in counts.items():
        print(f"  {cat:<30} {n} cases")
    print()


def _run_fingerprint(fuzzer, target: Device, active: bool = True) -> None:
    """Call fuzzer.fingerprint(), print result, and populate target Device fields."""
    mode = "active" if active else "passive"
    print(f"[fp] Fingerprinting {target.protocol.upper()} {target.ip}:{target.port} ({mode}) …")
    try:
        result = fuzzer.fingerprint(active=active)
    except Exception as exc:
        print(f"[fp] Error: {exc}")
        return
    if result.confidence == "none":
        print(f"[fp] No identity information found (method: {result.method or 'none'})")
        return
    # Populate Device fields
    if result.vendor != "unknown":
        target.vendor = result.vendor
    if result.model != "unknown":
        target.model = result.model
    if result.firmware != "unknown":
        target.firmware = result.firmware

    conf_badge = {"high": "★★★", "medium": "★★☆", "low": "★☆☆"}.get(result.confidence, "?")
    print(f"[fp] {conf_badge} vendor={result.vendor}  model={result.model}  "
          f"firmware={result.firmware}  serial={result.serial}  "
          f"confidence={result.confidence}  method={result.method}")


def _export_dry_run(fuzzer, target, categories, output_dir: str) -> None:
    """Generate all fuzz cases and write them to a TSV file without sending."""
    from datetime import datetime, timezone
    cases = fuzzer.generate_cases(categories=categories)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"dry-run-{target.protocol}-{ts}.tsv"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("case_id\tcategory\tdescription\tpayload_hex\n")
        for case_id, cat, desc, payload in cases:
            f.write(f"{case_id}\t{cat}\t{desc}\t{payload.hex()}\n")
    print(f"[dry-run] {len(cases)} cases → {out_path}")


def main():
    print_banner()
    print_warning()

    parser = build_parser()
    args = parser.parse_args()

    if args.setup:
        run_setup()

    if args.list_protocols:
        list_protocols()
        sys.exit(0)

    if args.list_categories:
        if args.protocol == "auto":
            parser.error("--list-categories requires --protocol <name>, not 'auto'")
        list_categories(args.protocol)
        sys.exit(0)

    if args.replay:
        replay_case(args.replay, args.output)
        sys.exit(0)

    if args.replay_all_crashes:
        replay_all_crashes(args.output)
        sys.exit(0)

    seeds = []
    edges = []
    viz = None

    with FuzzLogger(args.output) as logger:
        # Resolve targets
        if args.protocol == "auto":
            if not args.pcap and not args.sniff:
                parser.error("--protocol auto requires --pcap <file> or --sniff <iface>")
            targets, seeds, edges = run_auto_mode(args)
            if not args.no_viz:
                from core.visualizer import TopologyVisualizer
                viz = TopologyVisualizer()
                for t in targets:
                    viz.add_device(t)
                for src, dst, proto in edges:
                    viz.add_edge(src, dst, proto)
        else:
            if not args.target:
                parser.error(f"--target is required when --protocol is '{args.protocol}'")
            targets = [parse_target(args.target, args.protocol)]

        if not targets:
            print("[error] No targets identified. Exiting.")
            sys.exit(1)

        # Confirmation gate
        if not confirm_targets(targets, args.yes):
            sys.exit(0)

        categories = [c.strip() for c in args.categories.split(",")] if args.categories else None
        delay = (1.0 / args.rate_limit) if getattr(args, "rate_limit", None) else args.delay

        all_results = []
        for target in targets:
            addr = target.mac if target.protocol == "iec61850" and not target.ip else f"{target.ip}:{target.port}"
            action = "Generating" if args.dry_run else "Starting"
            print(f"\n[fuzz] {action} {target.protocol.upper()} fuzzer → {addr}")
            FuzzerClass = load_protocol_module(target.protocol)
            _sig = inspect.signature(FuzzerClass.__init__)
            _kwargs = dict(target=target, logger=logger, delay=delay, seeds=seeds)
            if "injection_file" in _sig.parameters and getattr(args, "injection_file", None):
                _kwargs["injection_file"] = args.injection_file
            if "unit_id" in _sig.parameters and getattr(args, "unit_id", None) is not None:
                _kwargs["unit_id"] = args.unit_id
            fuzzer = FuzzerClass(**_kwargs)

            try:
                # Fingerprint phase (before connect so it uses its own ephemeral socket)
                do_fp   = getattr(args, "fingerprint", False) or getattr(args, "fingerprint_passive", False)
                fp_active = getattr(args, "fingerprint", False) and not getattr(args, "fingerprint_passive", False)
                if do_fp:
                    _run_fingerprint(fuzzer, target, active=fp_active)

                if args.dry_run:
                    if hasattr(fuzzer, "generate_cases"):
                        _export_dry_run(fuzzer, target, categories, args.output)
                    else:
                        print(f"[warn] {target.protocol.upper()} generators not yet implemented — skipping dry-run.")
                else:
                    fuzzer.connect(target)
                    fuzzer.establish_presence()
                    results = fuzzer.fuzz(categories=categories)
                    all_results.extend(results)
                    print(f"[fuzz] Completed {len(results)} cases for {addr}")
            except NotImplementedError:
                print(f"[warn] {target.protocol.upper()} module is not yet implemented.")
            except KeyboardInterrupt:
                print("\n[abort] Fuzzing interrupted by user.")
                break
            finally:
                try:
                    fuzzer.close()
                except Exception:
                    pass

    if viz and all_results:
        for result in all_results:
            viz.add_result(result)
        viz.render(args.output)

    reporter = FuzzReporter(args.output)
    reporter.summarize()


if __name__ == "__main__":
    main()
