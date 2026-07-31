"""
opcua-anon-write-scan.py — OPC-UA anonymous-session write-access scanner

Connects to an OPC-UA server as an anonymous (unauthenticated) client, browses
the address space, and attempts a write to every discovered Variable node.
Flags any variable that accepts the write — anonymous sessions carry no role,
so an anonymous write succeeding at all is a signal worth reviewing, and is a
hard finding when the node's own declared UserAccessLevel says read-only.

Background: found via manual testing against an OpenPLC Runtime v4 instance.
Its per-role write-permission model (viewer/operator/engineer) is actually
enforced at write time for anonymous sessions too — the real issue is role
*elevation*: when a project has zero configured users, anonymous clients are
deliberately assigned the engineer/Admin role (user_manager.py, documented as
intentional), so any variable writable by the engineer role becomes writable
by unauthenticated clients. Variables set engineer-read-only stay protected,
and adding one named user flips anonymous back to read-only viewer. See
the icsFuzzer OpenPLC v4 write-permission finding. This scanner ignores
the internal mechanism and just answers the operator's real question — "can an
anonymous client write this variable right now?" — against any OPC-UA target.

Safety: this tool WRITES to live variables. By default it restores each
variable's original value immediately after confirming the write landed, and
refuses to run without --yes (or an interactive confirmation) since a target
process may act on the perturbed value before it's restored. Only tests
Boolean variables by default — numeric/string writes are opt-in via
--include-numeric / --include-string, since perturbing a real control
setpoint carries more operational risk than flipping a bit.

Usage:
    python3 opcua-anon-write-scan.py --target 127.0.0.1:4840 --endpoint-path /openplc/opcua --yes
    python3 opcua-anon-write-scan.py --target 192.168.1.20 --dry-run
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

try:
    from asyncua import Client, ua
except ImportError:
    print("Missing dependency: asyncua. Install with: pip install asyncua", file=sys.stderr)
    sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opcua-anon-write-scan",
        description="Scan an OPC-UA server for variables writable via an anonymous (unauthenticated) session.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  opcua-anon-write-scan.py --target 127.0.0.1:4840 --endpoint-path /openplc/opcua --yes
  opcua-anon-write-scan.py --target 192.168.1.20 --dry-run
  opcua-anon-write-scan.py --target 127.0.0.1:4840 --include-numeric --yes
        """,
    )
    parser.add_argument(
        "--target", required=True, metavar="HOST[:PORT]",
        help="Target host (and optional port, default 4840).",
    )
    parser.add_argument(
        "--endpoint-path", default="", metavar="PATH",
        help="Server endpoint path, e.g. /openplc/opcua (default: none).",
    )
    parser.add_argument(
        "--security-string", default=None, metavar="STR",
        help=(
            "Optional asyncua security string (e.g. "
            "'Basic256Sha256,SignAndEncrypt,cert.pem,key.pem') if the server "
            "requires a secure channel even for Anonymous auth. Default: "
            "SecurityPolicy=None (plain channel)."
        ),
    )
    parser.add_argument(
        "--include-ns0", action="store_true",
        help="Also probe standard OPC Foundation namespace (ns=0) nodes. Default: skip them (noise, not application data).",
    )
    parser.add_argument(
        "--include-numeric", action="store_true",
        help="Also test numeric (Int/UInt/Float/Double) variables, perturbing by +1 and restoring. Default: Boolean only.",
    )
    parser.add_argument(
        "--include-string", action="store_true",
        help="Also test String variables, appending a marker and restoring. Default: skipped (higher risk of visible side effects).",
    )
    parser.add_argument(
        "--max-depth", type=int, default=8, metavar="N",
        help="Maximum Browse recursion depth from the Objects folder (default: 8).",
    )
    parser.add_argument(
        "--no-restore", action="store_true",
        help="Do not write the original value back after a successful test write. NOT recommended against live targets.",
    )
    parser.add_argument(
        "--output", default="output", metavar="DIR",
        help="Output directory for the JSON report (default: ./output).",
    )
    parser.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the interactive confirmation prompt before performing live writes.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Browse and report declared access levels only — never attempt a write.",
    )
    parser.add_argument(
        "--timeout", type=float, default=8.0, metavar="SECONDS",
        help="Connection/request timeout in seconds (default: 8.0).",
    )
    return parser


def parse_target(target: str, default_port: int = 4840):
    if ":" in target:
        host, port = target.rsplit(":", 1)
        return host, int(port)
    return target, default_port


PERTURBABLE_NUMERIC_TYPES = {
    ua.VariantType.Byte, ua.VariantType.SByte, ua.VariantType.Int16, ua.VariantType.UInt16,
    ua.VariantType.Int32, ua.VariantType.UInt32, ua.VariantType.Int64, ua.VariantType.UInt64,
    ua.VariantType.Float, ua.VariantType.Double,
}


def _decode_access_level(raw) -> str:
    """Decode the OPC-UA AccessLevel/UserAccessLevel bitmask (bit0=CurrentRead, bit1=CurrentWrite)."""
    try:
        bits = int(raw)
    except (TypeError, ValueError):
        return str(raw)
    flags = []
    if bits & 0x01:
        flags.append("Read")
    if bits & 0x02:
        flags.append("Write")
    if bits & 0x04:
        flags.append("HistoryRead")
    if bits & 0x08:
        flags.append("HistoryWrite")
    return f"{bits}({'|'.join(flags) if flags else 'none'})"


def make_perturbed_value(current, variant_type, include_numeric: bool, include_string: bool):
    """Return (new_value, testable) — testable=False means skip this node's type."""
    if variant_type == ua.VariantType.Boolean:
        return (not current), True
    if include_numeric and variant_type in PERTURBABLE_NUMERIC_TYPES:
        return (current + 1), True
    if include_string and variant_type == ua.VariantType.String:
        marker = "__icsfuzzer_probe__"
        base = current if isinstance(current, str) else ""
        if base.endswith(marker):
            return base, True  # already probed value, still testable, will no-op restore
        return base + marker, True
    return current, False


async def scan(args) -> dict:
    host, port = parse_target(args.target)
    url = f"opc.tcp://{host}:{port}{args.endpoint_path}"
    print(f"[*] Connecting anonymously to {url} ...")

    client = Client(url=url, timeout=args.timeout)
    if args.security_string:
        await client.set_security_string(args.security_string)
    # Explicitly anonymous: no set_user()/set_password() call.

    results = []
    connected = False
    try:
        async with client:
            connected = True
            print("[+] Anonymous session established.")

            objects = client.get_objects_node()
            variables = await _browse_variables(objects, args.max_depth, args.include_ns0)
            print(f"[*] Discovered {len(variables)} Variable node(s) to probe.")

            for node in variables:
                entry = await _probe_node(node, args)
                results.append(entry)
                _print_entry(entry)

    except Exception as e:
        print(f"[!] Anonymous connection FAILED: {type(e).__name__}: {e}")
        return {
            "target": url,
            "anonymous_connect_succeeded": False,
            "error": f"{type(e).__name__}: {e}",
            "variables": [],
        }

    return {
        "target": url,
        "anonymous_connect_succeeded": connected,
        "variables": results,
    }


async def _browse_variables(start_node, max_depth: int, include_ns0: bool, depth: int = 0, seen=None):
    if seen is None:
        seen = set()
    found = []
    if depth > max_depth:
        return found
    try:
        children = await start_node.get_children()
    except Exception:
        return found
    for child in children:
        nid = child.nodeid
        key = (nid.NamespaceIndex, str(nid.Identifier))
        if key in seen:
            continue
        seen.add(key)
        if not include_ns0 and nid.NamespaceIndex == 0:
            continue
        try:
            node_class = await child.read_node_class()
        except Exception:
            continue
        if node_class == ua.NodeClass.Variable:
            found.append(child)
        # Recurse into Objects/Variables that may themselves have children
        found.extend(await _browse_variables(child, max_depth, include_ns0, depth + 1, seen))
    return found


async def _probe_node(node, args) -> dict:
    entry = {
        "node_id": node.nodeid.to_string(),
        "browse_name": None,
        "data_type": None,
        "declared_user_access_level": None,
        "value_before": None,
        "tested": False,
        "write_accepted": None,
        "value_changed": None,
        "restored": None,
        "error": None,
    }
    try:
        bname = await node.read_browse_name()
        entry["browse_name"] = bname.Name
    except Exception as e:
        entry["error"] = f"browse_name read failed: {e}"
        return entry

    try:
        dv = await node.read_data_value()
        variant_type = dv.Value.VariantType
        current = dv.Value.Value
        entry["data_type"] = str(variant_type)
        entry["value_before"] = repr(current)
    except Exception as e:
        entry["error"] = f"value read failed: {e}"
        return entry

    try:
        ual = await node.read_attribute(ua.AttributeIds.UserAccessLevel)
        entry["declared_user_access_level"] = _decode_access_level(ual.Value.Value)
    except Exception:
        entry["declared_user_access_level"] = "<unreadable>"

    if args.dry_run:
        return entry

    new_value, testable = make_perturbed_value(current, variant_type, args.include_numeric, args.include_string)
    if not testable:
        return entry

    entry["tested"] = True
    try:
        await node.write_value(ua.DataValue(ua.Variant(new_value, variant_type)))
    except Exception as e:
        entry["write_accepted"] = False
        entry["error"] = f"{type(e).__name__}: {e}"
        return entry

    entry["write_accepted"] = True
    # Poll rather than a single fixed sleep: scan-cycle propagation has been observed
    # to take up to ~1.5s in prior testing against this class of target, not just
    # one cycleTimeMs tick.
    readback = current
    for _ in range(10):
        await asyncio.sleep(0.15)
        try:
            readback = await node.read_value()
        except Exception as e:
            entry["error"] = f"readback failed: {e}"
            break
        if readback != current:
            break
    entry["value_changed"] = (readback != current)

    if not args.no_restore:
        try:
            await node.write_value(ua.DataValue(ua.Variant(current, variant_type)))
            confirm = readback
            for _ in range(10):
                await asyncio.sleep(0.15)
                confirm = await node.read_value()
                if confirm == current:
                    break
            entry["restored"] = (confirm == current)
        except Exception as e:
            entry["restored"] = False
            entry["error"] = (entry["error"] + "; " if entry["error"] else "") + f"restore failed: {e}"

    return entry


def _print_entry(entry: dict):
    name = entry["browse_name"] or entry["node_id"]
    if entry["error"] and not entry["tested"]:
        print(f"    {name}: SKIPPED ({entry['error']})")
        return
    if not entry["tested"]:
        print(f"    {name}: declared_access={entry['declared_user_access_level']} (not testable type, skipped)")
        return
    if entry["write_accepted"]:
        flag = "  <-- ANONYMOUS WRITE SUCCEEDED" if entry["value_changed"] else "  (write acked, value unchanged)"
        print(
            f"    {name}: declared_access={entry['declared_user_access_level']} "
            f"write=ACCEPTED changed={entry['value_changed']} restored={entry['restored']}{flag}"
        )
    else:
        print(f"    {name}: declared_access={entry['declared_user_access_level']} write=REJECTED ({entry['error']})")


def summarize(report: dict):
    print()
    print("=" * 70)
    if not report["anonymous_connect_succeeded"]:
        print("RESULT: could not establish an anonymous session — target does not")
        print("        appear to allow Anonymous auth (or is unreachable).")
        print("=" * 70)
        return

    vulnerable = [v for v in report["variables"] if v.get("write_accepted") and v.get("value_changed")]
    tested = [v for v in report["variables"] if v.get("tested")]
    if vulnerable:
        print(f"RESULT: VULNERABLE — {len(vulnerable)}/{len(tested)} tested variable(s) accepted")
        print("        a write from an anonymous, unauthenticated session:")
        for v in vulnerable:
            declared = v["declared_user_access_level"] or ""
            note = ""
            if declared not in ("<unreadable>", "") and "Write" not in declared:
                note = " (declared read-only via UserAccessLevel — protocol-level attribute itself is wrong, not just enforcement)"
            print(f"          - {v['browse_name']} ({v['node_id']}){note}")
        print()
        print("        Recommendation: disable Anonymous auth on this server, or")
        print("        confirm every anonymous-reachable variable is intentionally")
        print("        anonymous-writable at the PLC-logic level, not just in a")
        print("        per-role config that Anonymous sessions may bypass.")
    else:
        print(f"RESULT: clean — 0/{len(tested)} tested variable(s) accepted an anonymous write.")
    print("=" * 70)


async def main_async(args):
    if not args.dry_run and not args.yes:
        print("This scan performs LIVE writes to variables on the target and restores")
        print("them afterward (unless --no-restore is set). A target process may act on")
        print("the perturbed value before it's restored.")
        resp = input("Continue? [y/N] ").strip().lower()
        if resp != "y":
            print("Aborted.")
            return 1

    report = await scan(args)
    summarize(report)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"opcua-anon-write-scan-{int(time.time())}.json"
    out_file.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nReport written to {out_file}")
    return 0


def main():
    args = build_parser().parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
