#!/usr/bin/env python3
"""Extract a deduplicated, per-protocol fuzzing-seed corpus from the PNNL ICS network-capture
dataset (DOI 10.25584/PNNLDH/1838670 — DNP3/Modbus captures against SAGE RTU, SEL 451/351, GE
L90/D30, ControlWave IO, across ~14 labeled scenarios). Added 2026-11-05; reworked to use tshark
after scapy's rdpcap/PcapReader proved too slow and memory-heavy on this set's multi-GB
long-duration captures.

icsFuzzer already ingests a single pcap as in-memory seeds (`icsfuzzer.py --pcap`, core/capture.py).
This tool is the batch/corpus complement: point it at a directory of captures and it writes the
unique application-layer payloads to disk, one file per seed, grouped by protocol — a reusable
corpus the structured fuzzers can draw from (the DNP3/Modbus modules' `seeds=` argument).

WHY tshark, not scapy: tshark (C) streams a capture and emits only the fields we need at low, bounded
memory and high speed; scapy dissects every packet in Python and, via rdpcap, loads whole files into
RAM. This tool holds only the dedup index (one small record per UNIQUE seed) in memory — payload
bytes are written to disk on first sight and never retained — and flushes the manifest after every
capture, so a mid-run interruption still leaves a usable partial corpus.

Usage (from the ics-fuzzer repo root; requires tshark on PATH):
    python3 scripts/pnnl_corpus_extract.py <pcap-dir-or-file> [more...] \
        [--out output/pnnl-corpus] [--protocols dnp3,modbus] [--progress]

Output:
    <out>/<proto>/<sha16>.bin    one unique app-layer payload per file
    <out>/manifest.json          seed -> {sha256, proto, len, sources:[{pcap, scenario, src, dst}]}

SAFE: read-only. It only reads pcap files (via tshark) and writes seed files; it sends nothing on the
network. Downloaded captures are untrusted data — run against a copy in its own directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

# Application-layer seeds are keyed by transport port; values match icsfuzzer.py's PROTOCOL_PORTS.
PROTOCOL_PORTS = {"dnp3": 20000, "modbus": 502}

# tshark field order (pipe-separated; payloads render as plain hex, so '|' never collides).
_FIELDS = ["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
           "tcp.payload", "udp.payload"]
_SEP = "|"


def _scenario_from_path(pcap_path: Path) -> str:
    """Short scenario label from the filename (the PNNL set encodes its scenarios there)."""
    return pcap_path.stem.lower()


def build_filter(protocols) -> str:
    """A tshark display filter selecting non-empty app-layer payloads on the protocols' ports."""
    clauses = []
    for proto in protocols:
        port = PROTOCOL_PORTS[proto]
        clauses.append(f"(tcp.port=={port} && tcp.len>0)")
        clauses.append(f"(udp.port=={port} && udp.length>8)")
    return " || ".join(clauses)


def tshark_cmd(pcap: Path, display_filter: str) -> list:
    """The exact tshark argv used per capture (factored out so tests can assert its shape)."""
    cmd = ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
    for f in _FIELDS:
        cmd += ["-e", f]
    cmd += ["-E", f"separator={_SEP}", "-E", "occurrence=f"]
    return cmd


def parse_tshark_line(line: str, port_to_proto) -> "tuple | None":
    """Parse one pipe-separated tshark row into (proto, payload_bytes, src, dst), or None if it has
    no usable app-layer payload / matches no protocol. Pure — unit-testable with synthetic rows."""
    parts = line.rstrip("\n").split(_SEP)
    if len(parts) != len(_FIELDS):
        return None
    ip_src, ip_dst, tsp, tdp, usp, udp_p, tcp_pl, udp_pl = parts
    if tcp_pl:
        payload_hex, sport, dport = tcp_pl, tsp, tdp
    elif udp_pl:
        payload_hex, sport, dport = udp_pl, usp, udp_p
    else:
        return None
    proto = None
    for p in (dport, sport):
        try:
            proto = port_to_proto.get(int(p))
        except (TypeError, ValueError):
            proto = None
        if proto:
            break
    if proto is None:
        return None
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        return None
    if not payload:
        return None
    return proto, payload, ip_src or "?", ip_dst or "?"


def iter_pcaps(paths):
    for p in paths:
        p = Path(p)
        if p.is_dir():
            yield from sorted(f for f in p.rglob("*") if f.suffix.lower() in (".pcap", ".pcapng"))
        elif p.suffix.lower() in (".pcap", ".pcapng"):
            yield p


def build_corpus(paths, protocols, out_dir: Path, progress=False):
    """Stream every capture through tshark, dedup app-layer payloads by sha256, and write each unique
    seed to disk on first sight (payload bytes are NOT kept in memory). The manifest is rewritten
    after every capture so an interruption still leaves a usable corpus. Returns (manifest, stats)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    port_to_proto = {PROTOCOL_PORTS[p]: p for p in protocols}
    display_filter = build_filter(protocols)
    for proto in protocols:
        (out_dir / proto).mkdir(parents=True, exist_ok=True)

    manifest = {}                      # "proto/sha16.bin" -> {sha256, proto, len, sources:[...]}
    seen = {}                          # sha256 -> manifest key (so dups just append a source)
    stats = {proto: {"packets": 0, "unique": 0} for proto in protocols}
    files_seen = 0

    for pcap in iter_pcaps(paths):
        files_seen += 1
        scenario = _scenario_from_path(pcap)
        if progress:
            print(f"[.] {pcap.name}", file=sys.stderr, flush=True)
        proc = subprocess.Popen(tshark_cmd(pcap, display_filter), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
        try:
            for line in proc.stdout:
                m = parse_tshark_line(line, port_to_proto)
                if m is None:
                    continue
                proto, payload, src, dst = m
                stats[proto]["packets"] += 1
                sha = hashlib.sha256(payload).hexdigest()
                src_rec = {"pcap": pcap.name, "scenario": scenario, "src": src, "dst": dst}
                if sha not in seen:
                    key = f"{proto}/{sha[:16]}.bin"
                    (out_dir / key).write_bytes(payload)   # flush seed immediately
                    manifest[key] = {"sha256": sha, "proto": proto, "len": len(payload), "sources": [src_rec]}
                    seen[sha] = key
                else:
                    entry = manifest[seen[sha]]
                    if src_rec not in entry["sources"]:
                        entry["sources"].append(src_rec)
        finally:
            proc.stdout.close()
            proc.wait()
        _write_manifest(out_dir, manifest)   # kill-safe: current after every capture

    for proto in protocols:
        stats[proto]["unique"] = sum(1 for e in manifest.values() if e["proto"] == proto)
    stats["_files"] = files_seen
    return manifest, stats


def _write_manifest(out_dir: Path, manifest: dict):
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="pcap files or directories (recursed)")
    ap.add_argument("--out", default="output/pnnl-corpus", help="corpus output directory")
    ap.add_argument("--protocols", default="dnp3,modbus", help="comma-separated (default dnp3,modbus)")
    ap.add_argument("--progress", action="store_true", help="print each capture name as it streams")
    args = ap.parse_args()

    if shutil.which("tshark") is None:
        ap.error("tshark is required (install Wireshark/tshark and ensure it is on PATH)")

    protocols = [p.strip() for p in args.protocols.split(",") if p.strip()]
    unknown = [p for p in protocols if p not in PROTOCOL_PORTS]
    if unknown:
        ap.error(f"unknown protocol(s) {unknown}; known: {sorted(PROTOCOL_PORTS)}")

    out_dir = Path(args.out)
    manifest, stats = build_corpus(args.paths, protocols, out_dir, progress=args.progress)

    print(f"Read {stats['_files']} capture(s). Corpus -> {out_dir}")
    for proto in protocols:
        print(f"  {proto:8} {stats[proto]['packets']:7d} payload packets -> {stats[proto]['unique']:6d} unique seeds")
    print(f"  manifest: {out_dir / 'manifest.json'}")


if __name__ == "__main__":
    main()
