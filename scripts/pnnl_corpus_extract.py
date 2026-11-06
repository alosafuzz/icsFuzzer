#!/usr/bin/env python3
"""Extract a deduplicated, per-protocol fuzzing-seed corpus from the PNNL ICS network-capture
dataset (DOI 10.25584/PNNLDH/1838670 — DNP3/Modbus captures against SAGE RTU, SEL 451, ROC 800,
FloBoss across ~14 labeled scenarios). Added 2026-11-05.

icsFuzzer already ingests a single pcap as in-memory seeds (`icsfuzzer.py --pcap`, core/capture.py).
This tool is the batch/corpus complement: point it at a directory of the PNNL pcaps and it writes the
unique application-layer payloads to disk, one file per seed, grouped by protocol — a reusable corpus
the structured fuzzers can draw from (the DNP3/Modbus modules' `seeds=` argument), and which the
malformed/bad-CRC/fuzzing-labeled scenarios especially enrich.

Usage (from the ics-fuzzer repo root):
    python3 scripts/pnnl_corpus_extract.py <pcap-dir-or-file> [more...] \
        [--out output/pnnl-corpus] [--protocols dnp3,modbus]

Output:
    <out>/<proto>/<sha16>.bin        one unique app-layer payload per file
    <out>/manifest.json              seed -> {proto, len, sources:[{pcap, scenario, src, dst}]}

SAFE: read-only. It only reads pcap files and writes seed files; it sends nothing on the network.
Downloaded captures are untrusted data — run this against a copy in its own directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# Application-layer seeds are keyed by transport port. Kept local (not imported from icsfuzzer.py's
# PROTOCOL_PORTS) so this tool stays standalone; values match that table.
PROTOCOL_PORTS = {"dnp3": 20000, "modbus": 502}


def _scenario_from_path(pcap_path: Path) -> str:
    """A short scenario label derived from the capture's filename (the PNNL set names its 14
    scenarios in the filenames, e.g. 'normal', 'malformed', 'arp_spoof', ...)."""
    return pcap_path.stem.lower()


def extract_from_packets(packets, portmap=PROTOCOL_PORTS):
    """Pure extraction: given an iterable of scapy packets, return
    {proto: [ {payload: bytes, src: str, dst: str} , ... ]} for every TCP/UDP packet carrying a
    non-empty application-layer payload on a matched port. No dedup here (the caller dedups across
    files) — this keeps the function straightforward to unit-test against hand-built packets."""
    from scapy.layers.inet import TCP, UDP, IP  # local import so --help works without scapy

    out = {proto: [] for proto in portmap}
    port_to_proto = {port: proto for proto, port in portmap.items()}
    for pkt in packets:
        l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        if l4 is None:
            continue
        proto = port_to_proto.get(l4.dport) or port_to_proto.get(l4.sport)
        if proto is None:
            continue
        payload = bytes(l4.payload)
        if not payload:
            continue
        ip = pkt.getlayer(IP)
        src = ip.src if ip else "?"
        dst = ip.dst if ip else "?"
        out[proto].append({"payload": payload, "src": src, "dst": dst})
    return out


def iter_pcaps(paths):
    """Yield every .pcap/.pcapng under the given files/dirs."""
    for p in paths:
        p = Path(p)
        if p.is_dir():
            yield from sorted(f for f in p.rglob("*") if f.suffix.lower() in (".pcap", ".pcapng"))
        elif p.suffix.lower() in (".pcap", ".pcapng"):
            yield p


def build_corpus(paths, protocols):
    """Walk every pcap, extract per-protocol payloads, dedup by sha256. Returns
    (corpus, stats) where corpus[proto][sha] = {payload, len, sources:[...]}."""
    from scapy.all import rdpcap

    portmap = {p: PROTOCOL_PORTS[p] for p in protocols}
    corpus = {proto: {} for proto in portmap}
    stats = {proto: {"packets": 0, "unique": 0} for proto in portmap}
    files_seen = 0
    for pcap in iter_pcaps(paths):
        files_seen += 1
        scenario = _scenario_from_path(pcap)
        try:
            packets = rdpcap(str(pcap))
        except Exception as e:  # a corrupt/odd capture must not abort the whole batch
            print(f"[warn] could not read {pcap}: {e}", file=sys.stderr)
            continue
        per = extract_from_packets(packets, portmap)
        for proto, items in per.items():
            for it in items:
                stats[proto]["packets"] += 1
                sha = hashlib.sha256(it["payload"]).hexdigest()
                entry = corpus[proto].get(sha)
                src_rec = {"pcap": pcap.name, "scenario": scenario, "src": it["src"], "dst": it["dst"]}
                if entry is None:
                    corpus[proto][sha] = {"payload": it["payload"], "len": len(it["payload"]), "sources": [src_rec]}
                elif src_rec not in entry["sources"]:
                    entry["sources"].append(src_rec)
    for proto in corpus:
        stats[proto]["unique"] = len(corpus[proto])
    stats["_files"] = files_seen
    return corpus, stats


def write_corpus(corpus, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for proto, seeds in corpus.items():
        pdir = out_dir / proto
        pdir.mkdir(parents=True, exist_ok=True)
        for sha, entry in seeds.items():
            short = sha[:16]
            (pdir / f"{short}.bin").write_bytes(entry["payload"])
            manifest[f"{proto}/{short}.bin"] = {
                "sha256": sha, "proto": proto, "len": entry["len"], "sources": entry["sources"],
            }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="pcap files or directories (recursed)")
    ap.add_argument("--out", default="output/pnnl-corpus", help="corpus output directory")
    ap.add_argument("--protocols", default="dnp3,modbus", help="comma-separated (default dnp3,modbus)")
    args = ap.parse_args()

    protocols = [p.strip() for p in args.protocols.split(",") if p.strip()]
    unknown = [p for p in protocols if p not in PROTOCOL_PORTS]
    if unknown:
        ap.error(f"unknown protocol(s) {unknown}; known: {sorted(PROTOCOL_PORTS)}")

    corpus, stats = build_corpus(args.paths, protocols)
    out_dir = Path(args.out)
    write_corpus(corpus, out_dir)

    print(f"Read {stats['_files']} pcap file(s). Corpus -> {out_dir}")
    for proto in protocols:
        print(f"  {proto:8} {stats[proto]['packets']:6d} payload packets -> {stats[proto]['unique']:5d} unique seeds")
    print(f"  manifest: {out_dir / 'manifest.json'}")


if __name__ == "__main__":
    main()
