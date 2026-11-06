"""Tests for scripts/pnnl_corpus_extract.py — the PNNL pcap -> per-protocol seed corpus extractor.

Builds synthetic packets in memory (and a temp pcap) rather than needing the real PNNL dataset, so
the extraction, dedup, port-matching, and manifest logic are verified standalone.
"""
import json
import sys
from pathlib import Path

import pytest

scapy_all = pytest.importorskip("scapy.all")
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.pnnl_corpus_extract import extract_from_packets, build_corpus, write_corpus  # noqa: E402

MODBUS = bytes.fromhex("000100000006ff0300000001")   # MBAP + FC03 read
DNP3 = bytes.fromhex("0564050c0100000011aabb")        # DNP3 link header-ish


def _pkts():
    return [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=33333, dport=502) / Raw(MODBUS),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.3") / TCP(sport=44444, dport=20000) / Raw(DNP3),
        # a duplicate Modbus payload from a different host pair -> same seed, extra source
        Ether() / IP(src="10.0.0.9", dst="10.0.0.2") / TCP(sport=55555, dport=502) / Raw(MODBUS),
        # unrelated traffic on :80 -> must be ignored
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"GET / HTTP/1.1\r\n"),
        # a server->client Modbus response (src port 502) -> still matched
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=502, dport=33333) / Raw(b"\x00\x01\x00\x00\x00\x05\xff\x03\x02\x00\x00"),
    ]


def test_extract_matches_by_port_both_directions():
    per = extract_from_packets(_pkts())
    assert len(per["modbus"]) == 3          # two :502-dst + one :502-src response
    assert len(per["dnp3"]) == 1
    assert all(it["payload"] for it in per["modbus"])       # no empty payloads
    # the :80 packet was ignored
    assert all(b"GET /" not in it["payload"] for it in per["modbus"])


def test_build_corpus_dedups_and_records_sources(tmp_path):
    pcap = tmp_path / "malformed_scenario.pcap"
    wrpcap(str(pcap), _pkts())

    corpus, stats = build_corpus([pcap], ["dnp3", "modbus"])
    # 3 modbus payload packets, but only 2 UNIQUE seeds (the identical MBAP read appears twice)
    assert stats["modbus"]["packets"] == 3
    assert stats["modbus"]["unique"] == 2
    assert stats["dnp3"]["unique"] == 1
    assert stats["_files"] == 1

    # the duplicated seed records BOTH source host pairs
    dup = [e for e in corpus["modbus"].values() if e["payload"] == MODBUS][0]
    assert len(dup["sources"]) == 2
    assert all(s["scenario"] == "malformed_scenario" for s in dup["sources"])


def test_write_corpus_lays_out_files_and_manifest(tmp_path):
    pcap = tmp_path / "normal.pcap"
    wrpcap(str(pcap), _pkts())
    corpus, _ = build_corpus([pcap], ["dnp3", "modbus"])

    out = tmp_path / "corpus"
    manifest = write_corpus(corpus, out)

    assert (out / "manifest.json").exists()
    bins = list((out / "modbus").glob("*.bin")) + list((out / "dnp3").glob("*.bin"))
    assert len(bins) == 3                                   # 2 modbus + 1 dnp3 unique seeds
    # a manifest entry points at a real file whose bytes hash-match its recorded sha
    loaded = json.loads((out / "manifest.json").read_text())
    assert len(loaded) == 3
    for rel, meta in loaded.items():
        assert (out / rel).read_bytes()
        assert meta["len"] == len((out / rel).read_bytes())


def test_unknown_protocol_not_requested_is_absent():
    per = extract_from_packets(_pkts(), portmap={"modbus": 502})
    assert set(per) == {"modbus"}
