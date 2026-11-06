"""Tests for scripts/pnnl_corpus_extract.py — the PNNL pcap -> per-protocol seed corpus extractor
(tshark-based). Pure parsing/filter logic is tested with synthetic tshark rows (no tshark needed);
the end-to-end path is tested against a temp pcap and skipped when tshark is absent.
"""
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.pnnl_corpus_extract import (  # noqa: E402
    build_filter, tshark_cmd, parse_tshark_line, build_corpus, PROTOCOL_PORTS,
)

MODBUS = bytes.fromhex("000100000006ff0300000001")
DNP3 = bytes.fromhex("0564050c0100000011aabb")
P2P = {PROTOCOL_PORTS[p]: p for p in PROTOCOL_PORTS}


def _row(ip_src, ip_dst, tsp="", tdp="", usp="", udp="", tcp_pl="", udp_pl=""):
    return "|".join([ip_src, ip_dst, tsp, tdp, usp, udp, tcp_pl, udp_pl])


def test_build_filter_covers_tcp_and_udp_per_protocol():
    f = build_filter(["dnp3", "modbus"])
    assert "tcp.port==20000" in f and "tcp.port==502" in f
    assert "udp.port==20000" in f and "udp.length>8" in f


def test_tshark_cmd_shape():
    cmd = tshark_cmd(Path("x.pcap"), "tcp.port==502")
    assert cmd[:4] == ["tshark", "-r", "x.pcap", "-Y"]
    assert "tcp.payload" in cmd and "fields" in cmd and "separator=|" in cmd


def test_parse_matches_tcp_by_dst_and_src_port():
    # client->server (dst 502) and server->client (src 502) both resolve to modbus
    m1 = parse_tshark_line(_row("10.0.0.1", "10.0.0.2", "33333", "502", tcp_pl=MODBUS.hex()), P2P)
    assert m1 == ("modbus", MODBUS, "10.0.0.1", "10.0.0.2")
    m2 = parse_tshark_line(_row("10.0.0.2", "10.0.0.1", "502", "33333", tcp_pl=MODBUS.hex()), P2P)
    assert m2[0] == "modbus"


def test_parse_udp_dnp3_and_rejects_unmatched_and_empty():
    m = parse_tshark_line(_row("1.1.1.1", "2.2.2.2", usp="40000", udp="20000", udp_pl=DNP3.hex()), P2P)
    assert m == ("dnp3", DNP3, "1.1.1.1", "2.2.2.2")
    # port 80 -> no match; empty payload -> None; malformed hex -> None
    assert parse_tshark_line(_row("1.1.1.1", "2.2.2.2", "5", "80", tcp_pl="deadbeef"), P2P) is None
    assert parse_tshark_line(_row("1.1.1.1", "2.2.2.2", "5", "502", tcp_pl=""), P2P) is None
    assert parse_tshark_line(_row("1.1.1.1", "2.2.2.2", "5", "502", tcp_pl="zz"), P2P) is None


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_end_to_end_dedups_and_writes(tmp_path):
    scapy = pytest.importorskip("scapy.all")
    from scapy.all import Ether, IP, TCP, Raw, wrpcap
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=33333, dport=502) / Raw(MODBUS),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.3") / TCP(sport=44444, dport=20000) / Raw(DNP3),
        Ether() / IP(src="10.0.0.9", dst="10.0.0.2") / TCP(sport=55555, dport=502) / Raw(MODBUS),  # dup payload
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"GET / HTTP/1.1\r\n"),  # ignored
    ]
    pcap = tmp_path / "malformed_scenario.pcap"
    wrpcap(str(pcap), pkts)

    out = tmp_path / "corpus"
    manifest, stats = build_corpus([pcap], ["dnp3", "modbus"], out)

    assert stats["modbus"]["unique"] == 1          # the two identical MBAP reads collapse to one seed
    assert stats["dnp3"]["unique"] == 1
    assert stats["modbus"]["packets"] == 2          # both :502 packets counted
    # seeds written to disk + manifest on disk
    assert (out / "manifest.json").exists()
    bins = list((out / "modbus").glob("*.bin")) + list((out / "dnp3").glob("*.bin"))
    assert len(bins) == 2
    dup = [e for e in manifest.values() if e["proto"] == "modbus"][0]
    assert len(dup["sources"]) == 2 and all(s["scenario"] == "malformed_scenario" for s in dup["sources"])
