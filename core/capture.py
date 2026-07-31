"""Packet capture engine: live sniff and pcap ingestion via Scapy."""


class CaptureEngine:
    """Wraps Scapy for live sniffing and pcap loading.

    Returns raw Scapy packet lists for protocol fingerprinting
    and seed-based fuzzing.

    Requires: scapy, and root/CAP_NET_RAW for live sniffing.
    """

    def load_pcap(self, path: str) -> list:
        try:
            from scapy.all import rdpcap
        except ImportError:
            raise RuntimeError("scapy is required for pcap ingestion. Run: pip install scapy")
        packets = rdpcap(path)
        print(f"[capture] Loaded {len(packets)} packets from {path}")
        return list(packets)

    def sniff(self, interface: str, duration: int = 60) -> list:
        try:
            from scapy.all import sniff as scapy_sniff
        except ImportError:
            raise RuntimeError("scapy is required for live sniffing. Run: pip install scapy")

        # BPF filter covers all 7 protocol ports plus GOOSE EtherType
        bpf = (
            "tcp port 502 or tcp port 20000 or tcp port 4840 "
            "or tcp port 44818 or tcp port 102 or tcp port 2404 "
            "or udp port 47808 or ether proto 0x88b8"
        )
        print(f"[capture] Sniffing {interface} for {duration}s (filter: ICS protocols) ...")
        packets = scapy_sniff(iface=interface, filter=bpf, timeout=duration)
        print(f"[capture] Captured {len(packets)} packets")
        return list(packets)
