from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, wrpcap


def main() -> None:
    packets = []
    base_time = 1_700_001_000.0

    for idx in range(6):
        label = f"{idx:02x}a9f3c7d1e5b8a0c4f6d2e9b7a1c3d5f{idx:02x}"
        query = f"{label}.stage.c2.example"
        dns_packet = (
            IP(src="10.10.10.20", dst="198.51.100.53")
            / UDP(sport=53000 + idx, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=query, qtype="TXT"))
        )
        dns_packet.time = base_time + idx * 45
        packets.append(dns_packet)

    for idx in range(5):
        tcp_packet = (
            IP(src="10.10.10.20", dst="203.0.113.77")
            / TCP(sport=54000 + idx, dport=4443, flags="PA")
            / Raw(load=b"\x01\x00\x00\x04ping")
        )
        tcp_packet.time = base_time + 300 + idx * 60
        packets.append(tcp_packet)

    output = Path("data/pcap/demo_dns_tcp_c2.pcap")
    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)
    print(output)


if __name__ == "__main__":
    main()
