from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import IP, TCP, Raw, wrpcap


def main() -> None:
    packets = []
    base_time = 1_700_000_000.0
    for idx in range(6):
        sport = 50000 + idx
        request = (
            b"GET /api/checkin HTTP/1.1\r\n"
            b"Host: c2.example\r\n"
            b"User-Agent: flow-agent/1.0\r\n"
            b"Cookie: sid=abc123\r\n\r\n"
        )
        response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
        req = IP(src="10.10.10.20", dst="203.0.113.50") / TCP(sport=sport, dport=8080) / Raw(load=request)
        resp = IP(src="203.0.113.50", dst="10.10.10.20") / TCP(sport=8080, dport=sport) / Raw(load=response)
        req.time = base_time + idx * 30
        resp.time = base_time + idx * 30 + 0.2
        packets.extend([req, resp])

    output = Path("data/pcap/demo_http_beacon.pcap")
    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)
    print(output)


if __name__ == "__main__":
    main()

