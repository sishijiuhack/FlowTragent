from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.correlation.c2_detector import detect_c2
from src.parser.pcap_parser import parse_network_events


def main() -> None:
    try:
        import scapy  # noqa: F401
    except Exception:
        print("scapy not installed; skipping DNS/TCP C2 pipeline test")
        return

    subprocess.run([sys.executable, "tests/make_dns_tcp_c2_pcap.py"], cwd=PROJECT_ROOT, check=True)
    events = parse_network_events(str(PROJECT_ROOT / "data/pcap/demo_dns_tcp_c2.pcap"))
    protocols = {event.protocol for event in events}
    assert "DNS" in protocols
    assert "TCP" in protocols

    findings = detect_c2(events)
    finding_types = {finding["c2_type"] for finding in findings}
    assert "DNS C2 / Tunneling" in finding_types
    assert "TCP Beacon" in finding_types

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--mode",
            "pcap",
            "--input",
            "data/pcap/demo_dns_tcp_c2.pcap",
            "--demo-index",
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    report_path = PROJECT_ROOT / json.loads(result.stdout)["report"]
    report = report_path.read_text(encoding="utf-8")
    assert "## C2 Analysis" in report
    assert "DNS C2 / Tunneling" in report
    assert "TCP Beacon" in report
    assert "Possible compromise with C2 indicators" in report


if __name__ == "__main__":
    main()
