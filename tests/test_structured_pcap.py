from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.correlation.impact_analyzer import assess_impact
from src.parser.pcap_parser import parse_pcap_events


def main() -> None:
    try:
        import scapy  # noqa: F401
    except Exception:
        print("scapy not installed; skipping structured PCAP test")
        return

    subprocess.run([sys.executable, "tests/make_demo_pcap.py"], cwd=PROJECT_ROOT, check=True)
    events = parse_pcap_events(str(PROJECT_ROOT / "data/pcap/demo_attack.pcap"))
    assert len(events) == 1
    assert events[0].status_code == 200
    impact = assess_impact(
        events,
        [{"stage": "Exploitation", "confidence": "high", "evidence_ids": ["pkt-1"]}],
        [],
        [{"cve": "CVE-2021-44228", "rule_confirmed": True, "final_score": 0.8}],
    )
    assert impact["verdict"] == "Likely exploitation attempt with successful HTTP response"


if __name__ == "__main__":
    main()

