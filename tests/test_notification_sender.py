from __future__ import annotations

import json
import sys
from io import BytesIO
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.notification.sender import build_alert_payload, notification_fingerprint, send_notification


class _Response:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size: int = -1) -> bytes:
        return b"ok"


def _config(url: str = "https://example.invalid/hook") -> dict:
    return {
        "notification": {
            "enabled": True,
            "min_severity": "high",
            "webhook": {
                "enabled": True,
                "url": url,
                "timeout_seconds": 2,
                "headers": {"X-Test": "yes"},
            },
        }
    }


def _prefilter(severity: str = "high") -> dict:
    return {
        "severity": severity,
        "risk_score": 80,
        "recommended_action": "deep_analysis",
        "reasons": ["marker:log4shell_jndi"],
        "event_count": 3,
        "http_event_count": 2,
        "dns_event_count": 1,
        "tcp_event_count": 0,
        "top_sources": [["10.0.0.5", 3]],
        "top_destinations": [["10.0.0.10", 3]],
    }


def test_send_notification_posts_webhook_payload() -> None:
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        captured["headers"] = dict(request.header_items())
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return _Response()

    result = send_notification(
        _config(),
        "deep_analysis_reported",
        _prefilter(),
        "segment.pcap",
        report_path="reports/report.md",
        urlopen=fake_urlopen,
    )

    assert result["sent"] is True
    assert captured["url"] == "https://example.invalid/hook"
    assert captured["timeout"] == 2
    assert captured["headers"]["X-test"] == "yes"
    assert captured["payload"]["event_type"] == "deep_analysis_reported"
    assert captured["payload"]["report_path"] == "reports/report.md"
    assert captured["payload"]["severity"] == "high"


def test_send_notification_skips_below_min_severity() -> None:
    result = send_notification(_config(), "deep_analysis_reported", _prefilter("medium"), "segment.pcap")

    assert result["sent"] is False
    assert result["reason"] == "below_min_severity"


def test_build_alert_payload_keeps_operational_context() -> None:
    payload = build_alert_payload("deep_analysis_error", _prefilter("critical"), Path("segment.pcap"), error="boom")

    assert payload["event_type"] == "deep_analysis_error"
    assert payload["severity"] == "critical"
    assert payload["error"] == "boom"
    assert payload["stats"]["top_sources"] == [["10.0.0.5", 3]]


def test_notification_fingerprint_groups_related_reason_families() -> None:
    first = notification_fingerprint("deep_analysis_reported", _prefilter("high"))
    second_payload = _prefilter("high")
    second_payload["reasons"] = ["marker:spring4shell"]
    second = notification_fingerprint("deep_analysis_reported", second_payload)

    assert first == second
