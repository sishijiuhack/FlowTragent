"""Config-driven alert notifications."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def send_notification(
    config: dict[str, Any],
    event_type: str,
    prefilter: dict[str, Any],
    segment_path: str | Path,
    report_path: str | Path | None = None,
    error: str | None = None,
    urlopen=urllib.request.urlopen,
) -> dict[str, Any]:
    """Send configured notifications for one live alert event."""
    notification = (config or {}).get("notification") or {}
    if not notification.get("enabled", False):
        return {"sent": False, "reason": "disabled"}
    severity = str((prefilter or {}).get("severity") or "low").lower()
    if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(str(notification.get("min_severity") or "high").lower(), 2):
        return {"sent": False, "reason": "below_min_severity", "severity": severity}

    webhook = notification.get("webhook") or {}
    if not webhook.get("enabled", False):
        return {"sent": False, "reason": "webhook_disabled"}
    url = str(webhook.get("url") or "").strip()
    if not url:
        return {"sent": False, "reason": "webhook_url_missing"}

    payload = build_alert_payload(event_type, prefilter, segment_path, report_path=report_path, error=error)
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", **{str(k): str(v) for k, v in (webhook.get("headers") or {}).items()}},
        method="POST",
    )
    timeout = float(webhook.get("timeout_seconds") or 5)
    try:
        with urlopen(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200) or 200)
            body = response.read(512).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return {"sent": False, "reason": "webhook_error", "error": str(exc)}
    return {"sent": 200 <= status < 300, "reason": "sent" if 200 <= status < 300 else "webhook_http_error", "status": status, "response": body}


def notification_fingerprint(event_type: str, prefilter: dict[str, Any]) -> str:
    """Build a stable suppression fingerprint for similar notifications."""
    stats = prefilter or {}
    key = {
        "event_type": event_type,
        "severity": str(stats.get("severity") or "low"),
        "recommended_action": str(stats.get("recommended_action") or ""),
        "top_source": _top_value(stats.get("top_sources")),
        "top_destination": _top_value(stats.get("top_destinations")),
        "reason_families": sorted(_reason_families(stats.get("reasons") or [])),
    }
    return json.dumps(key, ensure_ascii=False, sort_keys=True)


def build_alert_payload(
    event_type: str,
    prefilter: dict[str, Any],
    segment_path: str | Path,
    report_path: str | Path | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Build a compact notification payload shared by all channels."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_type": event_type,
        "severity": str((prefilter or {}).get("severity") or "low"),
        "risk_score": int((prefilter or {}).get("risk_score") or 0),
        "recommended_action": str((prefilter or {}).get("recommended_action") or ""),
        "segment_path": str(segment_path),
        "report_path": str(report_path) if report_path else None,
        "error": error,
        "reasons": list((prefilter or {}).get("reasons") or []),
        "stats": {
            "event_count": (prefilter or {}).get("event_count"),
            "http_event_count": (prefilter or {}).get("http_event_count"),
            "dns_event_count": (prefilter or {}).get("dns_event_count"),
            "tcp_event_count": (prefilter or {}).get("tcp_event_count"),
            "top_sources": (prefilter or {}).get("top_sources") or [],
            "top_destinations": (prefilter or {}).get("top_destinations") or [],
        },
    }


def _top_value(values: Any) -> str:
    if not values:
        return "unknown"
    first = values[0]
    if isinstance(first, (list, tuple)) and first:
        return str(first[0])
    if isinstance(first, dict):
        return str(first.get("ip") or first.get("host") or first.get("value") or "unknown")
    return str(first)


def _reason_families(reasons: list[Any]) -> set[str]:
    families = set()
    for reason in reasons:
        text = str(reason)
        families.add(text.split(":", 1)[0] if ":" in text else text)
    return families or {"unknown"}
