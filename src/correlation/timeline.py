"""Timeline construction from structured events."""

from __future__ import annotations

from src.event.models import NetworkEvent


def build_timeline(events: list[NetworkEvent]) -> list[dict]:
    sorted_events = sorted(events, key=lambda event: event.timestamp or 0)
    timeline = []
    for event in sorted_events:
        endpoint = _endpoint(event)
        method = getattr(event, "method", None) or event.protocol
        uri = getattr(event, "uri", None) or event.dns_query
        timeline.append(
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "source": f"{event.src_ip}:{event.src_port}" if event.src_ip else None,
                "target": f"{event.dst_ip}:{event.dst_port}" if event.dst_ip else None,
                "method": method,
                "uri": uri,
                "host": getattr(event, "host", None),
                "status_code": getattr(event, "status_code", None),
                "response_size": getattr(event, "response_size", None),
                "response_summary": getattr(event, "response_summary", None),
                "summary": f"{endpoint} {event.summary}".strip(),
            }
        )
    return timeline


def _endpoint(event: NetworkEvent) -> str:
    if not event.src_ip or not event.dst_ip:
        return ""
    return f"{event.src_ip}:{event.src_port or '?'} -> {event.dst_ip}:{event.dst_port or '?'}"
