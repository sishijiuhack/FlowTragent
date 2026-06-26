"""Source and entry point aggregation."""

from __future__ import annotations

from collections import Counter, defaultdict

from src.event.models import HttpEvent


def summarize_sources(events: list[HttpEvent]) -> list[dict]:
    grouped: dict[str, list[HttpEvent]] = defaultdict(list)
    for event in events:
        grouped[event.src_ip or "unknown"].append(event)

    summaries = []
    for source, grouped_events in grouped.items():
        timestamps = [event.timestamp for event in grouped_events if event.timestamp is not None]
        uri_counts = Counter(event.uri for event in grouped_events if event.uri)
        ua_counts = Counter(event.user_agent for event in grouped_events if event.user_agent)
        targets = sorted({f"{event.dst_ip}:{event.dst_port}" for event in grouped_events if event.dst_ip})
        summaries.append(
            {
                "source_ip": source,
                "first_seen": min(timestamps) if timestamps else None,
                "last_seen": max(timestamps) if timestamps else None,
                "event_count": len(grouped_events),
                "top_uris": uri_counts.most_common(5),
                "top_user_agents": ua_counts.most_common(5),
                "targets": targets[:10],
            }
        )
    return summaries

