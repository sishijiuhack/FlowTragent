"""Source and entry point aggregation."""

from __future__ import annotations

from collections import Counter, defaultdict

from src.event.models import NetworkEvent


def summarize_sources(events: list[NetworkEvent]) -> list[dict]:
    grouped: dict[str, list[NetworkEvent]] = defaultdict(list)
    for event in events:
        grouped[event.src_ip or "unknown"].append(event)

    summaries = []
    for source, grouped_events in grouped.items():
        timestamps = [event.timestamp for event in grouped_events if event.timestamp is not None]
        uri_counts = Counter(getattr(event, "uri", None) for event in grouped_events if getattr(event, "uri", None))
        ua_counts = Counter(getattr(event, "user_agent", None) for event in grouped_events if getattr(event, "user_agent", None))
        dns_counts = Counter(event.dns_query for event in grouped_events if event.dns_query)
        targets = sorted({f"{event.dst_ip}:{event.dst_port}" for event in grouped_events if event.dst_ip})
        summaries.append(
            {
                "source_ip": source,
                "first_seen": min(timestamps) if timestamps else None,
                "last_seen": max(timestamps) if timestamps else None,
                "event_count": len(grouped_events),
                "top_uris": uri_counts.most_common(5),
                "top_user_agents": ua_counts.most_common(5),
                "top_dns_queries": dns_counts.most_common(5),
                "targets": targets[:10],
            }
        )
    return summaries
