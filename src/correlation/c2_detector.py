"""Simple C2 and beacon detection heuristics."""

from __future__ import annotations

from collections import defaultdict
from statistics import median

from src.event.models import C2Finding, HttpEvent


def detect_c2(events: list[HttpEvent]) -> list[dict]:
    groups: dict[tuple[str, str, int], list[HttpEvent]] = defaultdict(list)
    for event in events:
        if event.src_ip and event.dst_ip and event.dst_port:
            groups[(event.src_ip, event.dst_ip, event.dst_port)].append(event)

    findings: list[C2Finding] = []
    for (src_ip, dst_ip, dst_port), grouped in groups.items():
        ordered = sorted(grouped, key=lambda event: event.timestamp or 0)
        if len(ordered) < 4:
            continue
        times = [event.timestamp for event in ordered if event.timestamp is not None]
        intervals = [b - a for a, b in zip(times, times[1:]) if b >= a]
        indicators = []
        interval = jitter = None
        if len(intervals) >= 3:
            interval = median(intervals)
            jitter = median([abs(value - interval) for value in intervals])
            if interval > 0 and jitter / interval <= 0.25:
                indicators.append(f"regular interval median={interval:.2f}s jitter={jitter:.2f}s")
        user_agents = {event.user_agent for event in ordered if event.user_agent}
        uris = {event.uri for event in ordered if event.uri}
        if len(user_agents) == 1:
            indicators.append("stable user-agent")
        if len(uris) <= max(2, len(ordered) // 3):
            indicators.append("repeated URI pattern")
        if not indicators:
            continue
        findings.append(
            C2Finding(
                c2_type="HTTP Beacon",
                confidence="medium" if len(indicators) >= 2 else "low",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                first_seen=times[0] if times else None,
                last_seen=times[-1] if times else None,
                request_count=len(ordered),
                beacon_interval=interval,
                jitter=jitter,
                evidence_ids=[event.event_id for event in ordered],
                indicators=indicators,
            )
        )
    return [finding.to_dict() for finding in findings]

