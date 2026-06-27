"""Simple C2 and beacon detection heuristics."""

from __future__ import annotations

from collections import defaultdict
from statistics import median

from src.event.models import C2Finding, HttpEvent, NetworkEvent


def detect_c2(events: list[NetworkEvent]) -> list[dict]:
    findings: list[C2Finding] = []
    findings.extend(_detect_http_beacons([event for event in events if isinstance(event, HttpEvent)]))
    findings.extend(_detect_dns_c2(events))
    findings.extend(_detect_tcp_beacons(events))
    return [finding.to_dict() for finding in findings]


def _detect_http_beacons(events: list[HttpEvent]) -> list[C2Finding]:
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
        small_responses = [event for event in ordered if event.response_size is not None and event.response_size <= 120]
        if len(small_responses) >= len(ordered) * 0.75:
            indicators.append("small repeated responses")
        methods = {event.method for event in ordered if event.method}
        if methods and methods <= {"GET", "POST"}:
            indicators.append("beacon-like HTTP method pattern")
        if not indicators:
            continue
        strong_timing = any(indicator.startswith("regular interval") for indicator in indicators)
        confidence = "high" if strong_timing and len(indicators) >= 3 else "medium" if len(indicators) >= 2 else "low"
        findings.append(
            C2Finding(
                c2_type="HTTP Beacon",
                confidence=confidence,
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
    return findings


def _detect_dns_c2(events: list[NetworkEvent]) -> list[C2Finding]:
    dns_events = [event for event in events if event.protocol == "DNS" and event.dns_query]
    groups: dict[tuple[str, str, int], list[NetworkEvent]] = defaultdict(list)
    for event in dns_events:
        if event.src_ip and event.dst_ip:
            groups[(event.src_ip, event.dst_ip, event.dst_port or 53)].append(event)

    findings: list[C2Finding] = []
    for (src_ip, dst_ip, dst_port), grouped in groups.items():
        if len(grouped) < 4:
            continue
        ordered = sorted(grouped, key=lambda event: event.timestamp or 0)
        queries = [event.dns_query or "" for event in ordered]
        indicators = []
        long_labels = [query for query in queries if any(len(label) >= 32 for label in query.split("."))]
        high_entropy = [query for query in queries if _looks_encoded(query)]
        qtypes = {event.dns_qtype for event in ordered if event.dns_qtype}
        unique_queries = set(queries)
        base_domains = {_base_domain(query) for query in queries if query}

        if len(long_labels) >= max(2, len(ordered) // 2):
            indicators.append("long DNS labels")
        if len(high_entropy) >= max(2, len(ordered) // 2):
            indicators.append("encoded/high-entropy DNS names")
        if qtypes & {"16", "TXT"}:
            indicators.append("TXT query usage")
        if len(unique_queries) >= len(ordered) * 0.75 and len(base_domains) <= 2:
            indicators.append("many unique subdomains under few base domains")

        interval, jitter = _interval_stats(ordered)
        if interval and jitter is not None and interval > 0 and jitter / interval <= 0.3:
            indicators.append(f"regular interval median={interval:.2f}s jitter={jitter:.2f}s")

        if len(indicators) < 2:
            continue
        strong = any(item.startswith("regular interval") for item in indicators) or "encoded/high-entropy DNS names" in indicators
        confidence = "high" if strong and len(indicators) >= 3 else "medium"
        findings.append(
            C2Finding(
                c2_type="DNS C2 / Tunneling",
                confidence=confidence,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                first_seen=ordered[0].timestamp,
                last_seen=ordered[-1].timestamp,
                request_count=len(ordered),
                beacon_interval=interval,
                jitter=jitter,
                evidence_ids=[event.event_id for event in ordered],
                indicators=indicators,
            )
        )
    return findings


def _detect_tcp_beacons(events: list[NetworkEvent]) -> list[C2Finding]:
    tcp_events = [
        event
        for event in events
        if event.protocol == "TCP" and event.src_ip and event.dst_ip and event.dst_port and event.dst_port not in {80, 443}
    ]
    groups: dict[tuple[str, str, int], list[NetworkEvent]] = defaultdict(list)
    for event in tcp_events:
        groups[(event.src_ip or "", event.dst_ip or "", event.dst_port or 0)].append(event)

    findings: list[C2Finding] = []
    for (src_ip, dst_ip, dst_port), grouped in groups.items():
        ordered = sorted(grouped, key=lambda event: event.timestamp or 0)
        if len(ordered) < 4:
            continue
        interval, jitter = _interval_stats(ordered)
        indicators = []
        if interval and jitter is not None and interval > 0 and jitter / interval <= 0.25:
            indicators.append(f"regular interval median={interval:.2f}s jitter={jitter:.2f}s")
        small_payloads = [event for event in ordered if event.raw_size is not None and event.raw_size <= 128]
        if len(small_payloads) >= len(ordered) * 0.75:
            indicators.append("small repeated TCP payloads")
        if dst_port not in {22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995}:
            indicators.append("uncommon destination port")
        if len({event.src_port for event in ordered if event.src_port}) >= len(ordered) * 0.75:
            indicators.append("repeated outbound connections with changing source ports")
        if len(indicators) < 2:
            continue
        confidence = "high" if any(item.startswith("regular interval") for item in indicators) and len(indicators) >= 3 else "medium"
        findings.append(
            C2Finding(
                c2_type="TCP Beacon",
                confidence=confidence,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                first_seen=ordered[0].timestamp,
                last_seen=ordered[-1].timestamp,
                request_count=len(ordered),
                beacon_interval=interval,
                jitter=jitter,
                evidence_ids=[event.event_id for event in ordered],
                indicators=indicators,
            )
        )
    return findings


def _interval_stats(events: list[NetworkEvent]) -> tuple[float | None, float | None]:
    times = [event.timestamp for event in events if event.timestamp is not None]
    intervals = [b - a for a, b in zip(times, times[1:]) if b >= a]
    if len(intervals) < 3:
        return None, None
    interval = median(intervals)
    jitter = median([abs(value - interval) for value in intervals])
    return interval, jitter


def _base_domain(query: str) -> str:
    labels = [label for label in query.lower().split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else query.lower()


def _looks_encoded(query: str) -> bool:
    first_label = query.split(".", 1)[0]
    if len(first_label) < 24:
        return False
    charset = set(first_label.lower())
    alpha_num = sum(char.isalnum() for char in first_label)
    return alpha_num / max(1, len(first_label)) > 0.85 and len(charset) >= 12
