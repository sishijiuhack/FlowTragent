"""Simple C2 and beacon detection heuristics."""

from __future__ import annotations

from collections import defaultdict
from statistics import median

from src.event.models import C2Finding, HttpEvent, NetworkEvent


def detect_c2(events: list[NetworkEvent], config: dict | None = None) -> list[dict]:
    config = config or {}
    findings: list[C2Finding] = []
    findings.extend(_detect_http_beacons([event for event in events if isinstance(event, HttpEvent)], config))
    findings.extend(_detect_dns_c2(events, config))
    findings.extend(_detect_tcp_beacons(events, config))
    findings.extend(_detect_port_scans(events, config))
    findings.extend(_detect_icmp_anomalies(events, config))
    findings.extend(_detect_endpoint_external(events))
    return [finding.to_dict() for finding in findings]


def _detect_http_beacons(events: list[HttpEvent], config: dict) -> list[C2Finding]:
    min_requests = int(config.get("http_min_requests", 4))
    repeated_uri_divisor = int(config.get("http_repeated_uri_divisor", 3))
    small_response_bytes = int(config.get("http_small_response_bytes", 120))
    small_response_ratio = float(config.get("http_small_response_ratio", 0.75))
    timing_jitter_ratio = float(config.get("http_timing_jitter_ratio", 0.25))
    groups: dict[tuple[str, str, int], list[HttpEvent]] = defaultdict(list)
    for event in events:
        if event.src_ip and event.dst_ip and event.dst_port:
            groups[(event.src_ip, event.dst_ip, event.dst_port)].append(event)

    findings: list[C2Finding] = []
    for (src_ip, dst_ip, dst_port), grouped in groups.items():
        ordered = sorted(grouped, key=lambda event: event.timestamp or 0)
        if len(ordered) < min_requests:
            continue
        times = [event.timestamp for event in ordered if event.timestamp is not None]
        intervals = [b - a for a, b in zip(times, times[1:]) if b >= a]
        indicators = []
        interval = jitter = None
        if len(intervals) >= 3:
            interval = median(intervals)
            jitter = median([abs(value - interval) for value in intervals])
            if interval > 0 and jitter / interval <= timing_jitter_ratio:
                indicators.append(f"regular interval median={interval:.2f}s jitter={jitter:.2f}s")
        user_agents = {event.user_agent for event in ordered if event.user_agent}
        uris = {event.uri for event in ordered if event.uri}
        if len(user_agents) == 1:
            indicators.append("stable user-agent")
        if len(uris) <= max(2, len(ordered) // repeated_uri_divisor):
            indicators.append("repeated URI pattern")
        small_responses = [event for event in ordered if event.response_size is not None and event.response_size <= small_response_bytes]
        if len(small_responses) >= len(ordered) * small_response_ratio:
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


def _detect_dns_c2(events: list[NetworkEvent], config: dict) -> list[C2Finding]:
    min_requests = int(config.get("dns_min_requests", 4))
    jitter_ratio = float(config.get("dns_jitter_ratio", 0.3))
    long_label_min = int(config.get("dns_long_label_min", 32))
    high_entropy_label_min = int(config.get("dns_high_entropy_label_min", 24))
    unique_query_ratio = float(config.get("dns_unique_query_ratio", 0.75))
    dns_events = [event for event in events if event.protocol == "DNS" and event.dns_query]
    groups: dict[tuple[str, str, int], list[NetworkEvent]] = defaultdict(list)
    for event in dns_events:
        if event.src_ip and event.dst_ip:
            groups[(event.src_ip, event.dst_ip, event.dst_port or 53)].append(event)

    findings: list[C2Finding] = []
    for (src_ip, dst_ip, dst_port), grouped in groups.items():
        if len(grouped) < min_requests:
            continue
        ordered = sorted(grouped, key=lambda event: event.timestamp or 0)
        queries = [event.dns_query or "" for event in ordered]
        indicators = []
        long_labels = [query for query in queries if any(len(label) >= long_label_min for label in query.split("."))]
        high_entropy = [query for query in queries if _looks_encoded(query, high_entropy_label_min)]
        qtypes = {event.dns_qtype for event in ordered if event.dns_qtype}
        unique_queries = set(queries)
        base_domains = {_base_domain(query) for query in queries if query}

        if len(long_labels) >= max(2, len(ordered) // 2):
            indicators.append("long DNS labels")
        if len(high_entropy) >= max(2, len(ordered) // 2):
            indicators.append("encoded/high-entropy DNS names")
        if qtypes & {"16", "TXT"}:
            indicators.append("TXT query usage")
        if len(unique_queries) >= len(ordered) * unique_query_ratio and len(base_domains) <= 2:
            indicators.append("many unique subdomains under few base domains")

        interval, jitter = _interval_stats(ordered)
        if interval and jitter is not None and interval > 0 and jitter / interval <= jitter_ratio:
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


def _detect_tcp_beacons(events: list[NetworkEvent], config: dict) -> list[C2Finding]:
    min_packets = int(config.get("tcp_min_packets", 4))
    timing_jitter_ratio = float(config.get("tcp_timing_jitter_ratio", 0.25))
    small_payload_bytes = int(config.get("tcp_small_payload_bytes", 128))
    small_payload_ratio = float(config.get("tcp_small_payload_ratio", 0.75))
    ephemeral_unique_ratio = float(config.get("tcp_ephemeral_unique_ratio", 0.75))
    common_ports = set(int(port) for port in config.get("common_service_ports", [22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995]))
    http_service_ports = {
        int(event.dst_port)
        for event in events
        if isinstance(event, HttpEvent) and event.dst_port
    }
    tcp_events = [
        event
        for event in events
        if event.protocol == "TCP"
        and event.src_ip
        and event.dst_ip
        and event.dst_port
        and event.dst_port not in {80, 443}
        and event.dst_port not in http_service_ports
        and event.src_port not in http_service_ports
    ]
    groups: dict[tuple[str, str, int], list[NetworkEvent]] = defaultdict(list)
    for event in tcp_events:
        groups[(event.src_ip or "", event.dst_ip or "", event.dst_port or 0)].append(event)

    findings: list[C2Finding] = []
    for (src_ip, dst_ip, dst_port), grouped in groups.items():
        ordered = sorted(grouped, key=lambda event: event.timestamp or 0)
        if len(ordered) < min_packets:
            continue
        interval, jitter = _interval_stats(ordered)
        indicators = []
        if interval and jitter is not None and interval > 0 and jitter / interval <= timing_jitter_ratio:
            indicators.append(f"regular interval median={interval:.2f}s jitter={jitter:.2f}s")
        small_payloads = [event for event in ordered if event.raw_size is not None and event.raw_size <= small_payload_bytes]
        if len(small_payloads) >= len(ordered) * small_payload_ratio:
            indicators.append("small repeated TCP payloads")
        if dst_port not in common_ports:
            indicators.append("uncommon destination port")
        if len({event.src_port for event in ordered if event.src_port}) >= len(ordered) * ephemeral_unique_ratio:
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


def _detect_endpoint_external(events: list[NetworkEvent]) -> list[C2Finding]:
    endpoint_events = [
        event
        for event in events
        if event.protocol == "ENDPOINT" and event.src_ip and event.dst_ip and event.dst_port
    ]
    if not endpoint_events:
        return []
    network_destinations = {(event.dst_ip, event.dst_port) for event in events if event.protocol in {"HTTP", "DNS", "TCP"}}
    groups: dict[tuple[str, str, int], list[NetworkEvent]] = defaultdict(list)
    for event in endpoint_events:
        groups[(event.src_ip or "", event.dst_ip or "", event.dst_port or 0)].append(event)

    findings = []
    for (src_ip, dst_ip, dst_port), grouped in groups.items():
        indicators = []
        commands = " ".join(event.payload_clean.lower() for event in grouped)
        if any(marker in commands for marker in ("curl", "wget", "powershell", "certutil", "bash -c", "nc ", "ncat")):
            indicators.append("endpoint process initiated external network-capable command")
        if dst_port not in {22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995}:
            indicators.append("uncommon destination port from endpoint telemetry")
        if (dst_ip, dst_port) in network_destinations:
            indicators.append("endpoint destination also appears in network evidence")
        if len(grouped) >= 2:
            indicators.append("repeated endpoint events to same destination")
        if not indicators:
            continue
        timestamps = [event.timestamp for event in grouped if event.timestamp is not None]
        confidence = "high" if len(indicators) >= 2 else "medium"
        findings.append(
            C2Finding(
                c2_type="Endpoint External Connection",
                confidence=confidence,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                first_seen=min(timestamps) if timestamps else None,
                last_seen=max(timestamps) if timestamps else None,
                request_count=len(grouped),
                beacon_interval=None,
                jitter=None,
                evidence_ids=[event.event_id for event in grouped],
                indicators=indicators,
            )
        )
    return findings


def _detect_port_scans(events: list[NetworkEvent], config: dict) -> list[C2Finding]:
    min_ports = int(config.get("port_scan_min_ports", 10))
    time_window = float(config.get("port_scan_time_window", 60))
    tcp_events = [
        event
        for event in events
        if event.protocol == "TCP" and event.src_ip and event.dst_ip and event.dst_port
    ]
    groups: dict[tuple[str, str], list[NetworkEvent]] = defaultdict(list)
    for event in tcp_events:
        groups[(event.src_ip or "", event.dst_ip or "")].append(event)

    findings: list[C2Finding] = []
    for (src_ip, dst_ip), grouped in groups.items():
        ordered = sorted(grouped, key=lambda event: event.timestamp or 0)
        ports = {event.dst_port for event in ordered if event.dst_port}
        timestamps = [event.timestamp for event in ordered if event.timestamp is not None]
        if len(ports) < min_ports:
            continue
        if len(timestamps) >= 2 and max(timestamps) - min(timestamps) > time_window:
            continue
        indicators = [f"{len(ports)} distinct destination ports"]
        syn_events = [event for event in ordered if event.tcp_flags and "S" in str(event.tcp_flags) and "A" not in str(event.tcp_flags)]
        if len(syn_events) >= max(3, len(ordered) // 2):
            indicators.append("SYN-heavy connection pattern")
        confidence = "high" if len(ports) >= min_ports * 2 or len(indicators) >= 2 else "medium"
        findings.append(
            C2Finding(
                c2_type="TCP Port Scan",
                confidence=confidence,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=0,
                first_seen=min(timestamps) if timestamps else None,
                last_seen=max(timestamps) if timestamps else None,
                request_count=len(ordered),
                beacon_interval=None,
                jitter=None,
                evidence_ids=[event.event_id for event in ordered],
                indicators=indicators,
            )
        )
    return findings


def _detect_icmp_anomalies(events: list[NetworkEvent], config: dict) -> list[C2Finding]:
    min_events = int(config.get("icmp_min_events", 6))
    large_payload_bytes = int(config.get("icmp_large_payload_bytes", 96))
    groups: dict[tuple[str, str], list[NetworkEvent]] = defaultdict(list)
    for event in events:
        if event.protocol == "ICMP" and event.src_ip and event.dst_ip:
            groups[(event.src_ip or "", event.dst_ip or "")].append(event)

    findings: list[C2Finding] = []
    for (src_ip, dst_ip), grouped in groups.items():
        ordered = sorted(grouped, key=lambda event: event.timestamp or 0)
        if len(ordered) < min_events:
            continue
        indicators = []
        large_payloads = [event for event in ordered if event.raw_size is not None and event.raw_size >= large_payload_bytes]
        if len(large_payloads) >= max(2, len(ordered) // 2):
            indicators.append("large repeated ICMP payloads")
        interval, jitter = _interval_stats(ordered)
        if interval and jitter is not None and interval > 0 and jitter / interval <= float(config.get("icmp_jitter_ratio", 0.3)):
            indicators.append(f"regular interval median={interval:.2f}s jitter={jitter:.2f}s")
        if len({event.payload_clean for event in ordered if event.payload_clean}) <= max(2, len(ordered) // 3):
            indicators.append("repeated ICMP payload pattern")
        if len(indicators) < 2:
            continue
        timestamps = [event.timestamp for event in ordered if event.timestamp is not None]
        findings.append(
            C2Finding(
                c2_type="ICMP Tunnel / Beacon",
                confidence="high" if len(indicators) >= 3 else "medium",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=0,
                first_seen=min(timestamps) if timestamps else None,
                last_seen=max(timestamps) if timestamps else None,
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


def _looks_encoded(query: str, min_label_length: int = 24) -> bool:
    first_label = query.split(".", 1)[0]
    if len(first_label) < min_label_length:
        return False
    charset = set(first_label.lower())
    alpha_num = sum(char.isalnum() for char in first_label)
    return alpha_num / max(1, len(first_label)) > 0.85 and len(charset) >= 12
