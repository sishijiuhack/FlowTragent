"""Lightweight prefilter for live PCAP segments."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from src.core.settings import load_config
from src.parser.pcap_parser import parse_network_events


CRITICAL_MARKERS = {
    "log4shell_jndi": ("${jndi:", 70),
    "spring4shell": ("class.module.classloader", 55),
    "webshell_upload": ("multipart/form-data", 30),
}

SUSPICIOUS_MARKERS = {
    "path_traversal": ("../", 35),
    "encoded_path_traversal": (".%2e", 45),
    "sql_injection": (" or '1'='1", 35),
    "command_exec_cmd": ("cmd=", 35),
    "command_exec_exec": ("exec=", 35),
    "curl_download": ("curl ", 40),
    "wget_download": ("wget ", 40),
    "powershell": ("powershell", 45),
    "certutil": ("certutil", 45),
    "whoami": ("whoami", 25),
    "base64": ("base64", 20),
    "php_wrapper": ("php://", 35),
}

COMMON_SERVICE_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3389, 8080, 8443}


@dataclass
class PrefilterResult:
    pcap_path: str
    risk_score: int
    severity: str
    recommended_action: str
    reasons: list[str] = field(default_factory=list)
    event_count: int = 0
    http_event_count: int = 0
    dns_event_count: int = 0
    tcp_event_count: int = 0
    icmp_event_count: int = 0
    source_count: int = 0
    destination_count: int = 0
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    top_destinations: list[tuple[str, int]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def prefilter_pcap(pcap_path: str | Path, min_risk_score: int = 50, config: dict | None = None) -> PrefilterResult:
    """Score a PCAP segment without running retrieval, Agent, RAG, or LLM."""
    path = Path(pcap_path)
    prefilter_config = _prefilter_config(config)
    try:
        events = parse_network_events(str(path))
    except Exception as exc:  # pragma: no cover - defensive for corrupt live segments
        return PrefilterResult(
            pcap_path=str(path),
            risk_score=0,
            severity="error",
            recommended_action="skip",
            reasons=["parse_error"],
            error=str(exc),
        )

    reasons: list[str] = []
    score = 0
    src_counter: Counter[str] = Counter()
    dst_counter: Counter[str] = Counter()
    flow_times: dict[tuple[str, str, int | None, str], list[float]] = defaultdict(list)

    http_count = dns_count = tcp_count = 0
    icmp_count = 0
    for event in events:
        if event.src_ip:
            src_counter[event.src_ip] += 1
        if event.dst_ip:
            dst_counter[_endpoint(event.dst_ip, event.dst_port)] += 1
        if event.timestamp is not None and event.src_ip and event.dst_ip:
            flow_times[(event.src_ip, event.dst_ip, event.dst_port, event.protocol)].append(event.timestamp)

        protocol = (event.protocol or "").upper()
        if protocol == "HTTP":
            http_count += 1
            payload = (event.payload_clean or "").lower()
            for name, (marker, points) in CRITICAL_MARKERS.items():
                if marker in payload:
                    score += _marker_points(prefilter_config, "critical", name, points)
                    reasons.append(f"http_critical:{name}")
            for name, (marker, points) in SUSPICIOUS_MARKERS.items():
                if marker in payload:
                    score += _marker_points(prefilter_config, "suspicious", name, points)
                    reasons.append(f"http_marker:{name}")
        elif protocol == "DNS":
            dns_count += 1
            query = (event.dns_query or "").lower().strip(".")
            dns_score, dns_reasons = _score_dns_query(query, event.dns_qtype, prefilter_config)
            score += dns_score
            reasons.extend(dns_reasons)
        elif protocol == "TCP":
            tcp_count += 1
            common_ports = set(int(port) for port in prefilter_config.get("common_service_ports", COMMON_SERVICE_PORTS))
            min_external_port = int(prefilter_config.get("tcp_external_port_min", 1024))
            if event.dst_port and event.dst_port not in common_ports and event.dst_port >= min_external_port:
                score += int(prefilter_config.get("tcp_external_port_score", 8))
                reasons.append(f"tcp_external_service_port:{event.dst_port}")
        elif protocol == "ICMP":
            icmp_count += 1
            if event.raw_size is not None and event.raw_size >= int(prefilter_config.get("icmp_large_payload_bytes", 96)):
                score += int(prefilter_config.get("icmp_large_payload_score", 12))
                reasons.append("icmp_large_payload")

    for (src, dst, port, protocol), timestamps in flow_times.items():
        if len(timestamps) < int(prefilter_config.get("periodic_min_events", 3)):
            continue
        timestamps = sorted(timestamps)
        intervals = [later - earlier for earlier, later in zip(timestamps, timestamps[1:]) if later >= earlier]
        if not intervals:
            continue
        avg = sum(intervals) / len(intervals)
        jitter = _jitter(intervals, avg)
        if (
            float(prefilter_config.get("periodic_min_avg_seconds", 2)) <= avg <= float(prefilter_config.get("periodic_max_avg_seconds", 300))
            and jitter <= float(prefilter_config.get("periodic_max_jitter", 0.35))
        ):
            points = int(prefilter_config.get("periodic_http_dns_score", 25)) if protocol in {"HTTP", "DNS"} else int(prefilter_config.get("periodic_tcp_score", 18))
            score += points
            reasons.append(f"periodic_{protocol.lower()}:{src}->{dst}:{port or ''}")

    if len(dst_counter) >= int(prefilter_config.get("many_destinations_threshold", 20)):
        score += int(prefilter_config.get("many_destinations_score", 20))
        reasons.append("many_destinations")
    if len(src_counter) >= int(prefilter_config.get("many_sources_threshold", 20)):
        score += int(prefilter_config.get("many_sources_score", 15))
        reasons.append("many_sources")
    _score_port_scan(events, prefilter_config, reasons_score := {"score": 0, "reasons": []})
    score += reasons_score["score"]
    reasons.extend(reasons_score["reasons"])
    if icmp_count >= int(prefilter_config.get("icmp_many_events_threshold", 8)):
        score += int(prefilter_config.get("icmp_many_events_score", 18))
        reasons.append("icmp_many_events")

    deduped_reasons = _dedupe(reasons)
    score = min(score, int(prefilter_config.get("max_score", 100)))
    severity = _severity(score, deduped_reasons, prefilter_config)
    action = "deep_analysis" if severity in {"critical", "high"} or score >= min_risk_score else "skip"
    return PrefilterResult(
        pcap_path=str(path),
        risk_score=score,
        severity=severity,
        recommended_action=action,
        reasons=deduped_reasons,
        event_count=len(events),
        http_event_count=http_count,
        dns_event_count=dns_count,
        tcp_event_count=tcp_count,
        icmp_event_count=icmp_count,
        source_count=len(src_counter),
        destination_count=len(dst_counter),
        top_sources=src_counter.most_common(5),
        top_destinations=dst_counter.most_common(5),
    )


def _score_port_scan(events, config: dict, output: dict) -> None:
    min_ports = int(config.get("port_scan_min_ports", 10))
    score_points = int(config.get("port_scan_score", 30))
    ports_by_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
    for event in events:
        if event.protocol == "TCP" and event.src_ip and event.dst_ip and event.dst_port:
            ports_by_pair[(event.src_ip, event.dst_ip)].add(event.dst_port)
    for (src, dst), ports in ports_by_pair.items():
        if len(ports) >= min_ports:
            output["score"] += score_points
            output["reasons"].append(f"tcp_port_scan:{src}->{dst}:{len(ports)}ports")


def _prefilter_config(config: dict | None = None) -> dict:
    if config is None:
        config = load_config()
    return ((config.get("detection") or {}).get("prefilter") or config.get("prefilter") or {})


def _marker_points(config: dict, category: str, name: str, default: int) -> int:
    marker_weights = config.get("marker_weights") or {}
    return int((marker_weights.get(category) or {}).get(name, default))


def _score_dns_query(query: str, qtype: str | None, config: dict | None = None) -> tuple[int, list[str]]:
    config = config or {}
    if not query:
        return 0, []
    score = 0
    reasons = []
    labels = query.split(".")
    longest = max((len(label) for label in labels), default=0)
    if len(query) >= int(config.get("dns_long_query_length", 90)):
        score += int(config.get("dns_long_query_score", 20))
        reasons.append("dns_long_query")
    if longest >= int(config.get("dns_long_label_length", 40)):
        score += int(config.get("dns_long_label_score", 20))
        reasons.append("dns_long_label")
    if labels and _entropy(labels[0]) >= float(config.get("dns_entropy_threshold", 3.8)) and len(labels[0]) >= int(config.get("dns_entropy_label_length", 24)):
        score += int(config.get("dns_entropy_score", 18))
        reasons.append("dns_high_entropy_subdomain")
    if str(qtype or "").upper() == "TXT":
        score += int(config.get("dns_txt_score", 10))
        reasons.append("dns_txt_query")
    return score, reasons


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _jitter(intervals: list[float], avg: float) -> float:
    if avg <= 0:
        return 1.0
    return sum(abs(item - avg) for item in intervals) / len(intervals) / avg


def _severity(score: int, reasons: list[str], config: dict | None = None) -> str:
    config = config or {}
    severity = config.get("severity") or {}
    if score >= int(severity.get("critical_score", 85)) or any(reason.startswith("http_critical:") for reason in reasons):
        return "critical"
    if score >= int(severity.get("high_score", 60)):
        return "high"
    if score >= int(severity.get("medium_score", 30)):
        return "medium"
    return "low"


def _endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if port is not None else ip


def _dedupe(items: list[str]) -> list[str]:
    seen = set()
    output = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output
