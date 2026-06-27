"""Lightweight prefilter for live PCAP segments."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

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
    source_count: int = 0
    destination_count: int = 0
    top_sources: list[tuple[str, int]] = field(default_factory=list)
    top_destinations: list[tuple[str, int]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def prefilter_pcap(pcap_path: str | Path, min_risk_score: int = 50) -> PrefilterResult:
    """Score a PCAP segment without running retrieval, Agent, RAG, or LLM."""
    path = Path(pcap_path)
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
                    score += points
                    reasons.append(f"http_critical:{name}")
            for name, (marker, points) in SUSPICIOUS_MARKERS.items():
                if marker in payload:
                    score += points
                    reasons.append(f"http_marker:{name}")
        elif protocol == "DNS":
            dns_count += 1
            query = (event.dns_query or "").lower().strip(".")
            dns_score, dns_reasons = _score_dns_query(query, event.dns_qtype)
            score += dns_score
            reasons.extend(dns_reasons)
        elif protocol == "TCP":
            tcp_count += 1
            if event.dst_port and event.dst_port not in COMMON_SERVICE_PORTS and event.dst_port >= 1024:
                score += 8
                reasons.append(f"tcp_external_service_port:{event.dst_port}")

    for (src, dst, port, protocol), timestamps in flow_times.items():
        if len(timestamps) < 3:
            continue
        timestamps = sorted(timestamps)
        intervals = [later - earlier for earlier, later in zip(timestamps, timestamps[1:]) if later >= earlier]
        if not intervals:
            continue
        avg = sum(intervals) / len(intervals)
        jitter = _jitter(intervals, avg)
        if 2 <= avg <= 300 and jitter <= 0.35:
            points = 25 if protocol in {"HTTP", "DNS"} else 18
            score += points
            reasons.append(f"periodic_{protocol.lower()}:{src}->{dst}:{port or ''}")

    if len(dst_counter) >= 20:
        score += 20
        reasons.append("many_destinations")
    if len(src_counter) >= 20:
        score += 15
        reasons.append("many_sources")

    deduped_reasons = _dedupe(reasons)
    score = min(score, 100)
    severity = _severity(score, deduped_reasons)
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
        source_count=len(src_counter),
        destination_count=len(dst_counter),
        top_sources=src_counter.most_common(5),
        top_destinations=dst_counter.most_common(5),
    )


def _score_dns_query(query: str, qtype: str | None) -> tuple[int, list[str]]:
    if not query:
        return 0, []
    score = 0
    reasons = []
    labels = query.split(".")
    longest = max((len(label) for label in labels), default=0)
    if len(query) >= 90:
        score += 20
        reasons.append("dns_long_query")
    if longest >= 40:
        score += 20
        reasons.append("dns_long_label")
    if labels and _entropy(labels[0]) >= 3.8 and len(labels[0]) >= 24:
        score += 18
        reasons.append("dns_high_entropy_subdomain")
    if str(qtype or "").upper() == "TXT":
        score += 10
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


def _severity(score: int, reasons: list[str]) -> str:
    if score >= 85 or any(reason.startswith("http_critical:") for reason in reasons):
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
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
