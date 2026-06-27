"""PCAP and log parsing helpers."""

from __future__ import annotations

import csv
import re
from pathlib import Path

from src.event.models import HttpEvent, NetworkEvent


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ")


def clean_payload(payload: str) -> str:
    payload = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", ".", payload)
    payload = payload.replace("\r", " ").replace("\n", " ")
    payload = re.sub(r"\s+", " ", payload)
    return payload.strip()


def pcap_to_csv(pcap_path: str, output_csv: str) -> int:
    """Extract HTTP-like payloads from a PCAP and write NOVA-F-compatible CSV."""
    events = parse_pcap_events(pcap_path)
    rows = [{"id": event.event_id, "payload_clean": event.payload_clean} for event in events]

    output_path = Path(output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "payload_clean"])
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def parse_network_events(pcap_path: str) -> list[NetworkEvent]:
    """Extract HTTP, DNS, and lightweight TCP events from a PCAP."""
    try:
        from scapy.all import DNS, DNSQR, IP, IPv6, Raw, TCP, UDP, rdpcap
    except Exception as exc:
        raise RuntimeError("scapy is required for PCAP parsing. Install with: pip install scapy") from exc

    http_events = parse_pcap_events(pcap_path)
    http_packet_ids = {
        int(event.event_id.split("-", 1)[1])
        for event in http_events
        if event.event_id.startswith("pkt-") and event.event_id.split("-", 1)[1].isdigit()
    }
    events: list[NetworkEvent] = list(http_events)

    packets = rdpcap(pcap_path)
    for index, packet in enumerate(packets, start=1):
        if index in http_packet_ids:
            continue

        src_ip = dst_ip = None
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        if not src_ip and not dst_ip:
            continue

        timestamp = float(getattr(packet, "time", 0.0)) if getattr(packet, "time", None) is not None else None

        if DNS in packet and packet[DNS].qr == 0 and DNSQR in packet:
            query = _decode_dns_name(packet[DNSQR].qname)
            qtype = str(packet[DNSQR].qtype)
            src_port = int(packet[UDP].sport) if UDP in packet else None
            dst_port = int(packet[UDP].dport) if UDP in packet else None
            summary = f"DNS query {query} qtype={qtype}"
            events.append(
                NetworkEvent(
                    event_id=f"pkt-{index}",
                    timestamp=timestamp,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol="DNS",
                    payload_clean=summary,
                    summary=summary,
                    raw_size=len(bytes(packet)),
                    dns_query=query,
                    dns_qtype=qtype,
                )
            )
            continue

        if TCP in packet:
            raw_payload = bytes(packet[Raw].load) if Raw in packet else b""
            if raw_payload.startswith(HTTP_METHODS) or b"HTTP/" in raw_payload[:16]:
                continue
            if not raw_payload and "S" not in str(packet[TCP].flags):
                continue
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            flags = str(packet[TCP].flags)
            payload_preview = clean_payload(raw_payload.decode("utf-8", errors="ignore")) if raw_payload else ""
            summary = f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} flags={flags} size={len(raw_payload)}"
            if payload_preview:
                summary = f"{summary} payload={payload_preview[:120]}"
            events.append(
                NetworkEvent(
                    event_id=f"pkt-{index}",
                    timestamp=timestamp,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol="TCP",
                    payload_clean=payload_preview or summary,
                    summary=summary,
                    raw_size=len(raw_payload),
                    tcp_flags=flags,
                )
            )

    return sorted(events, key=lambda event: event.timestamp or 0)


def parse_pcap_events(pcap_path: str) -> list[HttpEvent]:
    """Extract structured HTTP-like events from a PCAP."""
    try:
        from scapy.all import IP, IPv6, Raw, TCP, rdpcap
    except Exception as exc:
        raise RuntimeError("scapy is required for PCAP parsing. Install with: pip install scapy") from exc

    events: list[HttpEvent] = []
    pending_requests: dict[tuple[str | None, str | None, int | None, int | None], HttpEvent] = {}
    packets = rdpcap(pcap_path)
    for index, packet in enumerate(packets, start=1):
        if Raw not in packet:
            continue
        raw = bytes(packet[Raw].load)
        if not raw.startswith(HTTP_METHODS) and b"HTTP/" not in raw:
            continue

        text = raw.decode("utf-8", errors="ignore")
        cleaned = clean_payload(text)
        if not cleaned:
            continue

        src_ip = dst_ip = None
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        src_port = dst_port = None
        if TCP in packet:
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)

        method, uri, headers, body, status_code, reason = _parse_http_text(text)
        if status_code is not None and method is None:
            request_key = (dst_ip, src_ip, dst_port, src_port)
            request = pending_requests.get(request_key)
            if request is not None:
                request.status_code = status_code
                request.response_reason = reason
                request.response_size = len(raw)
                request.response_summary = cleaned[:220] + ("..." if len(cleaned) > 220 else "")
            continue

        if method is None:
            continue

        events.append(
            HttpEvent(
                event_id=f"pkt-{index}",
                timestamp=float(getattr(packet, "time", 0.0)) if getattr(packet, "time", None) is not None else None,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="HTTP",
                payload_clean=cleaned,
                summary=cleaned[:220] + ("..." if len(cleaned) > 220 else ""),
                method=method,
                uri=uri,
                host=headers.get("host"),
                user_agent=headers.get("user-agent"),
                headers=headers,
                body=body,
                status_code=status_code,
                raw_size=len(raw),
            )
        )
        pending_requests[(src_ip, dst_ip, src_port, dst_port)] = events[-1]
    return events


def _decode_dns_name(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").rstrip(".")
    return str(value).rstrip(".")


def _parse_http_text(text: str) -> tuple[str | None, str | None, dict[str, str], str | None, int | None, str | None]:
    head, _, body = text.partition("\r\n\r\n")
    if not body:
        head, _, body = text.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    first = lines[0].strip() if lines else ""
    method = uri = None
    status_code = None
    reason = None
    if first.startswith("HTTP/"):
        parts = first.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
            reason = " ".join(parts[2:]) if len(parts) > 2 else None
    else:
        parts = first.split()
        if len(parts) >= 2:
            method = parts[0].upper()
            uri = parts[1]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return method, uri, headers, body or None, status_code, reason
