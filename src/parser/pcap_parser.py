"""PCAP and log parsing helpers."""

from __future__ import annotations

import csv
import re
from pathlib import Path

from src.event.models import HttpEvent


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ")


def clean_payload(payload: str) -> str:
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


def parse_pcap_events(pcap_path: str) -> list[HttpEvent]:
    """Extract structured HTTP-like events from a PCAP."""
    try:
        from scapy.all import IP, IPv6, Raw, TCP, rdpcap
    except Exception as exc:
        raise RuntimeError("scapy is required for PCAP parsing. Install with: pip install scapy") from exc

    events: list[HttpEvent] = []
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

        method, uri, headers, body, status_code = _parse_http_text(text)
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
            )
        )
    return events


def _parse_http_text(text: str) -> tuple[str | None, str | None, dict[str, str], str | None, int | None]:
    head, _, body = text.partition("\r\n\r\n")
    if not body:
        head, _, body = text.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    first = lines[0].strip() if lines else ""
    method = uri = None
    status_code = None
    if first.startswith("HTTP/"):
        parts = first.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
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
    return method, uri, headers, body or None, status_code
