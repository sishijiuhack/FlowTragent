"""PCAP and log parsing helpers."""

from __future__ import annotations

import csv
import re
from pathlib import Path


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ")


def clean_payload(payload: str) -> str:
    payload = payload.replace("\r", " ").replace("\n", " ")
    payload = re.sub(r"\s+", " ", payload)
    return payload.strip()


def pcap_to_csv(pcap_path: str, output_csv: str) -> int:
    """Extract HTTP-like payloads from a PCAP and write NOVA-F-compatible CSV."""
    try:
        from scapy.all import Raw, rdpcap
    except Exception as exc:
        raise RuntimeError("scapy is required for PCAP parsing. Install with: pip install scapy") from exc

    packets = rdpcap(pcap_path)
    rows = []
    for index, packet in enumerate(packets, start=1):
        if Raw not in packet:
            continue
        raw = bytes(packet[Raw].load)
        if not raw.startswith(HTTP_METHODS) and b"HTTP/" not in raw:
            continue
        text = raw.decode("utf-8", errors="ignore")
        cleaned = clean_payload(text)
        if cleaned:
            rows.append({"id": f"pkt-{index}", "payload_clean": cleaned})

    output_path = Path(output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "payload_clean"])
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)

