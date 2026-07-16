from __future__ import annotations

from pathlib import Path

import pytest

from src.parser.pcap_parser import parse_network_events


def test_parse_network_events_extracts_icmp(tmp_path: Path) -> None:
    scapy = pytest.importorskip("scapy.all")
    pcap = tmp_path / "icmp.pcap"
    packet = scapy.IP(src="10.0.0.60", dst="198.51.100.60") / scapy.ICMP(type=8, code=0) / (b"A" * 128)
    scapy.wrpcap(str(pcap), [packet])

    events = parse_network_events(str(pcap))

    assert len(events) == 1
    assert events[0].protocol == "ICMP"
    assert events[0].raw_size == 128
    assert "type=8" in events[0].summary
