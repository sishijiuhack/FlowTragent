from __future__ import annotations

from pathlib import Path

from src.event.models import NetworkEvent
from src.live import prefilter


def test_prefilter_scores_port_scan_and_icmp_anomaly(monkeypatch, tmp_path: Path) -> None:
    events = [
        *[
            NetworkEvent(
                event_id=f"scan-{idx}",
                timestamp=float(idx),
                src_ip="10.0.0.50",
                src_port=45000 + idx,
                dst_ip="10.0.0.10",
                dst_port=1000 + idx,
                protocol="TCP",
                payload_clean="",
                summary="SYN scan",
                raw_size=0,
                tcp_flags="S",
            )
            for idx in range(12)
        ],
        *[
            NetworkEvent(
                event_id=f"icmp-{idx}",
                timestamp=float(idx * 10),
                src_ip="10.0.0.60",
                src_port=None,
                dst_ip="198.51.100.60",
                dst_port=None,
                protocol="ICMP",
                payload_clean="A" * 128,
                summary="large icmp",
                raw_size=128,
            )
            for idx in range(8)
        ],
    ]
    monkeypatch.setattr(prefilter, "parse_network_events", lambda path: events)

    result = prefilter.prefilter_pcap(tmp_path / "segment.pcap", min_risk_score=50)

    assert result.recommended_action == "deep_analysis"
    assert result.icmp_event_count == 8
    assert any(reason.startswith("tcp_port_scan:") for reason in result.reasons)
    assert "icmp_large_payload" in result.reasons
    assert "icmp_many_events" in result.reasons
