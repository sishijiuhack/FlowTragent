"""Parse supplementary logs into FlowTragent evidence events."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.event.models import HttpEvent, LogEvent, NetworkEvent
from src.parser.pcap_parser import clean_payload


ACCESS_RE = re.compile(
    r'(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3}|-)\s+(?P<size>\d+|-)(?:\s+\"(?P<referrer>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?"
)


def parse_access_log(path: str | Path, event_prefix: str = "access") -> list[HttpEvent]:
    """Parse common/combined web access logs, JSONL, or CSV into HTTP events."""
    rows = _read_structured_or_lines(path)
    events: list[HttpEvent] = []
    for index, row in enumerate(rows, start=1):
        if isinstance(row, str):
            event = _parse_access_line(row, f"{event_prefix}-{index}")
        else:
            row = _normalize_row(row)
            event = _access_row_to_event(row, f"{event_prefix}-{index}")
        if event:
            events.append(event)
    return events


def parse_dns_log(path: str | Path, event_prefix: str = "dnslog") -> list[NetworkEvent]:
    """Parse DNS JSONL/CSV logs into DNS NetworkEvent entries."""
    events: list[NetworkEvent] = []
    for index, row in enumerate(_read_structured_or_lines(path), start=1):
        if isinstance(row, str):
            row = _parse_key_value_line(row)
        row = _normalize_row(row)
        query = _first(row, "query", "qname", "dns_query", "domain", "rrname", "dns.rrname")
        if not query:
            continue
        src_ip = _first(row, "src_ip", "client", "client_ip", "source_ip", "id.orig_h", "src_ip")
        dst_ip = _first(row, "dst_ip", "dest_ip", "server", "resolver", "destination_ip", "id.resp_h") or "dns-resolver"
        qtype = _first(row, "qtype", "type", "dns_qtype", "qtype_name", "dns.type") or "A"
        timestamp = _parse_timestamp(_first(row, "timestamp", "time", "@timestamp", "ts", "event.created"))
        summary = f"DNS query {query} qtype={qtype}"
        events.append(
            NetworkEvent(
                event_id=f"{event_prefix}-{index}",
                timestamp=timestamp,
                src_ip=src_ip,
                src_port=_to_int(_first(row, "src_port", "client_port")),
                dst_ip=dst_ip,
                dst_port=_to_int(_first(row, "dst_port", "server_port")) or 53,
                protocol="DNS",
                payload_clean=summary,
                summary=summary,
                dns_query=str(query).rstrip("."),
                dns_qtype=str(qtype),
            )
        )
    return events


def parse_endpoint_log(path: str | Path, event_prefix: str = "endpoint") -> list[LogEvent]:
    """Parse endpoint/process JSONL or CSV logs into LogEvent entries."""
    events: list[LogEvent] = []
    for index, row in enumerate(_read_structured_or_lines(path), start=1):
        if isinstance(row, str):
            row = _parse_key_value_line(row)
        row = _normalize_row(row)
        command = _first(row, "command_line", "cmdline", "cmd", "process_command_line", "CommandLine", "process.command_line")
        process = _first(row, "process_name", "process", "image", "Image", "exe", "process.name", "process.executable")
        action = _first(row, "action", "event_type", "EventType", "event", "operation", "event.action", "EventID") or "process"
        file_path = _first(row, "file_path", "path", "target_path", "TargetFilename", "file.path")
        host = _first(row, "host", "hostname", "computer", "Computer", "host.name", "agent.hostname")
        src_ip = _first(row, "src_ip", "host_ip", "source_ip", "SourceIp", "source.ip") or host
        dst_ip = _first(row, "dst_ip", "remote_ip", "destination_ip", "DestinationIp", "destination.ip")
        dst_port = _to_int(_first(row, "dst_port", "remote_port", "destination_port", "DestinationPort", "destination.port"))
        timestamp = _parse_timestamp(_first(row, "timestamp", "time", "@timestamp", "UtcTime", "ts", "event.created"))
        payload = clean_payload(" ".join(str(item) for item in [action, process, command, file_path] if item))
        if not payload:
            continue
        events.append(
            LogEvent(
                event_id=f"{event_prefix}-{index}",
                timestamp=timestamp,
                src_ip=str(src_ip) if src_ip else None,
                src_port=None,
                dst_ip=str(dst_ip) if dst_ip else None,
                dst_port=dst_port,
                protocol="ENDPOINT",
                payload_clean=payload,
                summary=payload[:220],
                log_type="endpoint",
                host=str(host) if host else None,
                user=_first(row, "user", "username", "User"),
                process_name=str(process) if process else None,
                command_line=str(command) if command else None,
                file_path=str(file_path) if file_path else None,
                action=str(action) if action else None,
            )
        )
    return events


def parse_log_bundle(
    access_logs: Iterable[str | Path] | None = None,
    dns_logs: Iterable[str | Path] | None = None,
    endpoint_logs: Iterable[str | Path] | None = None,
) -> list[NetworkEvent]:
    events: list[NetworkEvent] = []
    for idx, path in enumerate(access_logs or [], start=1):
        events.extend(parse_access_log(path, event_prefix=f"access{idx}"))
    for idx, path in enumerate(dns_logs or [], start=1):
        events.extend(parse_dns_log(path, event_prefix=f"dnslog{idx}"))
    for idx, path in enumerate(endpoint_logs or [], start=1):
        events.extend(parse_endpoint_log(path, event_prefix=f"endpoint{idx}"))
    return sorted(events, key=lambda event: event.timestamp or 0)


def _read_structured_or_lines(path: str | Path) -> list[dict[str, Any] | str]:
    file_path = Path(path)
    if file_path.suffix.lower() == ".csv":
        with file_path.open(newline="", encoding="utf-8") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    zeek_rows = _read_zeek_tsv(file_path)
    if zeek_rows:
        return zeek_rows
    rows: list[dict[str, Any] | str] = []
    with file_path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                rows.append(line)
            else:
                rows.append(parsed if isinstance(parsed, dict) else line)
    return rows


def _read_zeek_tsv(path: Path) -> list[dict[str, Any]]:
    fields = None
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line or fields is None:
                continue
            values = line.split("\t")
            rows.append(dict(zip(fields, values)))
    return rows


def _parse_access_line(line: str, event_id: str) -> HttpEvent | None:
    match = ACCESS_RE.search(line)
    if not match:
        return None
    request = match.group("request")
    method, uri = _parse_request(request)
    if not method:
        return None
    status = _to_int(match.group("status"))
    size = _to_int(match.group("size"))
    user_agent = match.group("ua")
    payload = clean_payload(f"{request} User-Agent: {user_agent or ''}")
    return HttpEvent(
        event_id=event_id,
        timestamp=_parse_apache_time(match.group("time")),
        src_ip=match.group("src_ip"),
        src_port=None,
        dst_ip=None,
        dst_port=80,
        protocol="HTTP",
        payload_clean=payload,
        summary=payload[:220],
        method=method,
        uri=uri,
        user_agent=user_agent,
        status_code=status,
        response_size=size,
    )


def _access_row_to_event(row: dict[str, Any], event_id: str) -> HttpEvent | None:
    method = _first(row, "method", "http_method", "http.http_method")
    uri = _first(row, "uri", "path", "url", "request_uri", "http.url", "url.path")
    request = _first(row, "request", "request_line")
    if request and (not method or not uri):
        method, uri = _parse_request(str(request))
    if not method or not uri:
        return None
    user_agent = _first(row, "user_agent", "ua", "http_user_agent", "http.http_user_agent", "user_agent.original")
    payload = clean_payload(str(request or f"{method} {uri} HTTP/1.1 User-Agent: {user_agent or ''}"))
    return HttpEvent(
        event_id=event_id,
        timestamp=_parse_timestamp(_first(row, "timestamp", "time", "@timestamp", "ts", "event.created")),
        src_ip=_first(row, "src_ip", "client_ip", "remote_addr", "source.ip", "id.orig_h"),
        src_port=_to_int(_first(row, "src_port", "remote_port", "source.port", "id.orig_p")),
        dst_ip=_first(row, "dst_ip", "server_ip", "host_ip", "destination.ip", "id.resp_h"),
        dst_port=_to_int(_first(row, "dst_port", "server_port", "destination.port", "id.resp_p")) or 80,
        protocol="HTTP",
        payload_clean=payload,
        summary=payload[:220],
        method=str(method).upper(),
        uri=str(uri),
        host=_first(row, "host", "http_host", "http.hostname"),
        user_agent=user_agent,
        status_code=_to_int(_first(row, "status", "status_code", "http.status")),
        response_size=_to_int(_first(row, "bytes", "size", "response_size", "http.length")),
    )


def _parse_request(request: str) -> tuple[str | None, str | None]:
    parts = request.split()
    if len(parts) < 2:
        return None, None
    return parts[0].upper(), parts[1]


def _parse_key_value_line(line: str) -> dict[str, str]:
    result = {}
    for key, value in re.findall(r"([\w.@-]+)=([^\s]+)", line):
        result[key] = value.strip('"')
    if not result:
        result["message"] = line
    return result


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    _flatten_nested(row, normalized)
    event_data = row.get("EventData")
    if isinstance(event_data, dict):
        normalized.update(event_data)
    data = row.get("data")
    if isinstance(data, dict):
        normalized.update(data)
    if row.get("event_type") == "dns" and isinstance(row.get("dns"), dict):
        dns = row["dns"]
        normalized.setdefault("query", dns.get("rrname") or dns.get("query"))
        normalized.setdefault("qtype", dns.get("rrtype") or dns.get("type"))
    if row.get("event_type") == "http" and isinstance(row.get("http"), dict):
        http = row["http"]
        normalized.setdefault("method", http.get("http_method"))
        normalized.setdefault("uri", http.get("url"))
        normalized.setdefault("user_agent", http.get("http_user_agent"))
        normalized.setdefault("status", http.get("status"))
    return normalized


def _flatten_nested(source: dict[str, Any], output: dict[str, Any], prefix: str = "") -> None:
    for key, value in source.items():
        full_key = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            _flatten_nested(value, output, full_key)
        else:
            output.setdefault(full_key, value)


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_timestamp(value: Any) -> float | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    normalized = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).timestamp()
    except ValueError:
        return _parse_apache_time(text)


def _parse_apache_time(value: str | None) -> float | None:
    if not value:
        return None
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return None
