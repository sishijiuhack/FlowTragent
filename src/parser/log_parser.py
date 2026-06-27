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
        query = _first(row, "query", "qname", "dns_query", "domain")
        if not query:
            continue
        src_ip = _first(row, "src_ip", "client", "client_ip", "source_ip")
        dst_ip = _first(row, "dst_ip", "server", "resolver", "destination_ip") or "dns-resolver"
        qtype = _first(row, "qtype", "type", "dns_qtype") or "A"
        timestamp = _parse_timestamp(_first(row, "timestamp", "time", "@timestamp", "ts"))
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
        command = _first(row, "command_line", "cmdline", "cmd", "process_command_line", "CommandLine")
        process = _first(row, "process_name", "process", "image", "Image", "exe")
        action = _first(row, "action", "event_type", "EventType", "event", "operation") or "process"
        file_path = _first(row, "file_path", "path", "target_path", "TargetFilename")
        host = _first(row, "host", "hostname", "computer", "Computer")
        src_ip = _first(row, "src_ip", "host_ip", "source_ip") or host
        dst_ip = _first(row, "dst_ip", "remote_ip", "destination_ip")
        dst_port = _to_int(_first(row, "dst_port", "remote_port", "destination_port"))
        timestamp = _parse_timestamp(_first(row, "timestamp", "time", "@timestamp", "UtcTime", "ts"))
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
    method = _first(row, "method", "http_method")
    uri = _first(row, "uri", "path", "url", "request_uri")
    request = _first(row, "request", "request_line")
    if request and (not method or not uri):
        method, uri = _parse_request(str(request))
    if not method or not uri:
        return None
    user_agent = _first(row, "user_agent", "ua", "http_user_agent")
    payload = clean_payload(str(request or f"{method} {uri} HTTP/1.1 User-Agent: {user_agent or ''}"))
    return HttpEvent(
        event_id=event_id,
        timestamp=_parse_timestamp(_first(row, "timestamp", "time", "@timestamp", "ts")),
        src_ip=_first(row, "src_ip", "client_ip", "remote_addr"),
        src_port=_to_int(_first(row, "src_port", "remote_port")),
        dst_ip=_first(row, "dst_ip", "server_ip", "host_ip"),
        dst_port=_to_int(_first(row, "dst_port", "server_port")) or 80,
        protocol="HTTP",
        payload_clean=payload,
        summary=payload[:220],
        method=str(method).upper(),
        uri=str(uri),
        host=_first(row, "host", "http_host"),
        user_agent=user_agent,
        status_code=_to_int(_first(row, "status", "status_code")),
        response_size=_to_int(_first(row, "bytes", "size", "response_size")),
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
