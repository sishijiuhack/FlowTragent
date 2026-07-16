"""Rule-based attack chain stage detection."""

from __future__ import annotations

from collections import defaultdict

from src.event.models import AttackStage, HttpEvent, NetworkEvent


SCAN_PATHS = ("/.env", "/wp-login", "/phpinfo", "/cgi-bin", "/actuator", "/server-status")
SCANNER_UA = ("curl", "python-requests", "go-http-client", "nuclei", "masscan", "zgrab")
RCE_MARKERS = (
    "cmd=",
    "exec=",
    "command=",
    ";id",
    "; id",
    "|id",
    "`id`",
    "$(",
    "&&",
    "bash -c",
    "powershell",
    "cmd.exe",
    "whoami",
    "uname",
    "id%20",
    "whoami%20",
    "sh%20",
    "bash%20",
)
DOWNLOAD_MARKERS = ("wget ", "wget%20", "curl ", "curl%20", "certutil", ".sh", ".exe", ".dll", ".jsp", ".php", ".aspx", "-o%20", "-o ")
WEBSHELL_MARKERS = ("multipart/form-data", "cmd=", "pass=", "shell=", "exec=", "action=")
FILE_DROP_ACTIONS = ("file_create", "file_write", "created", "writefile", "rename")
WEBSHELL_PATH_MARKERS = ("/www/", "/html/", "/htdocs/", "/webapps/", "\\inetpub\\", "\\wwwroot\\")
WEBSHELL_EXTENSIONS = (".jsp", ".php", ".aspx", ".ashx", ".war")
APP_CONFIRMATION_MARKERS = ("exception", "stack trace", "jndi lookup", "scriptengine", "ognl", "template error", "deserialization")
EXPLOIT_MARKERS = (
    "${jndi:",
    "%24%7bjndi",
    "jndi%3a",
    "ldap://",
    "ldap%3a%2f%2f",
    "rmi://",
    "rmi%3a%2f%2f",
    "../",
    "%2e%2e",
    "/etc/passwd",
    "union select",
    "sleep(",
    "url=http://",
    "url=https://",
    "redirect=http",
    "callback=http",
    "169.254.169.254",
    "metadata.google.internal",
    "<!entity",
    "<!doctype",
    "system \"file://",
    "file:///etc/passwd",
    "ysoserial",
    "ac ed 00 05",
    "ro0ab",
    "{{",
    "{%",
    "<%=",
    "${",
    ";id",
    "; id",
    "|id",
    "`id`",
    "$(",
    "&&",
)


def detect_attack_stages(events: list[NetworkEvent], candidates: list[dict], config: dict | None = None) -> list[dict]:
    config = config or {}
    stages: list[AttackStage] = []
    http_events = [event for event in events if isinstance(event, HttpEvent)]
    stages.extend(_detect_recon(http_events, config))
    stages.extend(_detect_exploitation(events, candidates, config))
    stages.extend(_detect_command_execution(events))
    stages.extend(_detect_payload_delivery(events))
    stages.extend(_detect_webshell(events))
    return [stage.to_dict() for stage in stages]


def _detect_recon(events: list[HttpEvent], config: dict) -> list[AttackStage]:
    threshold = int(config.get("recon_distinct_uri_threshold", 8))
    by_source: dict[str, set[str]] = defaultdict(set)
    evidence: dict[str, list[str]] = defaultdict(list)
    for event in events:
        source = event.src_ip or "unknown"
        uri = event.uri or ""
        ua = (event.user_agent or "").lower()
        if uri:
            by_source[source].add(uri)
        if any(path in uri.lower() for path in SCAN_PATHS) or any(marker in ua for marker in SCANNER_UA):
            evidence[source].append(event.event_id)

    stages = []
    for source, uris in by_source.items():
        if len(uris) >= threshold or evidence.get(source):
            ids = evidence.get(source) or [event.event_id for event in events if event.src_ip == source][:10]
            stages.append(
                _stage(
                    "Reconnaissance",
                    "HTTP probing / scanning",
                    "medium" if len(uris) >= threshold else "low",
                    [event for event in events if event.event_id in ids],
                    f"Source visited {len(uris)} distinct URI(s) or used scanner-like indicators.",
                )
            )
    return stages


def _detect_exploitation(events: list[NetworkEvent], candidates: list[dict], config: dict) -> list[AttackStage]:
    evidence_ids = []
    marker_evidence_ids = []
    for event in events:
        text = event.payload_clean.lower()
        if any(marker in text for marker in EXPLOIT_MARKERS):
            evidence_ids.append(event.event_id)
            marker_evidence_ids.append(event.event_id)
    high_cves = [item for item in candidates if _is_strong_cve_candidate(item, config)]
    if high_cves:
        evidence_ids.extend(str(item.get("event_id", "")) for item in high_cves if item.get("event_id"))
    evidence_ids = sorted({item for item in evidence_ids if item})
    if not evidence_ids and not high_cves:
        return []
    related_events = [event for event in events if event.event_id in evidence_ids] or events[:1]
    cves = sorted({str(item.get("cve")) for item in high_cves if item.get("cve")})
    reason = "Exploit-like payload markers observed"
    if cves:
        reason += f"; NOVA-F candidates: {', '.join(cves[:5])}"
    confidence = "high" if cves and marker_evidence_ids else "medium" if marker_evidence_ids or cves else "low"
    return [_stage("Exploitation", "Known vulnerability exploitation attempt", confidence, related_events, reason)]


def _is_strong_cve_candidate(item: dict, config: dict | None = None) -> bool:
    """Treat retrieval-only hits as weak unless they are clearly supported."""
    config = config or {}
    threshold = float(config.get("strong_cve_score_threshold", 0.75))
    score = float(item.get("final_score", item.get("score", 0.0)) or 0.0)
    return bool(item.get("rule_confirmed")) or bool(item.get("signals")) or score >= threshold


def _detect_command_execution(events: list[NetworkEvent]) -> list[AttackStage]:
    matched = [event for event in events if any(marker in event.payload_clean.lower() for marker in RCE_MARKERS)]
    if not matched:
        return []
    has_endpoint = any(event.protocol == "ENDPOINT" for event in matched)
    confidence = "high" if has_endpoint or any(getattr(event, "status_code", None) and 200 <= getattr(event, "status_code") < 400 for event in matched) else "medium"
    reason = "Command execution keywords were observed."
    if has_endpoint:
        reason += " Endpoint/process telemetry confirms command-line activity."
    return [_stage("Command Execution", "Command execution indicators", confidence, matched, reason)]


def _detect_payload_delivery(events: list[NetworkEvent]) -> list[AttackStage]:
    matched = [
        event
        for event in events
        if any(marker in event.payload_clean.lower() for marker in DOWNLOAD_MARKERS) or _is_endpoint_file_drop(event)
    ]
    if not matched:
        return []
    has_endpoint = any(event.protocol == "ENDPOINT" for event in matched)
    confidence = "high" if has_endpoint or any(getattr(event, "status_code", None) and 200 <= getattr(event, "status_code") < 400 for event in matched) else "medium"
    reason = "Download or executable/script indicators were observed."
    if has_endpoint:
        reason += " Endpoint/process telemetry confirms payload retrieval or file-write activity."
    return [_stage("Payload Delivery", "Payload download or script delivery", confidence, matched, reason)]


def _detect_webshell(events: list[NetworkEvent]) -> list[AttackStage]:
    matched = [
        event
        for event in events
        if any(marker in event.payload_clean.lower() for marker in WEBSHELL_MARKERS) or _is_webshell_artifact(event)
    ]
    if not matched:
        return []
    repeated_targets = len({getattr(event, "uri", None) for event in matched if getattr(event, "uri", None)}) < len(matched)
    has_endpoint = any(event.protocol == "ENDPOINT" for event in matched)
    confidence = "medium" if repeated_targets or has_endpoint or any(getattr(event, "status_code", None) and 200 <= getattr(event, "status_code") < 400 for event in matched) else "low"
    reason = "Webshell-like parameter, upload, or file artifact indicators were observed."
    if any(event.protocol == "ENDPOINT" for event in matched):
        reason += " Endpoint telemetry confirms a web-accessible script artifact."
    return [_stage("WebShell / Backdoor", "Possible webshell interaction", confidence, matched, reason)]


def _is_endpoint_file_drop(event: NetworkEvent) -> bool:
    if event.protocol != "ENDPOINT":
        return False
    text = event.payload_clean.lower()
    action = str(getattr(event, "action", "") or "").lower()
    file_path = str(getattr(event, "file_path", "") or "").lower()
    return bool(file_path and (any(marker in action for marker in FILE_DROP_ACTIONS) or any(marker in text for marker in FILE_DROP_ACTIONS)))


def _is_webshell_artifact(event: NetworkEvent) -> bool:
    text = event.payload_clean.lower()
    file_path = str(getattr(event, "file_path", "") or "").lower()
    if event.protocol == "ENDPOINT" and file_path:
        return any(root in file_path for root in WEBSHELL_PATH_MARKERS) and any(file_path.endswith(ext) for ext in WEBSHELL_EXTENSIONS)
    if event.protocol == "APPLICATION":
        return any(marker in text for marker in APP_CONFIRMATION_MARKERS) and any(marker in text for marker in WEBSHELL_MARKERS + EXPLOIT_MARKERS)
    return False


def _stage(stage: str, technique: str, confidence: str, events: list[NetworkEvent], reasoning: str) -> AttackStage:
    timestamps = [event.timestamp for event in events if event.timestamp is not None]
    return AttackStage(
        stage=stage,
        technique=technique,
        confidence=confidence,
        start_time=min(timestamps) if timestamps else None,
        end_time=max(timestamps) if timestamps else None,
        source_ip=events[0].src_ip if events else None,
        target_ip=events[0].dst_ip if events else None,
        evidence_ids=[event.event_id for event in events],
        reasoning=reasoning,
    )
