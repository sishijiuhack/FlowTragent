"""Rule-based attack chain stage detection."""

from __future__ import annotations

from collections import defaultdict

from src.event.models import AttackStage, HttpEvent


SCAN_PATHS = ("/.env", "/wp-login", "/phpinfo", "/cgi-bin", "/actuator", "/server-status")
SCANNER_UA = ("curl", "python-requests", "go-http-client", "nuclei", "masscan", "zgrab")
RCE_MARKERS = ("cmd=", "exec=", "bash -c", "powershell", "cmd.exe", "whoami", "uname", "id%20", "whoami%20", "sh%20", "bash%20")
DOWNLOAD_MARKERS = ("wget ", "wget%20", "curl ", "curl%20", "certutil", ".sh", ".exe", ".dll", ".jsp", ".php", ".aspx", "-o%20", "-o ")
WEBSHELL_MARKERS = ("multipart/form-data", "cmd=", "pass=", "shell=", "exec=", "action=")
EXPLOIT_MARKERS = ("${jndi:", "ldap://", "rmi://", "../", "%2e%2e", "/etc/passwd", "union select", "sleep(")


def detect_attack_stages(events: list[HttpEvent], candidates: list[dict]) -> list[dict]:
    stages: list[AttackStage] = []
    stages.extend(_detect_recon(events))
    stages.extend(_detect_exploitation(events, candidates))
    stages.extend(_detect_command_execution(events))
    stages.extend(_detect_payload_delivery(events))
    stages.extend(_detect_webshell(events))
    return [stage.to_dict() for stage in stages]


def _detect_recon(events: list[HttpEvent]) -> list[AttackStage]:
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
        if len(uris) >= 8 or evidence.get(source):
            ids = evidence.get(source) or [event.event_id for event in events if event.src_ip == source][:10]
            stages.append(
                _stage(
                    "Reconnaissance",
                    "HTTP probing / scanning",
                    "medium" if len(uris) >= 8 else "low",
                    [event for event in events if event.event_id in ids],
                    f"Source visited {len(uris)} distinct URI(s) or used scanner-like indicators.",
                )
            )
    return stages


def _detect_exploitation(events: list[HttpEvent], candidates: list[dict]) -> list[AttackStage]:
    evidence_ids = []
    for event in events:
        text = event.payload_clean.lower()
        if any(marker in text for marker in EXPLOIT_MARKERS):
            evidence_ids.append(event.event_id)
    high_cves = [item for item in candidates if float(item.get("score", 0.0)) >= 0.5]
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
    return [_stage("Exploitation", "Known vulnerability exploitation attempt", "high" if cves else "medium", related_events, reason)]


def _detect_command_execution(events: list[HttpEvent]) -> list[AttackStage]:
    matched = [event for event in events if any(marker in event.payload_clean.lower() for marker in RCE_MARKERS)]
    if not matched:
        return []
    confidence = "high" if any(event.status_code and 200 <= event.status_code < 400 for event in matched) else "medium"
    return [_stage("Command Execution", "Command execution indicators in HTTP payload", confidence, matched, "Command execution keywords were observed.")]


def _detect_payload_delivery(events: list[HttpEvent]) -> list[AttackStage]:
    matched = [event for event in events if any(marker in event.payload_clean.lower() for marker in DOWNLOAD_MARKERS)]
    if not matched:
        return []
    confidence = "high" if any(event.status_code and 200 <= event.status_code < 400 for event in matched) else "medium"
    return [_stage("Payload Delivery", "Payload download or script delivery", confidence, matched, "Download or executable/script indicators were observed.")]


def _detect_webshell(events: list[HttpEvent]) -> list[AttackStage]:
    matched = [event for event in events if any(marker in event.payload_clean.lower() for marker in WEBSHELL_MARKERS)]
    if not matched:
        return []
    repeated_targets = len({event.uri for event in matched if event.uri}) < len(matched)
    confidence = "medium" if repeated_targets or any(event.status_code and 200 <= event.status_code < 400 for event in matched) else "low"
    return [_stage("WebShell / Backdoor", "Possible webshell interaction", confidence, matched, "Webshell-like parameter or upload indicators were observed.")]


def _stage(stage: str, technique: str, confidence: str, events: list[HttpEvent], reasoning: str) -> AttackStage:
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
