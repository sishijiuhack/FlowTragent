"""Map FlowTragent findings to MITRE ATT&CK techniques."""

from __future__ import annotations

from typing import Any


STAGE_ATTACK_MAP = {
    "Reconnaissance": ("T1595", "Active Scanning"),
    "Exploitation": ("T1190", "Exploit Public-Facing Application"),
    "Command Execution": ("T1059", "Command and Scripting Interpreter"),
    "Payload Delivery": ("T1105", "Ingress Tool Transfer"),
    "WebShell / Backdoor": ("T1505.003", "Web Shell"),
}

C2_ATTACK_MAP = {
    "HTTP Beacon": ("T1071.001", "Web Protocols"),
    "DNS C2 / Tunneling": ("T1071.004", "DNS"),
    "TCP Beacon": ("T1095", "Non-Application Layer Protocol"),
    "Endpoint External Connection": ("T1105", "Ingress Tool Transfer"),
}


def map_attack_techniques(attack_chain: list[dict[str, Any]], c2_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mapped = []
    for stage in attack_chain:
        item = STAGE_ATTACK_MAP.get(str(stage.get("stage")))
        if not item:
            continue
        technique_id, technique_name = item
        mapped.append(
            {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic": _tactic_for_stage(str(stage.get("stage"))),
                "source": "attack_chain",
                "confidence": stage.get("confidence", "medium"),
                "evidence_ids": stage.get("evidence_ids", []),
                "reason": stage.get("reasoning", ""),
            }
        )
    for finding in c2_findings:
        item = C2_ATTACK_MAP.get(str(finding.get("c2_type")))
        if not item:
            continue
        technique_id, technique_name = item
        mapped.append(
            {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic": "Command and Control",
                "source": "c2_findings",
                "confidence": finding.get("confidence", "medium"),
                "evidence_ids": finding.get("evidence_ids", []),
                "reason": ", ".join(finding.get("indicators", []) or []),
            }
        )
    return _dedupe(mapped)


def _tactic_for_stage(stage: str) -> str:
    if stage == "Reconnaissance":
        return "Reconnaissance"
    if stage == "Exploitation":
        return "Initial Access"
    if stage in {"Command Execution", "Payload Delivery"}:
        return "Execution"
    if stage == "WebShell / Backdoor":
        return "Persistence"
    return "Unknown"


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in items:
        key = (item.get("technique_id"), tuple(item.get("evidence_ids", [])), item.get("source"))
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output
