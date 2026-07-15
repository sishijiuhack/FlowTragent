"""Impact assessment based on correlated evidence."""

from __future__ import annotations

from src.event.models import NetworkEvent


POST_EXPLOIT_STAGES = {"Command Execution", "Payload Delivery", "WebShell / Backdoor"}


def assess_impact(
    events: list[NetworkEvent],
    attack_chain: list[dict],
    c2_findings: list[dict],
    candidates: list[dict],
) -> dict:
    stages = {str(stage.get("stage")) for stage in attack_chain}
    top_cves = [item for item in candidates if item.get("rule_confirmed") or float(item.get("final_score", item.get("score", 0))) >= 0.5]
    post_exploit = [stage for stage in attack_chain if stage.get("stage") in POST_EXPLOIT_STAGES]
    response_codes = [getattr(event, "status_code") for event in events if getattr(event, "status_code", None) is not None]
    successful_http = [code for code in response_codes if 200 <= code < 400]
    rejected_http = [code for code in response_codes if 400 <= code < 500]

    evidence_ids = sorted(
        {
            evidence_id
            for stage in attack_chain
            for evidence_id in stage.get("evidence_ids", [])
            if evidence_id
        }
        | {
            evidence_id
            for finding in c2_findings
            for evidence_id in finding.get("evidence_ids", [])
            if evidence_id
        }
    )

    high_conf_c2 = [finding for finding in c2_findings if finding.get("confidence") == "high"]
    high_conf_post_exploit = [stage for stage in post_exploit if stage.get("confidence") == "high"]
    endpoint_post_exploit = [stage for stage in post_exploit if _stage_has_endpoint_evidence(stage, events)]
    only_rejected_http = bool(rejected_http) and not successful_http

    if high_conf_c2 and post_exploit:
        verdict = "Likely successful exploitation with C2 indicators"
        confidence = "high"
        reasoning = "Post-exploitation behavior and high-confidence C2/beacon communication were both detected."
    elif c2_findings and ("Exploitation" in stages or top_cves):
        verdict = "Possible successful exploitation with C2 indicators"
        confidence = "medium"
        reasoning = "Suspicious C2/beacon communication was detected with exploit-related traffic or CVE evidence."
    elif c2_findings:
        verdict = "Possible compromise with C2 indicators"
        confidence = "medium" if high_conf_c2 else "low"
        reasoning = "Suspicious C2/beacon communication was detected, but the provided traffic does not show the initial exploitation path."
    elif (high_conf_post_exploit or endpoint_post_exploit) and not only_rejected_http:
        verdict = "Likely successful exploitation"
        confidence = "high"
        reasoning = "High-confidence post-exploitation indicators such as command execution or payload delivery were observed."
    elif post_exploit and successful_http:
        verdict = "Possible successful exploitation"
        confidence = "medium"
        reasoning = "Post-exploitation-style indicators and a non-error HTTP response were observed, but host confirmation is still required."
    elif post_exploit and only_rejected_http:
        verdict = "Possible exploitation attempt"
        confidence = "low"
        reasoning = "Command execution or payload delivery parameters were observed, but all related HTTP responses were 4xx; successful exploitation is not supported by this network evidence."
    elif "Exploitation" in stages and top_cves and successful_http:
        verdict = "Likely exploitation attempt with successful HTTP response"
        confidence = "medium"
        reasoning = "Exploit payload indicators, CVE evidence, and a 2xx/3xx HTTP response were observed, but no post-exploitation or C2 evidence was found."
    elif "Exploitation" in stages and top_cves:
        verdict = "Likely exploitation attempt"
        confidence = "medium"
        reasoning = "Exploit payload indicators and CVE evidence were observed, but no post-exploitation or C2 evidence was found."
    elif "Exploitation" in stages:
        verdict = "Possible exploitation attempt"
        confidence = "low"
        reasoning = "Exploit-like payload markers were observed, but CVE confidence is limited."
    elif "Reconnaissance" in stages:
        verdict = "Reconnaissance or probing"
        confidence = "low"
        reasoning = "Scanning or probing behavior was observed without exploitation evidence."
    else:
        verdict = "Insufficient evidence"
        confidence = "low"
        reasoning = "No clear exploitation, post-exploitation, or C2 indicators were observed."

    missing = []
    if not post_exploit:
        missing.append("No command execution, payload delivery, or webshell evidence observed in the provided traffic.")
    if not c2_findings:
        missing.append("No C2/beacon pattern detected in the provided traffic.")
    if not response_codes:
        missing.append("No HTTP response status codes were available for success/failure validation.")
    elif rejected_http and not successful_http:
        missing.append("Only 4xx HTTP responses were observed for exploit-like requests; exploitation success is less likely from network evidence alone.")

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": reasoning,
        "evidence_ids": evidence_ids,
        "related_cves": _dedupe([item.get("cve") for item in top_cves if item.get("cve")]),
        "http_status_codes": response_codes,
        "missing_evidence": missing,
    }


def _stage_has_endpoint_evidence(stage: dict, events: list[NetworkEvent]) -> bool:
    event_ids = set(stage.get("evidence_ids", []) or [])
    return any(getattr(event, "protocol", None) == "ENDPOINT" and event.event_id in event_ids for event in events)


def _dedupe(items: list[str]) -> list[str]:
    output = []
    seen = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output
