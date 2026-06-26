"""Impact assessment based on correlated evidence."""

from __future__ import annotations

from src.event.models import HttpEvent


POST_EXPLOIT_STAGES = {"Command Execution", "Payload Delivery", "WebShell / Backdoor"}


def assess_impact(
    events: list[HttpEvent],
    attack_chain: list[dict],
    c2_findings: list[dict],
    candidates: list[dict],
) -> dict:
    stages = {str(stage.get("stage")) for stage in attack_chain}
    top_cves = [item for item in candidates if item.get("rule_confirmed") or float(item.get("final_score", item.get("score", 0))) >= 0.5]
    post_exploit = [stage for stage in attack_chain if stage.get("stage") in POST_EXPLOIT_STAGES]

    evidence_ids = sorted(
        {
            evidence_id
            for stage in attack_chain
            for evidence_id in stage.get("evidence_ids", [])
            if evidence_id
        }
    )

    if c2_findings:
        verdict = "Possible successful exploitation with C2 indicators"
        confidence = "medium"
        reasoning = "Suspicious C2/beacon communication was detected after exploit-related traffic."
    elif post_exploit:
        verdict = "Possible successful exploitation"
        confidence = "medium"
        reasoning = "Post-exploitation indicators such as command execution, payload delivery, or webshell behavior were observed."
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
    if not any(event.status_code is not None for event in events):
        missing.append("No HTTP response status codes were available for success/failure validation.")

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": reasoning,
        "evidence_ids": evidence_ids,
        "related_cves": [item.get("cve") for item in top_cves if item.get("cve")],
        "missing_evidence": missing,
    }

