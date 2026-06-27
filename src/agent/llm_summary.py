"""Structured LLM summary helpers with evidence-id validation."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List


LLM_SUMMARY_SCHEMA_VERSION = "llm-summary-v1"
RETRYABLE_LLM_STATUSES = {"empty_response", "invalid_json", "empty_structured_summary"}


def build_structured_llm_prompt(analysis: Dict[str, Any]) -> str:
    """Build a constrained prompt from deterministic evidence."""
    agent_findings = analysis.get("agent_findings") or {}
    evidence_pack = agent_findings.get("evidence_pack") or []
    evidence_lines = []
    for item in evidence_pack[:30]:
        evidence_lines.append(
            "- {id}: type={type} source={source} target={target} related={related} summary={summary}".format(
                id=item.get("evidence_id"),
                type=item.get("evidence_type"),
                source=item.get("source") or "",
                target=item.get("target") or "",
                related=", ".join(item.get("related", [])),
                summary=item.get("summary") or "",
            )
        )

    deterministic = {
        "impact_assessment": analysis.get("impact_assessment") or {},
        "top_cves": (analysis.get("top_cves") or [])[:5],
        "agent_findings": {
            "schema_version": agent_findings.get("schema_version"),
            "mode": agent_findings.get("mode"),
            "executive_summary": agent_findings.get("executive_summary"),
            "key_findings": agent_findings.get("key_findings", []),
            "limitations": agent_findings.get("limitations", []),
            "next_actions": agent_findings.get("next_actions", []),
        },
    }

    return (
        "You are a security incident response summarizer. Use only the deterministic evidence below. "
        "Do not change or override the deterministic impact verdict. Return JSON only, with this schema:\n"
        "{\n"
        f'  "schema_version": "{LLM_SUMMARY_SCHEMA_VERSION}",\n'
        '  "summary": "short incident summary",\n'
        '  "supported_claims": [{"claim": "claim text", "evidence_ids": ["pkt-1"]}],\n'
        '  "unsupported_claims": ["claim that lacks evidence"],\n'
        '  "recommended_actions": ["action"]\n'
        "}\n\n"
        "Every supported_claims item must include evidence_ids from the allowed list. "
        "If a claim has no matching evidence_id, put it in unsupported_claims. "
        "Return at least one supported_claim when packet evidence exists. "
        "unsupported_claims must be an array of plain strings, not objects.\n\n"
        f"Deterministic analysis JSON:\n{json.dumps(deterministic, ensure_ascii=False, indent=2)}\n\n"
        "Allowed evidence:\n"
        + ("\n".join(evidence_lines) if evidence_lines else "No packet evidence available.")
    )


def build_llm_repair_prompt(raw_text: str | None, analysis: Dict[str, Any]) -> str:
    """Ask the model to repair a previous response into strict JSON."""
    allowed_ids = [
        str(item.get("evidence_id"))
        for item in (analysis.get("agent_findings") or {}).get("evidence_pack", [])
        if item.get("evidence_id")
    ]
    return (
        "Repair the previous response into valid JSON only. Do not add markdown fences. "
        f'Use schema_version "{LLM_SUMMARY_SCHEMA_VERSION}". '
        "supported_claims evidence_ids must be selected only from this list: "
        f"{allowed_ids}. Claims without valid evidence IDs must go to unsupported_claims.\n\n"
        "Required JSON keys: schema_version, summary, supported_claims, unsupported_claims, recommended_actions. "
        "summary must not be empty. unsupported_claims must be plain strings.\n\n"
        f"Deterministic context:\n{build_structured_llm_prompt(analysis)}\n\n"
        f"Previous response:\n{raw_text or ''}"
    )


def parse_and_validate_llm_summary(raw_text: str | None, analysis: Dict[str, Any], model: str | None = None) -> Dict[str, Any]:
    """Parse LLM JSON and mark claims that reference unknown evidence IDs."""
    if not raw_text:
        return _error("empty_response", "LLM returned an empty response.", model=model)

    try:
        parsed = json.loads(_extract_json(raw_text))
    except (TypeError, ValueError) as exc:
        return _error("invalid_json", f"LLM response was not valid JSON: {exc}", raw_text=raw_text, model=model)

    allowed_ids = {
        str(item.get("evidence_id"))
        for item in (analysis.get("agent_findings") or {}).get("evidence_pack", [])
        if item.get("evidence_id")
    }
    supported = []
    unsupported = [_claim_text(item) for item in parsed.get("unsupported_claims", []) if _claim_text(item)]
    invalid_references = []
    unsupported_reasons = []
    supported_cves = _supported_cves(analysis)
    for item in parsed.get("supported_claims", []) or []:
        claim = str(item.get("claim", "")).strip()
        evidence_ids = [str(value) for value in item.get("evidence_ids", []) if str(value) in allowed_ids]
        rejected = [str(value) for value in item.get("evidence_ids", []) if str(value) not in allowed_ids]
        unsupported_cves = [cve for cve in _extract_cves(claim) if cve not in supported_cves]
        if rejected:
            invalid_references.append({"claim": claim, "invalid_evidence_ids": rejected})
        if unsupported_cves:
            unsupported_reasons.append({"claim": claim, "unsupported_cves": unsupported_cves})
        if claim and evidence_ids and not unsupported_cves:
            supported.append({"claim": claim, "evidence_ids": evidence_ids})
        elif claim:
            unsupported.append(claim)

    summary_text = str(parsed.get("summary", "")).strip()
    recommended_actions = [str(item) for item in parsed.get("recommended_actions", []) if item]
    empty_original_structure = not summary_text and not supported and not unsupported and not recommended_actions
    summary_unsupported_cves = [cve for cve in _extract_cves(summary_text) if cve not in supported_cves]
    if summary_text and summary_unsupported_cves:
        unsupported.append(summary_text)
        unsupported_reasons.append({"claim": summary_text, "unsupported_cves": summary_unsupported_cves})
        summary_text = _deterministic_summary_text(analysis)

    if not supported and allowed_ids and not empty_original_structure:
        fallback_claim = _deterministic_summary_text(analysis)
        if fallback_claim:
            supported.append({"claim": fallback_claim, "evidence_ids": sorted(allowed_ids)[:3]})

    status = "ok" if not invalid_references and not unsupported_reasons else "validated_with_dropped_claims"
    if invalid_references and not unsupported_reasons:
        status = "validated_with_dropped_references"
    if empty_original_structure:
        status = "empty_structured_summary"

    return {
        "schema_version": LLM_SUMMARY_SCHEMA_VERSION,
        "model": model,
        "status": status,
        "summary": summary_text,
        "supported_claims": supported,
        "unsupported_claims": _dedupe(unsupported),
        "recommended_actions": recommended_actions,
        "invalid_references": invalid_references,
        "unsupported_reasons": unsupported_reasons,
        "deterministic_verdict": (analysis.get("impact_assessment") or {}).get("verdict"),
    }


def needs_llm_retry(summary: Dict[str, Any]) -> bool:
    return summary.get("status") in RETRYABLE_LLM_STATUSES


def generate_validated_llm_summary(client: Any, analysis: Dict[str, Any], model: str | None = None) -> Dict[str, Any]:
    """Generate a structured summary with JSON-mode fallback and repair retry."""
    raw_summary = client.generate(build_structured_llm_prompt(analysis), json_format=True)
    structured_summary = parse_and_validate_llm_summary(raw_summary, analysis, model=model)
    structured_summary["generation_mode"] = "json_format"
    structured_summary["retry_attempted"] = False

    if structured_summary.get("status") == "empty_response":
        raw_summary = client.generate(build_structured_llm_prompt(analysis), json_format=False)
        structured_summary = parse_and_validate_llm_summary(raw_summary, analysis, model=model)
        structured_summary["generation_mode"] = "plain"
        structured_summary["retry_attempted"] = False

    if needs_llm_retry(structured_summary):
        repaired = client.generate(build_llm_repair_prompt(raw_summary, analysis), json_format=False)
        structured_summary = parse_and_validate_llm_summary(repaired, analysis, model=model)
        structured_summary["generation_mode"] = "repair_plain"
        structured_summary["retry_attempted"] = True

    if needs_llm_retry(structured_summary):
        fallback = build_deterministic_llm_fallback(analysis, model=model)
        fallback["generation_mode"] = structured_summary.get("generation_mode")
        fallback["retry_attempted"] = structured_summary.get("retry_attempted", False)
        fallback["fallback_reason"] = structured_summary.get("status")
        return fallback

    return structured_summary


def build_deterministic_llm_fallback(analysis: Dict[str, Any], model: str | None = None) -> Dict[str, Any]:
    """Produce a non-LLM summary when a model cannot return usable structured JSON."""
    agent_findings = analysis.get("agent_findings") or {}
    evidence_pack = agent_findings.get("evidence_pack") or []
    summary = _deterministic_summary_text(analysis)
    verdict = (analysis.get("impact_assessment") or {}).get("verdict")

    evidence_ids = [str(item.get("evidence_id")) for item in evidence_pack[:3] if item.get("evidence_id")]
    supported_claims = []
    if evidence_ids:
        supported_claims.append(
            {
                "claim": summary,
                "evidence_ids": evidence_ids,
            }
        )

    return {
        "schema_version": LLM_SUMMARY_SCHEMA_VERSION,
        "model": model,
        "status": "deterministic_fallback",
        "summary": summary,
        "supported_claims": supported_claims,
        "unsupported_claims": [],
        "recommended_actions": list(agent_findings.get("next_actions") or []),
        "invalid_references": [],
        "unsupported_reasons": [],
        "deterministic_verdict": verdict,
    }


def _extract_json(raw_text: str) -> str:
    text = raw_text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        return fenced.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1]
    return text


def _error(status: str, message: str, raw_text: str | None = None, model: str | None = None) -> Dict[str, Any]:
    return {
        "schema_version": LLM_SUMMARY_SCHEMA_VERSION,
        "model": model,
        "status": status,
        "summary": "",
        "supported_claims": [],
        "unsupported_claims": [message],
        "recommended_actions": [],
        "invalid_references": [],
        "raw_response": raw_text,
        "deterministic_verdict": None,
    }


def _dedupe(items: List[str]) -> List[str]:
    deduped = []
    for item in items:
        if item and item not in deduped:
            deduped.append(item)
    return deduped


def _claim_text(item: Any) -> str:
    if isinstance(item, dict):
        if not item:
            return ""
        return str(item.get("claim") or item.get("text") or item).strip()
    return str(item).strip()


def _extract_cves(text: str) -> List[str]:
    return [match.upper() for match in re.findall(r"CVE-\d{4}-\d{4,7}", text or "", flags=re.IGNORECASE)]


def _supported_cves(analysis: Dict[str, Any]) -> set[str]:
    supported = set()
    for item in analysis.get("top_cves") or []:
        cve = str(item.get("cve") or "").upper()
        if not cve:
            continue
        if item.get("rule_confirmed") or float(item.get("score") or 0) >= 0.8:
            supported.add(cve)
    for cve in (analysis.get("impact_assessment") or {}).get("related_cves") or []:
        if any(item.get("cve") == cve and item.get("rule_confirmed") for item in analysis.get("top_cves") or []):
            supported.add(str(cve).upper())
    return supported


def _deterministic_summary_text(analysis: Dict[str, Any]) -> str:
    impact = analysis.get("impact_assessment") or {}
    top_cve = (analysis.get("top_cves") or [{}])[0].get("cve")
    verdict = impact.get("verdict") or "Insufficient evidence"
    confidence = impact.get("confidence")
    summary = f"{verdict}"
    if confidence:
        summary += f" ({confidence} confidence)"
    if top_cve:
        summary += f"; primary CVE candidate: {top_cve}."
    else:
        summary += "."
    return summary
