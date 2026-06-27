"""Deterministic multi-agent evidence summarization."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List


def run_agent_layer(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Run deterministic agents over already-correlated evidence."""
    findings = [
        InvestigatorAgent().run(analysis),
        VulnerabilityJudgeAgent().run(analysis),
        TimelineAgent().run(analysis),
        ImpactAgent().run(analysis),
    ]
    return ReporterAgent().run(analysis, findings)


class InvestigatorAgent:
    name = "Investigator Agent"

    def run(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        events = analysis.get("structured_events", [])
        protocols = Counter(str(event.get("protocol", "UNKNOWN")) for event in events)
        evidence_ids = _collect_evidence_ids(analysis)
        if not events:
            return _finding(
                self.name,
                "No structured packet evidence was available.",
                "low",
                [],
                "The input did not produce structured HTTP/DNS/TCP events.",
            )
        protocol_text = ", ".join(f"{proto}={count}" for proto, count in sorted(protocols.items()))
        return _finding(
            self.name,
            f"Collected {len(events)} structured network event(s): {protocol_text}.",
            "high",
            evidence_ids[:12],
            "Evidence was derived from parsed PCAP events and correlated finding evidence IDs.",
        )


class VulnerabilityJudgeAgent:
    name = "Vulnerability Judge Agent"

    def run(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        candidates = analysis.get("top_cves", [])
        if not candidates:
            return _finding(
                self.name,
                "No CVE candidate is currently supported by retrieval evidence.",
                "low",
                [],
                "NOVA-F did not return candidates for the available HTTP payloads, or the sample contains no HTTP payload.",
            )
        top = candidates[0]
        score = float(top.get("score", 0.0))
        confidence = "high" if top.get("rule_confirmed") else "medium" if score >= 0.5 else "low"
        signals = ", ".join(top.get("signals", [])) or "retrieval similarity"
        return _finding(
            self.name,
            f"Top CVE candidate is {top.get('cve')} with final score {score:.4f}.",
            confidence,
            [str(top.get("event_id"))] if top.get("event_id") else [],
            f"Candidate ranking is based on NOVA-F retrieval plus rule signals: {signals}.",
        )


class TimelineAgent:
    name = "Timeline Agent"

    def run(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        timeline = analysis.get("attack_timeline", [])
        chain = analysis.get("attack_chain", [])
        c2_findings = analysis.get("c2_findings", [])
        if not timeline:
            return _finding(
                self.name,
                "No network timeline could be reconstructed.",
                "low",
                [],
                "No timestamped structured events were available.",
            )
        first = timeline[0]
        last = timeline[-1]
        stages = [stage.get("stage") for stage in chain if stage.get("stage")]
        c2_types = [finding.get("c2_type") for finding in c2_findings if finding.get("c2_type")]
        parts = []
        if stages:
            parts.append(f"attack stages: {', '.join(stages)}")
        if c2_types:
            parts.append(f"C2 indicators: {', '.join(c2_types)}")
        summary_tail = "; ".join(parts) if parts else "no explicit attack stage or C2 finding"
        return _finding(
            self.name,
            f"Timeline spans {len(timeline)} event(s), from {first.get('timestamp')} to {last.get('timestamp')}.",
            "high" if len(timeline) >= 2 else "medium",
            [str(item.get("event_id")) for item in timeline[:12] if item.get("event_id")],
            summary_tail,
        )


class ImpactAgent:
    name = "Impact Agent"

    def run(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        impact = analysis.get("impact_assessment") or {}
        if not impact:
            return _finding(
                self.name,
                "Impact could not be assessed from the available evidence.",
                "low",
                [],
                "Impact Assessment was not produced by the correlation pipeline.",
            )
        return _finding(
            self.name,
            f"Impact verdict: {impact.get('verdict')}.",
            impact.get("confidence") or "low",
            impact.get("evidence_ids", []),
            impact.get("reasoning") or "Impact was inferred from correlated exploit, post-exploitation, and C2 evidence.",
        )


class ReporterAgent:
    name = "Reporter Agent"

    def run(self, analysis: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        impact = analysis.get("impact_assessment") or {}
        top_cve = (analysis.get("top_cves") or [{}])[0]
        c2_findings = analysis.get("c2_findings", [])
        chain = analysis.get("attack_chain", [])

        summary_parts = []
        if impact.get("verdict"):
            summary_parts.append(f"Assessment: {impact.get('verdict')} ({impact.get('confidence', 'unknown')} confidence).")
        if top_cve.get("cve"):
            summary_parts.append(f"Primary CVE candidate: {top_cve.get('cve')}.")
        if c2_findings:
            summary_parts.append(f"C2 indicators detected: {', '.join(sorted({item.get('c2_type') for item in c2_findings if item.get('c2_type')}))}.")
        if not summary_parts:
            summary_parts.append("No decisive attack conclusion is available from the current evidence.")

        key_findings = [item["finding"] for item in findings if item.get("finding")]
        next_actions = _next_actions(analysis, chain, c2_findings, impact)
        return {
            "executive_summary": " ".join(summary_parts),
            "key_findings": key_findings,
            "agent_reasoning": findings,
            "next_actions": next_actions,
        }


def _collect_evidence_ids(analysis: Dict[str, Any]) -> List[str]:
    evidence = set()
    for stage in analysis.get("attack_chain", []):
        evidence.update(stage.get("evidence_ids", []))
    for finding in analysis.get("c2_findings", []):
        evidence.update(finding.get("evidence_ids", []))
    impact = analysis.get("impact_assessment") or {}
    evidence.update(impact.get("evidence_ids", []))
    return sorted(str(item) for item in evidence if item)


def _next_actions(
    analysis: Dict[str, Any],
    chain: List[Dict[str, Any]],
    c2_findings: List[Dict[str, Any]],
    impact: Dict[str, Any],
) -> List[str]:
    actions = [
        "Preserve PCAP, parsed CSV, generated JSON report, and related server logs as investigation evidence.",
        "Correlate the reported evidence IDs with web access logs, DNS logs, endpoint telemetry, and process execution logs.",
    ]
    if c2_findings:
        destinations = sorted({f"{item.get('dst_ip')}:{item.get('dst_port')}" for item in c2_findings if item.get("dst_ip")})
        actions.append(f"Investigate and temporarily block suspected C2 destination(s): {', '.join(destinations)}.")
    if any(stage.get("stage") in {"Command Execution", "Payload Delivery", "WebShell / Backdoor"} for stage in chain):
        actions.append("Collect host triage artifacts from affected assets, including process list, network sockets, web root diff, persistence entries, and recent file writes.")
    top_cve = (analysis.get("top_cves") or [{}])[0]
    if top_cve.get("cve"):
        actions.append(f"Validate service exposure and patch status for {top_cve.get('cve')}.")
    if str(impact.get("confidence", "")).lower() in {"high", "medium"}:
        actions.append("Prioritize containment and scoping before eradication to avoid losing volatile evidence.")
    return actions


def _finding(agent: str, finding: str, confidence: str, evidence_ids: List[str], reasoning: str) -> Dict[str, Any]:
    return {
        "agent": agent,
        "finding": finding,
        "confidence": confidence,
        "evidence_ids": [item for item in evidence_ids if item],
        "reasoning": reasoning,
    }
