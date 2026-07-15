"""Deterministic multi-agent evidence summarization."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from src.agent.langgraph_runner import run_agent_graph
from src.agent.schema import AgentEvidence, AgentFinding, AgentReport


def run_agent_layer(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Run deterministic agents over already-correlated evidence."""
    agents = [
        InvestigatorAgent(),
        VulnerabilityJudgeAgent(),
        TimelineAgent(),
        ImpactAgent(),
    ]
    state = run_agent_graph(analysis, agents)
    findings = state.get("findings", [])
    return ReporterAgent().run(analysis, findings, state.get("orchestration", {})).to_dict()


def run_agent_layer_sequential(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Run deterministic agents without LangGraph. Useful for debugging."""
    findings = [
        InvestigatorAgent().run(analysis),
        VulnerabilityJudgeAgent().run(analysis),
        TimelineAgent().run(analysis),
        ImpactAgent().run(analysis),
    ]
    orchestration = {
        "engine": "sequential",
        "nodes": ["Investigator Agent", "Vulnerability Judge Agent", "Timeline Agent", "Impact Agent"],
        "fallback_reason": None,
    }
    return ReporterAgent().run(analysis, findings, orchestration).to_dict()


class InvestigatorAgent:
    name = "Investigator Agent"

    def run(self, analysis: Dict[str, Any]) -> AgentFinding:
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
            {"protocols": dict(sorted(protocols.items())), "event_count": len(events)},
        )


class VulnerabilityJudgeAgent:
    name = "Vulnerability Judge Agent"

    def run(self, analysis: Dict[str, Any]) -> AgentFinding:
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
        evidence_ids = [str(item) for item in top.get("event_ids", []) if item]
        evidence_details = top.get("evidence_details", [])
        neighbor_ids = sorted({str(item.get("neighbor_id")) for item in evidence_details if item.get("neighbor_id")})
        label_votes = top.get("label_votes", {})
        evidence_bits = [f"signals: {signals}"]
        if neighbor_ids:
            evidence_bits.append(f"nearest samples: {', '.join(neighbor_ids[:5])}")
        if label_votes:
            votes = ", ".join(f"{label}={count}" for label, count in sorted(label_votes.items())[:5])
            evidence_bits.append(f"label votes: {votes}")
        return _finding(
            self.name,
            f"Top CVE candidate is {top.get('cve')} with final score {score:.4f}.",
            confidence,
            evidence_ids,
            f"Candidate ranking is based on NOVA-F retrieval plus rule evidence; {'; '.join(evidence_bits)}.",
            {
                "top_cve": top.get("cve"),
                "score": score,
                "event_ids": evidence_ids,
                "neighbor_ids": neighbor_ids,
                "label_votes": label_votes,
                "signals": top.get("signals", []),
            },
        )


class TimelineAgent:
    name = "Timeline Agent"

    def run(self, analysis: Dict[str, Any]) -> AgentFinding:
        timeline = analysis.get("attack_timeline", [])
        chain = analysis.get("attack_chain", [])
        c2_findings = analysis.get("c2_findings", [])
        evidence_paths = (analysis.get("evidence_graph") or {}).get("paths", [])
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
        if evidence_paths:
            parts.append(f"key evidence paths: {evidence_paths[0].get('summary')}")
        summary_tail = "; ".join(parts) if parts else "no explicit attack stage or C2 finding"
        return _finding(
            self.name,
            f"Timeline spans {len(timeline)} event(s), from {first.get('timestamp')} to {last.get('timestamp')}.",
            "high" if len(timeline) >= 2 else "medium",
            [str(item.get("event_id")) for item in timeline[:12] if item.get("event_id")],
            summary_tail,
            {
                "event_count": len(timeline),
                "first_seen": first.get("timestamp"),
                "last_seen": last.get("timestamp"),
                "attack_stages": stages,
                "c2_types": c2_types,
                "evidence_paths": evidence_paths[:5],
            },
        )


class ImpactAgent:
    name = "Impact Agent"

    def run(self, analysis: Dict[str, Any]) -> AgentFinding:
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
            {
                "verdict": impact.get("verdict"),
                "related_cves": impact.get("related_cves", []),
                "missing_evidence": impact.get("missing_evidence", []),
            },
        )


class ReporterAgent:
    name = "Reporter Agent"

    def run(
        self,
        analysis: Dict[str, Any],
        findings: List[AgentFinding],
        orchestration: Dict[str, Any] | None = None,
    ) -> AgentReport:
        impact = analysis.get("impact_assessment") or {}
        top_cve = (analysis.get("top_cves") or [{}])[0]
        c2_findings = analysis.get("c2_findings", [])
        chain = analysis.get("attack_chain", [])
        evidence_paths = (analysis.get("evidence_graph") or {}).get("paths", [])

        summary_parts = []
        if impact.get("verdict"):
            summary_parts.append(f"Assessment: {impact.get('verdict')} ({impact.get('confidence', 'unknown')} confidence).")
        if top_cve.get("cve"):
            if top_cve.get("rule_confirmed") or top_cve.get("signals"):
                summary_parts.append(f"Primary CVE candidate: {top_cve.get('cve')}.")
            else:
                summary_parts.append(f"Top retrieval-only CVE candidate: {top_cve.get('cve')} requires validation.")
        if c2_findings:
            summary_parts.append(f"C2 indicators detected: {', '.join(sorted({item.get('c2_type') for item in c2_findings if item.get('c2_type')}))}.")
        if evidence_paths:
            summary_parts.append(f"Key evidence path: {evidence_paths[0].get('summary')}.")
        if not summary_parts:
            summary_parts.append("No decisive attack conclusion is available from the current evidence.")

        key_findings = [item.finding for item in findings if item.finding]
        key_findings.extend(f"Evidence path: {item.get('summary')}" for item in evidence_paths[:3] if item.get("summary"))
        evidence_pack = _build_evidence_pack(analysis)
        confidence_summary = dict(Counter(item.confidence for item in findings if item.confidence))
        limitations = _limitations(analysis, impact)
        next_actions = _next_actions(analysis, chain, c2_findings, impact)
        return AgentReport(
            executive_summary=" ".join(summary_parts),
            key_findings=key_findings,
            agent_reasoning=findings,
            evidence_pack=evidence_pack,
            confidence_summary=confidence_summary,
            limitations=limitations,
            next_actions=next_actions,
            orchestration=orchestration or {},
        )


def _collect_evidence_ids(analysis: Dict[str, Any]) -> List[str]:
    evidence = set()
    for stage in analysis.get("attack_chain", []):
        evidence.update(stage.get("evidence_ids", []))
    for finding in analysis.get("c2_findings", []):
        evidence.update(finding.get("evidence_ids", []))
    impact = analysis.get("impact_assessment") or {}
    evidence.update(impact.get("evidence_ids", []))
    return sorted(str(item) for item in evidence if item)


def _build_evidence_pack(analysis: Dict[str, Any]) -> List[AgentEvidence]:
    pack: Dict[str, AgentEvidence] = {}
    for event in analysis.get("structured_events", []):
        event_id = str(event.get("event_id") or "")
        if not event_id:
            continue
        pack[event_id] = AgentEvidence(
            evidence_id=event_id,
            evidence_type=str(event.get("protocol") or "NetworkEvent"),
            summary=str(event.get("summary") or event.get("payload_clean") or "")[:220],
            source=_format_endpoint(event.get("src_ip"), event.get("src_port")),
            target=_format_endpoint(event.get("dst_ip"), event.get("dst_port")),
        )

    for cve in analysis.get("top_cves", []):
        for detail in cve.get("evidence_details", []) or []:
            event_id = str(detail.get("event_id") or "")
            if not event_id:
                continue
            evidence = pack.setdefault(
                event_id,
                AgentEvidence(
                    evidence_id=event_id,
                    evidence_type="CVE Evidence",
                    summary=str(detail.get("neighbor_payload") or "")[:220],
                ),
            )
            related = [
                str(cve.get("cve")),
                str(detail.get("neighbor_id")) if detail.get("neighbor_id") else "",
            ]
            evidence.related.extend(item for item in related if item and item not in evidence.related)

    for stage in analysis.get("attack_chain", []):
        for event_id in stage.get("evidence_ids", []) or []:
            evidence = pack.get(str(event_id))
            if evidence and stage.get("stage") not in evidence.related:
                evidence.related.append(str(stage.get("stage")))

    for finding in analysis.get("c2_findings", []):
        for event_id in finding.get("evidence_ids", []) or []:
            evidence = pack.get(str(event_id))
            if evidence and finding.get("c2_type") not in evidence.related:
                evidence.related.append(str(finding.get("c2_type")))

    return [pack[key] for key in sorted(pack)]


def _limitations(analysis: Dict[str, Any], impact: Dict[str, Any]) -> List[str]:
    limitations = list(impact.get("missing_evidence", []) or [])
    if not analysis.get("top_cves"):
        limitations.append("No CVE retrieval evidence is available for this input.")
    if not analysis.get("attack_timeline"):
        limitations.append("No timestamped attack timeline is available.")
    if not analysis.get("structured_events"):
        limitations.append("No structured packet evidence is available.")
    deduped = []
    for item in limitations:
        if item and item not in deduped:
            deduped.append(item)
    return deduped


def _format_endpoint(ip: Any, port: Any) -> str | None:
    if not ip:
        return None
    return f"{ip}:{port}" if port is not None else str(ip)


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
    if (analysis.get("evidence_graph") or {}).get("paths"):
        actions.append("Review the reported evidence graph paths to confirm the sequence from entry traffic to host activity and outbound communication.")
    top_cve = (analysis.get("top_cves") or [{}])[0]
    if top_cve.get("cve"):
        actions.append(f"Validate service exposure and patch status for {top_cve.get('cve')}.")
    if str(impact.get("confidence", "")).lower() in {"high", "medium"}:
        actions.append("Prioritize containment and scoping before eradication to avoid losing volatile evidence.")
    return actions


def _finding(
    agent: str,
    finding: str,
    confidence: str,
    evidence_ids: List[str],
    reasoning: str,
    data: Dict[str, Any] | None = None,
) -> AgentFinding:
    return AgentFinding(
        agent=agent,
        finding=finding,
        confidence=confidence,
        evidence_ids=[item for item in evidence_ids if item],
        reasoning=reasoning,
        data=data or {},
    )
