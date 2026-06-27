"""Report generation for FlowTragent."""

from __future__ import annotations

import json
from pathlib import Path


def write_report(analysis: dict, output_dir: str | Path = "reports") -> Path:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    stamp = analysis["generated_at"].replace(":", "").replace(".", "").replace("Z", "Z")
    md_path = output / f"flowtragent_report_{stamp}.md"
    json_path = output / f"flowtragent_report_{stamp}.json"

    lines = [
        "# FlowTragent Attack Trace Report",
        "",
        f"- Generated at: `{analysis['generated_at']}`",
        f"- Source file: `{analysis.get('source_file') or 'payload input'}`",
        f"- Parsed CSV: `{analysis.get('csv_file') or 'N/A'}`",
        f"- Payload count: `{analysis.get('payload_count', 0)}`",
        "",
        "## Attack Assessment",
    ]
    for attack_type in analysis.get("attack_types", []):
        lines.append(f"- {attack_type}")

    agent_findings = analysis.get("agent_findings") or {}
    if agent_findings:
        lines.extend(["", "## Executive Summary"])
        lines.append(agent_findings.get("executive_summary") or "No executive summary available.")

        key_findings = agent_findings.get("key_findings") or []
        if key_findings:
            lines.extend(["", "## Key Findings"])
            for item in key_findings:
                lines.append(f"- {item}")

    if analysis.get("llm_summary"):
        lines.extend(["", "## Agent Summary", analysis["llm_summary"]])

    lines.extend(["", "## Top CVE Candidates"])
    top_cves = analysis.get("top_cves", [])
    if top_cves:
        lines.extend(["| CVE | Final | Retrieval | Rule | Signals | Evidence |", "| --- | ---: | ---: | ---: | --- | --- |"])
        for item in top_cves:
            evidence = str(item.get("evidence", "")).replace("|", "\\|")[:160]
            lines.append(
                "| {cve} | {final} | {retrieval} | {rule} | {signals} | `{evidence}` |".format(
                    cve=item.get("cve"),
                    final=item.get("score"),
                    retrieval=_fmt(item.get("retrieval_score")),
                    rule=_fmt(item.get("rule_bonus")),
                    signals=", ".join(item.get("signals", [])),
                    evidence=evidence,
                )
            )
    else:
        lines.append("- No CVE candidate passed retrieval.")

    cve_evidence_rows = []
    for item in top_cves[:5]:
        for detail in (item.get("evidence_details") or [])[:3]:
            cve_evidence_rows.append((item, detail))
    if cve_evidence_rows:
        lines.extend(["", "## CVE Evidence"])
        lines.extend(["| CVE | Event | Neighbor | Score | Labels | Payload |", "| --- | --- | --- | ---: | --- | --- |"])
        for item, detail in cve_evidence_rows:
            payload = str(detail.get("neighbor_payload") or item.get("evidence") or "")[:140]
            labels = ", ".join(detail.get("neighbor_labels", []))
            lines.append(
                "| {cve} | {event_id} | {neighbor} | {score} | {labels} | `{payload}` |".format(
                    cve=item.get("cve", ""),
                    event_id=detail.get("event_id") or "",
                    neighbor=detail.get("neighbor_id") or "",
                    score=_fmt(detail.get("score")),
                    labels=_escape_table(labels),
                    payload=_escape_table(payload),
                )
            )

    lines.extend(["", "## Timeline"])
    for item in analysis.get("timeline", []):
        lines.append(f"{item.get('step')}. {item.get('event')}")

    attack_timeline = analysis.get("attack_timeline", [])
    if attack_timeline:
        lines.extend(["", "## Attack Timeline"])
        lines.extend(["| Event | Time | Source | Target | Method | URI | Status | Resp Size | Summary | Response |", "| --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |"])
        for item in attack_timeline:
            lines.append(
                "| {event_id} | {timestamp} | {source} | {target} | {method} | {uri} | {status} | {response_size} | `{summary}` | `{response}` |".format(
                    event_id=item.get("event_id", ""),
                    timestamp=_fmt(item.get("timestamp")),
                    source=item.get("source") or "",
                    target=item.get("target") or "",
                    method=item.get("method") or "",
                    uri=_escape_table(item.get("uri") or ""),
                    status=_fmt(item.get("status_code")),
                    response_size=_fmt(item.get("response_size")),
                    summary=_escape_table(str(item.get("summary") or "")[:180]),
                    response=_escape_table(str(item.get("response_summary") or "")[:120]),
                )
            )

    attack_chain = analysis.get("attack_chain", [])
    if attack_chain:
        lines.extend(["", "## Attack Chain"])
        lines.extend(["| Stage | Technique | Confidence | Source | Target | Evidence | Reasoning |", "| --- | --- | --- | --- | --- | --- | --- |"])
        for item in attack_chain:
            lines.append(
                "| {stage} | {technique} | {confidence} | {source} | {target} | {evidence} | {reasoning} |".format(
                    stage=item.get("stage", ""),
                    technique=item.get("technique", ""),
                    confidence=item.get("confidence", ""),
                    source=item.get("source_ip") or "",
                    target=item.get("target_ip") or "",
                    evidence=", ".join(item.get("evidence_ids", [])),
                    reasoning=_escape_table(item.get("reasoning", "")),
                )
            )

    c2_findings = analysis.get("c2_findings", [])
    if c2_findings:
        lines.extend(["", "## C2 Analysis"])
        lines.extend(["| Type | Confidence | Source | Destination | Count | Interval | Jitter | Indicators |", "| --- | --- | --- | --- | ---: | ---: | ---: | --- |"])
        for item in c2_findings:
            lines.append(
                "| {c2_type} | {confidence} | {src} | {dst}:{port} | {count} | {interval} | {jitter} | {indicators} |".format(
                    c2_type=item.get("c2_type", ""),
                    confidence=item.get("confidence", ""),
                    src=item.get("src_ip", ""),
                    dst=item.get("dst_ip", ""),
                    port=item.get("dst_port", ""),
                    count=item.get("request_count", ""),
                    interval=_fmt(item.get("beacon_interval")),
                    jitter=_fmt(item.get("jitter")),
                    indicators=_escape_table(", ".join(item.get("indicators", []))),
                )
            )

    source_summary = analysis.get("source_summary", [])
    if source_summary:
        lines.extend(["", "## Source Analysis"])
        for item in source_summary:
            lines.append(f"- Source `{item.get('source_ip')}`: {item.get('event_count')} event(s), targets: {', '.join(item.get('targets', []))}")
            if item.get("top_uris"):
                lines.append(f"  - Top URIs: {_format_pairs(item.get('top_uris', []))}")
            if item.get("top_user_agents"):
                lines.append(f"  - Top User-Agents: {_format_pairs(item.get('top_user_agents', []))}")
            if item.get("top_dns_queries"):
                lines.append(f"  - Top DNS Queries: {_format_pairs(item.get('top_dns_queries', []))}")

    impact = analysis.get("impact_assessment")
    if impact:
        lines.extend(["", "## Impact Assessment"])
        lines.append(f"- Verdict: `{impact.get('verdict')}`")
        lines.append(f"- Confidence: `{impact.get('confidence')}`")
        lines.append(f"- Reasoning: {impact.get('reasoning')}")
        if impact.get("related_cves"):
            lines.append(f"- Related CVEs: {', '.join(impact.get('related_cves', []))}")
        if impact.get("http_status_codes"):
            lines.append(f"- HTTP status codes: {', '.join(str(code) for code in impact.get('http_status_codes', []))}")
        if impact.get("evidence_ids"):
            lines.append(f"- Evidence: {', '.join(impact.get('evidence_ids', []))}")
        if impact.get("missing_evidence"):
            lines.append("- Missing evidence:")
            for item in impact.get("missing_evidence", []):
                lines.append(f"  - {item}")

    if agent_findings:
        reasoning = agent_findings.get("agent_reasoning") or []
        if reasoning:
            lines.extend(["", "## Agent Reasoning"])
            lines.extend(["| Agent | Confidence | Evidence | Reasoning |", "| --- | --- | --- | --- |"])
            for item in reasoning:
                lines.append(
                    "| {agent} | {confidence} | {evidence} | {reasoning} |".format(
                        agent=item.get("agent", ""),
                        confidence=item.get("confidence", ""),
                        evidence=", ".join(item.get("evidence_ids", [])),
                        reasoning=_escape_table(item.get("reasoning", "")),
                    )
                )
        next_actions = agent_findings.get("next_actions") or []
        if next_actions:
            lines.extend(["", "## Next Actions"])
            for item in next_actions:
                lines.append(f"- {item}")

    rag_context = analysis.get("rag_context", [])
    if rag_context:
        lines.extend(["", "## RAG Context"])
        for item in rag_context:
            lines.append(f"- `{item.get('id')}`: {item.get('text')}")

    lines.extend(["", "## Recommendations"])
    for item in analysis.get("recommendations", []):
        lines.append(f"- {item}")
    lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    json_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")
    return md_path


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _fmt(value) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def _format_pairs(pairs: list) -> str:
    rendered = []
    for key, count in pairs:
        rendered.append(f"`{key}` ({count})")
    return ", ".join(rendered)
