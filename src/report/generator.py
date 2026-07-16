"""Report generation for FlowTragent."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_report(analysis: dict, output_dir: str | Path = "reports") -> Path:
    """Write English Markdown, Chinese Markdown, and machine-readable JSON."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    stamp = analysis["generated_at"].replace(":", "").replace(".", "").replace("Z", "Z")
    md_path = output / f"flowtragent_report_{stamp}.md"
    zh_path = output / f"flowtragent_report_{stamp}_zh.md"
    json_path = output / f"flowtragent_report_{stamp}.json"

    md_path.write_text("\n".join(_render_report(analysis, language="en")), encoding="utf-8")
    zh_path.write_text("\n".join(_render_report(analysis, language="zh")), encoding="utf-8")
    json_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")
    return md_path


def _render_report(analysis: dict[str, Any], language: str) -> list[str]:
    zh = language == "zh"
    lines = [
        "# FlowTragent 攻击溯源报告" if zh else "# FlowTragent Attack Trace Report",
        "",
        f"- {'生成时间' if zh else 'Generated at'}: `{analysis['generated_at']}`",
        f"- {'来源文件' if zh else 'Source file'}: `{analysis.get('source_file') or 'payload input'}`",
        f"- {'解析 CSV' if zh else 'Parsed CSV'}: `{analysis.get('csv_file') or 'N/A'}`",
        f"- {'Payload 数量' if zh else 'Payload count'}: `{analysis.get('payload_count', 0)}`",
    ]

    _append_summary(lines, analysis, zh)
    _append_attack_types(lines, analysis, zh)
    _append_agent(lines, analysis, zh)
    _append_llm(lines, analysis, zh)
    _append_cves(lines, analysis, zh)
    _append_timeline(lines, analysis, zh)
    _append_attack_chain(lines, analysis, zh)
    _append_attack_mapping(lines, analysis, zh)
    _append_c2(lines, analysis, zh)
    _append_sources(lines, analysis, zh)
    _append_impact(lines, analysis, zh)
    _append_graph(lines, analysis, zh)
    _append_agent_details_without_graph(lines, analysis, zh)
    _append_rag(lines, analysis, zh)
    _append_recommendations(lines, analysis, zh)
    lines.append("")
    return lines


def _append_summary(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    impact = analysis.get("impact_assessment") or {}
    top_cve = _top_cve_label(analysis)
    graph_paths = (analysis.get("evidence_graph") or {}).get("paths") or []
    lines.extend(["", "## 中文摘要" if zh else "## Executive Summary"])
    if zh:
        impact_cn = _impact_cn(impact)
        lines.append(f"- 研判结论：`{impact_cn.get('verdict')}`")
        lines.append(f"- 置信度：`{impact_cn.get('confidence')}`")
        lines.append(f"- 研判依据：{_translate_text(impact_cn.get('reasoning') or '')}")
        lines.append(f"- 首要 CVE 候选：`{top_cve}`")
        if graph_paths:
            lines.append(f"- 关键证据路径：`{_translate_relation_text(graph_paths[0].get('summary') or '')}`")
    else:
        lines.append(f"- Verdict: `{impact.get('verdict', 'Insufficient evidence')}`")
        lines.append(f"- Confidence: `{impact.get('confidence', 'low')}`")
        lines.append(f"- Reasoning: {impact.get('reasoning', 'Evidence is insufficient for a firm conclusion.')}")
        lines.append(f"- Primary CVE candidate: `{top_cve}`")
        if graph_paths:
            lines.append(f"- Key evidence path: `{graph_paths[0].get('summary')}`")


def _append_attack_types(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    lines.extend(["", "## 攻击类型" if zh else "## Attack Assessment"])
    attack_types = analysis.get("attack_types") or []
    if not attack_types:
        lines.append("- 暂无明确攻击类型" if zh else "- No attack type identified.")
        return
    for attack_type in attack_types:
        lines.append(f"- {_translate_text(attack_type) if zh else attack_type}")


def _append_agent(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    agent = analysis.get("agent_findings") or {}
    if not agent:
        return
    lines.extend(["", "## Agent 元数据" if zh else "## Agent Metadata"])
    lines.append(f"- {'模式' if zh else 'Mode'}: `{agent.get('mode', 'unknown')}`")
    lines.append(f"- Schema: `{agent.get('schema_version', 'unknown')}`")
    orchestration = agent.get("orchestration") or {}
    if orchestration:
        lines.append(f"- {'编排引擎' if zh else 'Orchestration'}: `{orchestration.get('engine', 'unknown')}`")
        if orchestration.get("nodes"):
            lines.append(f"- Agent Nodes: {', '.join(orchestration.get('nodes', []))}")

    lines.extend(["", "## 执行摘要" if zh else "## Executive Summary"])
    summary = agent.get("executive_summary") or ("暂无 Agent 摘要。" if zh else "No executive summary available.")
    lines.append(_translate_text(summary) if zh else summary)

    key_findings = agent.get("key_findings") or []
    if key_findings:
        lines.extend(["", "## 关键发现" if zh else "## Key Findings"])
        for item in key_findings:
            lines.append(f"- {_translate_text(item) if zh else item}")


def _append_llm(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    llm = analysis.get("llm_structured_summary") or {}
    if not llm:
        return
    lines.extend(["", "## LLM 结构化摘要" if zh else "## LLM Structured Summary"])
    for key, label_en, label_zh in [
        ("status", "Status", "状态"),
        ("generation_mode", "Generation Mode", "生成模式"),
        ("model", "Model", "模型"),
        ("deterministic_verdict", "Deterministic Verdict", "确定性结论"),
    ]:
        if llm.get(key):
            value = _translate_text(str(llm.get(key))) if zh and key == "deterministic_verdict" else llm.get(key)
            lines.append(f"- {label_zh if zh else label_en}: `{value}`")
    if llm.get("summary"):
        lines.append(f"- {'摘要' if zh else 'Summary'}: {_translate_text(llm.get('summary')) if zh else llm.get('summary')}")
    if llm.get("supported_claims"):
        lines.append("- 有证据支撑的声明:" if zh else "- Supported claims:")
        for item in llm.get("supported_claims", []):
            lines.append(f"  - {item.get('claim')} Evidence: {', '.join(item.get('evidence_ids', []))}")
    if llm.get("unsupported_claims"):
        lines.append("- 证据不足的声明:" if zh else "- Unsupported claims:")
        for item in llm.get("unsupported_claims", []):
            lines.append(f"  - {item}")


def _append_cves(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    lines.extend(["", "## CVE 候选" if zh else "## Top CVE Candidates"])
    top_cves = analysis.get("top_cves") or []
    if not top_cves:
        lines.append("- 未检索到满足条件的 CVE 候选。" if zh else "- No CVE candidate passed retrieval.")
        return
    headers = (
        "| CVE | 支持层级 | 综合分 | 检索分 | 规则分 | 信号 | 证据 |",
        "| --- | --- | ---: | ---: | ---: | --- | --- |",
    ) if zh else (
        "| CVE | Support Level | Final | Retrieval | Rule | Signals | Evidence |",
        "| --- | --- | ---: | ---: | ---: | --- | --- |",
    )
    lines.extend(headers)
    for item in top_cves:
        evidence = _escape_table(str(item.get("evidence", ""))[:160])
        lines.append(
            f"| {item.get('cve')} | {_support_level_label(item.get('cve_support_level'), zh)} | {item.get('score')} | {_fmt(item.get('retrieval_score'))} | "
            f"{_fmt(item.get('rule_bonus'))} | {', '.join(item.get('signals', []))} | `{evidence}` |"
        )

    rows = []
    for item in top_cves[:5]:
        for detail in (item.get("evidence_details") or [])[:3]:
            rows.append((item, detail))
    if rows:
        lines.extend(["", "## CVE 证据" if zh else "## CVE Evidence"])
        lines.extend([
            "| CVE | 事件 | 近邻样本 | 分数 | 标签 | Payload |" if zh else "| CVE | Event | Neighbor | Score | Labels | Payload |",
            "| --- | --- | --- | ---: | --- | --- |",
        ])
        for item, detail in rows:
            payload = _escape_table(str(detail.get("neighbor_payload") or item.get("evidence") or "")[:140])
            labels = _escape_table(", ".join(detail.get("neighbor_labels", [])))
            lines.append(f"| {item.get('cve', '')} | {detail.get('event_id') or ''} | {detail.get('neighbor_id') or ''} | {_fmt(detail.get('score'))} | {labels} | `{payload}` |")


def _append_timeline(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    timeline = analysis.get("timeline") or []
    if timeline:
        lines.extend(["", "## 时间线" if zh else "## Timeline"])
        for item in timeline:
            lines.append(f"{item.get('step')}. {item.get('event')}")
    attack_timeline = analysis.get("attack_timeline") or []
    if attack_timeline:
        lines.extend(["", "## 攻击时间线" if zh else "## Attack Timeline"])
        lines.extend([
            "| 事件 | 时间 | 来源 | 目标 | 方法 | URI | 状态 | 响应大小 | 摘要 | 响应 |" if zh else "| Event | Time | Source | Target | Method | URI | Status | Resp Size | Summary | Response |",
            "| --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |",
        ])
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


def _append_attack_chain(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    chain = analysis.get("attack_chain") or []
    if not chain:
        return
    lines.extend(["", "## 攻击链" if zh else "## Attack Chain"])
    lines.extend([
        "| 阶段 | 技术 | 置信度 | 来源 | 目标 | 证据 | 推理 |" if zh else "| Stage | Technique | Confidence | Source | Target | Evidence | Reasoning |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])
    for item in chain:
        lines.append(
            "| {stage} | {technique} | {confidence} | {source} | {target} | {evidence} | {reasoning} |".format(
                stage=_translate_stage(item.get("stage", "")) if zh else item.get("stage", ""),
                technique=_translate_text(item.get("technique", "")) if zh else item.get("technique", ""),
                confidence=_confidence_zh(item.get("confidence")) if zh else item.get("confidence", ""),
                source=item.get("source_ip") or "",
                target=item.get("target_ip") or "",
                evidence=", ".join(item.get("evidence_ids", [])),
                reasoning=_escape_table(_translate_text(item.get("reasoning", "")) if zh else item.get("reasoning", "")),
            )
        )


def _append_attack_mapping(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    mapping = analysis.get("attack_mapping") or []
    if not mapping:
        return
    lines.extend(["", "## ATT&CK 映射" if zh else "## ATT&CK Mapping"])
    lines.extend([
        "| 技术 | 战术 | 置信度 | 证据 | 原因 |" if zh else "| Technique | Tactic | Confidence | Evidence | Reason |",
        "| --- | --- | --- | --- | --- |",
    ])
    for item in mapping:
        technique = f"{item.get('technique_id')} {item.get('technique_name')}"
        lines.append(
            f"| {_escape_table(technique)} | {_escape_table(item.get('tactic', ''))} | "
            f"{_confidence_zh(item.get('confidence')) if zh else item.get('confidence', '')} | "
            f"{', '.join(item.get('evidence_ids', []))} | {_escape_table(_translate_text(str(item.get('reason') or '')[:160]) if zh else str(item.get('reason') or '')[:160])} |"
        )


def _append_c2(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    findings = analysis.get("c2_findings") or []
    if not findings:
        return
    lines.extend(["", "## C2 分析" if zh else "## C2 Analysis"])
    lines.extend([
        "| 类型 | 置信度 | 来源 | 目的地 | 次数 | 间隔 | 抖动 | 指标 |" if zh else "| Type | Confidence | Source | Destination | Count | Interval | Jitter | Indicators |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | --- |",
    ])
    for item in findings:
        indicators = _escape_table(", ".join(item.get("indicators", [])))
        lines.append(
            f"| {_translate_text(item.get('c2_type', '')) if zh else item.get('c2_type', '')} | "
            f"{_confidence_zh(item.get('confidence')) if zh else item.get('confidence', '')} | "
            f"{item.get('src_ip', '')} | {item.get('dst_ip', '')}:{item.get('dst_port', '')} | "
            f"{item.get('request_count', '')} | {_fmt(item.get('beacon_interval'))} | {_fmt(item.get('jitter'))} | {indicators} |"
        )


def _append_sources(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    sources = analysis.get("source_summary") or []
    if not sources:
        return
    lines.extend(["", "## 来源分析" if zh else "## Source Analysis"])
    for item in sources:
        prefix = "来源" if zh else "Source"
        event_text = "事件" if zh else "event(s)"
        target_text = "目标" if zh else "targets"
        lines.append(f"- {prefix} `{item.get('source_ip')}`: {item.get('event_count')} {event_text}, {target_text}: {', '.join(item.get('targets', []))}")
        if item.get("top_uris"):
            lines.append(f"  - Top URIs: {_format_pairs(item.get('top_uris', []))}")
        if item.get("top_user_agents"):
            lines.append(f"  - Top User-Agents: {_format_pairs(item.get('top_user_agents', []))}")
        if item.get("top_dns_queries"):
            lines.append(f"  - Top DNS Queries: {_format_pairs(item.get('top_dns_queries', []))}")


def _append_impact(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    impact = analysis.get("impact_assessment") or {}
    if not impact:
        return
    lines.extend(["", "## 影响评估" if zh else "## Impact Assessment"])
    if zh:
        impact_cn = _impact_cn(impact)
        lines.append(f"- 结论: `{impact_cn.get('verdict')}`")
        lines.append(f"- 置信度: `{impact_cn.get('confidence')}`")
        lines.append(f"- 推理: {_translate_text(impact_cn.get('reasoning') or '')}")
    else:
        lines.append(f"- Verdict: `{impact.get('verdict')}`")
        lines.append(f"- Confidence: `{impact.get('confidence')}`")
        lines.append(f"- Reasoning: {impact.get('reasoning')}")
    if impact.get("related_cves"):
        lines.append(f"- {'相关 CVE' if zh else 'Related CVEs'}: {', '.join(impact.get('related_cves', []))}")
    if impact.get("http_status_codes"):
        lines.append(f"- HTTP status codes: {', '.join(str(code) for code in impact.get('http_status_codes', []))}")
    if impact.get("evidence_ids"):
        lines.append(f"- {'证据' if zh else 'Evidence'}: {', '.join(impact.get('evidence_ids', []))}")
    if impact.get("missing_evidence"):
        lines.append("- 证据缺口:" if zh else "- Missing evidence:")
        for item in impact.get("missing_evidence", []):
            lines.append(f"  - {_translate_text(item) if zh else item}")
    _append_evidence_structure(lines, impact, zh)


def _append_evidence_structure(lines: list[str], impact: dict[str, Any], zh: bool) -> None:
    observed = []
    if impact.get("evidence_ids"):
        evidence_label = "已关联证据 ID" if zh else "Correlated evidence IDs"
        observed.append(f"{evidence_label}: {', '.join(impact.get('evidence_ids', []))}")
    if impact.get("related_cves"):
        cve_label = "相关 CVE" if zh else "Related CVEs"
        observed.append(f"{cve_label}: {', '.join(impact.get('related_cves', []))}")
    if impact.get("http_status_codes"):
        status_label = "HTTP 状态码" if zh else "HTTP status codes"
        observed.append(f"{status_label}: {', '.join(str(code) for code in impact.get('http_status_codes', []))}")
    if not observed:
        observed.append("未观察到可用于支撑结论的直接证据。" if zh else "No direct supporting evidence was observed.")

    not_observed = [
        _translate_text(item) if zh else item
        for item in (impact.get("missing_evidence") or [])
    ] or ["暂无明确证据缺口。" if zh else "No explicit evidence gaps were recorded."]

    drivers = _confidence_drivers(impact, zh)
    reducers = _confidence_reducers(impact, zh)
    sections = [
        ("Evidence Observed", "已观察证据", observed),
        ("Not Observed", "未观察证据", not_observed),
        ("Confidence Drivers", "置信度提升因素", drivers),
        ("Reducers", "置信度降低因素", reducers),
    ]

    lines.extend(["", "## 证据结构" if zh else "## Evidence Structure"])
    for title, title_zh, items in sections:
        lines.append(f"### {title}（{title_zh}）" if zh else f"### {title}")
        for item in items:
            lines.append(f"- {item}")


def _confidence_drivers(impact: dict[str, Any], zh: bool) -> list[str]:
    drivers = []
    confidence = str(impact.get("confidence") or "").lower()
    if confidence in {"high", "medium"}:
        drivers.append(
            f"确定性影响研判置信度为 {_confidence_zh(confidence)}。"
            if zh
            else f"Deterministic impact confidence is {confidence}."
        )
    if impact.get("evidence_ids"):
        drivers.append("存在可追溯证据 ID 支撑研判。" if zh else "Traceable evidence IDs support the assessment.")
    if impact.get("related_cves"):
        drivers.append("存在与候选 CVE 关联的证据。" if zh else "Evidence is linked to candidate CVEs.")
    if any(200 <= int(code) < 400 for code in impact.get("http_status_codes", []) if str(code).isdigit()):
        drivers.append("观察到 2xx/3xx HTTP 响应。" if zh else "2xx/3xx HTTP responses were observed.")
    return drivers or ["暂无明确置信度提升因素。" if zh else "No explicit confidence drivers were recorded."]


def _confidence_reducers(impact: dict[str, Any], zh: bool) -> list[str]:
    reducers = []
    missing = impact.get("missing_evidence") or []
    if missing:
        reducers.extend(_translate_text(item) if zh else item for item in missing)
    status_codes = [int(code) for code in impact.get("http_status_codes", []) if str(code).isdigit()]
    if status_codes and all(400 <= code < 500 for code in status_codes):
        reducers.append(
            "仅观察到 4xx HTTP 响应，网络证据不支持成功利用结论。"
            if zh
            else "Only 4xx HTTP responses were observed, which does not support a successful exploitation conclusion."
        )
    if str(impact.get("confidence") or "").lower() == "low":
        reducers.append("确定性影响研判置信度为低。" if zh else "Deterministic impact confidence is low.")
    return reducers or ["暂无明确置信度降低因素。" if zh else "No explicit confidence reducers were recorded."]


def _append_graph(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    graph = analysis.get("evidence_graph") or {}
    if not graph.get("edges"):
        return
    lines.extend(["", "## 证据图谱" if zh else "## Evidence Graph"])
    mermaid_key = "mermaid_zh" if zh else "mermaid"
    dot_key = "dot_zh" if zh else "dot"
    if graph.get(mermaid_key):
        lines.extend(["```mermaid", graph.get(mermaid_key, ""), "```", ""])
    if graph.get(dot_key):
        lines.extend(["```graphviz", graph.get(dot_key, ""), "```", ""])
    lines.extend([
        "| 来源 | 关系 | 目标 | 置信度 | 原因 |" if zh else "| Source | Relation | Target | Confidence | Reason |",
        "| --- | --- | --- | --- | --- |",
    ])
    for item in graph.get("edges", [])[:30]:
        relation = _relation_zh(item.get("relation", "")) if zh else item.get("relation", "")
        reason = _translate_text(str(item.get("reason") or "")[:160]) if zh else str(item.get("reason") or "")[:160]
        lines.append(f"| {item.get('source_id', '')} | {_escape_table(relation)} | {item.get('target_id', '')} | {_confidence_zh(item.get('confidence')) if zh else item.get('confidence', '')} | {_escape_table(reason)} |")

    agent = analysis.get("agent_findings") or {}
    evidence_pack = agent.get("evidence_pack") or []
    if evidence_pack:
        lines.extend(["", "## Agent 证据包" if zh else "## Agent Evidence Pack"])
        lines.extend([
            "| 证据 | 类型 | 来源 | 目标 | 关联 | 摘要 |" if zh else "| Evidence | Type | Source | Target | Related | Summary |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for item in evidence_pack[:20]:
            lines.append(
                f"| {item.get('evidence_id', '')} | {item.get('evidence_type', '')} | {item.get('source') or ''} | "
                f"{item.get('target') or ''} | {_escape_table(', '.join(item.get('related', [])))} | "
                f"`{_escape_table(str(item.get('summary') or '')[:140])}` |"
            )
    reasoning = agent.get("agent_reasoning") or []
    if reasoning:
        lines.extend(["", "## Agent 推理" if zh else "## Agent Reasoning"])
        lines.extend([
            "| Agent | 置信度 | 证据 | 推理 |" if zh else "| Agent | Confidence | Evidence | Reasoning |",
            "| --- | --- | --- | --- |",
        ])
        for item in reasoning:
            reasoning_text = _translate_text(item.get("reasoning", "")) if zh else item.get("reasoning", "")
            lines.append(f"| {item.get('agent', '')} | {_confidence_zh(item.get('confidence')) if zh else item.get('confidence', '')} | {', '.join(item.get('evidence_ids', []))} | {_escape_table(reasoning_text)} |")
    if agent.get("next_actions"):
        lines.extend(["", "## 下一步处置建议" if zh else "## Next Actions"])
        for item in agent.get("next_actions", []):
            lines.append(f"- {_translate_text(item) if zh else item}")
    if agent.get("limitations"):
        lines.extend(["", "## 证据缺口" if zh else "## Evidence Gaps"])
        for item in agent.get("limitations", []):
            lines.append(f"- {_translate_text(item) if zh else item}")


def _append_agent_details_without_graph(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    """Keep agent evidence visible even when the evidence graph has no edges."""
    if (analysis.get("evidence_graph") or {}).get("edges"):
        return
    agent = analysis.get("agent_findings") or {}
    evidence_pack = agent.get("evidence_pack") or []
    if evidence_pack:
        lines.extend(["", "## Agent 证据包" if zh else "## Agent Evidence Pack"])
        lines.extend([
            "| 证据 | 类型 | 来源 | 目标 | 关联 | 摘要 |" if zh else "| Evidence | Type | Source | Target | Related | Summary |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for item in evidence_pack[:20]:
            lines.append(
                f"| {item.get('evidence_id', '')} | {item.get('evidence_type', '')} | {item.get('source') or ''} | "
                f"{item.get('target') or ''} | {_escape_table(', '.join(item.get('related', [])))} | "
                f"`{_escape_table(str(item.get('summary') or '')[:140])}` |"
            )
    reasoning = agent.get("agent_reasoning") or []
    if reasoning:
        lines.extend(["", "## Agent 推理" if zh else "## Agent Reasoning"])
        lines.extend([
            "| Agent | 置信度 | 证据 | 推理 |" if zh else "| Agent | Confidence | Evidence | Reasoning |",
            "| --- | --- | --- | --- |",
        ])
        for item in reasoning:
            reasoning_text = _translate_text(item.get("reasoning", "")) if zh else item.get("reasoning", "")
            lines.append(f"| {item.get('agent', '')} | {_confidence_zh(item.get('confidence')) if zh else item.get('confidence', '')} | {', '.join(item.get('evidence_ids', []))} | {_escape_table(reasoning_text)} |")
    if agent.get("next_actions"):
        lines.extend(["", "## 下一步处置建议" if zh else "## Next Actions"])
        for item in agent.get("next_actions", []):
            lines.append(f"- {_translate_text(item) if zh else item}")
    if agent.get("limitations"):
        lines.extend(["", "## 证据缺口" if zh else "## Evidence Gaps"])
        for item in agent.get("limitations", []):
            lines.append(f"- {_translate_text(item) if zh else item}")


def _append_rag(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    rag = analysis.get("rag_context") or []
    if not rag:
        return
    lines.extend(["", "## RAG 上下文" if zh else "## RAG Context"])
    for item in rag:
        lines.append(f"- `{item.get('id')}`: {item.get('text')}")


def _append_recommendations(lines: list[str], analysis: dict[str, Any], zh: bool) -> None:
    lines.extend(["", "## 修复建议" if zh else "## Recommendations"])
    for item in analysis.get("recommendations", []):
        lines.append(f"- {_translate_text(item) if zh else item}")


def _top_cve_label(analysis: dict[str, Any]) -> str:
    top = (analysis.get("top_cves") or [{}])[0]
    cve = top.get("cve") or "N/A"
    if cve == "N/A":
        return cve
    if top.get("rule_confirmed") or top.get("signals"):
        return cve
    return f"{cve} (retrieval-only candidate)"


def _support_level_label(value: Any, zh: bool) -> str:
    level = str(value or "unknown")
    if not zh:
        return level
    return {
        "rule_confirmed": "规则确认",
        "rule_supported": "规则信号支持",
        "retrieval_only": "仅检索候选",
        "weak_candidate": "弱候选",
        "unknown": "未知",
    }.get(level, level)


def _escape_table(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _fmt(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def _format_pairs(pairs: list) -> str:
    return ", ".join(f"`{key}` ({count})" for key, count in pairs)


def _impact_cn(impact: dict[str, Any]) -> dict[str, str]:
    verdict_map = {
        "Likely successful exploitation with C2 indicators": "疑似成功利用并伴随 C2 通信迹象",
        "Possible successful exploitation with C2 indicators": "可能成功利用并伴随 C2 通信迹象",
        "Possible compromise with C2 indicators": "可能存在失陷并伴随 C2 通信迹象",
        "Likely successful exploitation": "疑似成功利用",
        "Possible successful exploitation": "可能成功利用",
        "Likely exploitation attempt with successful HTTP response": "疑似漏洞利用尝试且收到成功 HTTP 响应",
        "Likely exploitation attempt": "疑似漏洞利用尝试",
        "Possible exploitation attempt": "可能的漏洞利用尝试",
        "Reconnaissance or probing": "侦察或探测行为",
        "Insufficient evidence": "证据不足",
    }
    reasoning = impact.get("reasoning") or "当前证据不足以形成明确研判。"
    return {
        "verdict": verdict_map.get(impact.get("verdict"), impact.get("verdict") or "证据不足"),
        "confidence": _confidence_zh(impact.get("confidence")),
        "reasoning": reasoning,
    }


def _confidence_zh(value: Any) -> str:
    return {"high": "高", "medium": "中", "low": "低"}.get(str(value or "").lower(), str(value or "低"))


def _translate_stage(value: str) -> str:
    return {
        "Reconnaissance": "侦察",
        "Exploitation": "漏洞利用",
        "Command Execution": "命令执行",
        "Payload Delivery": "载荷投递",
        "C2": "C2 通信",
        "Persistence": "持久化",
        "Impact": "影响",
    }.get(value, value)


def _relation_zh(value: str) -> str:
    mapping = {
        "same_asset": "同一资产",
        "temporal_sequence": "时间顺序",
        "process_external_connection": "进程外联",
        "process_to_network_destination": "进程到网络目的地",
        "dns_context_for_process": "DNS 与进程上下文",
    }
    if value.startswith("c2_sequence:"):
        return value.replace("c2_sequence:", "C2 通信序列:")
    if value.startswith("same_stage:"):
        return value.replace("same_stage:", "同一攻击阶段:")
    return mapping.get(value, value)


def _translate_relation_text(value: str) -> str:
    for token in [
        "same_asset",
        "temporal_sequence",
        "process_external_connection",
        "process_to_network_destination",
        "dns_context_for_process",
    ]:
        value = value.replace(token, _relation_zh(token))
    value = value.replace("c2_sequence:", "C2 通信序列:")
    value = value.replace("same_stage:", "同一攻击阶段:")
    return value


def _translate_text(value: str) -> str:
    if not value:
        return value
    replacements = {
        "Likely successful exploitation with C2 indicators": "疑似成功利用并伴随 C2 通信迹象",
        "Possible successful exploitation with C2 indicators": "可能成功利用并伴随 C2 通信迹象",
        "Likely successful exploitation": "疑似成功利用",
        "Possible successful exploitation": "可能成功利用",
        "Likely exploitation attempt": "疑似漏洞利用尝试",
        "Possible exploitation attempt": "可能的漏洞利用尝试",
        "Insufficient evidence": "证据不足",
        "Known vulnerability exploitation attempt": "已知漏洞利用尝试",
        "Command execution indicators": "命令执行指标",
        "Payload download or staging": "载荷下载或暂存",
        "HTTP beaconing": "HTTP Beacon 通信",
        "DNS beaconing": "DNS Beacon 通信",
        "TCP beaconing": "TCP Beacon 通信",
        "Endpoint External Connection": "终端外联",
        "Exploit-like payload markers observed": "观察到疑似漏洞利用 Payload 特征",
        "Endpoint/process telemetry shows command activity with a remote destination.": "终端或进程遥测显示命令活动并连接远程目的地。",
        "Network target/source matches endpoint host or host IP.": "网络事件的来源或目标与终端主机/IP 匹配。",
        "C2/beacon evidence sequence": "C2/Beacon 证据序列",
        "Evidence path:": "证据路径:",
        "Preserve the original PCAP, parsed CSV, web access logs, and server logs for evidence review.": "保留原始 PCAP、解析 CSV、Web 访问日志和服务器日志用于证据复核。",
        "Correlate source IP, requested URI, user agent, and response status around the suspicious timestamps.": "围绕可疑时间点关联来源 IP、请求 URI、User-Agent 和响应状态。",
    }
    translated = value
    for src, dst in replacements.items():
        translated = translated.replace(src, dst)
    return _translate_relation_text(translated)
