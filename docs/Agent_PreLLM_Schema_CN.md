# FlowTragent 接入 LLM 前 Agent 层 Schema

本文档定义 FlowTragent 当前 deterministic Agent 层的稳定输出结构。

当前阶段目标不是让 LLM 直接做最终判断，而是先把可审计证据链固定下来：

```text
structured_events
top_cves
attack_timeline
attack_chain
c2_findings
impact_assessment
source_summary
-> deterministic agent layer
-> agent_findings
```

## 1. agent_findings 顶层字段

```json
{
  "schema_version": "agent-v1",
  "mode": "deterministic",
  "executive_summary": "...",
  "key_findings": [],
  "agent_reasoning": [],
  "evidence_pack": [],
  "confidence_summary": {},
  "limitations": [],
  "next_actions": [],
  "orchestration": {
    "engine": "langgraph",
    "nodes": ["Investigator Agent", "Vulnerability Judge Agent", "Timeline Agent", "Impact Agent"],
    "fallback_reason": null
  }
}
```

字段说明：

- `schema_version`：Agent 输出契约版本，当前为 `agent-v1`。
- `mode`：当前固定为 `deterministic`，表示不依赖 LLM 判断。
- `executive_summary`：面向报告读者的简短结论。
- `key_findings`：核心发现列表。
- `agent_reasoning`：各 Agent 的结构化判断过程。
- `evidence_pack`：统一证据包，用于把 packet、CVE、attack stage、C2 finding 关联起来。
- `confidence_summary`：Agent 判断置信度统计。
- `limitations`：证据缺口。
- `next_actions`：处置建议。
- `orchestration`：Agent 编排元数据，记录实际使用 `langgraph` 还是 `sequential` fallback。

## 2. agent_reasoning 条目

```json
{
  "agent": "Vulnerability Judge Agent",
  "finding": "Top CVE candidate is CVE-2021-44228 with final score 1.6048.",
  "confidence": "high",
  "evidence_ids": ["pkt-1"],
  "reasoning": "Candidate ranking is based on NOVA-F retrieval plus rule evidence...",
  "data": {}
}
```

当前 Agent：

- `Investigator Agent`
- `Vulnerability Judge Agent`
- `Timeline Agent`
- `Impact Agent`
- `Reporter Agent`，负责汇总，不单独进入 `agent_reasoning`

## 3. evidence_pack 条目

```json
{
  "evidence_id": "pkt-1",
  "evidence_type": "HTTP",
  "summary": "10.10.10.5:44444 -> 10.10.10.20:80 GET ...",
  "source": "10.10.10.5:44444",
  "target": "10.10.10.20:80",
  "related": ["CVE-2021-44228", "demo-log4shell", "Exploitation"]
}
```

用途：

- 把报告中的 evidence ID 和原始结构化事件对齐。
- 把 NOVA-F 近邻样本、候选 CVE、攻击阶段、C2 finding 关联到同一个证据 ID。
- 为后续 LLM 总结提供受控上下文，避免模型凭空补全证据。

## 4. 接入 LLM 前的约束

后续接入 Ollama / LangGraph 时，应保持以下约束：

1. LLM 只能消费 `agent_findings`、`structured_events`、`top_cves` 等结构化输入。
2. LLM 不应覆盖 deterministic verdict，只能生成解释性摘要或补充分析建议。
3. LLM 输出必须回写到单独字段，例如 `llm_summary` 或 `llm_structured_summary`。
4. 如果 LLM 产生了无法映射到 `evidence_id` 的结论，应标记为 `unsupported_by_evidence`。
5. Markdown 报告中的最终影响判断仍以 `impact_assessment` 和 deterministic Agent 输出为准。

## 5. LangGraph 编排

当前 Agent 层已支持 LangGraph 编排，但节点仍是 deterministic Agent：

```text
Investigator Agent
-> Vulnerability Judge Agent
-> Timeline Agent
-> Impact Agent
-> Reporter Agent
```

如果 LangGraph 不可用或 API 行为变化，系统会降级到 sequential runner，并在：

```text
agent_findings.orchestration.fallback_reason
```

中记录原因。

## 6. 当前验证命令

```bash
python tests/test_agent_orchestrator.py
python tests/test_langgraph_runner.py
python tests/test_trace_agent_cve_evidence.py
python tests/test_pipeline.py
python tests/test_dns_tcp_c2_pipeline.py
python tests/test_post_exploit_and_c2_pipeline.py
```

## 7. LLM 结构化摘要接入约束

当前 LLM 接入只允许生成结构化摘要，不允许覆盖 deterministic 判断。

新增输出字段：

```text
llm_structured_summary
```

当前 schema：

```json
{
  "schema_version": "llm-summary-v1",
  "model": "phi3:mini",
  "status": "ok",
  "summary": "...",
  "supported_claims": [
    {
      "claim": "...",
      "evidence_ids": ["pkt-1"]
    }
  ],
  "unsupported_claims": [],
  "recommended_actions": [],
  "invalid_references": [],
  "deterministic_verdict": "..."
}
```

校验规则：

- `supported_claims[].evidence_ids` 必须存在于 `agent_findings.evidence_pack`。
- 引用了不存在 evidence ID 的 claim 会被降级到 `unsupported_claims`。
- 无法解析为 JSON 的 LLM 输出会标记为 `status=invalid_json`。
- Ollama 不可用时会标记为 `status=unavailable`，主流程仍生成 deterministic 报告。
- `deterministic_verdict` 来自 `impact_assessment.verdict`，LLM 不能覆盖。

验证命令：

```bash
python tests/test_llm_summary.py
python tests/test_ollama_unavailable_pipeline.py
```
