"""Evidence aggregation and deterministic analysis orchestration."""

from __future__ import annotations

from src.agent.agent import TraceAgent
from src.agent.llm_summary import generate_validated_llm_summary
from src.agent.orchestrator import run_agent_layer
from src.correlation.attack_chain import detect_attack_stages
from src.correlation.attack_mapper import map_attack_techniques
from src.correlation.c2_detector import detect_c2
from src.correlation.evidence_graph import build_evidence_graph
from src.correlation.impact_analyzer import assess_impact
from src.correlation.source_tracker import summarize_sources
from src.correlation.timeline import build_timeline
from src.core.ollama_client import OllamaClient
from src.rag.knowledge_base import KnowledgeBase


def analyze_evidence(
    payloads: list[str],
    candidates: list[dict],
    config: dict,
    enable_rag: bool,
    enable_ollama: bool,
    source_file: str | None = None,
    csv_file: str | None = None,
    events: list | None = None,
    network_events: list | None = None,
) -> dict:
    agent = TraceAgent()
    rag_context = []
    if enable_rag:
        query_text = "\n".join(payloads[:5])
        rag_context = KnowledgeBase(config["paths"]["rag_dir"]).query(query_text, top_k=3)

    analysis = agent.analyze(
        payloads=payloads,
        candidates=candidates,
        source_file=source_file,
        csv_file=csv_file,
        rag_context=rag_context,
        llm_summary=None,
    )
    evidence_events = network_events or events or []
    if evidence_events:
        detection_config = config.get("detection", {})
        attack_chain = detect_attack_stages(evidence_events, candidates, detection_config.get("attack_chain", {}))
        c2_findings = detect_c2(evidence_events, detection_config.get("c2", {}))
        analysis["structured_events"] = [event.to_dict() for event in evidence_events]
        analysis["attack_timeline"] = build_timeline(evidence_events)
        analysis["attack_chain"] = attack_chain
        analysis["c2_findings"] = c2_findings
        analysis["source_summary"] = summarize_sources(evidence_events)
        analysis["impact_assessment"] = assess_impact(evidence_events, attack_chain, c2_findings, candidates)
        analysis["attack_mapping"] = map_attack_techniques(attack_chain, c2_findings)
        analysis["evidence_graph"] = build_evidence_graph(evidence_events, attack_chain, c2_findings)
    analysis["agent_findings"] = run_agent_layer(analysis)
    _attach_llm_summary(analysis, config, enable_ollama)
    return analysis


def _attach_llm_summary(analysis: dict, config: dict, enable_ollama: bool) -> None:
    ollama_enabled = enable_ollama or bool(config.get("ollama", {}).get("enabled"))
    if not ollama_enabled:
        return
    model = config["ollama"]["model"]
    ollama = OllamaClient(config["ollama"]["host"], model)
    if ollama.is_available():
        if not ollama.has_model(model):
            analysis["llm_structured_summary"] = {
                "schema_version": "llm-summary-v1",
                "model": model,
                "status": "model_unavailable",
                "summary": "",
                "supported_claims": [],
                "unsupported_claims": [f"Ollama model is not available locally: {model}"],
                "recommended_actions": [],
                "invalid_references": [],
                "deterministic_verdict": (analysis.get("impact_assessment") or {}).get("verdict"),
                "available_models": ollama.list_models(),
            }
            analysis["llm_summary"] = f"Ollama model is not available locally: {model}"
        else:
            analysis["llm_structured_summary"] = generate_validated_llm_summary(ollama, analysis, model=model)
            analysis["llm_summary"] = analysis["llm_structured_summary"].get("summary") or None
    else:
        analysis["llm_structured_summary"] = {
            "schema_version": "llm-summary-v1",
            "model": model,
            "status": "unavailable",
            "summary": "",
            "supported_claims": [],
            "unsupported_claims": ["Ollama is not available; deterministic agent analysis was used."],
            "recommended_actions": [],
            "invalid_references": [],
            "deterministic_verdict": (analysis.get("impact_assessment") or {}).get("verdict"),
        }
        analysis["llm_summary"] = "Ollama is not available; deterministic agent analysis was used."
