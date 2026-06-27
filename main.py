"""FlowTragent command-line entry point."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.agent.agent import TraceAgent
from src.agent.orchestrator import run_agent_layer
from src.correlation.attack_chain import detect_attack_stages
from src.correlation.c2_detector import detect_c2
from src.correlation.impact_analyzer import assess_impact
from src.correlation.source_tracker import summarize_sources
from src.correlation.timeline import build_timeline
from src.core.nova_client import NovaClient
from src.core.ollama_client import OllamaClient
from src.core.settings import load_config
from src.parser.capture import capture_with_tcpdump
from src.parser.pcap_parser import parse_network_events, parse_pcap_events, pcap_to_csv
from src.rag.knowledge_base import KnowledgeBase
from src.report.generator import write_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FlowTragent attack tracing pipeline")
    parser.add_argument("--mode", choices=["pcap", "live", "payload"], required=True)
    parser.add_argument("--input", help="Input PCAP path or raw payload text")
    parser.add_argument("--interface", help="Network interface for live capture")
    parser.add_argument("--output-dir", default="reports", help="Report output directory")
    parser.add_argument("--config", default="config/config.yaml", help="Config YAML path")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--demo-index", action="store_true", help="Force demo index rebuild")
    parser.add_argument("--enable-rag", action="store_true", help="Attach local ChromaDB context to the report")
    parser.add_argument("--enable-ollama", action="store_true", help="Ask local Ollama to produce an agent summary")
    parser.add_argument("--capture-seconds", type=int, help="Live capture duration")
    parser.add_argument("--packet-count", type=int, default=0, help="Stop live capture after N packets when > 0")
    return parser.parse_args()


def run_payload(payload: str, config: dict, output_dir: Path, top_k: int, force_demo_index: bool, enable_rag: bool, enable_ollama: bool) -> Path:
    nova = _build_nova(config, force_demo_index)
    candidates = nova.search(payload, top_k=top_k)
    analysis = _analyze([payload], candidates, config, enable_rag, enable_ollama)
    return write_report(analysis, output_dir=output_dir)


def run_pcap(
    pcap_path: Path,
    config: dict,
    output_dir: Path,
    top_k: int,
    force_demo_index: bool,
    enable_rag: bool,
    enable_ollama: bool,
) -> Path:
    csv_path = Path(config["paths"]["csv_dir"]) / f"{pcap_path.stem}.csv"
    network_events = parse_network_events(str(pcap_path))
    events = parse_pcap_events(str(pcap_path))
    extracted = pcap_to_csv(str(pcap_path), str(csv_path))
    if not network_events:
        raise RuntimeError(f"No supported network events were extracted from {pcap_path}")

    payloads = [event.payload_clean for event in events if event.payload_clean.strip()]

    nova = _build_nova(config, force_demo_index)
    all_candidates = []
    for event in events:
        for rank, item in enumerate(nova.search(event.payload_clean, top_k=top_k), start=1):
            item["event_id"] = event.event_id
            item["rank"] = rank
            all_candidates.append(item)

    analysis = _analyze(
        payloads=payloads,
        candidates=all_candidates,
        config=config,
        enable_rag=enable_rag,
        enable_ollama=enable_ollama,
        source_file=str(pcap_path),
        csv_file=str(csv_path),
        events=events,
        network_events=network_events,
    )
    return write_report(analysis, output_dir=output_dir)


def _build_nova(config: dict, force_demo_index: bool) -> NovaClient:
    return NovaClient(
        index_dir=config["paths"]["index_dir"],
        model_name=config["retrieval"]["model_name"],
        force_demo_index=force_demo_index,
    )


def _analyze(
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

    llm_summary = None
    ollama_enabled = enable_ollama or bool(config.get("ollama", {}).get("enabled"))
    if ollama_enabled:
        ollama = OllamaClient(config["ollama"]["host"], config["ollama"]["model"])
        if ollama.is_available():
            llm_summary = ollama.generate(agent.build_llm_prompt(payloads, candidates, rag_context))
        else:
            llm_summary = "Ollama is not available; rule-based analysis was used."

    analysis = agent.analyze(
        payloads=payloads,
        candidates=candidates,
        source_file=source_file,
        csv_file=csv_file,
        rag_context=rag_context,
        llm_summary=llm_summary,
    )
    evidence_events = network_events or events or []
    if evidence_events:
        http_events = events or [event for event in evidence_events if getattr(event, "protocol", None) == "HTTP"]
        attack_chain = detect_attack_stages(http_events, candidates)
        c2_findings = detect_c2(evidence_events)
        analysis["structured_events"] = [event.to_dict() for event in evidence_events]
        analysis["attack_timeline"] = build_timeline(evidence_events)
        analysis["attack_chain"] = attack_chain
        analysis["c2_findings"] = c2_findings
        analysis["source_summary"] = summarize_sources(evidence_events)
        analysis["impact_assessment"] = assess_impact(http_events, attack_chain, c2_findings, candidates)
    analysis["agent_findings"] = run_agent_layer(analysis)
    return analysis


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    output_dir = Path(args.output_dir or config["paths"]["report_dir"])
    top_k = args.top_k or int(config["retrieval"]["top_k"])

    if args.mode == "live":
        if not args.interface:
            raise SystemExit("--interface is required for live mode")
        pcap_path = Path(config["paths"]["pcap_dir"]) / "live_capture.pcap"
        captured = capture_with_tcpdump(
            args.interface,
            pcap_path,
            duration=args.capture_seconds or int(config["live_capture"]["duration"]),
            packet_count=args.packet_count or int(config["live_capture"]["packet_count"]),
        )
        report_path = run_pcap(
            captured,
            config,
            output_dir,
            top_k,
            args.demo_index,
            args.enable_rag,
            args.enable_ollama,
        )
    elif args.mode == "payload":
        if not args.input:
            raise SystemExit("--input is required for payload mode")
        report_path = run_payload(args.input, config, output_dir, top_k, args.demo_index, args.enable_rag, args.enable_ollama)
    else:
        if not args.input:
            raise SystemExit("--input is required for pcap mode")
        report_path = run_pcap(Path(args.input), config, output_dir, top_k, args.demo_index, args.enable_rag, args.enable_ollama)

    print(json.dumps({"report": str(report_path)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
