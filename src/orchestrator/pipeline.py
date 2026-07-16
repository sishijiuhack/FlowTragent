"""Input-mode pipelines for FlowTragent analysis."""

from __future__ import annotations

from pathlib import Path

from src.core.nova_client import NovaClient
from src.orchestrator.analyzer import analyze_evidence
from src.parser.log_parser import parse_log_bundle
from src.parser.pcap_parser import parse_network_events, parse_pcap_events, pcap_to_csv
from src.report.generator import write_report


def run_payload(
    payload: str,
    config: dict,
    output_dir: Path,
    top_k: int,
    force_demo_index: bool,
    enable_rag: bool,
    enable_ollama: bool,
) -> Path:
    nova = _build_nova(config, force_demo_index)
    candidates = nova.search(payload, top_k=top_k)
    analysis = analyze_evidence([payload], candidates, config, enable_rag, enable_ollama)
    return write_report(analysis, output_dir=output_dir)


def run_pcap(
    pcap_path: Path,
    config: dict,
    output_dir: Path,
    top_k: int,
    force_demo_index: bool,
    enable_rag: bool,
    enable_ollama: bool,
    access_logs: list[str] | None = None,
    dns_logs: list[str] | None = None,
    endpoint_logs: list[str] | None = None,
    application_logs: list[str] | None = None,
    zeek_logs: list[str] | None = None,
    suricata_logs: list[str] | None = None,
) -> Path:
    csv_path = Path(config["paths"]["csv_dir"]) / f"{pcap_path.stem}.csv"
    network_events = parse_network_events(str(pcap_path))
    events = parse_pcap_events(str(pcap_path))
    log_events = parse_log_bundle(
        access_logs=access_logs,
        dns_logs=dns_logs,
        endpoint_logs=endpoint_logs,
        application_logs=application_logs,
        zeek_logs=zeek_logs,
        suricata_logs=suricata_logs,
    )
    network_events = sorted([*network_events, *log_events], key=lambda event: event.timestamp or 0)
    events = sorted(
        [*events, *[event for event in log_events if getattr(event, "protocol", None) == "HTTP"]],
        key=lambda event: event.timestamp or 0,
    )
    pcap_to_csv(str(pcap_path), str(csv_path))
    if not network_events:
        raise RuntimeError(f"No supported network events were extracted from {pcap_path}")

    payloads = [event.payload_clean for event in events if event.payload_clean.strip()]

    nova = _build_nova(config, force_demo_index)
    all_candidates = []
    event_payloads = [event.payload_clean for event in events]
    for event, event_candidates in zip(events, nova.batch_search(event_payloads, top_k=top_k)):
        for rank, item in enumerate(event_candidates, start=1):
            item["event_id"] = event.event_id
            item["rank"] = rank
            all_candidates.append(item)

    analysis = analyze_evidence(
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
