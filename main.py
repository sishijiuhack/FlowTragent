"""FlowTragent command-line entry point."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.core.settings import load_config
from src.orchestrator.pipeline import run_pcap, run_payload
from src.parser.capture import capture_with_tcpdump


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
    parser.add_argument("--access-log", action="append", default=[], help="Supplementary web access log path; can be repeated")
    parser.add_argument("--dns-log", action="append", default=[], help="Supplementary DNS log path; can be repeated")
    parser.add_argument("--endpoint-log", action="append", default=[], help="Supplementary endpoint/process log path; can be repeated")
    parser.add_argument("--app-log", action="append", default=[], help="Supplementary application log path; can be repeated")
    parser.add_argument("--zeek-log", action="append", default=[], help="Supplementary Zeek http/dns/ssl/conn log path; can be repeated")
    parser.add_argument("--suricata-log", action="append", default=[], help="Supplementary Suricata EVE JSON/JSONL path; can be repeated")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    output_dir = Path(args.output_dir or config["paths"]["report_dir"])
    top_k = args.top_k or int(config["retrieval"]["top_k"])

    if args.mode == "live":
        report_path = _run_live(args, config, output_dir, top_k)
    elif args.mode == "payload":
        if not args.input:
            raise SystemExit("--input is required for payload mode")
        report_path = run_payload(args.input, config, output_dir, top_k, args.demo_index, args.enable_rag, args.enable_ollama)
    else:
        if not args.input:
            raise SystemExit("--input is required for pcap mode")
        report_path = run_pcap(
            Path(args.input),
            config,
            output_dir,
            top_k,
            args.demo_index,
            args.enable_rag,
            args.enable_ollama,
            args.access_log,
            args.dns_log,
            args.endpoint_log,
            args.app_log,
            args.zeek_log,
            args.suricata_log,
        )

    print(json.dumps({"report": str(report_path)}, ensure_ascii=False, indent=2))


def _run_live(args: argparse.Namespace, config: dict, output_dir: Path, top_k: int) -> Path:
    if not args.interface:
        raise SystemExit("--interface is required for live mode")
    pcap_path = Path(config["paths"]["pcap_dir"]) / "live_capture.pcap"
    captured = capture_with_tcpdump(
        args.interface,
        pcap_path,
        duration=args.capture_seconds or int(config["live_capture"]["duration"]),
        packet_count=args.packet_count or int(config["live_capture"]["packet_count"]),
    )
    return run_pcap(
        captured,
        config,
        output_dir,
        top_k,
        args.demo_index,
        args.enable_rag,
        args.enable_ollama,
        args.access_log,
        args.dns_log,
        args.endpoint_log,
        args.app_log,
        args.zeek_log,
        args.suricata_log,
    )


if __name__ == "__main__":
    main()
