"""FlowTragent command-line entry point."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.agent.agent import TraceAgent
from src.core.nova_client import NovaClient
from src.parser.pcap_parser import pcap_to_csv
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
    return parser.parse_args()


def run_payload(payload: str, output_dir: Path, top_k: int, force_demo_index: bool) -> Path:
    nova = NovaClient(force_demo_index=force_demo_index)
    candidates = nova.search(payload, top_k=top_k)
    analysis = TraceAgent().analyze(payloads=[payload], candidates=candidates)
    return write_report(analysis, output_dir=output_dir)


def run_pcap(pcap_path: Path, output_dir: Path, top_k: int, force_demo_index: bool) -> Path:
    csv_path = Path("data/csv") / f"{pcap_path.stem}.csv"
    extracted = pcap_to_csv(str(pcap_path), str(csv_path))
    if extracted == 0:
        raise RuntimeError(f"No HTTP/TCP payloads were extracted from {pcap_path}")

    payloads = []
    import pandas as pd

    frame = pd.read_csv(csv_path)
    for value in frame["payload_clean"].fillna("").astype(str):
        if value.strip():
            payloads.append(value)

    nova = NovaClient(force_demo_index=force_demo_index)
    all_candidates = []
    for payload in payloads:
        all_candidates.extend(nova.search(payload, top_k=top_k))

    analysis = TraceAgent().analyze(
        payloads=payloads,
        candidates=all_candidates,
        source_file=str(pcap_path),
        csv_file=str(csv_path),
    )
    return write_report(analysis, output_dir=output_dir)


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)

    if args.mode == "live":
        raise SystemExit(
            "Live mode needs tcpdump capture first. Example: "
            "sudo tcpdump -i eth0 -w /tmp/test.pcap"
        )

    if args.mode == "payload":
        if not args.input:
            raise SystemExit("--input is required for payload mode")
        report_path = run_payload(args.input, output_dir, args.top_k, args.demo_index)
    else:
        if not args.input:
            raise SystemExit("--input is required for pcap mode")
        report_path = run_pcap(Path(args.input), output_dir, args.top_k, args.demo_index)

    print(json.dumps({"report": str(report_path)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
