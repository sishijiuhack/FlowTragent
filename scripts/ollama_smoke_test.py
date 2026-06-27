from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.ollama_client import OllamaClient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run an Ollama structured-summary smoke test.")
    parser.add_argument("--host", default="http://127.0.0.1:11434")
    parser.add_argument("--model", default="phi3:mini")
    parser.add_argument("--input", default="data/pcap/demo_attack.pcap")
    parser.add_argument("--skip-generate-pcap", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    client = OllamaClient(args.host, args.model, timeout=120)
    if not client.is_available():
        print(
            json.dumps(
                {
                    "status": "ollama_unavailable",
                    "host": args.host,
                    "model": args.model,
                    "hint": "Start Ollama and pull the model, e.g. `ollama serve` and `ollama pull phi3:mini`.",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    available_models = client.list_models()
    if args.model not in available_models:
        print(
            json.dumps(
                {
                    "status": "model_unavailable",
                    "host": args.host,
                    "model": args.model,
                    "available_models": available_models,
                    "hint": f"Pull the model first: `ollama pull {args.model}`. Or rerun with one of the available models.",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    if not args.skip_generate_pcap:
        subprocess.run([sys.executable, "tests/make_demo_pcap.py"], cwd=PROJECT_ROOT, check=True)

    config_path = PROJECT_ROOT / "data/csv/ollama_smoke_config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        "\n".join(
            [
                "project:",
                "  name: FlowTragent",
                "paths:",
                "  nova_f: libs/nova-f",
                "  pcap_dir: data/pcap",
                "  csv_dir: data/csv",
                "  index_dir: data/index",
                "  rag_dir: data/rag",
                "  report_dir: reports",
                "retrieval:",
                "  model_name: libs/nova-f/models/all-MiniLM-L6-v2",
                "  top_k: 5",
                "  score_threshold: 0.5",
                "ollama:",
                f"  host: {args.host}",
                f"  model: {args.model}",
                "  enabled: false",
                "live_capture:",
                "  duration: 30",
                "  packet_count: 0",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--mode",
            "pcap",
            "--input",
            args.input,
            "--demo-index",
            "--enable-ollama",
            "--config",
            str(config_path.relative_to(PROJECT_ROOT)),
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    report_path = PROJECT_ROOT / json.loads(result.stdout)["report"]
    analysis = json.loads(report_path.with_suffix(".json").read_text(encoding="utf-8"))
    print(
        json.dumps(
            {
                "status": "ok",
                "report": str(report_path.relative_to(PROJECT_ROOT)),
                "llm_status": analysis.get("llm_structured_summary", {}).get("status"),
                "generation_mode": analysis.get("llm_structured_summary", {}).get("generation_mode"),
                "retry_attempted": analysis.get("llm_structured_summary", {}).get("retry_attempted"),
                "supported_claims": len(analysis.get("llm_structured_summary", {}).get("supported_claims", [])),
                "unsupported_claims": len(analysis.get("llm_structured_summary", {}).get("unsupported_claims", [])),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
