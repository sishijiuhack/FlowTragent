"""Analyze live PCAP segments after lightweight prefiltering."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from main import run_pcap
from src.core.settings import load_config
from src.live.prefilter import prefilter_pcap
from src.storage.alert_store import AlertStore


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FlowTragent live analyzer worker")
    parser.add_argument("--watch-dir", default="data/live/incoming", help="Directory containing PCAP segments")
    parser.add_argument("--db", default="data/live/alerts.db", help="SQLite alert database")
    parser.add_argument("--config", default="config/config.yaml", help="Config YAML path")
    parser.add_argument("--output-dir", default="reports", help="Report output directory")
    parser.add_argument("--min-risk-score", type=int, default=50, help="Minimum score for deep analysis")
    parser.add_argument("--poll-seconds", type=float, default=5.0, help="Polling interval")
    parser.add_argument("--stable-seconds", type=float, default=1.0, help="File quiet time before processing")
    parser.add_argument("--once", action="store_true", help="Process current files once and exit")
    parser.add_argument("--demo-index", action="store_true", help="Force demo retrieval index")
    parser.add_argument("--enable-rag", action="store_true", help="Attach local RAG context")
    parser.add_argument("--enable-ollama", action="store_true", help="Allow Ollama in deep analysis")
    parser.add_argument("--top-k", type=int, default=5)
    return parser.parse_args()


def process_segment(
    pcap_path: str | Path,
    config: dict[str, Any],
    store: AlertStore,
    output_dir: str | Path = "reports",
    min_risk_score: int = 50,
    top_k: int = 5,
    force_demo_index: bool = False,
    enable_rag: bool = False,
    enable_ollama: bool = False,
) -> dict[str, Any]:
    """Prefilter one PCAP and run deep analysis only when needed."""
    path = Path(pcap_path)
    result = prefilter_pcap(path, min_risk_score=min_risk_score).to_dict()
    store.upsert_prefilter(result)
    if result["recommended_action"] != "deep_analysis":
        store.mark_skipped(path)
        return {"segment": str(path), "status": "skipped", "prefilter": result}

    store.mark_analyzing(path)
    try:
        report = run_pcap(
            path,
            config,
            Path(output_dir),
            top_k,
            force_demo_index,
            enable_rag,
            enable_ollama,
        )
    except Exception as exc:
        store.mark_error(path, str(exc))
        return {"segment": str(path), "status": "error", "error": str(exc), "prefilter": result}
    store.mark_reported(path, report)
    return {"segment": str(path), "status": "reported", "report": str(report), "prefilter": result}


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    store = AlertStore(args.db)
    watch_dir = Path(args.watch_dir)
    watch_dir.mkdir(parents=True, exist_ok=True)
    processed = {item["segment_path"] for item in store.list_alerts(limit=10000)}

    while True:
        for pcap_path in sorted([*watch_dir.glob("*.pcap"), *watch_dir.glob("*.pcapng")]):
            if str(pcap_path) in processed:
                continue
            if not _is_stable(pcap_path, args.stable_seconds):
                continue
            output = process_segment(
                pcap_path,
                config=config,
                store=store,
                output_dir=args.output_dir,
                min_risk_score=args.min_risk_score,
                top_k=args.top_k,
                force_demo_index=args.demo_index,
                enable_rag=args.enable_rag,
                enable_ollama=args.enable_ollama,
            )
            processed.add(str(pcap_path))
            print(json.dumps(output, ensure_ascii=False, indent=2))
        if args.once:
            return
        time.sleep(args.poll_seconds)


def _is_stable(path: Path, stable_seconds: float) -> bool:
    try:
        before = path.stat().st_size
        time.sleep(stable_seconds)
        after = path.stat().st_size
    except FileNotFoundError:
        return False
    return before == after and after > 0


if __name__ == "__main__":
    main()
