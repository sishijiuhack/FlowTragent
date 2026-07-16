"""Scheduled Ollama review for completed FlowTragent reports."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.llm_summary import generate_validated_llm_summary
from src.core.ollama_client import OllamaClient
from src.core.settings import load_config
from src.storage.alert_store import AlertStore


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run scheduled Ollama reviews for completed FlowTragent reports")
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--db", default=None, help="Alert DB path; defaults to live.alert_db")
    parser.add_argument("--report-dir", default=None, help="Report directory; defaults to paths.report_dir")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--interval-minutes", type=float, default=None)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--force", action="store_true", help="Regenerate summaries even when already present")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    interval = float(args.interval_minutes or config.get("live", {}).get("ollama_interval_minutes", 10))
    while True:
        results = run_scheduled_review(
            config,
            db_path=args.db,
            report_dir=args.report_dir,
            limit=args.limit,
            force=args.force,
        )
        print(json.dumps({"reviewed": results}, ensure_ascii=False, indent=2))
        if args.once:
            return
        time.sleep(max(1.0, interval * 60))


def run_scheduled_review(
    config: dict[str, Any],
    db_path: str | Path | None = None,
    report_dir: str | Path | None = None,
    limit: int = 20,
    force: bool = False,
    client_factory: Callable[[str, str], Any] = OllamaClient,
) -> list[dict[str, Any]]:
    if config.get("live", {}).get("ollama_mode", "scheduled") != "scheduled":
        return [{"status": "disabled", "reason": "live.ollama_mode is not scheduled"}]
    ollama_config = config.get("ollama", {})
    model = str(ollama_config.get("model") or "phi3:mini")
    client = client_factory(str(ollama_config.get("host") or "http://127.0.0.1:11434"), model)
    if not client.is_available():
        return [{"status": "ollama_unavailable", "model": model}]
    if not client.has_model(model):
        return [{"status": "model_unavailable", "model": model}]

    results = []
    for json_path in _candidate_report_jsons(config, db_path=db_path, report_dir=report_dir, limit=limit):
        results.append(_review_json_report(json_path, client, model=model, force=force))
    return results


def _candidate_report_jsons(
    config: dict[str, Any],
    db_path: str | Path | None = None,
    report_dir: str | Path | None = None,
    limit: int = 20,
) -> list[Path]:
    report_root = Path(report_dir or config["paths"]["report_dir"])
    db = Path(db_path or config.get("live", {}).get("alert_db", "data/live/alerts.db"))
    if db.exists():
        store = AlertStore(db)
        candidates = []
        for alert in store.list_alerts(limit=limit, status="reported"):
            report_path = alert.get("report_path")
            if not report_path:
                continue
            candidates.append(Path(report_path).with_suffix(".json"))
        return candidates
    return sorted(report_root.glob("flowtragent_report_*.json"), key=lambda path: path.stat().st_mtime, reverse=True)[:limit]


def _review_json_report(json_path: Path, client: Any, model: str, force: bool = False) -> dict[str, Any]:
    if not json_path.exists():
        return {"status": "missing_report_json", "report": str(json_path)}
    analysis = json.loads(json_path.read_text(encoding="utf-8"))
    if analysis.get("llm_structured_summary") and not force:
        return {"status": "already_reviewed", "report": str(json_path)}
    analysis["llm_structured_summary"] = generate_validated_llm_summary(client, analysis, model=model)
    analysis["llm_summary"] = analysis["llm_structured_summary"].get("summary") or None
    analysis["llm_review_mode"] = "scheduled"
    json_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"status": "reviewed", "report": str(json_path), "summary_status": analysis["llm_structured_summary"].get("status")}


if __name__ == "__main__":
    main()
