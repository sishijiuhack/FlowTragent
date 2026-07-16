"""Analyze live PCAP segments after lightweight prefiltering."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.settings import load_config
from src.core.structured_logging import log_event
from src.live.prefilter import prefilter_pcap
from src.notification import notification_fingerprint, send_notification
from src.orchestrator.pipeline import run_pcap
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
    max_deep_analyses_per_hour: int | None = None,
) -> dict[str, Any]:
    """Prefilter one PCAP and run deep analysis only when needed."""
    path = Path(pcap_path)
    result = prefilter_pcap(path, min_risk_score=min_risk_score, config=config).to_dict()
    store.upsert_prefilter(result)
    log_event(
        config,
        "live_analyzer_worker",
        "segment_prefiltered",
        "Live segment prefilter completed.",
        segment_path=str(path),
        severity=result.get("severity"),
        risk_score=result.get("risk_score"),
        recommended_action=result.get("recommended_action"),
    )
    if result["recommended_action"] != "deep_analysis":
        store.mark_skipped(path)
        log_event(config, "live_analyzer_worker", "segment_skipped", "Live segment skipped after prefilter.", segment_path=str(path), risk_score=result.get("risk_score"))
        return {"segment": str(path), "status": "skipped", "prefilter": result}
    if _rate_limited(store, max_deep_analyses_per_hour):
        store.mark_rate_limited(path)
        log_event(config, "live_analyzer_worker", "segment_rate_limited", "Live segment deep analysis rate limited.", level="WARNING", segment_path=str(path))
        _notify(config, store, "segment_rate_limited", result, path)
        return {"segment": str(path), "status": "rate_limited", "prefilter": result}

    store.mark_analyzing(path)
    log_event(config, "live_analyzer_worker", "deep_analysis_started", "Live segment deep analysis started.", segment_path=str(path))
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
        log_event(config, "live_analyzer_worker", "deep_analysis_error", "Live segment deep analysis failed.", level="ERROR", segment_path=str(path), error=str(exc))
        _notify(config, store, "deep_analysis_error", result, path, error=str(exc))
        return {"segment": str(path), "status": "error", "error": str(exc), "prefilter": result}
    store.mark_reported(path, report)
    log_event(config, "live_analyzer_worker", "deep_analysis_reported", "Live segment deep analysis reported.", segment_path=str(path), report_path=str(report))
    _notify(config, store, "deep_analysis_reported", result, path, report_path=report)
    return {"segment": str(path), "status": "reported", "report": str(report), "prefilter": result}


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    store = AlertStore(args.db, merge_window_seconds=int(config.get("live", {}).get("alert_merge_seconds", 180)))
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
                max_deep_analyses_per_hour=int(config.get("live", {}).get("max_deep_analyses_per_hour", 60)),
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


def _rate_limited(store: AlertStore, max_deep_analyses_per_hour: int | None) -> bool:
    if max_deep_analyses_per_hour is None or max_deep_analyses_per_hour <= 0:
        return False
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    return store.count_deep_analyses_since(since) >= max_deep_analyses_per_hour


def _notify(
    config: dict[str, Any],
    store: AlertStore,
    event_type: str,
    prefilter: dict[str, Any],
    segment_path: str | Path,
    report_path: str | Path | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    notification_config = (config or {}).get("notification") or {}
    if not _suppression_applies(notification_config, prefilter):
        result = send_notification(config, event_type, prefilter, segment_path, report_path=report_path, error=error)
        log_event(
            config,
            "live_analyzer_worker",
            "notification_result",
            "Notification attempt completed.",
            event_type=event_type,
            segment_path=str(segment_path),
            sent=result.get("sent"),
            reason=result.get("reason"),
            status=result.get("status"),
        )
        return result
    fingerprint = notification_fingerprint(event_type, prefilter)
    suppression = store.should_send_notification(
        fingerprint,
        {
            "event_type": event_type,
            "segment_path": str(segment_path),
            "report_path": str(report_path) if report_path else None,
            "error": error,
            "severity": prefilter.get("severity"),
            "risk_score": prefilter.get("risk_score"),
        },
        int(notification_config.get("suppress_window_seconds", 300)),
    )
    if not suppression.get("send"):
        log_event(
            config,
            "live_analyzer_worker",
            "notification_suppressed",
            "Notification suppressed by fingerprint window.",
            event_type=event_type,
            segment_path=str(segment_path),
            fingerprint=fingerprint,
            suppressed_count=suppression.get("suppressed_count"),
            last_sent_at=suppression.get("last_sent_at"),
        )
        return {"sent": False, "reason": "suppressed", "fingerprint": fingerprint, **suppression}
    result = send_notification(config, event_type, prefilter, segment_path, report_path=report_path, error=error)
    log_event(
        config,
        "live_analyzer_worker",
        "notification_result",
        "Notification attempt completed.",
        event_type=event_type,
        segment_path=str(segment_path),
        sent=result.get("sent"),
        reason=result.get("reason"),
        status=result.get("status"),
        fingerprint=fingerprint,
    )
    return {**result, "fingerprint": fingerprint}


def _suppression_applies(notification_config: dict[str, Any], prefilter: dict[str, Any]) -> bool:
    if not notification_config.get("enabled", False):
        return False
    webhook = notification_config.get("webhook") or {}
    if not webhook.get("enabled", False) or not str(webhook.get("url") or "").strip():
        return False
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    severity = str((prefilter or {}).get("severity") or "low").lower()
    minimum = str(notification_config.get("min_severity") or "high").lower()
    return order.get(severity, 0) >= order.get(minimum, 2)


if __name__ == "__main__":
    main()
