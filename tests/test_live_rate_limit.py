from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

from src.storage.alert_store import AlertStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_worker():
    path = PROJECT_ROOT / "scripts/live_analyzer_worker.py"
    spec = importlib.util.spec_from_file_location("live_analyzer_worker_rate_limit", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _deep_result(path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        to_dict=lambda: {
            "pcap_path": str(path),
            "severity": "high",
            "risk_score": 80,
            "recommended_action": "deep_analysis",
            "reasons": ["marker:log4shell_jndi"],
            "event_count": 1,
            "http_event_count": 1,
            "dns_event_count": 0,
            "tcp_event_count": 0,
            "source_count": 1,
            "destination_count": 1,
            "top_sources": [],
            "top_destinations": [],
        }
    )


def test_live_analyzer_marks_rate_limited(monkeypatch, tmp_path: Path) -> None:
    worker = _load_worker()
    segment = tmp_path / "segment.pcap"
    segment.write_bytes(b"pcap")
    store = AlertStore(tmp_path / "alerts.db")
    reports = tmp_path / "reports"
    reports.mkdir()
    report = reports / "report.md"
    report.write_text("# report\n", encoding="utf-8")
    log_path = tmp_path / "worker.jsonl"
    config = {"observability": {"structured_logs": {"enabled": True, "path": str(log_path), "level": "INFO"}}}
    notifications = []

    monkeypatch.setattr(worker, "prefilter_pcap", lambda path, min_risk_score, config: _deep_result(Path(path)))
    monkeypatch.setattr(worker, "run_pcap", lambda *args, **kwargs: report)
    monkeypatch.setattr(worker, "_notify", lambda config, store, event_type, prefilter, segment_path, report_path=None, error=None: notifications.append((event_type, str(segment_path), str(report_path) if report_path else None, error)) or {"sent": True})

    output = worker.process_segment(
        segment,
        config=config,
        store=store,
        output_dir=reports,
        max_deep_analyses_per_hour=0,
    )
    assert output["status"] == "reported"

    second = tmp_path / "segment-2.pcap"
    second.write_bytes(b"pcap")
    output = worker.process_segment(
        second,
        config=config,
        store=store,
        output_dir=reports,
        max_deep_analyses_per_hour=1,
    )

    assert output["status"] == "rate_limited"
    alert = store.get_by_segment(second)
    assert alert is not None
    assert alert["status"] == "rate_limited"
    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert "segment_rate_limited" in {record["event"] for record in records}
    assert [item[0] for item in notifications] == ["deep_analysis_reported", "segment_rate_limited"]


def test_worker_notification_suppression_skips_duplicate_send(monkeypatch, tmp_path: Path) -> None:
    worker = _load_worker()
    store = AlertStore(tmp_path / "alerts.db")
    log_path = tmp_path / "worker.jsonl"
    config = {
        "observability": {"structured_logs": {"enabled": True, "path": str(log_path), "level": "INFO"}},
        "notification": {
            "enabled": True,
            "min_severity": "high",
            "suppress_window_seconds": 300,
            "webhook": {"enabled": True, "url": "https://example.invalid/hook"},
        },
    }
    sent = []
    prefilter = _deep_result(tmp_path / "segment.pcap").to_dict()

    def fake_send_notification(config, event_type, prefilter, segment_path, report_path=None, error=None):
        sent.append((event_type, str(segment_path)))
        return {"sent": True, "reason": "sent", "status": 204}

    monkeypatch.setattr(worker, "send_notification", fake_send_notification)

    first = worker._notify(config, store, "deep_analysis_reported", prefilter, tmp_path / "a.pcap")
    second = worker._notify(config, store, "deep_analysis_reported", prefilter, tmp_path / "b.pcap")

    assert first["sent"] is True
    assert second["sent"] is False
    assert second["reason"] == "suppressed"
    assert sent == [("deep_analysis_reported", str(tmp_path / "a.pcap"))]
    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert "notification_suppressed" in {record["event"] for record in records}
