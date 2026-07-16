from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import web_app
from src.storage.alert_store import AlertStore


def _prefilter_result(segment: str, severity: str = "high", status_reason: str = "marker:log4shell") -> dict:
    return {
        "pcap_path": segment,
        "severity": severity,
        "risk_score": 75,
        "recommended_action": "deep_analysis",
        "reasons": [status_reason],
        "event_count": 5,
        "http_event_count": 4,
        "dns_event_count": 1,
        "tcp_event_count": 0,
        "source_count": 1,
        "destination_count": 1,
        "top_sources": [["10.0.0.5", 5]],
        "top_destinations": [["10.0.0.10", 5]],
    }


def test_metrics_endpoint_exposes_prometheus_text(monkeypatch, tmp_path: Path) -> None:
    alert_db = tmp_path / "alerts.db"
    incoming = tmp_path / "incoming"
    reports = tmp_path / "reports"
    pcaps = tmp_path / "pcap"
    index = tmp_path / "index"
    for path in (incoming, reports, pcaps, index):
        path.mkdir()
    (incoming / "queued.pcap").write_bytes(b"pcap")
    (reports / "flowtragent_report_demo.md").write_text("# demo\n", encoding="utf-8")
    (pcaps / "sample.pcap").write_bytes(b"pcap")
    (index / "vectors.npy").write_bytes(b"index")

    store = AlertStore(alert_db)
    store.upsert_prefilter(_prefilter_result("a.pcap", severity="high"))
    store.mark_reported("a.pcap", reports / "flowtragent_report_demo.md")
    store.upsert_prefilter(_prefilter_result("b.pcap", severity="medium", status_reason="periodic:http"))
    store.mark_rate_limited("b.pcap")
    store.should_send_notification("notify:test", {"event_type": "deep_analysis_reported"}, suppress_window_seconds=300)
    store.should_send_notification("notify:test", {"event_type": "deep_analysis_reported"}, suppress_window_seconds=300)

    monkeypatch.setattr(web_app, "ALERT_DB", alert_db)
    monkeypatch.setitem(web_app.CONFIG["paths"], "report_dir", str(reports))
    monkeypatch.setitem(web_app.CONFIG["paths"], "pcap_dir", str(pcaps))
    monkeypatch.setitem(web_app.CONFIG["paths"], "index_dir", str(index))
    monkeypatch.setitem(web_app.CONFIG.setdefault("live", {}), "incoming_dir", str(incoming))

    response = web_app.app.test_client().get("/metrics")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.mimetype == "text/plain"
    assert "# HELP flowtragent_pcaps_processed_total" in body
    assert "flowtragent_pcaps_processed_total 2" in body
    assert 'flowtragent_alerts_by_severity{severity="high"} 1' in body
    assert 'flowtragent_alerts_by_status{status="reported"} 1' in body
    assert "flowtragent_rate_limited_total 1" in body
    assert "flowtragent_notifications_suppressed_total 1" in body
    assert "flowtragent_live_segment_queue_size 1" in body
    assert "flowtragent_report_files_total 1" in body
    assert "flowtragent_nova_index_ready 1" in body
