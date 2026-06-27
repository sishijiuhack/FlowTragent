from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.storage.alert_store import AlertStore


def main() -> None:
    db_path = PROJECT_ROOT / "data/tmp/test_alerts.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    store = AlertStore(db_path)
    result = {
        "pcap_path": "data/live/incoming/segment_test.pcap",
        "risk_score": 88,
        "severity": "critical",
        "recommended_action": "deep_analysis",
        "reasons": ["http_critical:log4shell_jndi"],
        "event_count": 1,
        "http_event_count": 1,
        "dns_event_count": 0,
        "tcp_event_count": 0,
        "source_count": 1,
        "destination_count": 1,
        "top_sources": [("10.10.10.5", 1)],
        "top_destinations": [("10.10.10.20:80", 1)],
    }
    alert_id = store.upsert_prefilter(result)
    assert alert_id > 0
    item = store.get_by_segment(result["pcap_path"])
    assert item is not None
    assert item["severity"] == "critical"
    assert item["reasons"] == ["http_critical:log4shell_jndi"]
    store.mark_analyzing(result["pcap_path"])
    assert store.get_by_segment(result["pcap_path"])["status"] == "analyzing"
    store.mark_reported(result["pcap_path"], "reports/example.md")
    reported = store.get_by_segment(result["pcap_path"])
    assert reported["status"] == "reported"
    assert reported["report_path"] == "reports/example.md"
    assert store.list_alerts(limit=10)


if __name__ == "__main__":
    main()
