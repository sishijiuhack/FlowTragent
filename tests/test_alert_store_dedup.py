from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.storage.alert_store import AlertStore


def _prefilter_result(segment: str) -> dict:
    return {
        "pcap_path": segment,
        "severity": "high",
        "risk_score": 75,
        "recommended_action": "deep_analysis",
        "reasons": ["marker:log4shell_jndi", "periodic:http"],
        "event_count": 10,
        "http_event_count": 8,
        "dns_event_count": 0,
        "tcp_event_count": 2,
        "source_count": 1,
        "destination_count": 1,
        "top_sources": [["10.0.0.5", 10]],
        "top_destinations": [["10.0.0.10", 10]],
    }


def _activity_result(segment: str, reasons: list[str], dst: str = "10.0.0.10") -> dict:
    item = _prefilter_result(segment)
    item["reasons"] = reasons
    item["top_destinations"] = [[dst, 10]]
    return item


def test_duplicate_alert_updates_occurrence_count(tmp_path: Path) -> None:
    store = AlertStore(tmp_path / "alerts.db")

    first_id = store.upsert_prefilter(_prefilter_result("data/live/incoming/a.pcap"))
    second_id = store.upsert_prefilter(_prefilter_result("data/live/incoming/b.pcap"))

    assert first_id == second_id
    alerts = store.list_alerts()
    assert len(alerts) == 1
    assert alerts[0]["segment_path"] == "data/live/incoming/b.pcap"
    assert alerts[0]["occurrence_count"] == 2
    assert alerts[0]["alert_fingerprint"]
    assert alerts[0]["first_seen_at"]
    assert alerts[0]["last_seen_at"]


def test_alert_store_migrates_existing_database(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE live_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                segment_path TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                recommended_action TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                stats_json TEXT NOT NULL,
                report_path TEXT,
                error TEXT
            )
            """
        )

    store = AlertStore(db_path)
    alert_id = store.upsert_prefilter(_prefilter_result("data/live/incoming/new.pcap"))

    assert alert_id == 1
    alert = store.get_by_segment("data/live/incoming/new.pcap")
    assert alert is not None
    assert alert["occurrence_count"] == 1
    assert "alert_fingerprint" in alert


def test_same_alert_merges_across_consecutive_windows(tmp_path: Path) -> None:
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path, merge_window_seconds=180)
    first_id = store.upsert_prefilter(_prefilter_result("data/live/incoming/window-1.pcap"))
    older = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE live_alerts SET updated_at = ?, last_seen_at = ? WHERE id = ?", (older, older, first_id))

    second_id = store.upsert_prefilter(_prefilter_result("data/live/incoming/window-2.pcap"))

    assert second_id == first_id
    alerts = store.list_alerts()
    assert len(alerts) == 1
    assert alerts[0]["segment_path"] == "data/live/incoming/window-2.pcap"
    assert alerts[0]["occurrence_count"] == 2
    assert alerts[0]["first_seen_at"] <= alerts[0]["last_seen_at"]


def test_same_alert_outside_merge_window_creates_new_record(tmp_path: Path) -> None:
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path, merge_window_seconds=60)
    first_id = store.upsert_prefilter(_prefilter_result("data/live/incoming/old-window.pcap"))
    older = (datetime.now(timezone.utc) - timedelta(seconds=300)).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE live_alerts SET updated_at = ?, last_seen_at = ? WHERE id = ?", (older, older, first_id))

    second_id = store.upsert_prefilter(_prefilter_result("data/live/incoming/new-window.pcap"))

    assert second_id != first_id
    assert len(store.list_alerts()) == 2


def test_activity_view_correlates_related_alerts_across_windows(tmp_path: Path) -> None:
    store = AlertStore(tmp_path / "alerts.db", merge_window_seconds=60)
    store.upsert_prefilter(_activity_result("data/live/incoming/window-1.pcap", ["marker:scan", "periodic:http"]))
    store.upsert_prefilter(_activity_result("data/live/incoming/window-2.pcap", ["marker:rce", "c2:http"]))

    activities = store.list_activities(activity_window_seconds=900)

    assert len(activities) == 1
    assert activities[0]["source"] == "10.0.0.5"
    assert activities[0]["destination"] == "10.0.0.10"
    assert activities[0]["alert_count"] == 2
    assert activities[0]["occurrence_count"] == 2
    assert "marker" in activities[0]["reason_families"]


def test_activity_view_keeps_unrelated_destinations_separate(tmp_path: Path) -> None:
    store = AlertStore(tmp_path / "alerts.db", merge_window_seconds=60)
    store.upsert_prefilter(_activity_result("data/live/incoming/window-1.pcap", ["marker:scan"], dst="10.0.0.10"))
    store.upsert_prefilter(_activity_result("data/live/incoming/window-2.pcap", ["marker:rce"], dst="10.0.0.20"))

    activities = store.list_activities(activity_window_seconds=900)

    assert len(activities) == 2


def test_activity_view_respects_activity_window(tmp_path: Path) -> None:
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path, merge_window_seconds=60)
    first_id = store.upsert_prefilter(_activity_result("data/live/incoming/window-1.pcap", ["marker:scan"]))
    older = (datetime.now(timezone.utc) - timedelta(seconds=3600)).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE live_alerts SET created_at = ?, updated_at = ?, first_seen_at = ?, last_seen_at = ? WHERE id = ?",
            (older, older, older, older, first_id),
        )
    store.upsert_prefilter(_activity_result("data/live/incoming/window-2.pcap", ["marker:rce"]))

    activities = store.list_activities(activity_window_seconds=900)

    assert len(activities) == 2


def test_notification_suppression_allows_once_per_window(tmp_path: Path) -> None:
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path)
    fingerprint = "notify:test"
    event = {"event_type": "deep_analysis_reported", "segment_path": "a.pcap"}

    first = store.should_send_notification(fingerprint, event, suppress_window_seconds=300)
    second = store.should_send_notification(fingerprint, {**event, "segment_path": "b.pcap"}, suppress_window_seconds=300)

    assert first["send"] is True
    assert second["send"] is False
    assert second["reason"] == "suppressed"
    assert second["suppressed_count"] == 1


def test_notification_suppression_window_elapsed_allows_resend(tmp_path: Path) -> None:
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path)
    fingerprint = "notify:test"
    event = {"event_type": "deep_analysis_reported", "segment_path": "a.pcap"}
    first = store.should_send_notification(fingerprint, event, suppress_window_seconds=300)
    older = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE notification_state SET last_sent_at = ? WHERE fingerprint = ?", (older, fingerprint))

    second = store.should_send_notification(fingerprint, {**event, "segment_path": "b.pcap"}, suppress_window_seconds=300)

    assert first["send"] is True
    assert second["send"] is True
    assert second["reason"] == "window_elapsed"
