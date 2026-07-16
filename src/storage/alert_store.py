"""SQLite alert storage for live server mode."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS live_alerts (
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
    error TEXT,
    alert_fingerprint TEXT,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    first_seen_at TEXT,
    last_seen_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_live_alerts_created_at ON live_alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_live_alerts_status ON live_alerts(status);
CREATE INDEX IF NOT EXISTS idx_live_alerts_severity ON live_alerts(severity);
CREATE TABLE IF NOT EXISTS notification_state (
    fingerprint TEXT PRIMARY KEY,
    first_sent_at TEXT NOT NULL,
    last_sent_at TEXT NOT NULL,
    sent_count INTEGER NOT NULL DEFAULT 1,
    suppressed_count INTEGER NOT NULL DEFAULT 0,
    last_event_json TEXT NOT NULL
);
"""

DEFAULT_MERGE_WINDOW_SECONDS = 180
DEFAULT_ACTIVITY_WINDOW_SECONDS = 900


class AlertStore:
    """Small SQLite wrapper for live alert state."""

    def __init__(self, db_path: str | Path = "data/live/alerts.db", merge_window_seconds: int = DEFAULT_MERGE_WINDOW_SECONDS) -> None:
        self.db_path = Path(db_path)
        self.merge_window_seconds = max(1, int(merge_window_seconds))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def upsert_prefilter(self, result: dict[str, Any], status: str = "prefiltered") -> int:
        now = _now()
        segment_path = str(result.get("pcap_path") or result.get("segment_path") or "")
        if not segment_path:
            raise ValueError("prefilter result must include pcap_path")
        stats = {
            key: result.get(key)
            for key in [
                "event_count",
                "http_event_count",
                "dns_event_count",
                "tcp_event_count",
                "source_count",
                "destination_count",
                "top_sources",
                "top_destinations",
            ]
        }
        reasons = result.get("reasons") or []
        severity = str(result.get("severity") or "low")
        risk_score = int(result.get("risk_score") or 0)
        recommended_action = str(result.get("recommended_action") or "skip")
        fingerprint = _alert_fingerprint(result)
        with self._connect() as conn:
            duplicate = conn.execute(
                """
                SELECT id, occurrence_count FROM live_alerts
                WHERE alert_fingerprint = ? AND updated_at >= ?
                ORDER BY datetime(updated_at) DESC, id DESC
                LIMIT 1
                """,
                (fingerprint, _seconds_ago(self.merge_window_seconds)),
            ).fetchone()
            if duplicate:
                conn.execute(
                    """
                    UPDATE live_alerts SET
                        segment_path = ?,
                        updated_at = ?,
                        status = ?,
                        severity = ?,
                        risk_score = ?,
                        recommended_action = ?,
                        reasons_json = ?,
                        stats_json = ?,
                        error = ?,
                        occurrence_count = ?,
                        last_seen_at = ?
                    WHERE id = ?
                    """,
                    (
                        segment_path,
                        now,
                        status,
                        severity,
                        risk_score,
                        recommended_action,
                        json.dumps(reasons, ensure_ascii=False),
                        json.dumps(stats, ensure_ascii=False),
                        result.get("error"),
                        int(duplicate["occurrence_count"] or 1) + 1,
                        now,
                        int(duplicate["id"]),
                    ),
                )
                return int(duplicate["id"])
            conn.execute(
                """
                INSERT INTO live_alerts (
                    segment_path, created_at, updated_at, status, severity, risk_score,
                    recommended_action, reasons_json, stats_json, report_path, error,
                    alert_fingerprint, occurrence_count, first_seen_at, last_seen_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, 1, ?, ?)
                ON CONFLICT(segment_path) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    status=excluded.status,
                    severity=excluded.severity,
                    risk_score=excluded.risk_score,
                    recommended_action=excluded.recommended_action,
                    reasons_json=excluded.reasons_json,
                    stats_json=excluded.stats_json,
                    error=excluded.error,
                    alert_fingerprint=excluded.alert_fingerprint,
                    last_seen_at=excluded.last_seen_at
                """,
                (
                    segment_path,
                    now,
                    now,
                    status,
                    severity,
                    risk_score,
                    recommended_action,
                    json.dumps(reasons, ensure_ascii=False),
                    json.dumps(stats, ensure_ascii=False),
                    result.get("error"),
                    fingerprint,
                    now,
                    now,
                ),
            )
            row = conn.execute("SELECT id FROM live_alerts WHERE segment_path = ?", (segment_path,)).fetchone()
            return int(row["id"])

    def mark_analyzing(self, segment_path: str | Path) -> None:
        self._update(segment_path, status="analyzing")

    def mark_skipped(self, segment_path: str | Path) -> None:
        self._update(segment_path, status="skipped")

    def mark_rate_limited(self, segment_path: str | Path) -> None:
        self._update(segment_path, status="rate_limited", error="deep analysis rate limit exceeded")

    def mark_reported(self, segment_path: str | Path, report_path: str | Path) -> None:
        self._update(segment_path, status="reported", report_path=str(report_path), error=None)

    def mark_error(self, segment_path: str | Path, error: str) -> None:
        self._update(segment_path, status="error", error=error)

    def get_by_segment(self, segment_path: str | Path) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM live_alerts WHERE segment_path = ?", (str(segment_path),)).fetchone()
        return _row_to_dict(row) if row else None

    def list_alerts(self, limit: int = 100, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM live_alerts"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY datetime(created_at) DESC, id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_row_to_dict(row) for row in rows]

    def list_activities(self, limit: int = 100, activity_window_seconds: int = DEFAULT_ACTIVITY_WINDOW_SECONDS) -> list[dict[str, Any]]:
        """Build a cross-window activity view from recent alerts.

        Activities are derived from stored alerts so existing databases remain
        compatible. Alerts are linked when they involve the same top source and
        destination, occur close together, and share at least one reason family.
        """
        alerts = sorted(self.list_alerts(limit=limit), key=lambda item: _parse_time(item.get("first_seen_at") or item.get("created_at")) or datetime.min.replace(tzinfo=timezone.utc))
        activities: list[dict[str, Any]] = []
        for alert in alerts:
            key = _activity_key(alert)
            if not key:
                continue
            first_seen = alert.get("first_seen_at") or alert.get("created_at")
            last_seen = alert.get("last_seen_at") or alert.get("updated_at")
            reasons = _reason_families(alert.get("reasons") or [])
            matched = None
            for activity in activities:
                if activity["key"] != key:
                    continue
                if not (activity["reason_families"] & reasons):
                    continue
                if not _times_close(activity.get("last_seen_at"), first_seen, activity_window_seconds):
                    continue
                matched = activity
                break
            if matched is None:
                matched = {
                    "activity_id": f"activity-{len(activities) + 1}",
                    "key": key,
                    "source": key[0],
                    "destination": key[1],
                    "first_seen_at": first_seen,
                    "last_seen_at": last_seen,
                    "severity": alert.get("severity") or "low",
                    "max_risk_score": int(alert.get("risk_score") or 0),
                    "alert_count": 0,
                    "occurrence_count": 0,
                    "reason_families": set(),
                    "segments": [],
                    "reports": [],
                    "status_set": set(),
                }
                activities.append(matched)
            matched["first_seen_at"] = _min_time_text(matched.get("first_seen_at"), first_seen)
            matched["last_seen_at"] = _max_time_text(matched.get("last_seen_at"), last_seen)
            matched["severity"] = _max_severity(str(matched.get("severity") or "low"), str(alert.get("severity") or "low"))
            matched["max_risk_score"] = max(int(matched.get("max_risk_score") or 0), int(alert.get("risk_score") or 0))
            matched["alert_count"] = int(matched.get("alert_count") or 0) + 1
            matched["occurrence_count"] = int(matched.get("occurrence_count") or 0) + int(alert.get("occurrence_count") or 1)
            matched["reason_families"].update(reasons)
            matched["status_set"].add(str(alert.get("status") or "unknown"))
            if alert.get("segment_path"):
                matched["segments"].append(alert["segment_path"])
            if alert.get("report_path"):
                matched["reports"].append(alert["report_path"])

        output = []
        for activity in activities:
            item = dict(activity)
            item["reason_families"] = sorted(item["reason_families"])
            item["statuses"] = sorted(item.pop("status_set"))
            item["segments"] = item["segments"][:8]
            item["reports"] = item["reports"][:8]
            output.append(item)
        return sorted(output, key=lambda item: _parse_time(item.get("last_seen_at")) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)

    def count_deep_analyses_since(self, since: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count FROM live_alerts
                WHERE (status IN ('analyzing', 'reported', 'error') OR report_path IS NOT NULL) AND updated_at >= ?
                """,
                (since,),
            ).fetchone()
        return int(row["count"] or 0)

    def metrics_summary(self) -> dict[str, Any]:
        """Return aggregate counters used by the Prometheus metrics endpoint."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS count FROM live_alerts").fetchone()
            by_status = conn.execute("SELECT status, COUNT(*) AS count FROM live_alerts GROUP BY status").fetchall()
            by_severity = conn.execute("SELECT severity, COUNT(*) AS count FROM live_alerts GROUP BY severity").fetchall()
            occurrence = conn.execute("SELECT COALESCE(SUM(occurrence_count), 0) AS count FROM live_alerts").fetchone()
            deep = conn.execute(
                """
                SELECT COUNT(*) AS count FROM live_alerts
                WHERE status IN ('analyzing', 'reported', 'error') OR report_path IS NOT NULL
                """
            ).fetchone()
            rate_limited = conn.execute("SELECT COUNT(*) AS count FROM live_alerts WHERE status = 'rate_limited'").fetchone()
            suppressed = conn.execute("SELECT COALESCE(SUM(suppressed_count), 0) AS count FROM notification_state").fetchone()
        return {
            "alerts_total": int(total["count"] or 0),
            "alerts_by_status": {str(row["status"]): int(row["count"] or 0) for row in by_status},
            "alerts_by_severity": {str(row["severity"]): int(row["count"] or 0) for row in by_severity},
            "occurrences_total": int(occurrence["count"] or 0),
            "deep_analyses_total": int(deep["count"] or 0),
            "rate_limited_total": int(rate_limited["count"] or 0),
            "notifications_suppressed_total": int(suppressed["count"] or 0),
        }

    def should_send_notification(self, fingerprint: str, event: dict[str, Any], suppress_window_seconds: int) -> dict[str, Any]:
        """Record notification intent and decide whether it should be sent."""
        now = _now()
        window = max(1, int(suppress_window_seconds))
        payload = json.dumps(event, ensure_ascii=False, sort_keys=True)
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM notification_state WHERE fingerprint = ?", (fingerprint,)).fetchone()
            if row and _times_close(row["last_sent_at"], now, window):
                suppressed_count = int(row["suppressed_count"] or 0) + 1
                conn.execute(
                    """
                    UPDATE notification_state SET
                        suppressed_count = ?,
                        last_event_json = ?
                    WHERE fingerprint = ?
                    """,
                    (suppressed_count, payload, fingerprint),
                )
                return {
                    "send": False,
                    "reason": "suppressed",
                    "fingerprint": fingerprint,
                    "last_sent_at": row["last_sent_at"],
                    "suppressed_count": suppressed_count,
                }
            if row:
                sent_count = int(row["sent_count"] or 1) + 1
                conn.execute(
                    """
                    UPDATE notification_state SET
                        last_sent_at = ?,
                        sent_count = ?,
                        last_event_json = ?
                    WHERE fingerprint = ?
                    """,
                    (now, sent_count, payload, fingerprint),
                )
                return {"send": True, "reason": "window_elapsed", "fingerprint": fingerprint, "last_sent_at": now, "sent_count": sent_count}
            conn.execute(
                """
                INSERT INTO notification_state (
                    fingerprint, first_sent_at, last_sent_at, sent_count,
                    suppressed_count, last_event_json
                ) VALUES (?, ?, ?, 1, 0, ?)
                """,
                (fingerprint, now, now, payload),
            )
            return {"send": True, "reason": "first_seen", "fingerprint": fingerprint, "last_sent_at": now, "sent_count": 1}

    def _update(self, segment_path: str | Path, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = _now()
        assignments = ", ".join(f"{key} = ?" for key in fields)
        params = [*fields.values(), str(segment_path)]
        with self._connect() as conn:
            conn.execute(f"UPDATE live_alerts SET {assignments} WHERE segment_path = ?", params)

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            _ensure_columns(conn)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_live_alerts_fingerprint ON live_alerts(alert_fingerprint, updated_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_notification_state_last_sent ON notification_state(last_sent_at)")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["reasons"] = json.loads(item.pop("reasons_json") or "[]")
    item["stats"] = json.loads(item.pop("stats_json") or "{}")
    return item


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _seconds_ago(seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _alert_fingerprint(result: dict[str, Any]) -> str:
    reasons = sorted(str(item) for item in (result.get("reasons") or []))
    key = {
        "severity": str(result.get("severity") or "low"),
        "recommended_action": str(result.get("recommended_action") or "skip"),
        "reasons": reasons,
    }
    return json.dumps(key, ensure_ascii=False, sort_keys=True)


def _activity_key(alert: dict[str, Any]) -> tuple[str, str] | None:
    stats = alert.get("stats") or {}
    source = _top_endpoint(stats.get("top_sources")) or "unknown-src"
    destination = _top_endpoint(stats.get("top_destinations")) or "unknown-dst"
    if source == "unknown-src" and destination == "unknown-dst":
        return None
    return source, destination


def _top_endpoint(values: Any) -> str | None:
    if not values:
        return None
    first = values[0]
    if isinstance(first, (list, tuple)) and first:
        return str(first[0])
    if isinstance(first, dict):
        return str(first.get("ip") or first.get("host") or first.get("value") or "") or None
    return str(first)


def _reason_families(reasons: list[Any]) -> set[str]:
    families = set()
    for reason in reasons:
        text = str(reason)
        if ":" in text:
            families.add(text.split(":", 1)[0])
        else:
            families.add(text)
    return families or {"unknown"}


def _times_close(left: str | None, right: str | None, window_seconds: int) -> bool:
    left_dt = _parse_time(left)
    right_dt = _parse_time(right)
    if left_dt is None or right_dt is None:
        return True
    return abs((right_dt - left_dt).total_seconds()) <= max(1, int(window_seconds))


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _min_time_text(left: str | None, right: str | None) -> str | None:
    left_dt = _parse_time(left)
    right_dt = _parse_time(right)
    if left_dt is None:
        return right
    if right_dt is None:
        return left
    return left if left_dt <= right_dt else right


def _max_time_text(left: str | None, right: str | None) -> str | None:
    left_dt = _parse_time(left)
    right_dt = _parse_time(right)
    if left_dt is None:
        return right
    if right_dt is None:
        return left
    return left if left_dt >= right_dt else right


def _max_severity(left: str, right: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _ensure_columns(conn: sqlite3.Connection) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(live_alerts)").fetchall()}
    migrations = {
        "alert_fingerprint": "ALTER TABLE live_alerts ADD COLUMN alert_fingerprint TEXT",
        "occurrence_count": "ALTER TABLE live_alerts ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1",
        "first_seen_at": "ALTER TABLE live_alerts ADD COLUMN first_seen_at TEXT",
        "last_seen_at": "ALTER TABLE live_alerts ADD COLUMN last_seen_at TEXT",
    }
    for column, sql in migrations.items():
        if column not in existing:
            conn.execute(sql)
