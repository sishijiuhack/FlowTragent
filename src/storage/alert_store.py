"""SQLite alert storage for live server mode."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
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
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_live_alerts_created_at ON live_alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_live_alerts_status ON live_alerts(status);
CREATE INDEX IF NOT EXISTS idx_live_alerts_severity ON live_alerts(severity);
"""


class AlertStore:
    """Small SQLite wrapper for live alert state."""

    def __init__(self, db_path: str | Path = "data/live/alerts.db") -> None:
        self.db_path = Path(db_path)
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
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO live_alerts (
                    segment_path, created_at, updated_at, status, severity, risk_score,
                    recommended_action, reasons_json, stats_json, report_path, error
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                ON CONFLICT(segment_path) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    status=excluded.status,
                    severity=excluded.severity,
                    risk_score=excluded.risk_score,
                    recommended_action=excluded.recommended_action,
                    reasons_json=excluded.reasons_json,
                    stats_json=excluded.stats_json,
                    error=excluded.error
                """,
                (
                    segment_path,
                    now,
                    now,
                    status,
                    str(result.get("severity") or "low"),
                    int(result.get("risk_score") or 0),
                    str(result.get("recommended_action") or "skip"),
                    json.dumps(result.get("reasons") or [], ensure_ascii=False),
                    json.dumps(stats, ensure_ascii=False),
                    result.get("error"),
                ),
            )
            row = conn.execute("SELECT id FROM live_alerts WHERE segment_path = ?", (segment_path,)).fetchone()
            return int(row["id"])

    def mark_analyzing(self, segment_path: str | Path) -> None:
        self._update(segment_path, status="analyzing")

    def mark_skipped(self, segment_path: str | Path) -> None:
        self._update(segment_path, status="skipped")

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
