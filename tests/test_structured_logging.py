from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import web_app
from src.core.structured_logging import log_event


def _config(log_path: Path, level: str = "INFO") -> dict:
    return {"observability": {"structured_logs": {"enabled": True, "path": str(log_path), "level": level}}}


def test_log_event_writes_jsonl_and_redacts_sensitive_fields(tmp_path: Path) -> None:
    log_path = tmp_path / "flowtragent.jsonl"

    log_event(
        _config(log_path),
        "test_module",
        "audit_event",
        "Audit message.",
        user="alice",
        token="secret-token",
        nested={"password": "hidden", "value": "kept"},
    )

    record = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert record["timestamp"].endswith("Z")
    assert record["level"] == "INFO"
    assert record["module"] == "test_module"
    assert record["event"] == "audit_event"
    assert record["message"] == "Audit message."
    assert record["user"] == "alice"
    assert record["token"] == "[REDACTED]"
    assert record["nested"]["password"] == "[REDACTED]"
    assert record["nested"]["value"] == "kept"


def test_log_event_respects_level_filter(tmp_path: Path) -> None:
    log_path = tmp_path / "flowtragent.jsonl"

    log_event(_config(log_path, level="WARNING"), "test_module", "debug", "Filtered.", level="INFO")
    log_event(_config(log_path, level="WARNING"), "test_module", "warn", "Written.", level="WARNING")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "warn"


def test_web_payload_analysis_writes_structured_audit_log(monkeypatch, tmp_path: Path) -> None:
    log_path = tmp_path / "web.jsonl"
    monkeypatch.setitem(web_app.CONFIG, "observability", {"structured_logs": {"enabled": True, "path": str(log_path), "level": "INFO"}})
    monkeypatch.setattr(web_app, "run_payload", lambda *args, **kwargs: SimpleNamespace(name="flowtragent_report_stub.md"))

    response = web_app.app.test_client().post("/analyze-payload", data={"payload": "GET /?cmd=whoami HTTP/1.1"})

    assert response.status_code == 200
    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert [record["event"] for record in records] == ["payload_analysis_requested", "report_generated"]
    assert all(record["module"] == "web_app" for record in records)
