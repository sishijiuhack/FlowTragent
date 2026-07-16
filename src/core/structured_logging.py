"""Structured JSON Lines audit logging."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SENSITIVE_KEYS = {"token", "authorization", "password", "secret", "flowtragent_token"}


def log_event(
    config: dict[str, Any],
    module: str,
    event: str,
    message: str,
    level: str = "INFO",
    **fields: Any,
) -> None:
    """Append one structured JSONL audit event if structured logging is enabled."""
    settings = ((config or {}).get("observability") or {}).get("structured_logs") or {}
    if settings.get("enabled", True) is False:
        return
    path = Path(settings.get("path") or "logs/flowtragent.jsonl")
    minimum = _level_value(str(settings.get("level") or "INFO"))
    current = _level_value(level)
    if current < minimum:
        return
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "level": _level_name(level),
        "module": module,
        "event": event,
        "message": message,
        **_sanitize(fields),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in SENSITIVE_KEYS:
                output[key_text] = "[REDACTED]"
            else:
                output[key_text] = _sanitize(item)
        return output
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _level_name(level: str) -> str:
    return str(level or "INFO").upper()


def _level_value(level: str) -> int:
    return {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}.get(_level_name(level), 20)
