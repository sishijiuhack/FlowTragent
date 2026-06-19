"""Configuration loading for FlowTragent."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    "paths": {
        "csv_dir": "data/csv",
        "index_dir": "data/index",
        "report_dir": "reports",
        "rag_dir": "data/rag",
    },
    "retrieval": {
        "model_name": "sentence-transformers/all-MiniLM-L6-v2",
        "top_k": 5,
    },
    "ollama": {
        "host": "http://127.0.0.1:11434",
        "model": "phi3:mini",
        "enabled": False,
    },
    "live_capture": {
        "duration": 30,
        "packet_count": 0,
    },
}


def load_config(path: str | Path = "config/config.yaml") -> Dict[str, Any]:
    config = _deep_copy(DEFAULT_CONFIG)
    config_path = Path(path)
    if config_path.exists():
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Config file must contain a mapping: {config_path}")
        _deep_merge(config, loaded)
    return config


def _deep_merge(target: Dict[str, Any], source: Dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        else:
            target[key] = value


def _deep_copy(value: Dict[str, Any]) -> Dict[str, Any]:
    return {key: _deep_copy(item) if isinstance(item, dict) else item for key, item in value.items()}

