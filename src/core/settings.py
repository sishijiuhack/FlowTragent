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
    "live": {
        "alert_merge_seconds": 180,
        "max_deep_analyses_per_hour": 60,
    },
    "observability": {
        "structured_logs": {
            "enabled": True,
            "path": "logs/flowtragent.jsonl",
            "level": "INFO",
        },
    },
    "notification": {
        "enabled": False,
        "min_severity": "high",
        "suppress_window_seconds": 300,
        "webhook": {
            "enabled": False,
            "url": "",
            "timeout_seconds": 5,
            "headers": {},
        },
    },
    "detection": {
        "attack_chain": {
            "recon_distinct_uri_threshold": 8,
            "strong_cve_score_threshold": 0.75,
        },
        "c2": {
            "http_min_requests": 4,
            "http_repeated_uri_divisor": 3,
            "http_small_response_bytes": 120,
            "http_small_response_ratio": 0.75,
            "http_timing_jitter_ratio": 0.25,
            "dns_min_requests": 4,
            "dns_jitter_ratio": 0.3,
            "dns_long_label_min": 32,
            "dns_high_entropy_label_min": 24,
            "dns_unique_query_ratio": 0.75,
            "tcp_min_packets": 4,
            "tcp_timing_jitter_ratio": 0.25,
            "tcp_small_payload_bytes": 128,
            "tcp_small_payload_ratio": 0.75,
            "tcp_ephemeral_unique_ratio": 0.75,
            "common_service_ports": [22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995],
        },
        "prefilter": {
            "marker_weights": {
                "critical": {"log4shell_jndi": 70, "spring4shell": 55, "webshell_upload": 30},
                "suspicious": {
                    "path_traversal": 35,
                    "encoded_path_traversal": 45,
                    "sql_injection": 35,
                    "command_exec_cmd": 35,
                    "command_exec_exec": 35,
                    "curl_download": 40,
                    "wget_download": 40,
                    "powershell": 45,
                    "certutil": 45,
                    "whoami": 25,
                    "base64": 20,
                    "php_wrapper": 35,
                },
            },
            "common_service_ports": [20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3389, 8080, 8443],
            "tcp_external_port_min": 1024,
            "tcp_external_port_score": 8,
            "periodic_min_events": 3,
            "periodic_min_avg_seconds": 2,
            "periodic_max_avg_seconds": 300,
            "periodic_max_jitter": 0.35,
            "periodic_http_dns_score": 25,
            "periodic_tcp_score": 18,
            "many_destinations_threshold": 20,
            "many_destinations_score": 20,
            "many_sources_threshold": 20,
            "many_sources_score": 15,
            "dns_long_query_length": 90,
            "dns_long_query_score": 20,
            "dns_long_label_length": 40,
            "dns_long_label_score": 20,
            "dns_entropy_threshold": 3.8,
            "dns_entropy_label_length": 24,
            "dns_entropy_score": 18,
            "dns_txt_score": 10,
            "max_score": 100,
            "severity": {"critical_score": 85, "high_score": 60, "medium_score": 30},
        },
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
