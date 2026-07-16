from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import main
from src.orchestrator import pipeline
from src.orchestrator.analyzer import analyze_evidence


def test_main_is_cli_router_and_pipeline_exports_analysis_entrypoints() -> None:
    main_text = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
    assert hasattr(main, "parse_args")
    assert main.run_payload is pipeline.run_payload
    assert main.run_pcap is pipeline.run_pcap
    assert callable(analyze_evidence)
    assert "def run_payload" not in main_text
    assert "def run_pcap" not in main_text
    assert "def analyze_evidence" not in main_text
