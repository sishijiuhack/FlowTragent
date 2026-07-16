from __future__ import annotations

import importlib.util
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class FakeOllama:
    def __init__(self, host: str, model: str) -> None:
        self.host = host
        self.model = model

    def is_available(self) -> bool:
        return True

    def has_model(self, model: str) -> bool:
        return True

    def generate(self, prompt: str, json_format: bool = False) -> str:
        return json.dumps(
            {
                "schema_version": "llm-summary-v1",
                "summary": "Scheduled review summary.",
                "supported_claims": [{"claim": "Evidence supports the deterministic verdict.", "evidence_ids": ["pkt-1"]}],
                "unsupported_claims": [],
                "recommended_actions": ["Review affected host."],
            }
        )


class UnavailableOllama(FakeOllama):
    def is_available(self) -> bool:
        return False


def _load_review_module():
    path = PROJECT_ROOT / "scripts/scheduled_ollama_review.py"
    spec = importlib.util.spec_from_file_location("scheduled_ollama_review", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _write_report(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "impact_assessment": {"verdict": "Likely successful exploitation", "confidence": "high"},
                "top_cves": [{"cve": "CVE-2021-44228", "score": 0.95, "rule_confirmed": True}],
                "agent_findings": {
                    "evidence_pack": [
                        {
                            "evidence_id": "pkt-1",
                            "evidence_type": "HTTP",
                            "source": "10.0.0.5",
                            "target": "10.0.0.10",
                            "related": [],
                            "summary": "Exploit payload observed.",
                        }
                    ],
                    "next_actions": ["Review affected host."],
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def test_scheduled_review_updates_report_json(tmp_path: Path) -> None:
    module = _load_review_module()
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    report = report_dir / "flowtragent_report_test.json"
    _write_report(report)
    config = {
        "paths": {"report_dir": str(report_dir)},
        "live": {"ollama_mode": "scheduled", "alert_db": str(tmp_path / "missing.db")},
        "ollama": {"host": "http://127.0.0.1:11434", "model": "phi3:mini"},
    }

    results = module.run_scheduled_review(config, report_dir=report_dir, client_factory=FakeOllama)

    assert results[0]["status"] == "reviewed"
    updated = json.loads(report.read_text(encoding="utf-8"))
    assert updated["llm_review_mode"] == "scheduled"
    assert updated["llm_structured_summary"]["status"] == "ok"
    assert updated["llm_summary"] == "Scheduled review summary."


def test_scheduled_review_skips_when_ollama_unavailable(tmp_path: Path) -> None:
    module = _load_review_module()
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    report = report_dir / "flowtragent_report_test.json"
    _write_report(report)
    config = {
        "paths": {"report_dir": str(report_dir)},
        "live": {"ollama_mode": "scheduled", "alert_db": str(tmp_path / "missing.db")},
        "ollama": {"host": "http://127.0.0.1:11434", "model": "phi3:mini"},
    }

    results = module.run_scheduled_review(config, report_dir=report_dir, client_factory=UnavailableOllama)

    assert results == [{"status": "ollama_unavailable", "model": "phi3:mini"}]
    unchanged = json.loads(report.read_text(encoding="utf-8"))
    assert "llm_structured_summary" not in unchanged
