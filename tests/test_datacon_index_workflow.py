from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_holdout_fixture_has_required_metadata() -> None:
    path = PROJECT_ROOT / "tests/fixtures/eval_holdout.csv"
    rows = list(csv.DictReader(path.open(newline="", encoding="utf-8")))

    assert len(rows) >= 10
    assert {row["id"] for row in rows} == set(row["id"] for row in rows)
    for row in rows:
        assert row["payload_clean"].strip()
        assert row["cve_labels"].strip()
        assert row["source"].strip()
        assert row["split_note"] == "holdout_excluded_from_index"


def test_build_index_excludes_holdout_ids_and_writes_manifest(tmp_path: Path) -> None:
    output_dir = tmp_path / "index"
    env = os.environ.copy()
    env["FLOWTRAGENT_OFFLINE"] = "1"
    subprocess.run(
        [
            sys.executable,
            "scripts/build_demo_index.py",
            "--input",
            "tests/fixtures/train_payloads.csv",
            "--output-dir",
            str(output_dir),
            "--exclude-ids",
            "demo-log4shell",
        ],
        cwd=PROJECT_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    meta = json.loads((output_dir / "meta.json").read_text(encoding="utf-8"))
    manifest = json.loads((output_dir / "index_manifest.json").read_text(encoding="utf-8"))
    assert "demo-log4shell" not in meta["ids"]
    assert meta["sample_count"] == len(meta["ids"])
    assert manifest["sample_count"] == len(meta["ids"])
    assert meta["cve_distribution"]


def test_evaluation_quality_gate_reports_failure() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/evaluate_datacon_index.py",
            "--input",
            "tests/fixtures/train_payloads.csv",
            "--demo-index",
            "--limit",
            "3",
            "--top-k",
            "3",
            "--quality-gate",
            "--min-topk-recall",
            "1.1",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    metrics = json.loads(result.stdout)
    assert metrics["quality_gate"]["enabled"] is True
    assert metrics["quality_gate"]["passed"] is False


def test_evaluation_reports_root_cause_fields() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/evaluate_datacon_index.py",
            "--input",
            "tests/fixtures/train_payloads.csv",
            "--demo-index",
            "--limit",
            "3",
            "--top-k",
            "3",
            "--min-candidate-score",
            "1.1",
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    metrics = json.loads(result.stdout)
    assert "root_cause_summary" in metrics
    assert metrics["misses"]
    assert all("root_causes" in item for item in metrics["misses"])
