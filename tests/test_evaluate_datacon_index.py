from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
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
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    metrics = json.loads(result.stdout)
    assert metrics["samples"] >= 1
    assert "top1_accuracy" in metrics
    assert "topk_recall" in metrics


if __name__ == "__main__":
    main()
