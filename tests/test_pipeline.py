from __future__ import annotations

import subprocess
import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    subprocess.run([sys.executable, "tests/make_demo_pcap.py"], cwd=PROJECT_ROOT, check=True)
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--mode",
            "pcap",
            "--input",
            "data/pcap/demo_attack.pcap",
            "--demo-index",
            "--enable-rag",
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    assert "report" in result.stdout
    report_path = PROJECT_ROOT / json.loads(result.stdout)["report"]
    report = report_path.read_text(encoding="utf-8")
    assert "## Agent Metadata" in report
    assert "Schema: `agent-v1`" in report
    assert "Mode: `deterministic`" in report
    assert "Orchestration:" in report
    assert "## Executive Summary" in report
    assert "## CVE Evidence" in report
    assert "## Agent Evidence Pack" in report
    assert "## Agent Reasoning" in report
    assert "## Next Actions" in report
    assert "## Evidence Gaps" in report
    assert "pkt-1" in report
    assert "## Impact Assessment" in report
    assert "Likely exploitation attempt with successful HTTP response" in report
    assert "| pkt-1 |" in report
    assert "| 200 |" in report


if __name__ == "__main__":
    main()

