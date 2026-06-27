from __future__ import annotations

import json
import subprocess
import sys
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
            "--enable-ollama",
            "--config",
            "tests/fixtures/ollama_unavailable_config.yaml",
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    report_path = PROJECT_ROOT / json.loads(result.stdout)["report"]
    json_path = report_path.with_suffix(".json")
    analysis = json.loads(json_path.read_text(encoding="utf-8"))
    assert analysis["llm_structured_summary"]["status"] == "unavailable"
    report = report_path.read_text(encoding="utf-8")
    assert "## LLM Structured Summary" in report
    assert "Ollama is not available" in report


if __name__ == "__main__":
    main()
