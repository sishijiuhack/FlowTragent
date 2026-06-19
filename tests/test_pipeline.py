from __future__ import annotations

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
            "--enable-rag",
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    assert "report" in result.stdout


if __name__ == "__main__":
    main()

