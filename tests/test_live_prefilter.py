from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.live.prefilter import prefilter_pcap


def main() -> None:
    subprocess.run([sys.executable, "tests/make_demo_pcap.py"], cwd=PROJECT_ROOT, check=True)
    result = prefilter_pcap(PROJECT_ROOT / "data/pcap/demo_attack.pcap")
    assert result.risk_score >= 50
    assert result.severity in {"critical", "high"}
    assert result.recommended_action == "deep_analysis"
    assert any("log4shell_jndi" in reason for reason in result.reasons)
    assert result.http_event_count >= 1
    assert result.event_count >= 1


if __name__ == "__main__":
    main()
