from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.correlation.attack_mapper import map_attack_techniques


def main() -> None:
    mapped = map_attack_techniques(
        [{"stage": "Exploitation", "confidence": "high", "evidence_ids": ["pkt-1"], "reasoning": "exploit"}],
        [{"c2_type": "DNS C2 / Tunneling", "confidence": "medium", "evidence_ids": ["dns-1"], "indicators": ["TXT"]}],
    )
    ids = {item["technique_id"] for item in mapped}
    assert "T1190" in ids
    assert "T1071.004" in ids


if __name__ == "__main__":
    main()
