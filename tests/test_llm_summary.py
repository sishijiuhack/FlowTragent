from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.llm_summary import (
    build_llm_repair_prompt,
    build_structured_llm_prompt,
    needs_llm_retry,
    parse_and_validate_llm_summary,
)


def _analysis():
    return {
        "impact_assessment": {"verdict": "Likely successful exploitation", "confidence": "high"},
        "top_cves": [{"cve": "CVE-2021-44228", "score": 0.9}],
        "agent_findings": {
            "schema_version": "agent-v1",
            "mode": "deterministic",
            "executive_summary": "Assessment: Likely successful exploitation.",
            "key_findings": ["Command execution observed."],
            "limitations": [],
            "next_actions": ["Preserve evidence."],
            "evidence_pack": [
                {
                    "evidence_id": "pkt-1",
                    "evidence_type": "HTTP",
                    "summary": "cmd=whoami",
                    "source": "10.0.0.5:44444",
                    "target": "10.0.0.10:80",
                    "related": ["Command Execution"],
                }
            ],
        },
    }


def main() -> None:
    analysis = _analysis()
    prompt = build_structured_llm_prompt(analysis)
    assert "pkt-1" in prompt
    assert "Do not change or override" in prompt

    raw = """```json
{
  "schema_version": "llm-summary-v1",
  "summary": "The traffic shows command execution.",
  "supported_claims": [
    {"claim": "Command execution was observed.", "evidence_ids": ["pkt-1"]},
    {"claim": "A database was dumped.", "evidence_ids": ["pkt-999"]}
  ],
  "unsupported_claims": [],
  "recommended_actions": ["Collect endpoint telemetry."]
}
```"""
    parsed = parse_and_validate_llm_summary(raw, analysis, model="phi3:mini")
    assert parsed["status"] == "validated_with_dropped_references"
    assert parsed["supported_claims"] == [{"claim": "Command execution was observed.", "evidence_ids": ["pkt-1"]}]
    assert "A database was dumped." in parsed["unsupported_claims"]
    assert parsed["invalid_references"][0]["invalid_evidence_ids"] == ["pkt-999"]
    assert parsed["deterministic_verdict"] == "Likely successful exploitation"

    invalid = parse_and_validate_llm_summary("not json", analysis)
    assert invalid["status"] == "invalid_json"
    assert invalid["unsupported_claims"]
    assert needs_llm_retry(invalid)
    repair_prompt = build_llm_repair_prompt("not json", analysis)
    assert "pkt-1" in repair_prompt
    assert "valid JSON only" in repair_prompt


if __name__ == "__main__":
    main()
