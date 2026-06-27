from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.llm_summary import (
    build_deterministic_llm_fallback,
    build_llm_repair_prompt,
    build_structured_llm_prompt,
    generate_validated_llm_summary,
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
  "summary": "The traffic shows CVE-2021-41773.",
  "supported_claims": [
    {"claim": "Command execution was observed.", "evidence_ids": ["pkt-1"]},
    {"claim": "CVE-2021-41773 was detected.", "evidence_ids": ["pkt-1"]},
    {"claim": "A database was dumped.", "evidence_ids": ["pkt-999"]}
  ],
  "unsupported_claims": [],
  "recommended_actions": ["Collect endpoint telemetry."]
}
```"""
    parsed = parse_and_validate_llm_summary(raw, analysis, model="phi3:mini")
    assert parsed["status"] == "validated_with_dropped_claims"
    assert parsed["supported_claims"] == [{"claim": "Command execution was observed.", "evidence_ids": ["pkt-1"]}]
    assert parsed["summary"] == "Likely successful exploitation (high confidence); primary CVE candidate: CVE-2021-44228."
    assert "CVE-2021-41773 was detected." in parsed["unsupported_claims"]
    assert "The traffic shows CVE-2021-41773." in parsed["unsupported_claims"]
    assert "A database was dumped." in parsed["unsupported_claims"]
    assert parsed["invalid_references"][0]["invalid_evidence_ids"] == ["pkt-999"]
    assert parsed["unsupported_reasons"][0]["unsupported_cves"] == ["CVE-2021-41773"]
    assert parsed["deterministic_verdict"] == "Likely successful exploitation"

    invalid = parse_and_validate_llm_summary("not json", analysis)
    assert invalid["status"] == "invalid_json"
    assert invalid["unsupported_claims"]
    assert needs_llm_retry(invalid)
    repair_prompt = build_llm_repair_prompt("not json", analysis)
    assert "pkt-1" in repair_prompt
    assert "valid JSON only" in repair_prompt

    class FallbackClient:
        def __init__(self):
            self.calls = []

        def generate(self, prompt: str, json_format: bool = False):
            self.calls.append(json_format)
            if json_format:
                return ""
            return '{"schema_version":"llm-summary-v1","summary":"Command execution evidence exists.","supported_claims":[{"claim":"Command execution evidence exists.","evidence_ids":["pkt-1"]}],"unsupported_claims":[],"recommended_actions":["Collect endpoint telemetry."]}'

    fallback_client = FallbackClient()
    fallback = generate_validated_llm_summary(fallback_client, analysis, model="phi3:mini")
    assert fallback["status"] == "ok"
    assert fallback["generation_mode"] == "plain"
    assert fallback["retry_attempted"] is False
    assert fallback_client.calls == [True, False]

    class EmptyClient:
        def generate(self, prompt: str, json_format: bool = False):
            return "{}"

    deterministic = generate_validated_llm_summary(EmptyClient(), analysis, model="qwen2.5-coder:1.5b-base")
    assert deterministic["status"] == "deterministic_fallback"
    assert deterministic["fallback_reason"] == "empty_structured_summary"
    assert deterministic["summary"]
    assert deterministic["supported_claims"][0]["evidence_ids"] == ["pkt-1"]

    direct_fallback = build_deterministic_llm_fallback(analysis, model="test-model")
    assert direct_fallback["model"] == "test-model"
    assert direct_fallback["deterministic_verdict"] == "Likely successful exploitation"


if __name__ == "__main__":
    main()
