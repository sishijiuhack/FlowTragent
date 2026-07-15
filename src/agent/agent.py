"""Initial FlowTragent agent skeleton."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List


class TraceAgent:
    """Lightweight analysis chain that can later be upgraded to LangGraph."""

    def analyze(
        self,
        payloads: List[str],
        candidates: List[Dict],
        source_file: str | None = None,
        csv_file: str | None = None,
        rag_context: List[Dict] | None = None,
        llm_summary: str | None = None,
    ) -> Dict:
        cve_scores: Dict[str, float] = {}
        evidence: Dict[str, str] = {}
        details: Dict[str, Dict] = {}
        cve_evidence: Dict[str, List[Dict]] = {}
        for item in candidates:
            cve = item.get("cve", "UNKNOWN")
            score = float(item.get("final_score", item.get("score", 0.0)))
            cve_scores[cve] = max(cve_scores.get(cve, 0.0), score)
            evidence.setdefault(cve, item.get("evidence", ""))
            if cve not in details or score >= float(details[cve].get("final_score", details[cve].get("score", 0.0))):
                details[cve] = item
            cve_evidence.setdefault(cve, []).append(
                {
                    "event_id": item.get("event_id"),
                    "rank": item.get("rank"),
                    "score": round(score, 4),
                    "retrieval_score": item.get("retrieval_score"),
                    "rule_bonus": item.get("rule_bonus", 0.0),
                    "signals": item.get("signals", []),
                    "neighbor_id": item.get("neighbor_id") or item.get("source_id"),
                    "neighbor_payload": item.get("neighbor_payload") or item.get("evidence", ""),
                    "neighbor_labels": item.get("neighbor_labels", []),
                    "label_votes": item.get("label_votes", {}),
                }
            )

        ranked = [
            {
                "cve": cve,
                "score": round(score, 4),
                "retrieval_score": details.get(cve, {}).get("retrieval_score"),
                "raw_retrieval_score": details.get(cve, {}).get("raw_retrieval_score"),
                "rule_bonus": details.get(cve, {}).get("rule_bonus", 0.0),
                "rule_confirmed": details.get(cve, {}).get("rule_confirmed", False),
                "signals": details.get(cve, {}).get("signals", []),
                "neighbor_id": details.get(cve, {}).get("neighbor_id"),
                "neighbor_labels": details.get(cve, {}).get("neighbor_labels", []),
                "label_votes": details.get(cve, {}).get("label_votes", {}),
                "event_ids": sorted(
                    {
                        str(item.get("event_id"))
                        for item in cve_evidence.get(cve, [])
                        if item.get("event_id")
                    }
                ),
                "evidence_details": sorted(
                    cve_evidence.get(cve, []),
                    key=lambda item: (item.get("event_id") or "", item.get("rank") or 0),
                ),
                "evidence": evidence.get(cve, ""),
            }
            for cve, score in sorted(cve_scores.items(), key=lambda row: row[1], reverse=True)
        ]
        attack_types = self._infer_attack_types(payloads)
        timeline = [
            {
                "step": index,
                "event": self._summarize_payload(payload),
            }
            for index, payload in enumerate(payloads, start=1)
        ]
        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "source_file": source_file,
            "csv_file": csv_file,
            "payload_count": len(payloads),
            "attack_types": attack_types,
            "top_cves": ranked,
            "timeline": timeline,
            "rag_context": rag_context or [],
            "llm_summary": llm_summary,
            "recommendations": self._recommend(attack_types, ranked),
        }

    def build_llm_prompt(self, payloads: List[str], candidates: List[Dict], rag_context: List[Dict] | None = None) -> str:
        payload_preview = "\n".join(self._summarize_payload(payload) for payload in payloads[:5])
        cve_preview = "\n".join(f"- {item.get('cve')} score={item.get('score')}" for item in candidates[:8])
        rag_preview = "\n".join(f"- {item.get('text')}" for item in (rag_context or [])[:5])
        return (
            "You are a security incident analyst. Summarize the likely attack, "
            "candidate CVEs, evidence, and next response actions.\n\n"
            f"Payloads:\n{payload_preview}\n\n"
            f"Candidates:\n{cve_preview or 'None'}\n\n"
            f"Knowledge:\n{rag_preview or 'None'}"
        )

    @staticmethod
    def _infer_attack_types(payloads: List[str]) -> List[str]:
        text = "\n".join(payloads).lower()
        checks = {
            "Log4Shell/JNDI probing": ["${jndi:", "ldap://", "rmi://"],
            "SQL injection": [" or '1'='1", "union select", "sleep(", "'--"],
            "Path traversal": ["../", "%2e%2e", "/etc/passwd"],
            "Spring4Shell-style parameter abuse": ["class.module.classloader", "pipeline.first"],
            "Web shell upload/probing": ["cmd=", "whoami", "bash -c", "powershell"],
        }
        matched = [name for name, needles in checks.items() if any(needle in text for needle in needles)]
        return matched or ["Unknown web attack pattern"]

    @staticmethod
    def _summarize_payload(payload: str) -> str:
        compact = " ".join(payload.split())
        return compact[:220] + ("..." if len(compact) > 220 else "")

    @staticmethod
    def _recommend(attack_types: List[str], ranked: List[Dict]) -> List[str]:
        recommendations = [
            "Preserve the original PCAP, parsed CSV, web access logs, and server logs for evidence review.",
            "Correlate source IP, requested URI, user agent, and response status around the suspicious timestamps.",
        ]
        if ranked:
            top = ranked[0]
            if top.get("rule_confirmed"):
                recommendations.append(
                    f"Payload rule signals support {top['cve']}; prioritize validation and patch review for this CVE."
                )
            elif top.get("signals"):
                recommendations.append(f"Payload rule signals partially support {top['cve']}; validate service exposure and patch status.")
            elif float(top.get("score", 0.0)) >= 0.5:
                recommendations.append(f"{top['cve']} is a retrieval-only candidate; validate against payload rules, service fingerprint, and logs before prioritizing patch action.")
            else:
                recommendations.append("NOVA-F similarity scores are low; validate CVE candidates against payload rules and service context before prioritizing patches.")
        if any("SQL" in item for item in attack_types):
            recommendations.append("Review database error logs and parameterized query coverage.")
        if any("Path traversal" in item for item in attack_types):
            recommendations.append("Check web root access controls and block encoded traversal sequences.")
        return recommendations
