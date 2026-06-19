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
        for item in candidates:
            cve = item.get("cve", "UNKNOWN")
            score = float(item.get("score", 0.0))
            cve_scores[cve] = max(cve_scores.get(cve, 0.0), score)
            evidence.setdefault(cve, item.get("evidence", ""))

        ranked = [
            {"cve": cve, "score": round(score, 4), "evidence": evidence.get(cve, "")}
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
            recommendations.append(f"Prioritize validation and patch review for {ranked[0]['cve']}.")
        if any("SQL" in item for item in attack_types):
            recommendations.append("Review database error logs and parameterized query coverage.")
        if any("Path traversal" in item for item in attack_types):
            recommendations.append("Check web root access controls and block encoded traversal sequences.")
        return recommendations
