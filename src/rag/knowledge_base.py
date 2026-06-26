"""Optional local RAG knowledge base backed by ChromaDB."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

from src.core.nova_client import hash_embedding

os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
os.environ.setdefault("CHROMA_TELEMETRY", "False")
os.environ.setdefault("CHROMADB_TELEMETRY", "False")


SEED_DOCS = [
    {
        "id": "cve-2021-44228",
        "text": "CVE-2021-44228 Log4Shell abuses JNDI lookup strings such as ${jndi:ldap://host/a}.",
    },
    {
        "id": "cve-2021-42013",
        "text": "CVE-2021-42013 relates to Apache HTTP Server path traversal and file disclosure patterns.",
    },
    {
        "id": "attack-timeline",
        "text": "Attack trace reports should preserve packet evidence, request timeline, candidate CVEs, and remediation advice.",
    },
]


class KnowledgeBase:
    def __init__(self, persist_dir: str | Path = "data/rag") -> None:
        self.persist_dir = Path(persist_dir)
        self._collection = None

    def initialize(self) -> None:
        import chromadb

        self.persist_dir.mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(path=str(self.persist_dir))
        self._collection = client.get_or_create_collection("flowtragent_knowledge", embedding_function=None)
        if self._collection.count() == 0:
            self._collection.add(
                ids=[item["id"] for item in SEED_DOCS],
                documents=[item["text"] for item in SEED_DOCS],
                embeddings=[hash_embedding(item["text"]) for item in SEED_DOCS],
            )

    def query(self, text: str, top_k: int = 3) -> List[Dict[str, str]]:
        if self._collection is None:
            self.initialize()
        result = self._collection.query(query_embeddings=[hash_embedding(text)], n_results=top_k)
        docs = result.get("documents", [[]])[0]
        ids = result.get("ids", [[]])[0]
        return [{"id": doc_id, "text": doc} for doc_id, doc in zip(ids, docs)]
