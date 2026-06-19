from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.nova_client import hash_embedding


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a FlowTragent/NOVA-F style FAISS index from CSV")
    parser.add_argument("--input", required=True, help="CSV with id,payload_clean,cve_labels columns")
    parser.add_argument("--output-dir", default="data/index")
    parser.add_argument("--model", default="sentence-transformers/all-MiniLM-L6-v2")
    parser.add_argument("--payload-column", default="payload_clean")
    parser.add_argument("--id-column", default="id")
    parser.add_argument("--label-column", default="cve_labels")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    frame = pd.read_csv(input_path)
    required = [args.id_column, args.payload_column, args.label_column]
    missing = [column for column in required if column not in frame.columns]
    if missing:
        raise SystemExit(f"Missing required columns: {', '.join(missing)}")

    payloads = frame[args.payload_column].fillna("").astype(str).tolist()
    ids = frame[args.id_column].fillna("").astype(str).tolist()
    labels = [_parse_labels(value) for value in frame[args.label_column].fillna("").astype(str).tolist()]
    vectors = _embed(payloads, args.model)
    _normalize(vectors)

    try:
        import faiss

        index = faiss.IndexFlatIP(vectors.shape[1])
        index.add(vectors.astype("float32"))
        faiss.write_index(index, str(output_dir / "faiss.index"))
    except Exception as exc:
        raise SystemExit(f"faiss-cpu is required to build the native index: {exc}") from exc

    np.save(output_dir / "train_embeddings.npy", vectors)
    meta = {
        "ids": ids,
        "payloads": payloads,
        "cve_labels": labels,
        "embedding_model": args.model,
        "payload_column": args.payload_column,
        "id_column": args.id_column,
        "label_column": args.label_column,
    }
    (output_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"index": str(output_dir / "faiss.index"), "meta": str(output_dir / "meta.json")}, indent=2))


def _embed(payloads: list[str], model_name: str) -> np.ndarray:
    import os

    if os.getenv("FLOWTRAGENT_OFFLINE") == "1":
        return np.array([hash_embedding(payload) for payload in payloads], dtype="float32")
    try:
        from sentence_transformers import SentenceTransformer

        model = SentenceTransformer(model_name)
        return model.encode(payloads, convert_to_numpy=True, normalize_embeddings=False).astype("float32")
    except Exception:
        return np.array([hash_embedding(payload) for payload in payloads], dtype="float32")


def _normalize(vectors: np.ndarray) -> None:
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    vectors /= norms


def _parse_labels(value: str) -> list[str]:
    cleaned = value.replace("[", " ").replace("]", " ").replace('"', " ").replace("'", " ")
    labels = []
    for part in cleaned.replace(",", " ").replace(";", " ").split():
        item = part.strip().upper()
        if item.startswith("CVE-") and item not in labels:
            labels.append(item)
    return labels


if __name__ == "__main__":
    main()
