from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
import sys
from pathlib import Path

import numpy as np

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

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
    parser.add_argument("--exclude-ids", default="", help="Optional CSV or JSON list of ids to exclude from the index")
    parser.add_argument("--manifest-name", default="index_manifest.json")
    parser.add_argument("--source-name", default="")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    exclude_ids = _load_ids(args.exclude_ids)

    rows = _load_rows(input_path, args.id_column, args.payload_column, args.label_column, exclude_ids)
    if not rows:
        raise SystemExit("No rows available after filtering")

    payloads = [row["payload"] for row in rows]
    ids = [row["id"] for row in rows]
    labels = [row["labels"] for row in rows]
    vectors = _embed(payloads, args.model)
    _normalize(vectors)

    try:
        import faiss

        index = faiss.IndexFlatIP(vectors.shape[1])
        index.add(vectors.astype("float32"))
        faiss.write_index(index, str(output_dir / "faiss.index"))
        index_mode = "faiss"
    except Exception:
        (output_dir / "faiss.index").write_text("numpy fallback index; install faiss-cpu for native index\n", encoding="utf-8")
        np.save(output_dir / "demo_vectors.npy", vectors)
        index_mode = "numpy"

    np.save(output_dir / "train_embeddings.npy", vectors)
    label_counts = Counter(label for row in labels for label in row)
    meta = {
        "ids": ids,
        "payloads": payloads,
        "cve_labels": labels,
        "embedding_model": args.model,
        "payload_column": args.payload_column,
        "id_column": args.id_column,
        "label_column": args.label_column,
        "sample_count": len(ids),
        "cve_distribution": dict(sorted(label_counts.items())),
        "source_input": str(input_path),
        "source_name": args.source_name or input_path.name,
        "excluded_ids": sorted(exclude_ids),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "manifest_name": args.manifest_name,
        "index_mode": index_mode,
    }
    (output_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / args.manifest_name).write_text(
        json.dumps(
            {
                "index_path": str(output_dir / "faiss.index"),
                "meta_path": str(output_dir / "meta.json"),
                "sample_count": len(ids),
                "cve_distribution": dict(sorted(label_counts.items())),
                "source_input": str(input_path),
                "excluded_ids": sorted(exclude_ids),
                "created_at": meta["created_at"],
                "index_mode": index_mode,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "index": str(output_dir / "faiss.index"),
                "meta": str(output_dir / "meta.json"),
                "manifest": str(output_dir / args.manifest_name),
                "sample_count": len(ids),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


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


def _load_rows(
    path: Path,
    id_column: str,
    payload_column: str,
    label_column: str,
    exclude_ids: set[str],
) -> list[dict[str, object]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = [id_column, payload_column, label_column]
        missing = [column for column in required if column not in reader.fieldnames]
        if missing:
            raise SystemExit(f"Missing required columns: {', '.join(missing)}")
        rows = []
        for row in reader:
            row_id = str(row.get(id_column, "")).strip()
            if exclude_ids and row_id in exclude_ids:
                continue
            payload = str(row.get(payload_column, "")).strip()
            labels = _parse_labels(str(row.get(label_column, "")))
            if not row_id or not payload or not labels:
                continue
            rows.append({"id": row_id, "payload": payload, "labels": labels})
    return rows


def _load_ids(value: str) -> set[str]:
    if not value:
        return set()
    path = Path(value)
    if path.exists():
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return set()
        if path.suffix.lower() == ".json":
            loaded = json.loads(text)
            if isinstance(loaded, list):
                return {str(item).strip() for item in loaded if str(item).strip()}
            if isinstance(loaded, dict) and "ids" in loaded:
                return {str(item).strip() for item in loaded["ids"] if str(item).strip()}
            raise SystemExit(f"Unsupported JSON format in {path}")
        if path.suffix.lower() == ".csv":
            with path.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                if not reader.fieldnames or "id" not in reader.fieldnames:
                    raise SystemExit(f"CSV exclude file must contain an id column: {path}")
                return {str(row.get("id", "")).strip() for row in reader if str(row.get("id", "")).strip()}
        return {line.strip() for line in text.splitlines() if line.strip()}
    return {item.strip() for item in value.split(",") if item.strip()}


if __name__ == "__main__":
    main()
