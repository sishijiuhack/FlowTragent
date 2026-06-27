from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.nova_client import NovaClient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate FlowTragent/NOVA-F retrieval on labeled DataCon CSV.")
    parser.add_argument("--input", required=True, help="CSV with payload_clean and cve_labels columns.")
    parser.add_argument("--index-dir", default="data/index")
    parser.add_argument("--model", default="libs/nova-f/models/all-MiniLM-L6-v2")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--demo-index", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    client = NovaClient(index_dir=args.index_dir, model_name=args.model, force_demo_index=args.demo_index)
    total = top1 = topk = 0
    misses = []
    with Path(args.input).open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            labels = _labels(row.get("cve_labels"))
            payload = row.get("payload_clean") or row.get("payload") or ""
            if not labels or not payload:
                continue
            results = client.search(payload, top_k=args.top_k)
            cves = [item.get("cve") for item in results]
            total += 1
            if cves and cves[0] in labels:
                top1 += 1
            if any(cve in labels for cve in cves):
                topk += 1
            elif len(misses) < 20:
                misses.append({"id": row.get("id"), "labels": sorted(labels), "predicted": cves[: args.top_k]})
            if args.limit and total >= args.limit:
                break
    metrics = {
        "samples": total,
        "top1_accuracy": round(top1 / total, 4) if total else 0.0,
        "topk_recall": round(topk / total, 4) if total else 0.0,
        "top_k": args.top_k,
        "misses": misses,
    }
    print(json.dumps(metrics, ensure_ascii=False, indent=2))


def _labels(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip() for item in str(value).replace(";", ",").split(",") if item.strip()}


if __name__ == "__main__":
    main()
