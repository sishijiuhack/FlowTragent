from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
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
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--demo-index", action="store_true")
    parser.add_argument("--min-top1-accuracy", type=float, default=0.0)
    parser.add_argument("--min-topk-recall", type=float, default=0.0)
    parser.add_argument("--min-macro-topk-recall", type=float, default=0.0)
    parser.add_argument("--report-path", default="")
    parser.add_argument("--quality-gate", action="store_true")
    parser.add_argument("--min-candidate-score", type=float, default=0.0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    client = NovaClient(
        index_dir=args.index_dir,
        model_name=args.model,
        force_demo_index=args.demo_index,
        min_retrieval_score=args.min_candidate_score,
    )
    index_labels = _index_labels(Path(args.index_dir))
    total = top1 = topk = 0
    per_cve: dict[str, dict[str, int]] = defaultdict(lambda: {"support": 0, "hit": 0, "top1": 0})
    misses = []
    false_positive_examples = []
    rows = _load_rows(Path(args.input), args.limit)
    for batch in _chunks(rows, max(1, args.batch_size)):
        payloads = [row["payload"] for row in batch]
        batch_results = client.batch_search(payloads, top_k=args.top_k)
        for row, results in zip(batch, batch_results):
            labels = row["labels"]
            cves = [item.get("cve") for item in results]
            total += 1
            top1_hit = bool(cves and cves[0] in labels)
            topk_hit = any(cve in labels for cve in cves)
            if top1_hit:
                top1 += 1
            if topk_hit:
                topk += 1
            for cve in labels:
                per_cve[cve]["support"] += 1
                if cve in cves:
                    per_cve[cve]["hit"] += 1
                if top1_hit and cves[0] == cve:
                    per_cve[cve]["top1"] += 1
            if not topk_hit and len(misses) < 20:
                misses.append(
                    {
                        "id": row["id"],
                        "labels": sorted(labels),
                        "predicted": cves[: args.top_k],
                        "root_causes": _miss_root_causes(row, labels, cves, index_labels),
                    }
                )
            unexpected = [cve for cve in cves[: args.top_k] if cve not in labels]
            if unexpected and len(false_positive_examples) < 20:
                false_positive_examples.append(
                    {
                        "id": row["id"],
                        "labels": sorted(labels),
                        "unexpected": unexpected[:5],
                        "predicted": cves[: args.top_k],
                        "root_causes": _false_positive_root_causes(row, results, labels, args.min_candidate_score),
                    }
                )
    by_cve = {
        cve: {
            "support": values["support"],
            "top1_recall": round(values["top1"] / values["support"], 4) if values["support"] else 0.0,
            "topk_recall": round(values["hit"] / values["support"], 4) if values["support"] else 0.0,
        }
        for cve, values in sorted(per_cve.items())
    }
    macro_topk = sum(item["topk_recall"] for item in by_cve.values()) / len(by_cve) if by_cve else 0.0
    macro_top1 = sum(item["top1_recall"] for item in by_cve.values()) / len(by_cve) if by_cve else 0.0
    metrics = {
        "samples": total,
        "top1_accuracy": round(top1 / total, 4) if total else 0.0,
        "topk_recall": round(topk / total, 4) if total else 0.0,
        "macro_cve_top1_recall": round(macro_top1, 4),
        "macro_cve_topk_recall": round(macro_topk, 4),
        "top_k": args.top_k,
        "by_cve": by_cve,
        "misses": misses,
        "false_positive_examples": false_positive_examples,
        "root_cause_summary": _root_cause_summary(misses, false_positive_examples),
        "quality_gate": _quality_gate(metrics={
            "top1_accuracy": round(top1 / total, 4) if total else 0.0,
            "topk_recall": round(topk / total, 4) if total else 0.0,
            "macro_cve_topk_recall": round(macro_topk, 4),
        }, args=args),
    }
    if args.report_path:
        Path(args.report_path).write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    if args.quality_gate and not metrics["quality_gate"]["passed"]:
        raise SystemExit(2)


def _load_rows(path: Path, limit: int) -> list[dict]:
    rows = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            labels = _labels(row.get("cve_labels"))
            payload = row.get("payload_clean") or row.get("payload") or ""
            if not labels or not payload:
                continue
            rows.append({"id": row.get("id"), "labels": labels, "payload": payload})
            if limit and len(rows) >= limit:
                break
    return rows


def _chunks(rows: list[dict], size: int):
    for start in range(0, len(rows), size):
        yield rows[start : start + size]


def _labels(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip().upper() for item in re.split(r"[\s,;]+", str(value)) if item.strip()}


def _quality_gate(metrics: dict[str, float], args: argparse.Namespace) -> dict[str, object]:
    thresholds = {
        "min_top1_accuracy": float(args.min_top1_accuracy),
        "min_topk_recall": float(args.min_topk_recall),
        "min_macro_topk_recall": float(args.min_macro_topk_recall),
    }
    passed = (
        metrics["top1_accuracy"] >= thresholds["min_top1_accuracy"]
        and metrics["topk_recall"] >= thresholds["min_topk_recall"]
        and metrics["macro_cve_topk_recall"] >= thresholds["min_macro_topk_recall"]
    )
    if not args.quality_gate and all(value == 0.0 for value in thresholds.values()):
        return {"enabled": False, "passed": True, "thresholds": thresholds}
    return {"enabled": bool(args.quality_gate), "passed": passed, "thresholds": thresholds}


def _index_labels(index_dir: Path) -> set[str]:
    meta_path = index_dir / "meta.json"
    if not meta_path.exists():
        return set()
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    labels: set[str] = set()
    for row in meta.get("cve_labels", []) or []:
        labels.update(_labels(" ".join(row) if isinstance(row, list) else str(row)))
    return labels


def _miss_root_causes(row: dict, labels: set[str], predicted: list[str], index_labels: set[str]) -> list[str]:
    causes = []
    payload = str(row.get("payload", ""))
    if any(label not in index_labels for label in labels):
        causes.append("index_missing")
    if _looks_encoded_or_obfuscated(payload):
        causes.append("payload_normalization")
    if not predicted:
        causes.append("low_similarity_suppression")
    elif labels and index_labels and not any(label not in index_labels for label in labels):
        causes.append("semantic_distance")
    if _same_family_confusion(labels, predicted):
        causes.append("rule_conflict")
    return causes or ["semantic_distance"]


def _false_positive_root_causes(
    row: dict,
    results: list[dict],
    labels: set[str],
    min_candidate_score: float,
) -> list[str]:
    causes = []
    unexpected = [item for item in results if item.get("cve") not in labels]
    if not labels:
        causes.append("empty_or_non_vulnerability_label")
    if any(float(item.get("retrieval_score", item.get("score", 0.0))) <= min_candidate_score for item in unexpected):
        causes.append("low_similarity_candidate")
    if _same_family_confusion(labels, [str(item.get("cve")) for item in unexpected]):
        causes.append("rule_conflict")
    if _looks_encoded_or_obfuscated(str(row.get("payload", ""))):
        causes.append("payload_normalization")
    return causes or ["semantic_distance"]


def _root_cause_summary(misses: list[dict], false_positive_examples: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for item in [*misses, *false_positive_examples]:
        for cause in item.get("root_causes", []) or []:
            counts[cause] += 1
    return dict(sorted(counts.items()))


def _looks_encoded_or_obfuscated(payload: str) -> bool:
    lowered = payload.lower()
    return "%" in lowered or "${" in lowered or "\\x" in lowered or ".." in lowered or "jnd${" in lowered


def _same_family_confusion(labels: set[str], predicted: list[str]) -> bool:
    if not labels or not predicted:
        return False
    family_markers = {
        "apache_path_traversal": {"CVE-2021-41773", "CVE-2021-42013"},
        "ivanti_connect_secure": {"CVE-2023-46805", "CVE-2024-21887"},
        "omigod": {"CVE-2021-38645", "CVE-2021-38647", "CVE-2021-38648", "CVE-2021-38649"},
    }
    for family in family_markers.values():
        if labels & family and any(cve in family for cve in predicted):
            return True
    return False


if __name__ == "__main__":
    main()
