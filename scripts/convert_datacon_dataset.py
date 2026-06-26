from __future__ import annotations

import argparse
import base64
import csv
import gzip
import json
import sys
import zlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.pcap_parser import clean_payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert DataCon HTTP CVE JSONL.GZ to FlowTragent CSV")
    parser.add_argument("--input", required=True, type=Path, help="Path to train.json.gz or test.json.gz")
    parser.add_argument("--output", required=True, type=Path, help="Output CSV path")
    parser.add_argument("--keep-unlabeled", action="store_true", help="Keep rows without CVE labels")
    parser.add_argument("--limit", type=int, default=0, help="Optional max rows to read")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = 0
    with gzip.open(args.input, "rt", encoding="utf-8", errors="replace") as handle, args.output.open(
        "w", newline="", encoding="utf-8"
    ) as output_handle:
        writer = csv.DictWriter(output_handle, fieldnames=["id", "payload_clean", "cve_labels", "labeled"])
        writer.writeheader()
        for line_no, line in enumerate(handle, start=1):
            if args.limit and line_no > args.limit:
                break
            if not line.strip():
                continue
            obj = json.loads(line)
            labels = _labels(obj.get("cve_labels", ""))
            if not args.keep_unlabeled and not labels:
                continue
            writer.writerow(
                {
                    "id": str(obj.get("id", line_no)),
                    "payload_clean": clean_payload(_decode_payload(str(obj.get("payload", "")))),
                    "cve_labels": " ".join(labels),
                    "labeled": str(obj.get("labeled", "")),
                }
            )
            rows += 1

    print(json.dumps({"input": str(args.input), "output": str(args.output), "rows": rows}, indent=2))


def _decode_payload(value: str) -> str:
    if not value:
        return ""
    raw = base64.b64decode(value)
    try:
        return zlib.decompress(raw).decode("utf-8", errors="replace")
    except zlib.error:
        return zlib.decompress(raw, -zlib.MAX_WBITS).decode("utf-8", errors="replace")


def _labels(value: object) -> list[str]:
    if value is None:
        return []
    parts = value if isinstance(value, list) else str(value).replace(",", " ").replace(";", " ").split()
    labels = []
    for part in parts:
        label = str(part).strip().upper()
        if label.startswith("CVE-") and label not in labels:
            labels.append(label)
    return labels


if __name__ == "__main__":
    main()
