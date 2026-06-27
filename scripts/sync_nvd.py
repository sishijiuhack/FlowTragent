from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import requests


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync NVD CVE data into a JSONL knowledge source.")
    parser.add_argument("--output", default="data/rag/nvd_cves.jsonl")
    parser.add_argument("--input-json", help="Optional local NVD API JSON fixture for offline conversion.")
    parser.add_argument("--keyword", default="apache")
    parser.add_argument("--results-per-page", type=int, default=200)
    parser.add_argument("--max-pages", type=int, default=1)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--sleep", type=float, default=0.6)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    records = []
    if args.input_json:
        records.extend(_convert_payload(json.loads(Path(args.input_json).read_text(encoding="utf-8"))))
    else:
        headers = {"apiKey": args.api_key} if args.api_key else {}
        for page in range(args.max_pages):
            params = {
                "keywordSearch": args.keyword,
                "resultsPerPage": args.results_per_page,
                "startIndex": page * args.results_per_page,
            }
            response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, headers=headers, timeout=30)
            response.raise_for_status()
            records.extend(_convert_payload(response.json()))
            time.sleep(args.sleep)

    with output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(json.dumps({"output": str(output), "rows": len(records)}, ensure_ascii=False, indent=2))


def _convert_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions") or []
        description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics") or {}
        cvss = _cvss_score(metrics)
        references = [ref.get("url") for ref in cve.get("references", {}).get("referenceData", []) if ref.get("url")]
        if not cve_id:
            continue
        records.append(
            {
                "id": cve_id,
                "source": "NVD",
                "description": description,
                "cvss": cvss,
                "published": cve.get("published"),
                "lastModified": cve.get("lastModified"),
                "references": references[:10],
                "text": f"{cve_id}: {description}",
            }
        )
    return records


def _cvss_score(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            return values[0].get("cvssData", {}).get("baseScore")
    return None


if __name__ == "__main__":
    main()
