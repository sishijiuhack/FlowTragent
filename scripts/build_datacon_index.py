from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_demo_index import main as build_index_main


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the full FlowTragent DataCon retrieval index")
    parser.add_argument("--input", default="data/csv/datacon_train_labeled.csv")
    parser.add_argument("--output-dir", default="data/index/datacon_full")
    parser.add_argument("--exclude-ids", default="tests/fixtures/eval_holdout.csv")
    parser.add_argument("--model", default="libs/nova-f/models/all-MiniLM-L6-v2")
    parser.add_argument("--payload-column", default="payload_clean")
    parser.add_argument("--id-column", default="id")
    parser.add_argument("--label-column", default="cve_labels")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sys.argv = [
        "scripts/build_demo_index.py",
        "--input",
        args.input,
        "--output-dir",
        args.output_dir,
        "--model",
        args.model,
        "--payload-column",
        args.payload_column,
        "--id-column",
        args.id_column,
        "--label-column",
        args.label_column,
        "--exclude-ids",
        args.exclude_ids,
        "--manifest-name",
        "datacon_full_manifest.json",
        "--source-name",
        Path(args.input).name,
    ]
    build_index_main()


if __name__ == "__main__":
    main()
