from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export FlowTragent evidence_graph DOT/PNG from a JSON report.")
    parser.add_argument("report_json", help="Path to reports/flowtragent_report_*.json")
    parser.add_argument("--dot-output", help="DOT output path. Defaults to report JSON path with .dot suffix.")
    parser.add_argument("--png-output", help="PNG output path. Requires Graphviz `dot` command.")
    parser.add_argument("--skip-png", action="store_true", help="Only write DOT, even if --png-output is provided.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report_json = Path(args.report_json)
    analysis = json.loads(report_json.read_text(encoding="utf-8"))
    dot_text = (analysis.get("evidence_graph") or {}).get("dot")
    if not dot_text:
        raise SystemExit("Report does not contain evidence_graph.dot.")

    dot_output = Path(args.dot_output) if args.dot_output else report_json.with_suffix(".dot")
    dot_output.write_text(dot_text, encoding="utf-8")

    result = {"dot": str(dot_output)}
    if args.png_output and not args.skip_png:
        dot_bin = shutil.which("dot")
        if not dot_bin:
            result["png"] = None
            result["error"] = "Graphviz `dot` was not found. Install with: sudo apt install graphviz"
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return
        png_output = Path(args.png_output)
        subprocess.run([dot_bin, "-Tpng", str(dot_output), "-o", str(png_output)], check=True)
        result["png"] = str(png_output)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(json.dumps({"error": f"Graphviz export failed: {exc}"}, ensure_ascii=False, indent=2))
        sys.exit(exc.returncode)
