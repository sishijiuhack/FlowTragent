from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    tmp = PROJECT_ROOT / "data" / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    report = tmp / "graph_report.json"
    report.write_text(
        json.dumps(
            {
                "evidence_graph": {
                    "dot": 'digraph FlowTragentEvidence {\n  "a" -> "b" [label="related"];\n}'
                }
            }
        ),
        encoding="utf-8",
    )
    dot_output = tmp / "graph_report.dot"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/export_graphviz.py",
            str(report.relative_to(PROJECT_ROOT)),
            "--dot-output",
            str(dot_output.relative_to(PROJECT_ROOT)),
            "--skip-png",
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    output = json.loads(result.stdout)
    assert output["dot"] == str(dot_output.relative_to(PROJECT_ROOT))
    assert dot_output.exists()
    assert "FlowTragentEvidence" in dot_output.read_text(encoding="utf-8")


if __name__ == "__main__":
    main()
