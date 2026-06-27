from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import web_app


def main() -> None:
    client = web_app.app.test_client()

    index = client.get("/")
    assert index.status_code == 200
    assert "FlowTragent" in index.get_data(as_text=True)
    assert "PCAP + 日志分析" in index.get_data(as_text=True)

    report_dir = PROJECT_ROOT / web_app.CONFIG["paths"]["report_dir"]
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().isoformat().replace(":", "").replace(".", "") + "Z"
    md_name = f"flowtragent_report_webtest_{stamp}.md"
    md_path = report_dir / md_name
    json_path = md_path.with_suffix(".json")
    md_path.write_text("# test\n", encoding="utf-8")
    json_path.write_text(
        json.dumps(
            {
                "payload_count": 1,
                "impact_assessment": {"verdict": "Likely successful exploitation", "confidence": "high"},
                "attack_chain": [
                    {
                        "stage": "Command Execution",
                        "technique": "Command execution indicators",
                        "confidence": "high",
                        "evidence_ids": ["endpoint1-1"],
                    }
                ],
                "evidence_graph": {
                    "nodes": [{"node_id": "endpoint1-1", "node_type": "ENDPOINT"}],
                    "edges": [
                        {
                            "source_id": "endpoint1-1",
                            "target_id": "external:203.0.113.50:8080",
                            "relation": "process_external_connection",
                            "confidence": "high",
                            "reason": "Endpoint/process telemetry shows command activity with a remote destination.",
                        }
                    ],
                    "mermaid": "flowchart TD\n  endpoint1_1 --> external_203_0_113_50_8080",
                    "dot": 'digraph FlowTragentEvidence {\n  "endpoint1-1" -> "external:203.0.113.50:8080" [label="process_external_connection"];\n}',
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    detail = client.get(f"/view-report/{md_name}")
    body = detail.get_data(as_text=True)
    assert detail.status_code == 200
    assert "Evidence Graph" in body
    assert "Graphviz DOT" in body
    assert "process_external_connection" in body

    svg = client.get(f"/graph-svg/{json_path.name}")
    assert svg.status_code == 200
    assert svg.mimetype in {"image/svg+xml", "text/plain"}
    assert "FlowTragentEvidence" in svg.get_data(as_text=True) or "<svg" in svg.get_data(as_text=True)

    search = client.get("/?q=webtest")
    assert search.status_code == 200
    assert md_name in search.get_data(as_text=True)

    archive = client.get("/export-reports.zip")
    assert archive.status_code == 200
    assert archive.mimetype == "application/zip"

    delete = client.post(f"/delete-report/{md_name}", follow_redirects=True)
    assert delete.status_code == 200
    assert not md_path.exists()
    assert not json_path.exists()


if __name__ == "__main__":
    main()
