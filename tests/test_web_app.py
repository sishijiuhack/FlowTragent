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
    index_body = index.get_data(as_text=True)
    assert index.status_code == 200
    assert "FlowTragent" in index_body
    assert "PCAP + 日志分析" in index_body
    assert "灰" not in index_body

    report_dir = PROJECT_ROOT / web_app.CONFIG["paths"]["report_dir"]
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().isoformat().replace(":", "").replace(".", "") + "Z"
    md_name = f"flowtragent_report_webtest_{stamp}.md"
    md_path = report_dir / md_name
    zh_path = report_dir / f"{md_path.stem}_zh.md"
    json_path = md_path.with_suffix(".json")
    md_path.write_text("# test\n", encoding="utf-8")
    zh_path.write_text("# 中文测试\n", encoding="utf-8")
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
                    "mermaid": "flowchart TD\n  endpoint1_1 -->|process_external_connection| external_203_0_113_50_8080",
                    "mermaid_zh": "flowchart TD\n  endpoint1_1 -->|进程外联| external_203_0_113_50_8080",
                    "dot": 'digraph FlowTragentEvidence {\n  "endpoint1-1" -> "external:203.0.113.50:8080" [label="process_external_connection"];\n}',
                    "dot_zh": 'digraph FlowTragentEvidence {\n  "endpoint1-1" -> "external:203.0.113.50:8080" [label="进程外联"];\n}',
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    detail_en = client.get(f"/view-report/{md_name}?lang=en")
    body_en = detail_en.get_data(as_text=True)
    assert detail_en.status_code == 200
    assert "Evidence Graph" in body_en
    assert "Graphviz DOT" in body_en
    assert "process_external_connection" in body_en
    assert "English" in body_en

    detail_zh = client.get(f"/view-report/{md_name}?lang=zh")
    body_zh = detail_zh.get_data(as_text=True)
    assert detail_zh.status_code == 200
    assert "证据图谱" in body_zh
    assert "进程外联" in body_zh
    assert "疑似成功利用" in body_zh

    svg_en = client.get(f"/graph-svg/{json_path.name}?lang=en")
    assert svg_en.status_code == 200
    assert svg_en.mimetype in {"image/svg+xml", "text/plain"}
    svg_en_body = svg_en.get_data(as_text=True)
    assert "FlowTragentEvidence" in svg_en_body or "<svg" in svg_en_body

    svg_zh = client.get(f"/graph-svg/{json_path.name}?lang=zh")
    assert svg_zh.status_code == 200
    assert svg_zh.mimetype in {"image/svg+xml", "text/plain"}
    svg_zh_body = svg_zh.get_data(as_text=True)
    assert "进程外联" in svg_zh_body or "<svg" in svg_zh_body

    search = client.get("/?q=webtest")
    search_body = search.get_data(as_text=True)
    assert search.status_code == 200
    assert md_name in search_body
    assert f"{md_path.stem}_zh.md" in search_body

    archive = client.get("/export-reports.zip")
    assert archive.status_code == 200
    assert archive.mimetype == "application/zip"

    delete = client.post(f"/delete-report/{md_name}", follow_redirects=True)
    assert delete.status_code == 200
    assert not md_path.exists()
    assert not zh_path.exists()
    assert not json_path.exists()


if __name__ == "__main__":
    main()
