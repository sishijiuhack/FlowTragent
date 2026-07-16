from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import web_app


def main() -> None:
    previous_token = os.environ.pop("FLOWTRAGENT_TOKEN", None)
    client = web_app.app.test_client()
    try:
        _run_web_ui_checks(client)
    finally:
        if previous_token is None:
            os.environ.pop("FLOWTRAGENT_TOKEN", None)
        else:
            os.environ["FLOWTRAGENT_TOKEN"] = previous_token


def _run_web_ui_checks(client) -> None:

    index = client.get("/")
    index_body = index.get_data(as_text=True)
    assert index.status_code == 200
    assert "FlowTragent" in index_body
    assert "PCAP + 日志分析" in index_body
    assert "实时告警" in index_body
    assert "灰" not in index_body

    alerts = client.get("/alerts")
    alerts_body = alerts.get_data(as_text=True)
    assert alerts.status_code == 200
    health = client.get("/health")
    assert health.status_code == 200
    health_json = health.get_json()
    assert health_json["status"] in {"ok", "degraded"}
    assert set(health_json["components"]) == {"capture_worker", "analyzer_worker", "nova_index"}
    assert "running" in health_json["components"]["capture_worker"]
    assert "running" in health_json["components"]["analyzer_worker"]
    assert "index_dir" in health_json["components"]["nova_index"]
    assert "report_dir" in health_json["paths"]
    assert "Attack Activities" in alerts_body
    assert "实时告警" in alerts_body
    assert "准实时预筛结果" in alerts_body

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
    assert 'class="mermaid"' in body_en
    assert "/static/app.css" in body_en
    assert "/static/report.js" in body_en
    assert "Show Mermaid / DOT source" in body_en
    report_js = client.get("/static/report.js")
    assert report_js.status_code == 200
    assert "mermaid.initialize" in report_js.get_data(as_text=True)

    detail_zh = client.get(f"/view-report/{md_name}?lang=zh")
    body_zh = detail_zh.get_data(as_text=True)
    assert detail_zh.status_code == 200
    assert "证据图谱" in body_zh
    assert "进程外联" in body_zh
    assert "疑似成功利用" in body_zh
    assert "查看 Mermaid / DOT 源码" in body_zh

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

    _run_upload_security_checks(client, report_dir)

    os.environ["FLOWTRAGENT_TOKEN"] = "webtest-secret"
    assert client.get("/alerts").status_code == 401
    assert client.get("/health").status_code == 200
    assert client.get("/alerts?token=wrong").status_code == 401
    assert client.get("/alerts?token=webtest-secret").status_code == 200
    assert client.post("/analyze-payload", data={"payload": "GET / HTTP/1.1"}).status_code == 401
    assert client.get(f"/reports/{md_name}").status_code == 401
    assert client.get(f"/reports/{md_name}", headers={"X-FlowTragent-Token": "webtest-secret"}).status_code == 200
    assert client.get("/export-reports.zip").status_code == 401
    assert client.get("/export-reports.zip", headers={"Authorization": "Bearer webtest-secret"}).status_code == 200
    assert client.get(f"/graph-svg/{json_path.name}?lang=en").status_code == 401
    assert client.get(f"/graph-svg/{json_path.name}?lang=en&token=webtest-secret").status_code == 200
    denied_delete = client.post(f"/delete-report/{md_name}", data={"flowtragent_token": "wrong"})
    assert denied_delete.status_code == 401
    assert md_path.exists()

    delete = client.post(
        f"/delete-report/{md_name}",
        data={"flowtragent_token": "webtest-secret"},
        follow_redirects=True,
    )
    assert delete.status_code == 200
    assert not md_path.exists()
    assert not zh_path.exists()
    assert not json_path.exists()


def _run_upload_security_checks(client, report_dir: Path) -> None:
    original_run_pcap = web_app.run_pcap
    original_max_upload_bytes = web_app.MAX_UPLOAD_BYTES
    calls = []

    def fake_run_pcap(pcap_path, *args, **kwargs):
        calls.append({"path": Path(pcap_path), "kwargs": kwargs})
        return SimpleNamespace(name="flowtragent_report_upload_stub.md")

    web_app.run_pcap = fake_run_pcap
    try:
        rejected_ext = client.post(
            "/analyze-pcap",
            data={"pcap": (BytesIO(b"\xd4\xc3\xb2\xa1bad"), "bad.exe")},
            content_type="multipart/form-data",
        )
        assert rejected_ext.status_code == 400
        assert "Unsupported upload file type" in rejected_ext.get_data(as_text=True)

        rejected_magic = client.post(
            "/analyze-pcap",
            data={"pcap": (BytesIO(b"not a pcap"), "bad.pcap")},
            content_type="multipart/form-data",
        )
        assert rejected_magic.status_code == 400
        assert "magic header" in rejected_magic.get_data(as_text=True)

        rejected_log = client.post(
            "/analyze-pcap",
            data={
                "pcap": (BytesIO(b"\xd4\xc3\xb2\xa1valid"), "ok.pcap"),
                "access_log": (BytesIO(b"GET / HTTP/1.1"), "access.exe"),
            },
            content_type="multipart/form-data",
        )
        assert rejected_log.status_code == 400
        assert "access_log" in rejected_log.get_data(as_text=True)

        web_app.MAX_UPLOAD_BYTES = 8
        rejected_size = client.post(
            "/analyze-pcap",
            data={"pcap": (BytesIO(b"\xd4\xc3\xb2\xa1" + b"x" * 16), "large.pcap")},
            content_type="multipart/form-data",
        )
        assert rejected_size.status_code == 400
        assert "limit" in rejected_size.get_data(as_text=True)
        web_app.MAX_UPLOAD_BYTES = original_max_upload_bytes

        accepted = client.post(
            "/analyze-pcap",
            data={
                "pcap": (BytesIO(b"\xd4\xc3\xb2\xa1valid"), "ok.pcap"),
                "access_log": (BytesIO(b"GET / HTTP/1.1"), "access.log"),
                "app_log": (BytesIO(b"message=deserialization_exception"), "app.log"),
            },
            content_type="multipart/form-data",
        )
        assert accepted.status_code == 200
        assert calls
        assert calls[-1]["path"].name == "ok.pcap"
        assert calls[-1]["path"].exists()
        assert calls[-1]["kwargs"]["application_logs"][0].endswith("app_log_app.log")
    finally:
        for path in (
            Path(web_app.CONFIG["paths"]["pcap_dir"]) / "ok.pcap",
            Path(web_app.CONFIG["paths"]["csv_dir"]) / "uploads" / "access_log_access.log",
            Path(web_app.CONFIG["paths"]["csv_dir"]) / "uploads" / "app_log_app.log",
        ):
            path.unlink(missing_ok=True)
        web_app.run_pcap = original_run_pcap
        web_app.MAX_UPLOAD_BYTES = original_max_upload_bytes


if __name__ == "__main__":
    main()
