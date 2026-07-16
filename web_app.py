"""Flask UI for FlowTragent."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from hmac import compare_digest
from pathlib import Path

from flask import Flask, Response, jsonify, redirect, render_template, request, send_file, send_from_directory, url_for
from werkzeug.utils import secure_filename

from src.core.settings import load_config
from src.core.structured_logging import log_event
from src.orchestrator.pipeline import run_payload, run_pcap
from src.storage.alert_store import AlertStore


app = Flask(__name__)
CONFIG = load_config()
ALERT_DB = Path(CONFIG.get("live", {}).get("alert_db", "data/live/alerts.db"))
WEB_CONFIG = CONFIG.get("web", {})
MAX_UPLOAD_BYTES = int(WEB_CONFIG.get("max_upload_mb", 50)) * 1024 * 1024
ALLOWED_PCAP_EXTENSIONS = {str(item).lower() for item in WEB_CONFIG.get("allowed_pcap_extensions", [".pcap", ".cap", ".pcapng"])}
ALLOWED_LOG_EXTENSIONS = {str(item).lower() for item in WEB_CONFIG.get("allowed_log_extensions", [".log", ".txt", ".jsonl", ".csv"])}
PCAP_MAGIC_PREFIXES = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

PROTECTED_ENDPOINTS = {
    "alerts",
    "analyze_payload",
    "analyze_pcap",
    "download_report",
    "delete_report",
    "export_reports_zip",
    "graph_svg",
}


@app.before_request
def require_token_for_sensitive_routes():
    if request.endpoint in PROTECTED_ENDPOINTS and not _token_is_valid():
        return Response("FLOWTRAGENT_TOKEN is required for this operation.", status=401, mimetype="text/plain")


@app.get("/")
def index():
    q = request.args.get("q", "").strip()
    return render_template("index.html", report=None, reports=_recent_reports(query=q), q=q, summary=_ui_summary())


@app.get("/alerts")
def alerts():
    limit = int(request.args.get("limit", "100"))
    store = AlertStore(ALERT_DB)
    return render_template("alerts.html", alerts=store.list_alerts(limit=limit), activities=store.list_activities(limit=limit))


@app.get("/health")
def health():
    components = {
        "capture_worker": _process_health("scripts/live_capture_worker.py"),
        "analyzer_worker": _process_health("scripts/live_analyzer_worker.py"),
        "nova_index": _nova_index_health(),
    }
    status = "ok" if components["nova_index"]["status"] == "ready" else "degraded"
    return jsonify(
        {
            "status": status,
            "components": components,
            "paths": {
                "report_dir": _path_health(CONFIG["paths"]["report_dir"]),
                "pcap_dir": _path_health(CONFIG["paths"]["pcap_dir"]),
                "live_incoming_dir": _path_health(CONFIG.get("live", {}).get("incoming_dir", "data/live/incoming")),
                "alert_db": _path_health(ALERT_DB, expect_file=True),
            },
        }
    )


@app.get("/metrics")
def metrics():
    store = AlertStore(ALERT_DB)
    return Response(_render_prometheus_metrics(store), mimetype="text/plain; version=0.0.4; charset=utf-8")


@app.post("/analyze-payload")
def analyze_payload():
    payload = request.form.get("payload", "").strip()
    if not payload:
        return redirect(url_for("index"))
    log_event(CONFIG, "web_app", "payload_analysis_requested", "Payload analysis requested.", payload_size=len(payload))
    report = run_payload(
        payload,
        CONFIG,
        Path(CONFIG["paths"]["report_dir"]),
        int(CONFIG["retrieval"]["top_k"]),
        _checked("demo_index"),
        _checked("enable_rag"),
        _checked("enable_ollama"),
    )
    log_event(CONFIG, "web_app", "report_generated", "Payload report generated.", report_path=str(report), input_type="payload")
    return render_template("index.html", report=report, reports=_recent_reports(), q="", summary=_ui_summary())


@app.post("/analyze-pcap")
def analyze_pcap():
    upload = request.files.get("pcap")
    if upload is None or not upload.filename:
        return redirect(url_for("index"))
    error = _validate_upload(upload, ALLOWED_PCAP_EXTENSIONS, require_pcap_magic=True)
    if error:
        log_event(CONFIG, "web_app", "upload_rejected", "PCAP upload rejected.", level="WARNING", filename=upload.filename, reason=error)
        return Response(error, status=400, mimetype="text/plain")
    filename = secure_filename(upload.filename)
    pcap_path = Path(CONFIG["paths"]["pcap_dir"]) / filename
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    _rewind_upload(upload)
    upload.save(pcap_path)

    uploaded_logs, log_error = _save_optional_logs()
    if log_error:
        pcap_path.unlink(missing_ok=True)
        log_event(CONFIG, "web_app", "upload_rejected", "Supplementary log upload rejected.", level="WARNING", filename=upload.filename, reason=log_error)
        return Response(log_error, status=400, mimetype="text/plain")
    log_event(
        CONFIG,
        "web_app",
        "pcap_analysis_requested",
        "PCAP analysis requested.",
        pcap_path=str(pcap_path),
        supplementary_log_count=sum(len(items) for items in uploaded_logs.values()),
    )
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
        application_logs=uploaded_logs["app_log"],
    )
    log_event(CONFIG, "web_app", "report_generated", "PCAP report generated.", report_path=str(report), input_type="pcap", pcap_path=str(pcap_path))
    return render_template("index.html", report=report, reports=_recent_reports(), q="", summary=_ui_summary())


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
    return render_template(
        "report_detail.html",
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
    safe_name = secure_filename(filename)
    log_event(CONFIG, "web_app", "report_downloaded", "Report downloaded.", filename=safe_name)
    return send_from_directory(CONFIG["paths"]["report_dir"], safe_name, as_attachment=False)


@app.post("/delete-report/<path:filename>")
def delete_report(filename: str):
    safe_name = secure_filename(filename)
    report_dir = Path(CONFIG["paths"]["report_dir"])
    base = Path(_base_md_name(safe_name)).stem
    deleted = []
    for suffix in (".md", "_zh.md", ".json", ".dot", "_zh.dot", ".png", ".svg"):
        target = report_dir / f"{base}{suffix}"
        if target.exists() and target.resolve().parent == report_dir.resolve():
            target.unlink()
            deleted.append(target.name)
    log_event(CONFIG, "web_app", "report_deleted", "Report artifacts deleted.", filename=safe_name, deleted_files=deleted)
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
    log_event(CONFIG, "web_app", "reports_exported", "Reports ZIP exported.", archive_path=tmp.name)
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


def _token_is_valid() -> bool:
    expected = os.getenv("FLOWTRAGENT_TOKEN", "")
    if not expected:
        return True
    supplied = _request_token()
    return bool(supplied) and compare_digest(supplied, expected)


def _request_token() -> str:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (
        request.headers.get("X-FlowTragent-Token", "")
        or request.form.get("flowtragent_token", "")
        or request.args.get("token", "")
    ).strip()


def _process_health(process_marker: str) -> dict[str, object]:
    if os.name == "nt":
        return {"status": "unknown", "running": None, "reason": "process check is only available on Linux"}
    try:
        result = subprocess.run(["pgrep", "-f", process_marker], check=False, capture_output=True, text=True, timeout=2)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "unknown", "running": None, "reason": str(exc)}
    pids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return {"status": "running" if pids else "stopped", "running": bool(pids), "pids": pids}


def _nova_index_health() -> dict[str, object]:
    index_dir = Path(CONFIG["paths"].get("index_dir", "data/index"))
    nova_f = Path(CONFIG["paths"].get("nova_f", "libs/nova-f"))
    model = Path(CONFIG["retrieval"].get("model_name", ""))
    index_files = sorted(path.name for path in index_dir.glob("*") if path.is_file()) if index_dir.exists() else []
    ready = index_dir.exists() and bool(index_files)
    return {
        "status": "ready" if ready else "missing",
        "index_dir": str(index_dir),
        "index_files": index_files[:20],
        "nova_f_exists": nova_f.exists(),
        "model_exists": model.exists(),
    }


def _render_prometheus_metrics(store: AlertStore) -> str:
    summary = store.metrics_summary()
    index_health = _nova_index_health()
    report_dir = Path(CONFIG["paths"]["report_dir"])
    pcap_dir = Path(CONFIG["paths"]["pcap_dir"])
    incoming_dir = Path(CONFIG.get("live", {}).get("incoming_dir", "data/live/incoming"))
    metrics: list[tuple[str, str, float, dict[str, str] | None]] = [
        ("flowtragent_pcaps_processed_total", "Total live PCAP segments observed by the alert store.", float(summary["alerts_total"]), None),
        ("flowtragent_alert_occurrences_total", "Total alert occurrences including merged duplicate windows.", float(summary["occurrences_total"]), None),
        ("flowtragent_deep_analyses_total", "Total deep analyses started, reported, or errored.", float(summary["deep_analyses_total"]), None),
        ("flowtragent_rate_limited_total", "Total live segments skipped by deep-analysis rate limiting.", float(summary["rate_limited_total"]), None),
        ("flowtragent_notifications_suppressed_total", "Total notifications suppressed by fingerprint windows.", float(summary["notifications_suppressed_total"]), None),
        ("flowtragent_live_segment_queue_size", "Current PCAP files waiting in the live incoming directory.", float(_count_matching_files(incoming_dir, {".pcap", ".pcapng"})), None),
        ("flowtragent_report_files_total", "Current generated report markdown files.", float(_count_matching_files(report_dir, {".md"})), None),
        ("flowtragent_alert_db_size_bytes", "SQLite alert database size in bytes.", float(ALERT_DB.stat().st_size if ALERT_DB.exists() else 0), None),
        ("flowtragent_nova_index_ready", "Whether the configured NOVA index directory contains index files.", 1.0 if index_health["status"] == "ready" else 0.0, None),
        ("flowtragent_pcap_storage_files", "Current PCAP files in the configured PCAP directory.", float(_count_matching_files(pcap_dir, {".pcap", ".pcapng", ".cap"})), None),
    ]
    for severity, count in sorted(summary["alerts_by_severity"].items()):
        metrics.append(("flowtragent_alerts_by_severity", "Current alerts grouped by severity.", float(count), {"severity": severity}))
    for status, count in sorted(summary["alerts_by_status"].items()):
        metrics.append(("flowtragent_alerts_by_status", "Current alerts grouped by status.", float(count), {"status": status}))
    return _prometheus_text(metrics)


def _prometheus_text(metrics: list[tuple[str, str, float, dict[str, str] | None]]) -> str:
    lines = []
    emitted_help = set()
    for name, help_text, value, labels in metrics:
        if name not in emitted_help:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            emitted_help.add(name)
        label_text = _prometheus_labels(labels or {})
        lines.append(f"{name}{label_text} {_format_metric_value(value)}")
    return "\n".join(lines) + "\n"


def _prometheus_labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    parts = [f'{key}="{_escape_label(value)}"' for key, value in sorted(labels.items())]
    return "{" + ",".join(parts) + "}"


def _escape_label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _format_metric_value(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:.6f}"


def _count_matching_files(directory: Path, suffixes: set[str]) -> int:
    if not directory.exists():
        return 0
    return sum(1 for path in directory.iterdir() if path.is_file() and path.suffix.lower() in suffixes)


def _ui_summary() -> dict[str, object]:
    store = AlertStore(ALERT_DB)
    metrics = store.metrics_summary()
    report_dir = Path(CONFIG["paths"]["report_dir"])
    incoming_dir = Path(CONFIG.get("live", {}).get("incoming_dir", "data/live/incoming"))
    index_health = _nova_index_health()
    return {
        "nova_status": index_health["status"],
        "report_count": _count_matching_files(report_dir, {".md"}),
        "live_queue": _count_matching_files(incoming_dir, {".pcap", ".pcapng"}),
        "alert_count": metrics.get("alerts_total", 0),
        "high_alerts": sum(metrics.get("alerts_by_severity", {}).get(item, 0) for item in ("critical", "high")),
    }


def _path_health(path: str | Path, expect_file: bool = False) -> dict[str, object]:
    target = Path(path)
    exists = target.is_file() if expect_file else target.exists()
    return {"path": str(target), "exists": exists}


def _validate_upload(upload, allowed_extensions: set[str], require_pcap_magic: bool = False) -> str | None:
    filename = secure_filename(upload.filename or "")
    if not filename:
        return "Upload filename is required."
    suffix = Path(filename).suffix.lower()
    if suffix not in allowed_extensions:
        return f"Unsupported upload file type: {suffix or '(none)'}."
    size = _upload_size(upload)
    if size > MAX_UPLOAD_BYTES:
        return f"Upload exceeds {WEB_CONFIG.get('max_upload_mb', 50)} MB limit."
    if require_pcap_magic and not _has_pcap_magic(upload):
        return "Uploaded PCAP failed magic header validation."
    return None


def _upload_size(upload) -> int:
    stream = upload.stream
    position = stream.tell()
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(position)
    return size


def _has_pcap_magic(upload) -> bool:
    stream = upload.stream
    position = stream.tell()
    stream.seek(0)
    header = stream.read(4)
    stream.seek(position)
    return header in PCAP_MAGIC_PREFIXES


def _rewind_upload(upload) -> None:
    upload.stream.seek(0)


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


def _save_optional_logs() -> tuple[dict[str, list[str]], str | None]:
    saved = {"access_log": [], "dns_log": [], "endpoint_log": [], "app_log": []}
    upload_dir = Path(CONFIG["paths"]["csv_dir"]) / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    for field in saved:
        upload = request.files.get(field)
        if upload is None or not upload.filename:
            continue
        error = _validate_upload(upload, ALLOWED_LOG_EXTENSIONS)
        if error:
            return saved, f"{field}: {error}"
        filename = secure_filename(upload.filename)
        path = upload_dir / f"{field}_{filename}"
        _rewind_upload(upload)
        upload.save(path)
        saved[field].append(str(path))
    return saved, None


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
