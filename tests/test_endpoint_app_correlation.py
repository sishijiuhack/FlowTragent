from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.correlation.attack_chain import detect_attack_stages
from src.correlation.evidence_graph import build_evidence_graph
from src.correlation.impact_analyzer import assess_impact
from src.event.models import HttpEvent, LogEvent
from src.parser.log_parser import parse_application_log, parse_log_bundle


def _exploit_404() -> HttpEvent:
    return HttpEvent(
        event_id="http-1",
        timestamp=10.0,
        src_ip="10.0.0.5",
        src_port=44444,
        dst_ip="10.0.0.10",
        dst_port=80,
        protocol="HTTP",
        payload_clean="GET /shell?cmd=whoami HTTP/1.1",
        summary="blocked command probe",
        method="GET",
        uri="/shell?cmd=whoami",
        host="victim",
        user_agent="curl",
        headers={},
        status_code=404,
    )


def _file_drop() -> LogEvent:
    return LogEvent(
        event_id="endpoint-file-1",
        timestamp=12.0,
        src_ip="10.0.0.10",
        src_port=None,
        dst_ip=None,
        dst_port=None,
        protocol="ENDPOINT",
        payload_clean="file_create w3wp C:\\inetpub\\wwwroot\\upload\\cmd.aspx",
        summary="webshell file created",
        log_type="endpoint",
        host="victim",
        process_name="w3wp.exe",
        file_path="C:\\inetpub\\wwwroot\\upload\\cmd.aspx",
        action="file_create",
    )


def test_endpoint_file_artifact_confirms_post_exploit_despite_4xx() -> None:
    events = [_exploit_404(), _file_drop()]
    chain = detect_attack_stages(events, candidates=[])
    stage_names = {stage["stage"] for stage in chain}

    assert "Payload Delivery" in stage_names
    assert "WebShell / Backdoor" in stage_names

    impact = assess_impact(events, chain, [], [])
    assert impact["verdict"] == "Likely successful exploitation"
    assert impact["confidence"] == "high"


def test_application_log_confirmation_edges_link_back_to_network_event(tmp_path: Path) -> None:
    app_log = tmp_path / "app.jsonl"
    app_log.write_text(
        json.dumps(
            {
                "timestamp": 11.0,
                "host": "10.0.0.10",
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.10",
                "uri": "/shell?cmd=whoami",
                "message": "Template error while evaluating cmd parameter; stack trace recorded",
                "status": 500,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    app_events = parse_application_log(app_log)
    assert len(app_events) == 1
    assert app_events[0].protocol == "APPLICATION"

    graph = build_evidence_graph([_exploit_404(), app_events[0]], [], [])
    relations = {edge["relation"] for edge in graph["edges"]}
    assert "application_log_confirmation" in relations


def test_endpoint_file_artifact_adds_graph_node() -> None:
    graph = build_evidence_graph([_exploit_404(), _file_drop()], [], [])
    relations = {edge["relation"] for edge in graph["edges"]}
    node_types = {node["node_type"] for node in graph["nodes"]}

    assert "endpoint_file_artifact" in relations
    assert "FileArtifact" in node_types


def test_parse_log_bundle_accepts_application_logs(tmp_path: Path) -> None:
    app_log = tmp_path / "app.csv"
    app_log.write_text(
        "timestamp,host,src_ip,dst_ip,uri,message,status\n"
        "11.0,10.0.0.10,10.0.0.5,10.0.0.10,/login,deserialization exception stack trace,500\n",
        encoding="utf-8",
    )
    events = parse_log_bundle(application_logs=[app_log])
    assert len(events) == 1
    assert events[0].protocol == "APPLICATION"


def test_endpoint_noise_does_not_override_4xx_downgrade() -> None:
    endpoint_noise = LogEvent(
        event_id="endpoint-noise",
        timestamp=12.0,
        src_ip="10.0.0.10",
        src_port=None,
        dst_ip=None,
        dst_port=None,
        protocol="ENDPOINT",
        payload_clean="heartbeat normal service health check",
        summary="normal endpoint event",
        log_type="endpoint",
        host="victim",
        action="heartbeat",
    )
    impact = assess_impact(
        [_exploit_404(), endpoint_noise],
        [{"stage": "Command Execution", "confidence": "medium", "evidence_ids": ["http-1", "endpoint-noise"]}],
        [],
        [],
    )
    assert impact["verdict"] == "Possible exploitation attempt"
    assert impact["confidence"] == "low"
