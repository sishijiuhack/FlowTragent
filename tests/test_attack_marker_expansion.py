from __future__ import annotations

from src.correlation.attack_chain import detect_attack_stages
from src.event.models import HttpEvent


def _event(event_id: str, payload: str) -> HttpEvent:
    return HttpEvent(
        event_id=event_id,
        timestamp=1.0,
        src_ip="10.0.0.5",
        src_port=44444,
        dst_ip="10.0.0.10",
        dst_port=80,
        protocol="HTTP",
        payload_clean=payload,
        summary=payload,
        method="GET",
        uri="/",
        host="victim",
        user_agent="curl",
        headers={},
    )


def test_new_exploit_marker_families_create_exploitation_stage() -> None:
    events = [
        _event("ssrf", "GET /fetch?url=http://169.254.169.254/latest/meta-data HTTP/1.1"),
        _event("xxe", 'POST /xml HTTP/1.1 <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'),
        _event("deser", "POST /deserialize HTTP/1.1 rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="),
        _event("ssti", "GET /render?name={{7*7}} HTTP/1.1"),
        _event("cmdi", "GET /cgi-bin/admin.cgi?Command=;id HTTP/1.1"),
    ]

    stages = detect_attack_stages(events, [])

    exploitation = [stage for stage in stages if stage["stage"] == "Exploitation"]
    assert exploitation
    assert set(exploitation[0]["evidence_ids"]) == {"ssrf", "xxe", "deser", "ssti", "cmdi"}


def test_command_injection_markers_create_command_execution_stage() -> None:
    stages = detect_attack_stages([_event("cmdi", "GET /cgi-bin/admin.cgi?Command=;id HTTP/1.1")], [])

    assert any(stage["stage"] == "Command Execution" and "cmdi" in stage["evidence_ids"] for stage in stages)
