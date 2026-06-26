"""Structured event and finding models for FlowTragent."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class NetworkEvent:
    event_id: str
    timestamp: float | None
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str
    payload_clean: str
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HttpEvent(NetworkEvent):
    method: str | None = None
    uri: str | None = None
    host: str | None = None
    user_agent: str | None = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: str | None = None
    status_code: int | None = None
    response_reason: str | None = None
    response_size: int | None = None
    response_summary: str | None = None


@dataclass
class RetrievalEvidence:
    event_id: str
    candidate_cve: str
    score: float
    rank: int
    neighbor_id: str | None = None
    neighbor_payload: str | None = None
    neighbor_labels: List[str] = field(default_factory=list)
    engine: str = "nova-f"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackStage:
    stage: str
    technique: str
    confidence: str
    start_time: float | None
    end_time: float | None
    source_ip: str | None
    target_ip: str | None
    evidence_ids: List[str]
    reasoning: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class C2Finding:
    c2_type: str
    confidence: str
    src_ip: str
    dst_ip: str
    dst_port: int
    first_seen: float | None
    last_seen: float | None
    request_count: int
    beacon_interval: float | None
    jitter: float | None
    evidence_ids: List[str]
    indicators: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
