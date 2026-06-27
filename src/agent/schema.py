"""Stable schema for deterministic agent output."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


AGENT_SCHEMA_VERSION = "agent-v1"


@dataclass
class AgentFinding:
    agent: str
    finding: str
    confidence: str
    evidence_ids: List[str] = field(default_factory=list)
    reasoning: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgentEvidence:
    evidence_id: str
    evidence_type: str
    summary: str
    source: str | None = None
    target: str | None = None
    related: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgentReport:
    executive_summary: str
    key_findings: List[str]
    agent_reasoning: List[AgentFinding]
    evidence_pack: List[AgentEvidence]
    confidence_summary: Dict[str, int]
    limitations: List[str]
    next_actions: List[str]
    schema_version: str = AGENT_SCHEMA_VERSION
    mode: str = "deterministic"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["agent_reasoning"] = [item.to_dict() for item in self.agent_reasoning]
        data["evidence_pack"] = [item.to_dict() for item in self.evidence_pack]
        return data
