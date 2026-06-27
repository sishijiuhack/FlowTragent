"""Build cross-source evidence relationships."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from src.event.models import NetworkEvent


@dataclass
class EvidenceNode:
    node_id: str
    node_type: str
    label: str
    timestamp: float | None
    source: str | None
    target: str | None


@dataclass
class EvidenceEdge:
    source_id: str
    target_id: str
    relation: str
    confidence: str
    reason: str


def build_evidence_graph(
    events: list[NetworkEvent],
    attack_chain: list[dict],
    c2_findings: list[dict],
    time_window: float = 600.0,
) -> dict[str, list[dict[str, Any]]]:
    """Build lightweight graph edges across packet/log/finding evidence."""
    nodes = _event_nodes(events)
    edges: list[EvidenceEdge] = []
    edges.extend(_stage_edges(attack_chain))
    edges.extend(_c2_edges(c2_findings))
    edges.extend(_asset_edges(events))
    edges.extend(_temporal_edges(events, time_window=time_window))
    edges.extend(_endpoint_outbound_edges(events))
    edges = _dedupe_edges(edges)
    nodes.extend(_external_nodes(edges, nodes))
    return {
        "nodes": [asdict(node) for node in nodes],
        "edges": [asdict(edge) for edge in edges],
    }


def _event_nodes(events: list[NetworkEvent]) -> list[EvidenceNode]:
    nodes = []
    for event in events:
        nodes.append(
            EvidenceNode(
                node_id=event.event_id,
                node_type=event.protocol,
                label=(event.summary or event.payload_clean)[:120],
                timestamp=event.timestamp,
                source=_endpoint(event.src_ip, event.src_port),
                target=_endpoint(event.dst_ip, event.dst_port),
            )
        )
    return nodes


def _stage_edges(attack_chain: list[dict]) -> list[EvidenceEdge]:
    edges = []
    for stage in attack_chain:
        stage_name = str(stage.get("stage") or "Attack Stage")
        evidence_ids = [str(item) for item in stage.get("evidence_ids", []) if item]
        for earlier, later in zip(evidence_ids, evidence_ids[1:]):
            edges.append(
                EvidenceEdge(
                    source_id=earlier,
                    target_id=later,
                    relation=f"same_stage:{stage_name}",
                    confidence=str(stage.get("confidence") or "medium"),
                    reason=str(stage.get("reasoning") or f"Both evidence items support {stage_name}."),
                )
            )
    return edges


def _c2_edges(c2_findings: list[dict]) -> list[EvidenceEdge]:
    edges = []
    for finding in c2_findings:
        evidence_ids = [str(item) for item in finding.get("evidence_ids", []) if item]
        for earlier, later in zip(evidence_ids, evidence_ids[1:]):
            edges.append(
                EvidenceEdge(
                    source_id=earlier,
                    target_id=later,
                    relation=f"c2_sequence:{finding.get('c2_type')}",
                    confidence=str(finding.get("confidence") or "medium"),
                    reason=", ".join(finding.get("indicators", []) or ["C2/beacon evidence sequence"]),
                )
            )
    return edges


def _asset_edges(events: list[NetworkEvent]) -> list[EvidenceEdge]:
    edges = []
    endpoint_events = [event for event in events if event.protocol == "ENDPOINT"]
    network_events = [event for event in events if event.protocol != "ENDPOINT"]
    for net_event in network_events:
        for endpoint_event in endpoint_events:
            if not _same_asset(net_event, endpoint_event):
                continue
            edges.append(
                EvidenceEdge(
                    source_id=net_event.event_id,
                    target_id=endpoint_event.event_id,
                    relation="same_asset",
                    confidence="high",
                    reason="Network target/source matches endpoint host or host IP.",
                )
            )
    return edges


def _temporal_edges(events: list[NetworkEvent], time_window: float) -> list[EvidenceEdge]:
    ordered = sorted([event for event in events if event.timestamp is not None], key=lambda event: event.timestamp or 0)
    edges = []
    for earlier, later in zip(ordered, ordered[1:]):
        delta = (later.timestamp or 0) - (earlier.timestamp or 0)
        if delta < 0 or delta > time_window:
            continue
        if earlier.event_id == later.event_id:
            continue
        edges.append(
            EvidenceEdge(
                source_id=earlier.event_id,
                target_id=later.event_id,
                relation="temporal_sequence",
                confidence="medium" if delta <= 120 else "low",
                reason=f"Events occurred {delta:.1f}s apart.",
            )
        )
    return edges


def _endpoint_outbound_edges(events: list[NetworkEvent]) -> list[EvidenceEdge]:
    edges = []
    endpoint_events = [event for event in events if event.protocol == "ENDPOINT" and event.dst_ip]
    followup_events = [event for event in events if event.protocol in {"DNS", "TCP", "HTTP"}]
    for endpoint_event in endpoint_events:
        command = endpoint_event.payload_clean.lower()
        if not any(marker in command for marker in ("curl", "wget", "powershell", "certutil", "bash -c")):
            continue
        edges.append(
            EvidenceEdge(
                source_id=endpoint_event.event_id,
                target_id=f"external:{endpoint_event.dst_ip}:{endpoint_event.dst_port or ''}",
                relation="process_external_connection",
                confidence="high",
                reason="Endpoint/process telemetry shows command activity with a remote destination.",
            )
        )
        for event in followup_events:
            if event.event_id == endpoint_event.event_id:
                continue
            if event.dst_ip and event.dst_ip == endpoint_event.dst_ip:
                edges.append(
                    EvidenceEdge(
                        source_id=endpoint_event.event_id,
                        target_id=event.event_id,
                        relation="process_to_network_destination",
                        confidence="high",
                        reason="Endpoint remote destination matches network evidence destination.",
                    )
                )
            if event.dns_query and endpoint_event.dst_ip in endpoint_event.payload_clean:
                edges.append(
                    EvidenceEdge(
                        source_id=event.event_id,
                        target_id=endpoint_event.event_id,
                        relation="dns_context_for_process",
                        confidence="low",
                        reason="DNS evidence is temporally available near endpoint process activity.",
                    )
                )
    return edges


def _same_asset(network_event: NetworkEvent, endpoint_event: NetworkEvent) -> bool:
    endpoint_ids = {
        value
        for value in [
            endpoint_event.src_ip,
            getattr(endpoint_event, "host", None),
        ]
        if value
    }
    return bool(endpoint_ids & {network_event.src_ip, network_event.dst_ip})


def _dedupe_edges(edges: list[EvidenceEdge]) -> list[EvidenceEdge]:
    seen = set()
    deduped = []
    for edge in edges:
        key = (edge.source_id, edge.target_id, edge.relation)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(edge)
    return deduped


def _external_nodes(edges: list[EvidenceEdge], nodes: list[EvidenceNode]) -> list[EvidenceNode]:
    known = {node.node_id for node in nodes}
    external = []
    for edge in edges:
        for node_id in (edge.source_id, edge.target_id):
            if not node_id.startswith("external:") or node_id in known:
                continue
            known.add(node_id)
            external.append(
                EvidenceNode(
                    node_id=node_id,
                    node_type="ExternalDestination",
                    label=node_id.removeprefix("external:"),
                    timestamp=None,
                    source=None,
                    target=node_id.removeprefix("external:"),
                )
            )
    return external


def _endpoint(ip: str | None, port: int | None) -> str | None:
    if not ip:
        return None
    return f"{ip}:{port}" if port is not None else ip
