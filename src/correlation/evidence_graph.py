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
    graph = {
        "nodes": [asdict(node) for node in nodes],
        "edges": [asdict(edge) for edge in edges],
    }
    graph["paths"] = extract_key_paths(graph)
    graph["mermaid"] = render_mermaid_graph(graph, language="en")
    graph["mermaid_zh"] = render_mermaid_graph(graph, language="zh")
    graph["dot"] = render_dot_graph(graph, language="en")
    graph["dot_zh"] = render_dot_graph(graph, language="zh")
    return graph


def extract_key_paths(graph: dict[str, Any], max_paths: int = 12) -> list[dict[str, Any]]:
    """Extract compact evidence paths useful for agent reasoning."""
    edges = graph.get("edges", [])
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        adjacency.setdefault(str(edge.get("source_id")), []).append(edge)

    starts = [
        str(node.get("node_id"))
        for node in graph.get("nodes", [])
        if str(node.get("node_type")) in {"HTTP", "DNS", "TCP"} and node.get("node_id")
    ]
    paths = []
    for start in starts:
        _walk_paths(adjacency, start, [start], [], paths, max_depth=4)
        if len(paths) >= max_paths:
            break
    return paths[:max_paths]


def _walk_paths(
    adjacency: dict[str, list[dict[str, Any]]],
    current: str,
    node_path: list[str],
    relation_path: list[str],
    output: list[dict[str, Any]],
    max_depth: int,
) -> None:
    if len(node_path) > max_depth:
        return
    outgoing = adjacency.get(current, [])
    if not outgoing:
        if len(node_path) >= 2:
            output.append(
                {
                    "nodes": list(node_path),
                    "relations": list(relation_path),
                    "summary": _path_summary(node_path, relation_path),
                }
            )
        return
    for edge in outgoing:
        target = str(edge.get("target_id") or "")
        if not target or target in node_path:
            continue
        next_nodes = [*node_path, target]
        next_relations = [*relation_path, str(edge.get("relation") or "related")]
        if target.startswith("external:") or len(next_nodes) >= max_depth:
            output.append({"nodes": next_nodes, "relations": next_relations, "summary": _path_summary(next_nodes, next_relations)})
        else:
            _walk_paths(adjacency, target, next_nodes, next_relations, output, max_depth)


def _path_summary(nodes: list[str], relations: list[str]) -> str:
    parts = []
    for index, node in enumerate(nodes):
        parts.append(node)
        if index < len(relations):
            parts.append(f"--{relations[index]}-->")
    return " ".join(parts)


def render_mermaid_graph(graph: dict[str, Any], max_edges: int = 40, language: str = "en") -> str:
    """Render an evidence graph as a Mermaid flowchart."""
    nodes = {str(node.get("node_id")): node for node in graph.get("nodes", []) if node.get("node_id")}
    lines = ["flowchart TD"]
    emitted_nodes = set()
    for edge in graph.get("edges", [])[:max_edges]:
        source_id = str(edge.get("source_id") or "")
        target_id = str(edge.get("target_id") or "")
        if not source_id or not target_id:
            continue
        for node_id in (source_id, target_id):
            if node_id in emitted_nodes:
                continue
            node = nodes.get(node_id, {"node_id": node_id, "node_type": "External", "label": node_id})
            lines.append(f"  {_mermaid_id(node_id)}[{_mermaid_label(node, language=language)}]")
            emitted_nodes.add(node_id)
        relation = _mermaid_text(_relation_label(str(edge.get("relation") or "related"), language=language))
        lines.append(f"  {_mermaid_id(source_id)} -->|{relation}| {_mermaid_id(target_id)}")
    if len(lines) == 1:
        lines.append("  empty[没有证据图谱边]" if language == "zh" else "  empty[No evidence graph edges]")
    return "\n".join(lines)


def render_dot_graph(graph: dict[str, Any], max_edges: int = 80, language: str = "en") -> str:
    """Render an evidence graph as Graphviz DOT."""
    nodes = {str(node.get("node_id")): node for node in graph.get("nodes", []) if node.get("node_id")}
    lines = [
        "digraph FlowTragentEvidence {",
        "  rankdir=LR;",
        '  graph [fontname="Arial"];',
        '  node [shape=box, style="rounded,filled", fillcolor="#f6f8fa", fontname="Arial"];',
        '  edge [fontname="Arial"];',
    ]
    emitted_nodes = set()
    for edge in graph.get("edges", [])[:max_edges]:
        source_id = str(edge.get("source_id") or "")
        target_id = str(edge.get("target_id") or "")
        if not source_id or not target_id:
            continue
        for node_id in (source_id, target_id):
            if node_id in emitted_nodes:
                continue
            node = nodes.get(node_id, {"node_id": node_id, "node_type": "External", "label": node_id})
            lines.append(f'  "{_dot_escape(node_id)}" [label="{_dot_label(node, language=language)}"];')
            emitted_nodes.add(node_id)
        lines.append(
            '  "{source}" -> "{target}" [label="{relation}", color="{color}"];'.format(
                source=_dot_escape(source_id),
                target=_dot_escape(target_id),
                relation=_dot_escape(_relation_label(str(edge.get("relation") or "related"), language=language)),
                color=_edge_color(str(edge.get("confidence") or "")),
            )
        )
    lines.append("}")
    return "\n".join(lines)


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


def _mermaid_id(node_id: str) -> str:
    safe = "".join(char if char.isalnum() else "_" for char in node_id)
    if not safe or safe[0].isdigit():
        safe = f"n_{safe}"
    return safe


def _mermaid_label(node: dict[str, Any], language: str = "en") -> str:
    node_id = str(node.get("node_id") or "")
    node_type = _node_type_label(str(node.get("node_type") or "Evidence"), language=language)
    label = str(node.get("label") or node_id)
    compact = f"{node_id}\\n{node_type}\\n{label[:80]}"
    return f'"{_mermaid_text(compact)}"'


def _mermaid_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', "'").replace("|", "/").replace("\n", "\\n")


def _dot_label(node: dict[str, Any], language: str = "en") -> str:
    node_id = str(node.get("node_id") or "")
    node_type = _node_type_label(str(node.get("node_type") or "Evidence"), language=language)
    label = str(node.get("label") or node_id)[:90]
    return _dot_escape(f"{node_id}\\n{node_type}\\n{label}")


def _node_type_label(node_type: str, language: str) -> str:
    if language != "zh":
        return node_type
    return {
        "HTTP": "HTTP流量",
        "DNS": "DNS查询",
        "TCP": "TCP连接",
        "ENDPOINT": "终端日志",
        "ExternalDestination": "外部目的地",
        "Evidence": "证据",
        "External": "外部节点",
    }.get(node_type, node_type)


def _relation_label(relation: str, language: str) -> str:
    if language != "zh":
        return relation
    mapping = {
        "same_asset": "同一资产",
        "temporal_sequence": "时间顺序",
        "process_external_connection": "进程外联",
        "process_to_network_destination": "进程到网络目的地",
        "dns_context_for_process": "DNS与进程上下文",
        "related": "关联",
    }
    if relation.startswith("c2_sequence:"):
        return relation.replace("c2_sequence:", "C2通信序列:")
    if relation.startswith("same_stage:"):
        return relation.replace("same_stage:", "同一攻击阶段:")
    return mapping.get(relation, relation)


def _dot_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _edge_color(confidence: str) -> str:
    if confidence.lower() == "high":
        return "#166534"
    if confidence.lower() == "medium":
        return "#a16207"
    return "#64748b"


def _endpoint(ip: str | None, port: int | None) -> str | None:
    if not ip:
        return None
    return f"{ip}:{port}" if port is not None else ip
