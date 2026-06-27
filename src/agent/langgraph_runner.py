"""Optional LangGraph orchestration for deterministic agents."""

from __future__ import annotations

import warnings
from typing import Any, Dict, List, TypedDict

from src.agent.schema import AgentFinding


class AgentGraphState(TypedDict, total=False):
    analysis: Dict[str, Any]
    findings: List[AgentFinding]
    orchestration: Dict[str, Any]


def run_agent_graph(analysis: Dict[str, Any], agents: List[Any]) -> AgentGraphState:
    """Run deterministic agents through LangGraph when available.

    If LangGraph is unavailable or changes API behavior, this function falls
    back to a sequential runner while preserving the same state shape.
    """
    try:
        return _run_langgraph(analysis, agents)
    except Exception as exc:
        return _run_sequential(
            analysis,
            agents,
            engine="sequential",
            fallback_reason=f"{type(exc).__name__}: {exc}",
        )


def _run_langgraph(analysis: Dict[str, Any], agents: List[Any]) -> AgentGraphState:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"langgraph\..*")
        warnings.filterwarnings("ignore", message=".*allowed_objects.*")
        try:
            from langchain_core._api.deprecation import LangChainPendingDeprecationWarning

            warnings.filterwarnings("ignore", category=LangChainPendingDeprecationWarning)
        except Exception:
            pass
        from langgraph.graph import END, StateGraph

    graph = StateGraph(AgentGraphState)

    previous = None
    for index, agent in enumerate(agents):
        node_name = f"agent_{index}_{_slug(agent.name)}"

        def _node(state: AgentGraphState, current_agent=agent) -> AgentGraphState:
            findings = list(state.get("findings", []))
            findings.append(current_agent.run(state["analysis"]))
            return {"findings": findings}

        graph.add_node(node_name, _node)
        if previous is None:
            graph.set_entry_point(node_name)
        else:
            graph.add_edge(previous, node_name)
        previous = node_name

    if previous is None:
        return {"analysis": analysis, "findings": [], "orchestration": {"engine": "langgraph", "nodes": []}}
    graph.add_edge(previous, END)
    compiled = graph.compile()
    result = compiled.invoke({"analysis": analysis, "findings": []})
    return {
        "analysis": analysis,
        "findings": result.get("findings", []),
        "orchestration": {
            "engine": "langgraph",
            "nodes": [agent.name for agent in agents],
            "fallback_reason": None,
        },
    }


def _run_sequential(
    analysis: Dict[str, Any],
    agents: List[Any],
    engine: str = "sequential",
    fallback_reason: str | None = None,
) -> AgentGraphState:
    return {
        "analysis": analysis,
        "findings": [agent.run(analysis) for agent in agents],
        "orchestration": {
            "engine": engine,
            "nodes": [agent.name for agent in agents],
            "fallback_reason": fallback_reason,
        },
    }


def _slug(value: str) -> str:
    return "".join(char.lower() if char.isalnum() else "_" for char in value).strip("_")
