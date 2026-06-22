"""The bounded reasoning graph (target architecture §1), built on LangGraph.

This replaces the fixed linear loop with two LangGraph ``StateGraph``s over the typed
:class:`GuardianCaseState`:

* **investigation** — intake → scope/identity gate → plan → collect → analyse →
  challenge → adjudicate. A conditional edge halts the case immediately if the
  deterministic scope gate fails (fail closed, §12). It ends either at
  ``AWAITING_APPROVAL`` (a finding to approve) or ``COMPLETED`` (abstained).
* **execution** — controlled execution → observe → learn. Only ever run *after* a
  human approval, which the Temporal outer workflow gates (see ``temporal_workflow``).

Nodes return typed :class:`CaseStateDelta`s; a reducer applies them to produce a new
immutable state, so nodes cannot clobber one another. Execution is bounded: a step cap
maps a runaway graph to a recorded HALT rather than an open-ended loop, and an
exhausted budget halts before the graph even starts.
"""

from __future__ import annotations

from typing import Annotated, Callable

from langgraph.graph import END, START, StateGraph
from langgraph.errors import GraphRecursionError
from pydantic import BaseModel

from .nodes import (
    adjudicate,
    analyse,
    challenge,
    collect,
    controlled_execution,
    intake,
    learn,
    observe,
    plan,
    scope_verify,
)
from .state import CaseStateDelta, CaseStatus, GuardianCaseState

# A generous default super-step cap; the per-case budget can lower it.
DEFAULT_MAX_STEPS = 50


def _reduce_case(
    current: GuardianCaseState | None,
    update: GuardianCaseState | CaseStateDelta,
) -> GuardianCaseState:
    """LangGraph channel reducer: set the initial case, then apply deltas to it."""
    if isinstance(update, GuardianCaseState):
        return update
    if current is None:  # pragma: no cover - defensive; the graph always sets case first
        raise ValueError("cannot apply a delta before the case is initialised")
    return current.apply(update)


class GraphState(BaseModel):
    """The LangGraph state: a single immutable case behind a delta-applying reducer."""

    case: Annotated[GuardianCaseState, _reduce_case]


def _node(fn: Callable[[GuardianCaseState], CaseStateDelta]) -> Callable[[GraphState], dict]:
    """Wrap a pure node function as a LangGraph node returning a channel update."""

    def _run(state: GraphState) -> dict:
        return {"case": fn(state.case)}

    _run.__name__ = fn.__name__
    return _run


def _after_scope(state: GraphState) -> str:
    """Fail closed: a halted scope gate ends the case; otherwise continue to plan."""
    return END if state.case.status is CaseStatus.HALTED else "plan"


def build_investigation_graph():
    """Compile the investigation graph (intake → … → adjudicate)."""
    g = StateGraph(GraphState)
    g.add_node("intake", _node(intake))
    g.add_node("scope_verify", _node(scope_verify))
    g.add_node("plan", _node(plan))
    g.add_node("collect", _node(collect))
    g.add_node("analyse", _node(analyse))
    g.add_node("challenge", _node(challenge))
    g.add_node("adjudicate", _node(adjudicate))

    g.add_edge(START, "intake")
    g.add_edge("intake", "scope_verify")
    g.add_conditional_edges("scope_verify", _after_scope, {END: END, "plan": "plan"})
    g.add_edge("plan", "collect")
    g.add_edge("collect", "analyse")
    g.add_edge("analyse", "challenge")
    g.add_edge("challenge", "adjudicate")
    g.add_edge("adjudicate", END)
    return g.compile()


def build_execution_graph():
    """Compile the post-approval execution graph (execute → observe → learn)."""
    g = StateGraph(GraphState)
    g.add_node("controlled_execution", _node(controlled_execution))
    g.add_node("observe", _node(observe))
    g.add_node("learn", _node(learn))
    g.add_edge(START, "controlled_execution")
    g.add_edge("controlled_execution", "observe")
    g.add_edge("observe", "learn")
    g.add_edge("learn", END)
    return g.compile()


def _run(graph, case: GuardianCaseState, *, max_steps: int) -> GuardianCaseState:
    """Run a compiled graph under a hard step cap; map overruns to a recorded HALT."""
    exhausted = case.budgets.exhausted()
    if exhausted:
        return case.model_copy(update={"status": CaseStatus.HALTED})
    try:
        result = graph.invoke({"case": case}, {"recursion_limit": max_steps})
    except GraphRecursionError:
        # Bounded: a runaway graph halts rather than looping forever.
        return case.model_copy(update={"status": CaseStatus.HALTED})
    return result["case"]


def run_investigation(case: GuardianCaseState, *, max_steps: int = DEFAULT_MAX_STEPS) -> GuardianCaseState:
    """Run the investigation graph and return the resulting immutable case state."""
    cap = min(max_steps, case.budgets.max_iterations)
    return _run(build_investigation_graph(), case, max_steps=cap)


def run_execution(case: GuardianCaseState, *, max_steps: int = DEFAULT_MAX_STEPS) -> GuardianCaseState:
    """Run the post-approval execution graph. Caller must have verified approval."""
    cap = min(max_steps, case.budgets.max_iterations)
    return _run(build_execution_graph(), case, max_steps=cap)


__all__ = [
    "GraphState",
    "build_investigation_graph",
    "build_execution_graph",
    "run_investigation",
    "run_execution",
    "DEFAULT_MAX_STEPS",
]
