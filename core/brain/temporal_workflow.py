"""Temporal outer workflow — durable case + approval lifecycle (target architecture §1).

Temporal owns the *durable* business workflow: it runs the bounded LangGraph inner
reasoning graph inside activities, suspends on a human approval, survives crashes via
Temporal's event-history replay, and resumes deterministically. LangGraph owns the
bounded reasoning *within* each phase; Temporal owns the long-lived orchestration
*around* it. This is the official split the roadmap calls for.

Why activities run the graph: a Temporal workflow must be deterministic and is replayed
from history, so non-deterministic / heavyweight work (LangGraph, model calls, scanners)
runs in **activities**, not in the workflow body. The graph is therefore imported lazily
*inside* the activities, never at workflow-module import time.

The case is passed across the activity boundary as a JSON-safe dict
(``GuardianCaseState.model_dump(mode="json")``) so no custom Temporal data converter is
required.
"""

from __future__ import annotations

from datetime import timedelta

from temporalio import activity, workflow

from .state import CaseStatus, GuardianCaseState

# Statuses at which the investigation graph stops and hands back to the outer workflow.
_AWAITING = CaseStatus.AWAITING_APPROVAL.value
_TERMINAL = {CaseStatus.COMPLETED.value, CaseStatus.HALTED.value, CaseStatus.ABORTED.value}


def needs_approval(status: str) -> bool:
    """Pure predicate: does the outer workflow need to wait for a human after phase 1?"""
    return status == _AWAITING


# --- activities (run the heavy, non-deterministic inner graph) -----------------
@activity.defn
async def run_investigation_activity(case_json: dict) -> dict:
    from .graph import run_investigation  # lazy: keep LangGraph out of the workflow sandbox

    case = GuardianCaseState.model_validate(case_json)
    result = run_investigation(case)
    return result.model_dump(mode="json")


@activity.defn
async def run_execution_activity(case_json: dict) -> dict:
    from .graph import run_execution

    case = GuardianCaseState.model_validate(case_json)
    result = run_execution(case)
    return result.model_dump(mode="json")


# --- the durable outer workflow ------------------------------------------------
@workflow.defn
class GuardianCaseWorkflow:
    """Durable case workflow: investigate → (await human approval) → execute.

    The model never decides authority here: the workflow only proceeds to the
    execution graph when a signed human approval arrives via :meth:`approve`. A
    rejection (or an approval that never comes) leaves the case un-executed.
    """

    def __init__(self) -> None:
        self._decision: str | None = None  # "approved" | "rejected"

    @workflow.run
    async def run(self, case_json: dict) -> dict:
        # Phase 1: bounded investigation in an activity.
        case_json = await workflow.execute_activity(
            run_investigation_activity,
            case_json,
            start_to_close_timeout=timedelta(minutes=15),
        )
        status = case_json.get("status")
        if status in _TERMINAL or not needs_approval(status):
            return case_json  # halted or abstained — nothing to approve, done.

        # Phase 2: suspend durably until a human decision arrives (the interrupt).
        await workflow.wait_condition(lambda: self._decision is not None)
        if self._decision != "approved":
            return {**case_json, "status": CaseStatus.ABORTED.value}

        # Phase 3: post-approval execution in an activity.
        return await workflow.execute_activity(
            run_execution_activity,
            case_json,
            start_to_close_timeout=timedelta(minutes=15),
        )

    @workflow.signal
    async def approve(self, decision: str) -> None:
        """Human decision signal: "approved" or "rejected". Never self-granted."""
        if decision in ("approved", "rejected"):
            self._decision = decision

    @workflow.query
    def decision(self) -> str | None:
        return self._decision


__all__ = [
    "GuardianCaseWorkflow",
    "run_investigation_activity",
    "run_execution_activity",
    "needs_approval",
]
