"""Optional Temporal backend (temporalio/sdk-python) for durable, restart-safe workflows.

Temporal provides durability: a workflow can pause for human approval for as long as needed
and survive worker restarts. This module wires the same state machine + engine into a
Temporal workflow when the SDK is installed; otherwise Guardian uses the in-process engine
(orchestration/engine.py), which enforces the identical invariants and is fully testable.

Design (when temporalio is present):
  - the workflow advances through the WorkflowMachine states as Temporal activities;
  - it BLOCKS on a `production_approval` signal until two distinct authenticated reviewers
    have signalled (replayed signals rejected by the ApprovalLedger);
  - immediately before the execute activity it RE-ASKS the OPA/policy gate;
  - a `kill` signal freezes the workflow.

This file deliberately keeps the Temporal import lazy so the rest of Guardian has no hard
dependency on a running Temporal cluster.
"""

from __future__ import annotations


def temporal_available() -> bool:
    """True if the temporalio SDK is importable."""
    try:
        import temporalio  # noqa: F401
        return True
    except Exception:
        return False


TASK_QUEUE = "guardian-security-workflows"
PRODUCTION_APPROVAL_SIGNAL = "production_approval"
KILL_SIGNAL = "kill"

# Concrete @workflow.defn / @activity.defn classes are added when temporalio is adopted in
# deployment (Phase 1 rollout). The in-process engine is the reference implementation and the
# system of behaviour until then; see docs/phase1_orchestration.md.
__all__ = [
    "temporal_available",
    "TASK_QUEUE",
    "PRODUCTION_APPROVAL_SIGNAL",
    "KILL_SIGNAL",
]
