"""Guardian durable orchestration (Phase 1).

A monotonic, restart-safe security-workflow state machine with two-reviewer approvals,
replay protection, risk tiers, budgets, kill switches, and a last-moment policy re-check
before execution. Temporal makes it durable in deployment; the in-process engine here
enforces the same invariants and is fully testable.
"""

from __future__ import annotations

from .approvals import ApprovalLedger, ClosedLedgerError, ReplaySignalError, ReviewerSignal
from .engine import (
    BudgetExceeded,
    KillSwitch,
    NotEnoughApprovers,
    RiskTier,
    SecurityWorkflowEngine,
    WorkflowBudget,
    WorkflowFrozen,
)
from .state_machine import IllegalTransition, State, WorkflowMachine
from .temporal_backend import temporal_available

__all__ = [
    "ApprovalLedger",
    "ReviewerSignal",
    "ReplaySignalError",
    "ClosedLedgerError",
    "SecurityWorkflowEngine",
    "KillSwitch",
    "WorkflowBudget",
    "RiskTier",
    "WorkflowFrozen",
    "BudgetExceeded",
    "NotEnoughApprovers",
    "WorkflowMachine",
    "State",
    "IllegalTransition",
    "temporal_available",
]
