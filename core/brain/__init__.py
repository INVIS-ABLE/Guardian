"""Guardian Brain package.

* :mod:`core.brain.orchestrator` — the current gated, auditable orchestrator
  (``GuardianBrain``, ``build_policy_input`` …). Re-exported here so existing
  imports (``from core.brain import GuardianBrain, build_policy_input``) keep working.
* :mod:`core.brain.state` — the typed, immutable case-state contract that replaces
  the mutable blackboard (``GuardianCaseState``, ``CaseStateDelta`` …). Build-order
  step 1; consumed by the reasoning graph that will sit behind the orchestrator.
"""

from __future__ import annotations

from .graph import (
    build_execution_graph,
    build_investigation_graph,
    run_execution,
    run_investigation,
)
from .failures import FailureBehavior, FailureClass, behavior_for, is_fatal
from .orchestrator import (
    POST_APPROVAL_STAGES,
    WORKFLOW,
    BrainRun,
    GuardianBrain,
    StageResult,
    build_policy_input,
    run_from_scope_file,
)
from .state import (
    CaseStateDelta,
    CaseStatus,
    CaseTrigger,
    ExecutionBudgets,
    GuardianCaseState,
    VerifiedScope,
)

__all__ = [
    # orchestrator (unchanged public API)
    "GuardianBrain",
    "BrainRun",
    "StageResult",
    "WORKFLOW",
    "POST_APPROVAL_STAGES",
    "build_policy_input",
    "run_from_scope_file",
    # typed case-state contracts
    "GuardianCaseState",
    "CaseStateDelta",
    "CaseStatus",
    "ExecutionBudgets",
    "VerifiedScope",
    "CaseTrigger",
    # reasoning graph (LangGraph) + failure taxonomy
    "build_investigation_graph",
    "build_execution_graph",
    "run_investigation",
    "run_execution",
    "FailureClass",
    "FailureBehavior",
    "behavior_for",
    "is_fatal",
]
