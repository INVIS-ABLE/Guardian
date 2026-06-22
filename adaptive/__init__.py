"""Guardian Level 6 — the Adaptive Immune Fortress.

This package implements the *autonomic control core* that the Level 6 directive layers on
top of the existing Level 5 authorities. It deliberately holds **no new authority**:

* OPA stays the sole authorisation authority.
* Temporal stays the durable-workflow authority.
* The Plan Compiler stays the only path from AI proposal to executable plan.
* The Capability Authority stays the only issuer of execution permission.
* immudb stays the immutable-evidence authority.
* Shadow Guardian stays the independent-verification authority.
* The Privacy Fabric stays structurally outside message plaintext and keys.

What lives here is the *governor*: the control-state machine, the autonomy budget that
shrinks Guardian's freedom as uncertainty rises, and the healing contracts that say which
reversible repairs are even eligible. Everything in this package produces typed
recommendations and budgets that the authorities above consume — it never executes, never
authorises, and never touches private content.

See ``docs/adaptive/README.md`` for the directive-to-code map and the acceptance-test
traceability matrix.
"""

from __future__ import annotations

from .autonomy.budgets import AutonomyBudget, compute_autonomy_budget
from .autonomy.degradation import EnvironmentHealth, IncidentSeverity, SignalState
from .autonomy.states import (
    AutonomyClass,
    ControlState,
    StateTransitionError,
    TransitionProposal,
    apply_transition,
    permitted_classes,
    propose_transition,
)
from .healing.contracts import (
    HealingContract,
    HealingContractViolation,
    assert_repair_allowed,
)

__all__ = [
    "ControlState",
    "AutonomyClass",
    "TransitionProposal",
    "StateTransitionError",
    "propose_transition",
    "apply_transition",
    "permitted_classes",
    "SignalState",
    "IncidentSeverity",
    "EnvironmentHealth",
    "AutonomyBudget",
    "compute_autonomy_budget",
    "HealingContract",
    "HealingContractViolation",
    "assert_repair_allowed",
]
