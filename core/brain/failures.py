"""Failure taxonomy for the reasoning graph (target architecture §12).

The old linear Brain caught an agent exception, marked that node "refused", and
*continued* through later nodes. That is fail-open: a patch must never be generated
from a case whose scope verification or evidence integrity failed. This module gives
each class of failure an explicit, bounded behaviour, so the graph fails closed where
it must and degrades safely where it can.

The behaviours are advisory metadata the graph nodes consult — they do not execute
side effects themselves. The graph turns a ``HALT`` into an aborted case, a ``REJECT``
into a rejected action, and so on.
"""

from __future__ import annotations

from enum import Enum


class FailureClass(str, Enum):
    """The kind of thing that failed during a case."""

    SCOPE_IDENTITY_OWNERSHIP_POLICY = "scope_identity_ownership_policy"
    EVIDENCE_COLLECTOR = "evidence_collector"
    SPECIALIST_MODEL = "specialist_model"
    MEMORY_UNAVAILABLE = "memory_unavailable"
    AUDIT_EVIDENCE_BACKEND = "audit_evidence_backend"
    VERIFICATION = "verification"
    APPROVAL_BACKEND = "approval_backend"
    OBSERVABILITY = "observability"


class FailureBehavior(str, Enum):
    """What the graph should do in response."""

    HALT = "halt"                              # stop the case, fail closed
    RETRY_THEN_GAP = "retry_then_mark_gap"     # retry, then record an evidence gap
    FALLBACK_OR_ABSTAIN = "fallback_or_abstain"
    CONTINUE_NO_RETRIEVAL = "continue_without_retrieval"  # development only
    REJECT = "reject_proposed_action"
    DEGRADED_OR_HALT = "degraded_or_halt_by_risk"


# The static base mapping (target architecture §12 table).
_BASE_POLICY: dict[FailureClass, FailureBehavior] = {
    FailureClass.SCOPE_IDENTITY_OWNERSHIP_POLICY: FailureBehavior.HALT,
    FailureClass.EVIDENCE_COLLECTOR: FailureBehavior.RETRY_THEN_GAP,
    FailureClass.SPECIALIST_MODEL: FailureBehavior.FALLBACK_OR_ABSTAIN,
    FailureClass.MEMORY_UNAVAILABLE: FailureBehavior.CONTINUE_NO_RETRIEVAL,
    FailureClass.AUDIT_EVIDENCE_BACKEND: FailureBehavior.HALT,
    FailureClass.VERIFICATION: FailureBehavior.REJECT,
    FailureClass.APPROVAL_BACKEND: FailureBehavior.HALT,
    FailureClass.OBSERVABILITY: FailureBehavior.DEGRADED_OR_HALT,
}


def behavior_for(
    failure: FailureClass,
    *,
    environment: str = "staging",
    risk: str = "high",
) -> FailureBehavior:
    """Resolve the behaviour for a failure, applying the environment/risk caveats.

    * Memory unavailable may only be tolerated (continue without retrieval) in
      ``development``; anywhere else it halts — production must fail closed rather than
      silently dropping retrieval.
    * Observability failure is risk-weighted: it halts for high-risk work and degrades
      otherwise.
    """
    base = _BASE_POLICY[failure]

    if failure is FailureClass.MEMORY_UNAVAILABLE and environment != "development":
        return FailureBehavior.HALT

    if failure is FailureClass.OBSERVABILITY:
        return FailureBehavior.HALT if risk == "high" else FailureBehavior.DEGRADED_OR_HALT

    return base


def is_fatal(behavior: FailureBehavior) -> bool:
    """Whether a behaviour ends the case (used by the graph to route to an abort)."""
    return behavior is FailureBehavior.HALT


__all__ = ["FailureClass", "FailureBehavior", "behavior_for", "is_fatal"]
