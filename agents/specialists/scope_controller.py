"""Scope controller — deterministic scope/identity/ownership specialist (§6, §1).

This is the one specialist that must **never** use a model: a model never decides
whether Guardian has authority to proceed. It verifies the case's scope and ownership
deterministically and emits a typed policy decision. A failed check is a hard ``fail``
(the graph turns that into a halt); a passed check authorises *investigation only* —
never execution or approval.
"""

from __future__ import annotations

from core.evidence.models import PolicyDecisionRecord

from .base import Specialist, SpecialistResult, SpecialistTask


class ScopeController(Specialist):
    name = "scope_controller"
    work_class = None  # deterministic — no model, ever

    def run(self, task: SpecialistTask) -> SpecialistResult:
        scope = task.scope
        if not scope.ownership_verified:
            record = PolicyDecisionRecord(
                action="proceed_case", mode="scope_verify", allow=False,
                denies=("ownership_unverified",),
            )
            return SpecialistResult(
                specialist=self.name, verdict="fail", confidence=1.0,
                delta=_delta(record), notes=("ownership not verified — halt",),
            )
        record = PolicyDecisionRecord(action="proceed_case", mode="scope_verify", allow=True)
        return SpecialistResult(
            specialist=self.name, verdict="pass", confidence=1.0,
            delta=_delta(record),
            notes=(f"scope verified for asset {scope.asset} in {scope.environment}",),
        )


def _delta(record: PolicyDecisionRecord):
    from core.brain.state import CaseStateDelta
    return CaseStateDelta(policy_decisions=(record,))


__all__ = ["ScopeController"]
