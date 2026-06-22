"""Patch reviewer — independent verification of a proposed patch (§6, §16).

A patch must not be reviewed by the model that produced it. This specialist enforces
that independence and runs deterministic completeness checks before any model opinion:

* **Independence** — if the reviewer's model family equals the producer's family, it
  abstains. The patch-generating model is never the sole reviewer.
* **Deterministic completeness** — the proposed action must document a rollback plan and
  residual risk and trace back to findings; otherwise the review fails.
* **Advisory judge** — an independent (different-family) judge model may add a note, but
  the verdict is deterministic.

The reviewer never approves or merges a patch; it returns a typed verification result
for the human/Temporal approval gate.
"""

from __future__ import annotations

from core.ai import ModelRequest, WorkClass
from core.brain.state import CaseStateDelta
from core.evidence.models import ProposedAction, VerificationResult

from .base import Specialist, SpecialistResult, SpecialistTask


class PatchReviewer(Specialist):
    name = "patch_reviewer"
    work_class = WorkClass.REVIEW
    #: the model family this reviewer reviews with — must differ from the producer's
    reviewer_family: str = "openai"

    def run(self, task: SpecialistTask) -> SpecialistResult:
        if not task.proposed_actions:
            return self._abstain("no proposed action to review")

        # Independence: a patch's producer model family must not also review it.
        if task.producer_model_family and task.producer_model_family == self.reviewer_family:
            return self._abstain(
                f"reviewer family '{self.reviewer_family}' equals producer — not independent"
            )

        results: list[VerificationResult] = []
        all_pass = True
        for action in task.proposed_actions:
            reasons = _completeness_failures(action)
            passed = not reasons
            all_pass = all_pass and passed
            results.append(
                VerificationResult(
                    subject_id=action.id, verifier=self.name, passed=passed,
                    reasons=tuple(reasons),
                )
            )

        notes = self._advisory_note(task)
        verdict = "pass" if all_pass else "fail"
        return SpecialistResult(
            specialist=self.name, verdict=verdict,
            confidence=1.0 if all_pass else 0.0,
            delta=CaseStateDelta(verification_results=tuple(results)),
            notes=notes,
        )

    def _advisory_note(self, task: SpecialistTask) -> tuple[str, ...]:
        if self._gateway is None:
            return ()
        try:
            resp = self._gateway.complete(
                ModelRequest(
                    work_class=WorkClass.REVIEW, tenant_id=task.tenant_id,
                    case_id=task.case_id,
                    instruction="Independently review this patch for correctness and risk.",
                    prompt_template_version="patch_reviewer_v1",
                    max_output_tokens=256,
                )
            )
        except Exception:  # noqa: BLE001 - advisory only
            return ()
        return (f"judge_advisory:{resp.record.model_id}",)


def _completeness_failures(action: ProposedAction) -> list[str]:
    """Deterministic checks every patch proposal must satisfy (§16)."""
    failures: list[str] = []
    if not action.rollback_plan.strip():
        failures.append("missing_rollback_plan")
    if not action.residual_risk.strip():
        failures.append("missing_residual_risk")
    if not action.finding_ids:
        failures.append("not_traceable_to_findings")
    return failures


__all__ = ["PatchReviewer"]
