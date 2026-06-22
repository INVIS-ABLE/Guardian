"""Evidence adjudicator — evidence-led verdict, never majority vote (§6, §7).

The adjudicator decides whether a hypothesis is established. It does **not** count votes
or trust a model: the verdict is deterministic and requires grounding — supporting
evidence, no unresolved contradictions, and a clear affected asset. If nothing is
grounded it abstains ("insufficient evidence") rather than inventing a conclusion. It
may consult an independent judge model for an advisory note, but the judge cannot change
the deterministic verdict.
"""

from __future__ import annotations

from core.ai import ModelRequest, WorkClass
from core.brain.state import CaseStateDelta
from core.evidence.models import (
    AssetRef,
    Finding,
    Hypothesis,
    Provenance,
    VerificationResult,
)

from .base import Specialist, SpecialistResult, SpecialistTask


class EvidenceAdjudicator(Specialist):
    name = "evidence_adjudicator"
    work_class = WorkClass.REVIEW  # judge is advisory only; verdict stays deterministic

    def run(self, task: SpecialistTask) -> SpecialistResult:
        if not task.hypotheses:
            return self._abstain("no hypotheses to adjudicate")

        results: list[VerificationResult] = []
        established: list[Hypothesis] = []
        for h in task.hypotheses:
            passed = _established(h)
            results.append(
                VerificationResult(
                    subject_id=h.id, verifier=self.name, passed=passed,
                    reasons=() if passed else ("not grounded / unresolved contradiction",),
                )
            )
            if passed:
                established.append(h)

        notes = self._advisory_note(task)

        if not established:
            return SpecialistResult(
                specialist=self.name, verdict="abstain", abstained=True,
                delta=CaseStateDelta(verification_results=tuple(results)),
                notes=("insufficient evidence — no grounded hypothesis", *notes),
            )

        findings = tuple(_finding(h, task) for h in established)
        return SpecialistResult(
            specialist=self.name, verdict="pass",
            confidence=max(h.confidence for h in established),
            delta=CaseStateDelta(verification_results=tuple(results), findings=findings),
            notes=notes,
        )

    def _advisory_note(self, task: SpecialistTask) -> tuple[str, ...]:
        """Best-effort independent judge opinion. Never changes the verdict."""
        if self._gateway is None or self.work_class is None:
            return ()
        try:
            resp = self._gateway.complete(
                ModelRequest(
                    work_class=self.work_class, tenant_id=task.tenant_id,
                    case_id=task.case_id,
                    instruction="As an independent reviewer, note any reason to doubt these findings.",
                    prompt_template_version="adjudicator_v1",
                    evidence=task.evidence, max_output_tokens=256,
                )
            )
        except Exception:  # noqa: BLE001 - advisory only; failure must not block the verdict
            return ()
        return (f"judge_advisory:{resp.record.model_id}",)


def _established(h: Hypothesis) -> bool:
    return (
        h.status in ("supported", "confirmed")
        and h.is_grounded
        and not h.contradicting_evidence_ids
        and len(h.affected_assets) > 0
    )


def _finding(h: Hypothesis, task: SpecialistTask) -> Finding:
    asset = h.affected_assets[0] if h.affected_assets else AssetRef(
        kind="asset", identifier=task.scope.asset)
    return Finding(
        title=f"Adjudicated finding on {asset.identifier}", severity="high",
        description=h.statement, asset=asset, evidence_ids=h.supporting_evidence_ids,
        hypothesis_id=h.id, provenance=Provenance(tool="evidence_adjudicator"),
    )


__all__ = ["EvidenceAdjudicator"]
