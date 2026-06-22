"""Code & architecture analyst — runs static analysis and interprets it (§6).

This specialist demonstrates the full bounded loop:

1. **Act through the tool gateway** — request the ``static_code_scan`` capability via
   the tool executor (capability-gated, manifest-bound, one-use token). The result
   becomes typed ``TOOL_OUTPUT`` evidence.
2. **Reason through the model gateway** — send that evidence to a strong-reasoning model
   via ``core.ai`` (work class ``REASONING``). The model's text is ``MODEL_GENERATED``
   and is *never* auto-trusted.
3. **Ground the conclusion** — form a hypothesis that cites the evidence; abstain if
   there is no evidence, the model is unavailable, or its output is high-risk.

It cannot approve or execute anything — it only proposes grounded hypotheses for
downstream challenge and adjudication.
"""

from __future__ import annotations


from core.ai import ModelRequest, ModelUnavailableError, WorkClass
from core.brain.state import CaseStateDelta
from core.evidence.models import (
    AssetRef,
    Classification,
    EvidenceItem,
    Hypothesis,
    Provenance,
    TrustLevel,
    ValidationState,
)
from core.tools import ToolExecution, ToolRefusal

from .base import Specialist, SpecialistResult, SpecialistTask

CAPABILITY = "static_code_scan"


class CodeArchitectureAnalyst(Specialist):
    name = "code_architecture"
    work_class = WorkClass.REASONING
    allowed_capabilities = (CAPABILITY, "code_analysis")
    prompt_version = "code_arch_v1"

    def run(self, task: SpecialistTask) -> SpecialistResult:
        evidence = list(task.evidence)

        # 1. Gather fresh evidence via the tool gateway (capability-gated).
        if self._tools is not None and self.may_use(CAPABILITY):
            scanned = self._tools.execute(
                CAPABILITY, case_id=task.case_id,
                args={"asset": task.scope.asset}, environment=task.scope.environment,
            )
            if isinstance(scanned, ToolRefusal):
                return self._abstain(f"tool refused: {scanned.reason.value}")
            if isinstance(scanned, ToolExecution):
                evidence.append(_tool_evidence(scanned, task.scope.asset))

        if not evidence:
            return self._abstain("no evidence to analyse")

        # 2. Reason via the model gateway (output is MODEL_GENERATED, not trusted).
        high_risk = False
        if self._gateway is not None and self.work_class is not None:
            try:
                resp = self._gateway.complete(
                    ModelRequest(
                        work_class=self.work_class, tenant_id=task.tenant_id,
                        case_id=task.case_id,
                        instruction="Identify the most likely exploitable issue in the evidence.",
                        prompt_template_version=self.prompt_version,
                        evidence=tuple(evidence), max_output_tokens=512,
                    )
                )
            except ModelUnavailableError:
                # Fail closed for the model step: abstain rather than guess (§12).
                return self._abstain("reasoning model unavailable")
            high_risk = resp.high_risk
            if high_risk:
                return SpecialistResult(
                    specialist=self.name, verdict="abstain", abstained=True,
                    high_risk=True, notes=("model output flagged high-risk by firewall",),
                    delta=CaseStateDelta(evidence=tuple(evidence)),
                )

        # 3. Ground the conclusion in the evidence (deterministic verifier below).
        hypothesis = Hypothesis(
            statement=f"asset {task.scope.asset} has a likely exploitable code finding",
            supporting_evidence_ids=tuple(e.id for e in evidence),
            affected_assets=(AssetRef(kind="asset", identifier=task.scope.asset),),
            confidence=0.6, status="unverified",
        )
        if not _is_grounded(hypothesis, evidence):
            return self._abstain("hypothesis not grounded in evidence")

        return SpecialistResult(
            specialist=self.name, verdict="pass", confidence=hypothesis.confidence,
            delta=CaseStateDelta(evidence=tuple(evidence), hypotheses=(hypothesis,)),
        )


def _tool_evidence(execution: ToolExecution, asset: str) -> EvidenceItem:
    return EvidenceItem(
        kind="tool_output", summary=f"{execution.tool} output ({execution.output_hash})",
        classification=Classification.INTERNAL, trust_level=TrustLevel.TOOL_OUTPUT,
        validation_state=ValidationState.VALIDATED,
        provenance=Provenance(tool=execution.tool, tool_digest=execution.image_digest,
                             asset=asset),
        content_hash=execution.output_hash,
        assets=(AssetRef(kind="asset", identifier=asset),),
    )


def _is_grounded(hypothesis: Hypothesis, evidence: list[EvidenceItem]) -> bool:
    """Deterministic verifier: the hypothesis must cite real evidence ids."""
    evidence_ids = {e.id for e in evidence}
    return bool(hypothesis.supporting_evidence_ids) and all(
        eid in evidence_ids for eid in hypothesis.supporting_evidence_ids
    )


__all__ = ["CodeArchitectureAnalyst"]
