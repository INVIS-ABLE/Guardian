"""Evidence & competing-hypothesis engine — Sovereign system #7.

Guardian reasons from a *claim-and-evidence graph*, not a chat transcript: every case holds
competing hypotheses, each with explicit supporting AND contradicting evidence, and the engine
adjudicates them **from the evidence** — never by majority vote or by which hypothesis sounds
most confident (docs/sovereign_ops_plane.md, brain_v2.md §4/§7).

The adjudicator:
  * weighs *verified* evidence above unverified (an untrusted log line is not proof),
  * refuses to call a hypothesis ``supported``/``confirmed`` if it has no verified support or any
    unresolved contradiction (it becomes ``inconclusive`` instead),
  * recalibrates confidence against history (:mod:`core.reasoning.calibration`) and abstains when
    the evidence is insufficient — reporting "insufficient evidence" rather than inventing one,
  * flags **unresolved disagreement** when two rival hypotheses are both evidence-supported.

Operates only on the typed contracts in :mod:`core.evidence.models`; it adds no new authority.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from core.evidence.models import EvidenceItem, Hypothesis, HypothesisStatus

from .calibration import Calibrator

# Evidence weighting: verified evidence counts fully; unverified is weak corroboration only.
_VERIFIED_WEIGHT = 1.0
_UNVERIFIED_WEIGHT = 0.3


class HypothesisVerdict(BaseModel):
    """The engine's evidence-grounded verdict on one hypothesis (recomputed, not trusted)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: UUID
    statement: str
    status: HypothesisStatus
    confidence: float
    support_weight: float
    contradiction_weight: float
    verified_support: int
    insufficient_evidence: bool
    uncertainty_reasons: tuple[str, ...]


class CaseVerdict(BaseModel):
    """The adjudicated outcome across all competing hypotheses in a case."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    verdicts: tuple[HypothesisVerdict, ...]
    leading_hypothesis_id: UUID | None
    unresolved_disagreement: bool
    abstained: bool

    def leading(self) -> HypothesisVerdict | None:
        if self.leading_hypothesis_id is None:
            return None
        return next(v for v in self.verdicts if v.hypothesis_id == self.leading_hypothesis_id)


def _weigh(evidence: list[EvidenceItem]) -> tuple[float, int]:
    weight = sum(_VERIFIED_WEIGHT if e.is_verified_evidence else _UNVERIFIED_WEIGHT for e in evidence)
    verified = sum(1 for e in evidence if e.is_verified_evidence)
    return weight, verified


def adjudicate_hypothesis(
    h: Hypothesis,
    evidence: Mapping[UUID, EvidenceItem],
    *,
    calibrator: Calibrator | None = None,
) -> HypothesisVerdict:
    """Recompute a hypothesis's status + confidence purely from its cited evidence."""
    supporting = [evidence[i] for i in h.supporting_evidence_ids if i in evidence]
    contradicting = [evidence[i] for i in h.contradicting_evidence_ids if i in evidence]
    sw, verified_sup = _weigh(supporting)
    cw, verified_con = _weigh(contradicting)

    reasons: list[str] = list(h.uncertainty_reasons)
    missing_cited = (
        len(h.supporting_evidence_ids) - len(supporting)
        + len(h.contradicting_evidence_ids) - len(contradicting)
    )
    if missing_cited:
        reasons.append(f"{missing_cited} cited evidence item(s) not present in the case")

    insufficient = verified_sup == 0  # no verified support ⇒ cannot ground a positive claim
    status: HypothesisStatus
    if sw == 0 and cw == 0:
        status, raw = "unverified", 0.0
        reasons.append("no evidence cited")
    elif cw > 0 and cw >= sw:
        status, raw = "contradicted", cw / (sw + cw)
    elif h.contradicting_evidence_ids:
        # Has support but also unresolved contradiction ⇒ never 'supported' (grounding rule §7).
        status, raw = "inconclusive", sw / (sw + cw)
        reasons.append("unresolved contradicting evidence")
    elif insufficient:
        status, raw = "inconclusive", min(sw, 0.5)
        reasons.append("supporting evidence is unverified")
    else:
        # Verified support, no contradiction.
        confirmed = verified_sup >= 2
        status = "confirmed" if confirmed else "supported"
        raw = min(1.0, 0.6 + 0.2 * verified_sup)

    confidence = raw
    if calibrator is not None and status in ("supported", "confirmed"):
        confidence = calibrator.calibrated(raw)
        if calibrator.should_abstain(raw):
            insufficient = True
            status = "inconclusive"
            reasons.append("confidence not supported by calibration history")

    return HypothesisVerdict(
        hypothesis_id=h.id,
        statement=h.statement,
        status=status,
        confidence=round(confidence, 4),
        support_weight=round(sw, 4),
        contradiction_weight=round(cw, 4),
        verified_support=verified_sup,
        insufficient_evidence=insufficient,
        uncertainty_reasons=tuple(dict.fromkeys(reasons)),  # de-dup, keep order
    )


_POSITIVE: frozenset[HypothesisStatus] = frozenset({"supported", "confirmed"})


def adjudicate(
    hypotheses: Iterable[Hypothesis],
    evidence: Iterable[EvidenceItem] | Mapping[UUID, EvidenceItem],
    *,
    calibrator: Calibrator | None = None,
) -> CaseVerdict:
    """Adjudicate competing hypotheses from the evidence (not by vote or stated confidence)."""
    index: Mapping[UUID, EvidenceItem]
    index = evidence if isinstance(evidence, Mapping) else {e.id: e for e in evidence}

    verdicts = tuple(adjudicate_hypothesis(h, index, calibrator=calibrator) for h in hypotheses)
    positive = [v for v in verdicts if v.status in _POSITIVE]

    # Leading = the strongest *evidence-grounded* verdict (verified support, then confidence) —
    # deterministic, and only when something is actually grounded.
    leading_id: UUID | None = None
    if positive:
        best = max(positive, key=lambda v: (v.verified_support, v.confidence, str(v.hypothesis_id)))
        leading_id = best.hypothesis_id

    # Two or more rival hypotheses both evidence-supported ⇒ unresolved disagreement to surface.
    unresolved = len(positive) >= 2
    abstained = leading_id is None
    return CaseVerdict(
        verdicts=verdicts,
        leading_hypothesis_id=leading_id,
        unresolved_disagreement=unresolved,
        abstained=abstained,
    )
