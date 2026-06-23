"""ACH matrix & diagnosticity — a complementary view over the competing-hypothesis engine.

System #7 already *adjudicates* hypotheses from evidence (:mod:`core.reasoning.hypothesis`):
it recomputes each hypothesis's status/confidence, weighs verified above unverified, and
abstains when grounding is missing. This module adds the other half of Heuer's **Analysis of
Competing Hypotheses** — the part that tells an analyst *what to look at and what to test next*:

  * the **matrix** — for every (hypothesis, evidence) pair, is the evidence consistent,
    inconsistent, or neutral?
  * **diagnosticity** — which evidence actually *discriminates* between hypotheses, and which is
    non-diagnostic noise (consistent with everything, so it decides nothing);
  * a **least-contradicted ranking** with a decisiveness margin — ACH's core move is to favour
    the hypothesis hardest to *disprove*, not the one with the most support; and
  * the **falsification tests** to run next to seek disproof of the leader.

It does **not** re-derive evidence weighting: it calls :func:`core.reasoning.hypothesis.adjudicate`
and ranks on the adjudicator's own ``contradiction_weight``, so the two views can never drift.
Read-only and authority-free, like the rest of Wave 2.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from core.evidence.models import EvidenceItem, Hypothesis, TestProposal

from .calibration import Calibrator
from .hypothesis import (
    _UNVERIFIED_WEIGHT,
    _VERIFIED_WEIGHT,
    CaseVerdict,
    HypothesisVerdict,
    adjudicate,
)

# How much clearer the least-contradicted hypothesis must be (in contradiction weight) than the
# runner-up before ACH calls the field decisive rather than "gather more diagnostic evidence".
_DECISIVE_MARGIN = 1.0


class Consistency(str, Enum):
    """An evidence item's relation to a hypothesis in the ACH matrix."""

    CONSISTENT = "consistent"      # the hypothesis predicts / explains this evidence
    INCONSISTENT = "inconsistent"  # the evidence contradicts the hypothesis (the diagnostic case)
    NEUTRAL = "neutral"            # neither supports nor refutes it


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Cell(_Frozen):
    """One (hypothesis, evidence) entry of the ACH matrix."""

    evidence_id: UUID
    summary: str
    consistency: Consistency
    weight: float                  # the evidence's trust weight (the adjudicator's scale)


class MatrixRow(_Frozen):
    """One hypothesis's row of the ACH matrix."""

    hypothesis_id: UUID
    statement: str
    cells: tuple[Cell, ...]


class DiagnosticEvidence(_Frozen):
    """Evidence that discriminates between hypotheses — the only evidence that decides anything."""

    evidence_id: UUID
    summary: str
    weight: float
    consistent_with: tuple[UUID, ...]
    inconsistent_with: tuple[UUID, ...]


class ACHView(_Frozen):
    """The ACH overlay on a case verdict: ranking by disproof, diagnosticity, and tests to run."""

    case: CaseVerdict                       # the adjudicator's verdict (status/confidence/abstain)
    ranked: tuple[HypothesisVerdict, ...]   # re-sorted least-contradicted first
    leading_id: UUID | None                 # least-contradicted hypothesis
    runner_up_id: UUID | None
    decisive: bool                          # is the leader clearly separated by contradiction?
    margin: float                           # runner_up.contradiction_weight − leading's
    diagnostic_evidence: tuple[DiagnosticEvidence, ...]
    non_diagnostic_evidence: tuple[UUID, ...]
    next_tests: tuple[TestProposal, ...]    # falsification tests for the leader (seek disproof)
    verdict: str


def _index(evidence: Iterable[EvidenceItem] | Mapping[UUID, EvidenceItem]) -> dict[UUID, EvidenceItem]:
    return dict(evidence) if isinstance(evidence, Mapping) else {e.id: e for e in evidence}


def _weight(item: EvidenceItem) -> float:
    return _VERIFIED_WEIGHT if item.is_verified_evidence else _UNVERIFIED_WEIGHT


def _consistency(h: Hypothesis, evidence_id: UUID) -> Consistency:
    if evidence_id in h.contradicting_evidence_ids:
        return Consistency.INCONSISTENT
    if evidence_id in h.supporting_evidence_ids:
        return Consistency.CONSISTENT
    return Consistency.NEUTRAL


def ach_matrix(
    hypotheses: Iterable[Hypothesis],
    evidence: Iterable[EvidenceItem] | Mapping[UUID, EvidenceItem],
) -> tuple[MatrixRow, ...]:
    """The full ACH matrix: a row per hypothesis, a cell per evidence item."""
    index = _index(evidence)
    rows = []
    for h in hypotheses:
        cells = tuple(
            Cell(evidence_id=eid, summary=item.summary,
                 consistency=_consistency(h, eid), weight=_weight(item))
            for eid, item in index.items()
        )
        rows.append(MatrixRow(hypothesis_id=h.id, statement=h.statement, cells=cells))
    return tuple(rows)


def diagnostic_split(
    hypotheses: Iterable[Hypothesis],
    evidence: Iterable[EvidenceItem] | Mapping[UUID, EvidenceItem],
) -> tuple[tuple[DiagnosticEvidence, ...], tuple[UUID, ...]]:
    """Split evidence into diagnostic (discriminating) and non-diagnostic (decides nothing)."""
    index = _index(evidence)
    hyps = list(hypotheses)
    diagnostic: list[DiagnosticEvidence] = []
    non_diagnostic: list[UUID] = []
    for eid, item in index.items():
        consistent, inconsistent = [], []
        for h in hyps:
            rel = _consistency(h, eid)
            if rel is Consistency.CONSISTENT:
                consistent.append(h.id)
            elif rel is Consistency.INCONSISTENT:
                inconsistent.append(h.id)
        # Diagnostic iff it contradicts at least one hypothesis but not all of them: evidence
        # inconsistent with *every* hypothesis (or with none) cannot discriminate between them.
        if inconsistent and len(inconsistent) < len(hyps):
            diagnostic.append(DiagnosticEvidence(
                evidence_id=eid, summary=item.summary, weight=_weight(item),
                consistent_with=tuple(consistent), inconsistent_with=tuple(inconsistent),
            ))
        else:
            non_diagnostic.append(eid)
    diagnostic.sort(key=lambda d: (-d.weight, str(d.evidence_id)))
    return tuple(diagnostic), tuple(non_diagnostic)


def analyze(
    hypotheses: Iterable[Hypothesis],
    evidence: Iterable[EvidenceItem] | Mapping[UUID, EvidenceItem],
    *,
    calibrator: Calibrator | None = None,
) -> ACHView:
    """Run the ACH overlay: adjudicate, rank least-contradicted, split diagnosticity, test next."""
    index = _index(evidence)
    hyps = list(hypotheses)
    case = adjudicate(hyps, index, calibrator=calibrator)

    # Rank on the adjudicator's own contradiction weight (single source of truth): least-
    # contradicted first; break ties by more support, then statement for determinism.
    ranked = tuple(sorted(
        case.verdicts,
        key=lambda v: (v.contradiction_weight, -v.support_weight, v.statement),
    ))
    leading = ranked[0] if ranked else None
    runner_up = ranked[1] if len(ranked) > 1 else None
    margin = (runner_up.contradiction_weight - leading.contradiction_weight) if (leading and runner_up) else 0.0
    decisive = bool(leading) and (runner_up is None or margin >= _DECISIVE_MARGIN)

    diagnostic, non_diagnostic = diagnostic_split(hyps, index)
    by_id = {h.id: h for h in hyps}
    next_tests = by_id[leading.hypothesis_id].falsification_tests if leading else ()

    return ACHView(
        case=case, ranked=ranked,
        leading_id=leading.hypothesis_id if leading else None,
        runner_up_id=runner_up.hypothesis_id if runner_up else None,
        decisive=decisive, margin=margin,
        diagnostic_evidence=diagnostic, non_diagnostic_evidence=non_diagnostic,
        next_tests=next_tests, verdict=_verdict(case, leading, decisive),
    )


def _verdict(case: CaseVerdict, leading: HypothesisVerdict | None, decisive: bool) -> str:
    if leading is None:
        return "no hypotheses to analyse"
    if case.abstained:
        return ("adjudicator abstains — no hypothesis is grounded; gather verified evidence or "
                "run the falsification tests before concluding")
    if case.unresolved_disagreement:
        return ("two or more rival hypotheses are both evidence-supported — unresolved "
                "disagreement; run diagnostic tests to separate them")
    if decisive:
        return ("leading hypothesis is the least-contradicted and clearly separated — run its "
                "falsification tests to seek disproof before acting")
    return ("inconclusive — the least-contradicted hypotheses are too close; gather diagnostic "
            "evidence or run the falsification tests")
