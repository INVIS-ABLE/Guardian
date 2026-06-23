"""Multi-model reasoning council — Sovereign system #9.

For a serious case, one model running one prompt is not enough. The council runs the case
through bounded, adversarial *roles* — and the adjudicator decides **from the evidence, not by
majority vote** (docs/sovereign_ops_plane.md #9, brain_v2.md §7):

    primary investigator → sceptic → alternative-hypothesis analyst
        → attack-path analyst → privacy examiner → evidence adjudicator

Each role is a deterministic function over the typed contracts (so the council is fully testable
offline and replayable). In production each role is routed to an appropriate — and for critical
cases, a *different* — model family via the core.ai gateway; that routing is the only part that
varies, the role contracts and the adjudication rules stay fixed.

The council never executes anything. It produces a verdict + the dissent, and escalates to a human
whenever the evidence is insufficient, contradicted, disputed, or unchallenged — cognition
proposes, authority disposes.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from core.evidence.models import EvidenceItem, Hypothesis
from core.twin import DigitalTwin

from .calibration import Calibrator
from .causal import CausalReport, root_cause
from .hypothesis import CaseVerdict, adjudicate

CouncilDecision = Literal["proceed", "insufficient_evidence", "contradicted", "escalate"]


class Case(BaseModel):
    """The material a council deliberates over. Read-only; metadata-only."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    evidence: tuple[EvidenceItem, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    twin: DigitalTwin | None = None
    observed: tuple[str, ...] = ()   # observed-compromised asset ids (for the attack-path role)
    sink: str | None = None          # the sensitive asset reached (for the attack-path role)


class CouncilVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: CouncilDecision
    requires_human: bool
    case_verdict: CaseVerdict
    sceptic_challenges: tuple[str, ...]
    alternatives_considered: int
    privacy_violations: tuple[str, ...]   # evidence ids that carry privacy-forbidden content
    evidence_gaps: tuple[str, ...]
    attack_path: CausalReport | None


def _sceptic(case: Case, verdict: CaseVerdict) -> tuple[str, ...]:
    """Try to disprove the leading hypothesis: what would make it wrong?"""
    challenges: list[str] = []
    leading = verdict.leading()
    if leading is None:
        return ()
    hyp = next((h for h in case.hypotheses if h.id == leading.hypothesis_id), None)
    if hyp is not None and not hyp.falsification_tests:
        challenges.append("leading hypothesis proposes no falsification test")
    if leading.uncertainty_reasons:
        challenges.extend(f"uncertainty: {r}" for r in leading.uncertainty_reasons)
    if leading.contradiction_weight > 0:
        challenges.append("leading hypothesis still has contradicting evidence")
    return tuple(dict.fromkeys(challenges))


def _evidence_gaps(case: Case, verdict: CaseVerdict) -> tuple[str, ...]:
    gaps: list[str] = []
    if not case.evidence:
        gaps.append("no evidence in the case")
    if all(not e.is_verified_evidence for e in case.evidence) and case.evidence:
        gaps.append("no verified evidence — all support is unverified")
    if verdict.leading() is None and case.hypotheses:
        gaps.append("no hypothesis is evidence-grounded")
    return tuple(gaps)


def convene(case: Case, *, calibrator: Calibrator | None = None) -> CouncilVerdict:
    """Run the case through the council roles and return an evidence-based verdict."""
    # Primary investigator + adjudicator (evidence-grounded, not a vote).
    verdict = adjudicate(case.hypotheses, case.evidence, calibrator=calibrator)

    # Sceptic + alternative-hypothesis analyst.
    challenges = _sceptic(case, verdict)
    alternatives = len(case.hypotheses)

    # Attack-path analyst (only when an incident over a twin is supplied).
    attack_path: CausalReport | None = None
    if case.twin is not None and case.sink is not None and case.observed:
        attack_path = root_cause(case.twin, observed=list(case.observed), sink=case.sink)

    # Privacy examiner: no privacy-forbidden content may sit in a reasoned case.
    privacy = tuple(str(e.id) for e in case.evidence if e.is_privacy_forbidden)
    gaps = _evidence_gaps(case, verdict)

    # Evidence adjudicator: decide — explicitly, never by majority.
    leading = verdict.leading()
    if privacy:
        decision: CouncilDecision = "escalate"
    elif leading is None or verdict.abstained:
        decision = "insufficient_evidence"
    elif leading.status == "contradicted":
        decision = "contradicted"
    elif verdict.unresolved_disagreement:
        decision = "escalate"
    else:
        decision = "proceed"

    # A human is required whenever the council did not cleanly converge, when only one
    # hypothesis was considered (no real contest), or when the sceptic's challenges stand.
    requires_human = (
        decision != "proceed"
        or alternatives < 2
        or bool(challenges)
        or bool(privacy)
    )

    return CouncilVerdict(
        decision=decision,
        requires_human=requires_human,
        case_verdict=verdict,
        sceptic_challenges=challenges,
        alternatives_considered=alternatives,
        privacy_violations=privacy,
        evidence_gaps=gaps,
        attack_path=attack_path,
    )
