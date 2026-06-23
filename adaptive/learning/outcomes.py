"""Learning from outcomes (directive §20).

After every completed case Guardian records a typed ``OutcomeRecord`` — what it believed,
what it did, and what actually happened. The Outcome Learner may then *propose* changes
(new detections, thresholds, runbooks, eval cases, twin corrections), but those proposals
**enter review and never change production behaviour directly**. So every proposal here is
created in the ``PROPOSED`` state and cannot be self-applied.
"""

from __future__ import annotations

from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class OutcomeRecord(BaseModel):
    """The post-case record the learner reasons over (§20). Immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: UUID
    initial_trigger: str = Field(min_length=1)
    initial_confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: tuple[str, ...] = ()
    final_conclusion: str = ""
    human_decision: str = ""
    action_taken: str = ""
    expected_result: str = ""
    actual_result: str = ""
    rollback_required: bool = False
    time_to_detection_seconds: float | None = Field(default=None, ge=0.0)
    time_to_containment_seconds: float | None = Field(default=None, ge=0.0)
    time_to_recovery_seconds: float | None = Field(default=None, ge=0.0)
    false_positive: bool = False
    privacy_impact: bool = False
    availability_impact: bool = False
    tool_reliability: float | None = Field(default=None, ge=0.0, le=1.0)
    missing_evidence: tuple[str, ...] = ()
    lessons: tuple[str, ...] = ()


class ProposalKind(str, Enum):
    NEW_DETECTION = "new_detection"
    UPDATED_THRESHOLD = "updated_threshold"
    NEW_RUNBOOK = "new_runbook"
    TOOL_RANKING_CHANGE = "tool_ranking_change"
    NEW_EVALUATION_CASE = "new_evaluation_case"
    NEW_DOCUMENTATION = "new_documentation"
    TWIN_CORRECTION = "twin_correction"


class ProposalStatus(str, Enum):
    PROPOSED = "proposed"      # the only state the learner can create
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"


class LearningProposal(BaseModel):
    """A proposed change from the learner. Always starts PROPOSED; never auto-applied (§20)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    proposal_id: UUID = Field(default_factory=uuid4)
    case_id: UUID
    kind: ProposalKind
    summary: str = Field(min_length=1)
    rationale: str = ""
    status: ProposalStatus = ProposalStatus.PROPOSED

    def model_post_init(self, _ctx: object) -> None:
        # Defence in depth: a freshly minted proposal can only ever be PROPOSED.
        if self.status is not ProposalStatus.PROPOSED:
            raise ValueError("a new LearningProposal must start in the PROPOSED state")


def propose_from_outcome(outcome: OutcomeRecord) -> tuple[LearningProposal, ...]:
    """Derive review-bound proposals from one outcome. Heuristic, conservative, advisory.

    The learner never changes production: it returns PROPOSED items for human review.
    """
    proposals: list[LearningProposal] = []

    if outcome.false_positive:
        proposals.append(LearningProposal(
            case_id=outcome.case_id, kind=ProposalKind.UPDATED_THRESHOLD,
            summary="tune detection to reduce false positives",
            rationale=f"case concluded false positive: {outcome.final_conclusion}",
        ))
    if outcome.missing_evidence:
        proposals.append(LearningProposal(
            case_id=outcome.case_id, kind=ProposalKind.NEW_DETECTION,
            summary="add collection for evidence that was missing",
            rationale=f"missing evidence: {', '.join(outcome.missing_evidence)}",
        ))
    if outcome.rollback_required:
        proposals.append(LearningProposal(
            case_id=outcome.case_id, kind=ProposalKind.NEW_EVALUATION_CASE,
            summary="add a regression/eval case for the rolled-back action",
            rationale="action required rollback; capture it as an evaluation case",
        ))
    if not outcome.false_positive and outcome.actual_result and outcome.lessons:
        proposals.append(LearningProposal(
            case_id=outcome.case_id, kind=ProposalKind.NEW_DOCUMENTATION,
            summary="record the confirmed lessons from this case",
            rationale="; ".join(outcome.lessons),
        ))
    return tuple(proposals)


__all__ = [
    "OutcomeRecord",
    "ProposalKind",
    "ProposalStatus",
    "LearningProposal",
    "propose_from_outcome",
]
