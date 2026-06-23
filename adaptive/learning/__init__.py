"""Learning from outcomes — proposals enter review, never change production (directive §20)."""

from .outcomes import (
    LearningProposal,
    OutcomeRecord,
    ProposalKind,
    ProposalStatus,
    propose_from_outcome,
)

__all__ = [
    "OutcomeRecord",
    "ProposalKind",
    "ProposalStatus",
    "LearningProposal",
    "propose_from_outcome",
]
