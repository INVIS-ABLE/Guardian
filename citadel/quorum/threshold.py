"""Threshold gate — the verifier for key custody (Citadel System 24).

Collects verified votes for a proposal and decides whether the threshold of DISTINCT participants is
met before expiry. A single identity can never satisfy a root operation: duplicate votes from the
same participant count once, and recovery operations additionally require an offline recovery
custodian (credentials outside the runtime plane).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .participants import ParticipantRegistry
from .proposals import Proposal
from .signatures import Vote, verify_vote


@dataclass(frozen=True)
class ThresholdDecision:
    satisfied: bool
    operation: str
    distinct_approvers: int
    threshold: int
    reasons: tuple[str, ...]


@dataclass
class ThresholdGate:
    registry: ParticipantRegistry
    _votes: dict[str, dict[str, Vote]] = field(default_factory=dict)  # proposal_id -> pid -> vote

    def submit(self, proposal: Proposal, vote: Vote, *, now: float) -> bool:
        """Record a vote if it is valid, from an enrolled participant, and the proposal is live."""
        if proposal.is_expired(now):
            return False
        participant = self.registry.get(vote.participant_id)
        if participant is None or not verify_vote(participant, proposal, vote):
            return False
        self._votes.setdefault(proposal.proposal_id, {})[vote.participant_id] = vote
        return True

    def decide(self, proposal: Proposal, *, now: float) -> ThresholdDecision:
        reasons: list[str] = []
        if proposal.is_expired(now):
            reasons.append("proposal_expired")
        votes = self._votes.get(proposal.proposal_id, {})
        approvers = set(votes)                         # distinct participant ids only
        distinct = len(approvers)
        if distinct < proposal.threshold:
            reasons.append(f"below_threshold:{distinct}/{proposal.threshold}")
        if proposal.requires_recovery_custodian:
            recovery_ids = {p.participant_id for p in self.registry.recovery_custodians()}
            if not (approvers & recovery_ids):
                reasons.append("recovery_operation_needs_offline_recovery_custodian")
        return ThresholdDecision(
            satisfied=not reasons, operation=proposal.operation.value,
            distinct_approvers=distinct, threshold=proposal.threshold, reasons=tuple(reasons),
        )


__all__ = ["ThresholdDecision", "ThresholdGate"]
