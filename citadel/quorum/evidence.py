"""Quorum result evidence — the independent verifier for the trust quorum (Citadel System 38).

Builds the signed, fully-attributable result record (the result_fields in configs/citadel/quorum.yaml)
and independently re-verifies a ceremony: every recorded vote is valid, the approvers are distinct,
and the threshold is met. Independent of the ThresholdGate that collected the votes.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ceremonies import KeyCeremony
from .participants import ParticipantRegistry
from .proposals import Proposal
from .signatures import Vote, verify_vote


@dataclass(frozen=True)
class QuorumResult:
    operation: str
    participants: tuple[str, ...]
    threshold: int
    result: str                  # "approved" | "denied"
    policy_digest: str
    target_digest: str
    evidence_digest: str


def build_result(ceremony: KeyCeremony) -> QuorumResult:
    return QuorumResult(
        operation=ceremony.proposal.operation.value,
        participants=tuple(sorted(ceremony.participant_ids)),
        threshold=ceremony.decision.threshold,
        result="approved" if ceremony.ok else "denied",
        policy_digest=ceremony.proposal.policy_digest,
        target_digest=ceremony.proposal.target_digest,
        evidence_digest=ceremony.evidence_digest,
    )


def independently_verify(
    registry: ParticipantRegistry, proposal: Proposal, votes: list[Vote]
) -> bool:
    """Re-verify a quorum from scratch: distinct, valid votes meeting the threshold. No single
    identity can satisfy it (duplicate participant ids collapse to one)."""
    distinct: set[str] = set()
    for vote in votes:
        participant = registry.get(vote.participant_id)
        if participant is None or not verify_vote(participant, proposal, vote):
            continue
        distinct.add(vote.participant_id)
    if proposal.requires_recovery_custodian:
        recovery_ids = {p.participant_id for p in registry.recovery_custodians()}
        if not (distinct & recovery_ids):
            return False
    return len(distinct) >= proposal.threshold


__all__ = ["QuorumResult", "build_result", "independently_verify"]
