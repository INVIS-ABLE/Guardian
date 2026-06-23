"""Quorum vote signatures (Citadel Systems 24 + 38).

Each vote is a participant's signature over the canonical proposal — so a vote cannot be forged or
moved to a different proposal. Uses the shared ``core.signing`` primitive (Ed25519, HMAC fallback).
"""

from __future__ import annotations

from dataclasses import dataclass

from core import signing

from .participants import Participant
from .proposals import Proposal


@dataclass(frozen=True)
class Vote:
    proposal_id: str
    participant_id: str
    signature: str


def cast_vote(participant: Participant, private_key: str, proposal: Proposal) -> Vote:
    """Produce a participant's signed vote over the exact proposal."""
    signature = signing.sign(private_key, proposal.canonical())
    return Vote(proposal_id=proposal.proposal_id, participant_id=participant.participant_id,
                signature=signature)


def verify_vote(participant: Participant, proposal: Proposal, vote: Vote) -> bool:
    """A vote is valid only if it is for this proposal and signed by this participant's credential."""
    if vote.proposal_id != proposal.proposal_id or vote.participant_id != participant.participant_id:
        return False
    return signing.verify(participant.public_key, proposal.canonical(), vote.signature)


__all__ = ["Vote", "cast_vote", "verify_vote"]
