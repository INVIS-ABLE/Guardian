"""Quorum participants (Citadel Systems 24 + 38).

Each participant is an independent custodian/reviewer with their OWN signing credential. The core
rule: distinct participants, distinct credentials — so no single identity (and no single credential
reused) can ever satisfy a threshold. Recovery custodians hold their material OUTSIDE the normal
runtime plane (Wave-20 invariant 18).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ParticipantRole(str, Enum):
    CUSTODIAN = "custodian"
    REVIEWER = "reviewer"
    RECOVERY_CUSTODIAN = "recovery_custodian"   # credential held offline, outside runtime


@dataclass(frozen=True)
class Participant:
    participant_id: str
    public_key: str                 # distinct signing credential (hex)
    role: ParticipantRole
    offline: bool = False           # True for recovery material held outside the runtime plane


class ParticipantRegistry:
    """The set of enrolled quorum participants. Enforces distinct ids AND distinct credentials."""

    def __init__(self) -> None:
        self._by_id: dict[str, Participant] = {}
        self._keys: set[str] = set()

    def enrol(self, participant: Participant) -> None:
        if participant.participant_id in self._by_id:
            raise ValueError(f"duplicate participant id: {participant.participant_id}")
        if participant.public_key in self._keys:
            raise ValueError("credential reuse: participants must have distinct credentials")
        self._by_id[participant.participant_id] = participant
        self._keys.add(participant.public_key)

    def get(self, participant_id: str) -> Participant | None:
        return self._by_id.get(participant_id)

    def runtime_custodians(self) -> list[Participant]:
        return [p for p in self._by_id.values() if not p.offline]

    def recovery_custodians(self) -> list[Participant]:
        return [p for p in self._by_id.values() if p.role is ParticipantRole.RECOVERY_CUSTODIAN]


__all__ = ["ParticipantRole", "Participant", "ParticipantRegistry"]
