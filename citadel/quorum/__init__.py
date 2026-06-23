"""Citadel Systems 24 + 38 — Key Custody / Threshold Trust + Multi-Party Trust Quorum (Wave 24).

Root operations require a threshold of DISTINCT participants with DISTINCT credentials — no single
identity can complete one. Recovery operations additionally require an offline recovery custodian
(credentials outside the runtime plane). Ceremonies produce signed, independently-verifiable evidence.

Owner (custody): OpenBao (production secret/key store). Independent verifiers: ``threshold.py``
(custody) and ``evidence.py`` (quorum). Composes ``orchestration.approvals`` patterns for root ops.
"""

from __future__ import annotations

from .ceremonies import KeyCeremony, KeyClass
from .evidence import QuorumResult, build_result, independently_verify
from .expiry import is_live, remaining_seconds
from .participants import Participant, ParticipantRegistry, ParticipantRole
from .proposals import REQUIRED_THRESHOLD, Proposal, RootOperation
from .signatures import Vote, cast_vote, verify_vote
from .threshold import ThresholdDecision, ThresholdGate

__all__ = [
    "KeyCeremony", "KeyClass", "QuorumResult", "build_result", "independently_verify",
    "is_live", "remaining_seconds", "Participant", "ParticipantRegistry", "ParticipantRole",
    "REQUIRED_THRESHOLD", "Proposal", "RootOperation", "Vote", "cast_vote", "verify_vote",
    "ThresholdDecision", "ThresholdGate",
]
