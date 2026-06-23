"""Proposal expiry helpers (Citadel Systems 24 + 38).

Quorum approvals are time-bounded: a proposal that is not satisfied before it expires cannot be
completed, and stale votes never accumulate into a late approval.
"""

from __future__ import annotations

from .proposals import Proposal


def remaining_seconds(proposal: Proposal, *, now: float) -> float:
    return max(0.0, proposal.expires_at - now)


def is_live(proposal: Proposal, *, now: float) -> bool:
    return not proposal.is_expired(now)


__all__ = ["remaining_seconds", "is_live"]
