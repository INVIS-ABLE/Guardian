"""Guardian reversible containment (blueprint area 21 / Phase 6).

The *respond* half: Guardian recommends containment, but only a deterministic adapter executes
it — enumerated reversible actions only, every parameter validated, confidence + blast-radius
bounded, policy-checked, audited, with an exact target, expiry and documented rollback. No
AI-generated command runs.
"""

from __future__ import annotations

from .actions import REVERSIBLE_ACTIONS, ContainmentAction, is_reversible_action
from .adapter import (
    ContainmentOrder,
    ContainmentRejected,
    ContainmentRequest,
    DeterministicContainmentAdapter,
)

__all__ = [
    "ContainmentAction",
    "REVERSIBLE_ACTIONS",
    "is_reversible_action",
    "ContainmentRequest",
    "ContainmentOrder",
    "ContainmentRejected",
    "DeterministicContainmentAdapter",
]
