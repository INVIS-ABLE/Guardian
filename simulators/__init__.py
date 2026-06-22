"""Guardian defensive simulator library.

Only simulators that operate against *owned* staging systems and *test* accounts live
here. Each emits the mandatory ``SimulatorResult`` output contract. The full library
(see docs/architecture.md) is rolled out incrementally; this MVP ships three:

  - privacy_leak          (Privacy Leak Simulator)
  - banned_user_return    (Banned User Return Simulator)
  - moderator_abuse       (Moderator Abuse Simulator)
"""

from __future__ import annotations

from .banned_user_return import BannedUserReturnSimulator
from .base import BaseSimulator
from .moderator_abuse import ModeratorAbuseSimulator
from .privacy_leak import PrivacyLeakSimulator

REGISTRY: dict[str, type[BaseSimulator]] = {
    PrivacyLeakSimulator.name: PrivacyLeakSimulator,
    BannedUserReturnSimulator.name: BannedUserReturnSimulator,
    ModeratorAbuseSimulator.name: ModeratorAbuseSimulator,
}

# Planned simulators (not yet implemented) — declared so scope/docs stay honest.
PLANNED: tuple[str, ...] = (
    "account_takeover",
    "credential_stuffing",
    "password_spray",
    "scraper",
    "api_abuse",
    "bot_swarm",
    "fake_user",
    "harassment_wave",
    "grooming_risk",
    "staff_permission_abuse",
    "health_data_exposure",
    "data_breach_response",
    "upload_abuse",
    "report_system_abuse",
    "recovery_rollback",
    "supply_chain_tamper",
)

__all__ = [
    "BaseSimulator",
    "PrivacyLeakSimulator",
    "BannedUserReturnSimulator",
    "ModeratorAbuseSimulator",
    "REGISTRY",
    "PLANNED",
]
