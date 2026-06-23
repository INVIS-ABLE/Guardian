"""Controlled cryptographic migration (Citadel System 23).

Migration moves an algorithm through an explicit lifecycle. The cardinal rule (Wave-20 invariant
25): you must be able to **dual-read** before you cut over to a new primary — so a reader can still
verify data written under the old algorithm. Skipping dual-read, or going backwards, is rejected.
Retirement/destruction are deliberate, never automatic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MigrationState(str, Enum):
    DISCOVERED = "discovered"
    CLASSIFIED = "classified"
    DUAL_WRITE = "dual-write"        # write both old and new
    DUAL_READ = "dual-read"          # read both old and new (required before cutover)
    HYBRID = "hybrid"                # classical + PQ in combination
    NEW_PRIMARY = "new-primary"      # new algorithm is primary; old still readable
    LEGACY_READ_ONLY = "legacy-read-only"
    RETIRED = "retired"
    DESTROYED = "destroyed"
    VERIFIED = "verified"


# The only forward transitions permitted. Cutover to NEW_PRIMARY is reachable only via DUAL_READ
# (directly, or through HYBRID for a PQ migration).
_ALLOWED: dict[MigrationState, frozenset[MigrationState]] = {
    MigrationState.DISCOVERED: frozenset({MigrationState.CLASSIFIED}),
    MigrationState.CLASSIFIED: frozenset({MigrationState.DUAL_WRITE}),
    MigrationState.DUAL_WRITE: frozenset({MigrationState.DUAL_READ}),
    MigrationState.DUAL_READ: frozenset({MigrationState.HYBRID, MigrationState.NEW_PRIMARY}),
    MigrationState.HYBRID: frozenset({MigrationState.NEW_PRIMARY}),
    MigrationState.NEW_PRIMARY: frozenset({MigrationState.LEGACY_READ_ONLY}),
    MigrationState.LEGACY_READ_ONLY: frozenset({MigrationState.RETIRED}),
    MigrationState.RETIRED: frozenset({MigrationState.DESTROYED}),
    MigrationState.DESTROYED: frozenset({MigrationState.VERIFIED}),
    MigrationState.VERIFIED: frozenset(),
}


class MigrationError(ValueError):
    """Raised on an illegal migration transition (e.g. cutover without dual-read)."""


@dataclass
class MigrationPlan:
    asset_id: str
    from_algorithm: str
    to_algorithm: str
    state: MigrationState = MigrationState.DISCOVERED
    history: list[MigrationState] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.history is None:
            self.history = [self.state]

    def can_advance(self, to: MigrationState) -> bool:
        return to in _ALLOWED.get(self.state, frozenset())

    def advance(self, to: MigrationState) -> MigrationState:
        if not self.can_advance(to):
            raise MigrationError(
                f"{self.asset_id}: illegal transition {self.state.value} -> {to.value} "
                f"(cutover requires dual-read first)"
            )
        self.state = to
        self.history.append(to)
        return to

    @property
    def dual_read_reached(self) -> bool:
        return MigrationState.DUAL_READ in self.history

    @property
    def cutover_done(self) -> bool:
        return MigrationState.NEW_PRIMARY in self.history


__all__ = ["MigrationState", "MigrationError", "MigrationPlan"]
