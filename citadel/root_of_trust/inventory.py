"""Platform inventory — the source of truth for *which* platforms are approved.

A platform that is not in the inventory is unknown, and an unknown platform can never receive a
production capability (the gate denies it). This is deliberately separate from the cryptographic
attestation check (``core.machine_attestation``): membership first, then proof.
"""

from __future__ import annotations

from .schemas import PlatformIdentity, PlatformStatus


class PlatformInventory:
    """In-memory approved-platform registry. Production backs this with the durable evidence store;
    the contract (membership + status) is the point and is what the gate consults."""

    def __init__(self) -> None:
        self._platforms: dict[str, PlatformIdentity] = {}

    def add(self, identity: PlatformIdentity) -> None:
        self._platforms[identity.node_id] = identity

    def get(self, node_id: str) -> PlatformIdentity | None:
        return self._platforms.get(node_id)

    def is_known(self, node_id: str) -> bool:
        return node_id in self._platforms

    def is_active(self, node_id: str) -> bool:
        identity = self._platforms.get(node_id)
        return identity is not None and identity.active

    def set_status(self, node_id: str, status: PlatformStatus) -> PlatformIdentity:
        identity = self._platforms[node_id]
        updated = PlatformIdentity(
            node_id=identity.node_id, ak_public_key=identity.ak_public_key,
            golden_pcrs=identity.golden_pcrs, approved_firmware=identity.approved_firmware,
            approved_kernels=identity.approved_kernels, enrolled_at=identity.enrolled_at,
            status=status, attestation_max_age_seconds=identity.attestation_max_age_seconds,
        )
        self._platforms[node_id] = updated
        return updated

    def active_platforms(self) -> list[PlatformIdentity]:
        return [p for p in self._platforms.values() if p.active]

    def all_platforms(self) -> list[PlatformIdentity]:
        return list(self._platforms.values())


__all__ = ["PlatformInventory"]
