"""Key/algorithm rotation scheduling (Citadel System 23).

A registered crypto asset with a rotation period that has lapsed is due for rotation — surfaced so
keys do not silently outlive their intended lifetime.
"""

from __future__ import annotations

from .inventory import CryptoAsset, CryptoInventory


def is_due(asset: CryptoAsset, *, now: float, last_rotated_at: float) -> bool:
    if asset.rotation_period_days <= 0:
        return False
    return now >= last_rotated_at + asset.rotation_period_days * 86400


def due_for_rotation(
    inventory: CryptoInventory, *, now: float, last_rotated_at: dict[str, float]
) -> list[str]:
    """Return the ids of assets whose rotation period has lapsed."""
    return [
        a.asset_id for a in inventory.all()
        if is_due(a, now=now, last_rotated_at=last_rotated_at.get(a.asset_id, 0.0))
    ]


__all__ = ["is_due", "due_for_rotation"]
