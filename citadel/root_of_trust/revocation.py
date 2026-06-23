"""Platform revocation and quarantine.

Quarantine is reversible (a drifted platform may be re-attested and cleared); revocation is
permanent removal from approved inventory. A quarantined or revoked platform is denied a production
capability by the gate. Clearing a quarantine is a deliberate operator action, never automatic.
"""

from __future__ import annotations

from .inventory import PlatformInventory
from .schemas import PlatformIdentity, PlatformStatus


def quarantine(inventory: PlatformInventory, node_id: str) -> PlatformIdentity:
    """Mark a platform quarantined (drift / failed attestation). Reversible via ``clear``."""
    return inventory.set_status(node_id, PlatformStatus.QUARANTINED)


def revoke(inventory: PlatformInventory, node_id: str) -> PlatformIdentity:
    """Permanently revoke a platform from approved inventory."""
    return inventory.set_status(node_id, PlatformStatus.REVOKED)


def clear_quarantine(inventory: PlatformInventory, node_id: str) -> PlatformIdentity:
    """Return a quarantined platform to ENROLLED after it has been re-attested clean.

    Refuses to clear a REVOKED platform — revocation is permanent.
    """
    identity = inventory.get(node_id)
    if identity is None:
        raise KeyError(node_id)
    if identity.status is PlatformStatus.REVOKED:
        raise ValueError(f"{node_id}: revoked platforms cannot be cleared")
    return inventory.set_status(node_id, PlatformStatus.ENROLLED)


__all__ = ["quarantine", "revoke", "clear_quarantine"]
