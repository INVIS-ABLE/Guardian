"""Deception assets — registry, lifecycle, and the cardinal safety rule (Citadel System 30, Wave 30).

Every deception asset (honeytoken, decoy credential/file/route/...) is registered, carries ZERO real
privilege and ZERO real user data, and has an expiry + rotation schedule. The cardinal rule
(Wave-20 invariants 21, 22): a test/deception credential can never authenticate to production, and a
honeytoken never grants genuine privilege — enforced structurally, not by convention.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from enum import Enum


class DeceptionKind(str, Enum):
    HONEYTOKEN = "honeytoken"
    HONEY_CREDENTIAL = "honey_credential"
    DECOY_FILE = "decoy_file"
    DECOY_API_KEY = "decoy_api_key"
    DECOY_REPOSITORY = "decoy_repository"
    DECOY_DB_RECORD = "decoy_database_record"
    DECOY_CLOUD_OBJECT = "decoy_cloud_object"
    DECOY_ADMIN_ROUTE = "decoy_administrative_route"
    DECOY_SERVICE_ACCOUNT = "decoy_service_account"
    DECOY_HOST = "decoy_host"


@dataclass(frozen=True)
class DeceptionAsset:
    """A registered decoy. By construction it grants no real privilege and holds no real data."""

    asset_id: str
    kind: DeceptionKind
    token: str                       # the planted marker (looks real, is inert)
    alert_owner: str
    created_at: float
    expires_at: float
    rotation_period_days: int = 30

    # These are invariants, not configurable — a decoy can never be made to grant real access.
    grants_real_privilege: bool = field(default=False, init=False)
    contains_real_user_data: bool = field(default=False, init=False)

    def is_expired(self, now: float) -> bool:
        return now >= self.expires_at


class DeceptionRegistry:
    """The set of planted deception assets. Expired assets are removed; tokens are unique."""

    def __init__(self) -> None:
        self._assets: dict[str, DeceptionAsset] = {}
        self._tokens: set[str] = set()

    def plant(self, asset: DeceptionAsset) -> None:
        if asset.grants_real_privilege or asset.contains_real_user_data:
            raise ValueError("deception asset must never grant real privilege or hold real data")
        self._assets[asset.asset_id] = asset
        self._tokens.add(asset.token)

    def is_deception_token(self, token: str) -> bool:
        return token in self._tokens

    def get_by_token(self, token: str) -> DeceptionAsset | None:
        for a in self._assets.values():
            if a.token == token:
                return a
        return None

    def active(self, *, now: float) -> list[DeceptionAsset]:
        return [a for a in self._assets.values() if not a.is_expired(now)]

    def prune_expired(self, *, now: float) -> list[str]:
        """Remove (and return ids of) expired deception assets — they must not linger."""
        expired = [aid for aid, a in self._assets.items() if a.is_expired(now)]
        for aid in expired:
            self._tokens.discard(self._assets[aid].token)
            del self._assets[aid]
        return expired


def new_honeytoken() -> str:
    """A unique, inert marker that looks like a credential/key but authorises nothing."""
    return "GUARDIAN-CANARY-" + secrets.token_hex(16)


__all__ = ["DeceptionKind", "DeceptionAsset", "DeceptionRegistry", "new_honeytoken"]
