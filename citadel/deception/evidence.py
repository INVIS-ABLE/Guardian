"""Deception triggers + signed evidence — the verifier for System 30.

When a deception asset is touched, that is a high-signal event: it produces SIGNED, verifiable
evidence and routes an alert/case to the asset's owner. Crucially, a deception/test credential can
NEVER authenticate to production — ``deny_production_auth`` is the structural guard.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from core import signing

from .registry import DeceptionAsset, DeceptionRegistry


@dataclass(frozen=True)
class TriggerEvidence:
    asset_id: str
    kind: str
    source: str             # who/where touched it (ip, principal, route)
    at: float
    signature: str

    def canonical_unsigned(self) -> bytes:
        return json.dumps(
            {"asset_id": self.asset_id, "kind": self.kind, "source": self.source, "at": self.at},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

    @property
    def evidence_digest(self) -> str:
        return hashlib.sha256(self.canonical_unsigned()).hexdigest()


def record_trigger(
    asset: DeceptionAsset, *, source: str, at: float, signing_key: str
) -> TriggerEvidence:
    """Produce signed evidence that a specific decoy was triggered."""
    unsigned = json.dumps(
        {"asset_id": asset.asset_id, "kind": asset.kind.value, "source": source, "at": at},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    signature = signing.sign(signing_key, unsigned)
    return TriggerEvidence(asset_id=asset.asset_id, kind=asset.kind.value, source=source,
                           at=at, signature=signature)


def verify_trigger(evidence: TriggerEvidence, public_key: str) -> bool:
    return signing.verify(public_key, evidence.canonical_unsigned(), evidence.signature)


def deny_production_auth(registry: DeceptionRegistry, presented_token: str) -> bool:
    """A presented credential that matches a deception token must NEVER authenticate to production.

    Returns True if the token is a deception token (and therefore authentication MUST be denied).
    """
    return registry.is_deception_token(presented_token)


__all__ = ["TriggerEvidence", "record_trigger", "verify_trigger", "deny_production_auth"]
