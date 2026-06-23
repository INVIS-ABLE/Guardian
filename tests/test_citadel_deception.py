"""Wave 30 acceptance — Citadel Deception & Tripwire Grid (System 30)."""

from __future__ import annotations

import pytest

from core import signing
from citadel.deception import (
    DeceptionAsset,
    DeceptionKind,
    DeceptionRegistry,
    deny_production_auth,
    new_honeytoken,
    record_trigger,
    verify_trigger,
)

NOW = 1_000_000.0


def _asset(asset_id="d1", ttl=86400.0, token=None) -> DeceptionAsset:
    return DeceptionAsset(
        asset_id=asset_id, kind=DeceptionKind.HONEY_CREDENTIAL,
        token=token or new_honeytoken(), alert_owner="secops",
        created_at=NOW, expires_at=NOW + ttl,
    )


def test_deception_asset_never_grants_real_privilege():
    a = _asset()
    assert a.grants_real_privilege is False and a.contains_real_user_data is False


def test_deception_credential_cannot_authenticate_to_production():
    reg = DeceptionRegistry()
    a = _asset()
    reg.plant(a)
    # presenting the planted decoy credential MUST be denied production auth
    assert deny_production_auth(reg, a.token) is True
    assert deny_production_auth(reg, "a-real-looking-but-unknown-token") is False


def test_planting_real_privilege_is_rejected():
    reg = DeceptionRegistry()
    bad = DeceptionAsset.__new__(DeceptionAsset)  # bypass frozen init to simulate tampering
    object.__setattr__(bad, "asset_id", "x")
    object.__setattr__(bad, "kind", DeceptionKind.HONEYTOKEN)
    object.__setattr__(bad, "token", "t")
    object.__setattr__(bad, "alert_owner", "o")
    object.__setattr__(bad, "created_at", NOW)
    object.__setattr__(bad, "expires_at", NOW + 1)
    object.__setattr__(bad, "rotation_period_days", 30)
    object.__setattr__(bad, "grants_real_privilege", True)
    object.__setattr__(bad, "contains_real_user_data", False)
    with pytest.raises(ValueError):
        reg.plant(bad)


def test_trigger_produces_verifiable_signed_evidence():
    kp = signing.generate_keypair()
    a = _asset()
    evidence = record_trigger(a, source="10.0.0.5", at=NOW, signing_key=kp.private)
    assert verify_trigger(evidence, kp.public) is True
    assert len(evidence.evidence_digest) == 64
    # tampering with the source invalidates the signature
    tampered = type(evidence)(asset_id=a.asset_id, kind=a.kind.value, source="0.0.0.0",
                              at=NOW, signature=evidence.signature)
    assert verify_trigger(tampered, kp.public) is False


def test_expired_deception_assets_are_pruned():
    reg = DeceptionRegistry()
    reg.plant(_asset("live", ttl=86400.0))
    reg.plant(_asset("stale", ttl=10.0))
    pruned = reg.prune_expired(now=NOW + 100)
    assert pruned == ["stale"]
    assert {a.asset_id for a in reg.active(now=NOW + 100)} == {"live"}
