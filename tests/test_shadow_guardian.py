"""The Shadow Guardian independently re-verifies capability transitions and freezes on
divergence — without holding any execution power."""

from __future__ import annotations

from uuid import uuid4

import pytest

from core.tools.capability import issue_token
from core.tools.manifest import (
    NetworkMode,
    ResourceLimits,
    ToolManifest,
    sign_manifest,
)
from shadow_guardian import (
    CapabilityFrozen,
    FreezeLatch,
    ObservedCall,
    ShadowGate,
    ShadowGuardian,
)

KEY = b"trusted-manifest-key"


def _manifest(**over) -> ToolManifest:
    base = dict(
        capability="static_code_scan", tool="semgrep",
        image_digest="sha256:" + "a" * 64,
        input_schema="schemas/in@1", output_schema="schemas/out@1",
        allowed_environments=("staging",), network=NetworkMode.DENY_ALL,
    )
    base.update(over)
    return ToolManifest(**base)


def _setup(monkeypatch, **manifest_over):
    monkeypatch.setenv("GUARDIAN_MANIFEST_KEY", KEY.decode())
    manifest = _manifest(**manifest_over)
    signed = sign_manifest(manifest)
    case_id = uuid4()
    args = {"target": "github.com/invisable/app", "rules": "p/ci"}
    token = issue_token(manifest, case_id=case_id, args=args, environment="staging")
    observed = ObservedCall(case_id=case_id, tool_digest=manifest.image_digest,
                            args=args, environment="staging")
    return manifest, signed, token, observed, args


def test_matching_transition_passes_and_does_not_freeze(monkeypatch):
    _, signed, token, observed, _ = _setup(monkeypatch)
    shadow = ShadowGuardian(manifest_key=KEY)
    report = shadow.verify_transition(
        token=token, signed_manifest=signed, observed=observed, evidence_receipt="rec-1"
    )
    assert report.ok, report.failures()
    assert not report.frozen
    assert not shadow.latch.frozen


def test_tampered_args_detected_and_freezes(monkeypatch):
    _, signed, token, _observed, _ = _setup(monkeypatch)
    shadow = ShadowGuardian(manifest_key=KEY)
    # The executor claims to run DIFFERENT args than the token bound.
    tampered = ObservedCall(case_id=token.case_id, tool_digest=token.tool_digest,
                            args={"target": "evil.example.com"}, environment="staging")
    report = shadow.verify_transition(
        token=token, signed_manifest=signed, observed=tampered, evidence_receipt="rec-1"
    )
    assert not report.ok
    assert report.frozen
    assert any(f.check == "args_hash_matches_observed" for f in report.failures())


def test_forged_manifest_signature_detected(monkeypatch):
    _, signed, token, observed, _ = _setup(monkeypatch)
    # The Shadow holds a DIFFERENT trusted key than whoever signed the manifest.
    shadow = ShadowGuardian(manifest_key=b"a-different-trusted-key")
    report = shadow.verify_transition(
        token=token, signed_manifest=signed, observed=observed, evidence_receipt="rec-1"
    )
    assert not report.ok
    assert any(f.check == "manifest_signature" for f in report.failures())
    assert report.frozen


def test_expired_token_detected(monkeypatch):
    from datetime import timedelta

    _, signed, token, observed, _ = _setup(monkeypatch)
    shadow = ShadowGuardian(manifest_key=KEY)
    future = token.expires_at + timedelta(seconds=1)
    report = shadow.verify_transition(
        token=token, signed_manifest=signed, observed=observed,
        evidence_receipt="rec-1", now=future,
    )
    assert not report.ok
    assert any(f.check == "token_unexpired" for f in report.failures())


def test_increased_limits_detected(monkeypatch):
    manifest, signed, token, observed, _ = _setup(monkeypatch)
    shadow = ShadowGuardian(manifest_key=KEY)
    # Forge a token that grants MORE CPU than the manifest permits.
    inflated = token.model_copy(update={
        "limits": ResourceLimits(cpu=manifest.limits.cpu + 8, memory_mb=manifest.limits.memory_mb,
                                 runtime_seconds=manifest.limits.runtime_seconds,
                                 output_bytes=manifest.limits.output_bytes)
    })
    report = shadow.verify_transition(
        token=inflated, signed_manifest=signed, observed=observed, evidence_receipt="rec-1"
    )
    assert not report.ok
    assert any(f.check == "limits_not_increased" for f in report.failures())


def test_missing_evidence_receipt_detected(monkeypatch):
    _, signed, token, observed, _ = _setup(monkeypatch)
    shadow = ShadowGuardian(manifest_key=KEY)
    report = shadow.verify_transition(
        token=token, signed_manifest=signed, observed=observed, evidence_receipt=None
    )
    assert not report.ok
    assert any(f.check == "evidence_receipt_present" for f in report.failures())


# --- freeze latch + issuance gate ---------------------------------------------
def test_freeze_latch_blocks_issuance_until_sovereign_root_clears():
    latch = FreezeLatch()
    gate = ShadowGate(latch)
    gate.assert_issuable()  # ok initially
    latch.trip("divergence")
    with pytest.raises(CapabilityFrozen):
        gate.assert_issuable()
    # The primary cannot clear its own freeze.
    with pytest.raises(PermissionError):
        latch.clear_by_sovereign_root(authorized=False)
    latch.clear_by_sovereign_root(authorized=True)
    gate.assert_issuable()  # unfrozen again


def test_unavailable_shadow_freezes_issuance():
    gate = ShadowGate(FreezeLatch(), shadow_available=False)
    with pytest.raises(CapabilityFrozen):
        gate.assert_issuable()


def test_divergence_then_issuance_is_blocked(monkeypatch):
    # End-to-end: a bad transition trips the latch, and the issuance gate then refuses.
    _, signed, token, _observed, _ = _setup(monkeypatch)
    shadow = ShadowGuardian(manifest_key=KEY)
    bad = ObservedCall(case_id=token.case_id, tool_digest=token.tool_digest,
                       args={"x": 1}, environment="staging")
    shadow.verify_transition(token=token, signed_manifest=signed, observed=bad,
                             evidence_receipt="rec-1")
    with pytest.raises(CapabilityFrozen):
        shadow.gate().assert_issuable()


def test_shadow_holds_no_execution_methods():
    # Assurance: the Shadow Guardian exposes verification + freeze only — never execution.
    api = set(dir(ShadowGuardian))
    assert "verify_transition" in api and "gate" in api
    assert not any(n in api for n in ("execute", "run", "issue", "deploy", "apply"))
