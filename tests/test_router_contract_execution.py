"""End-to-end: the Brain's router executes connectors through the signed contract,
records evidence, and refuses forged/replayed/expired authorizations."""

from __future__ import annotations

from time import time

from connectors.contract import ActionRequest, sign_authorization
from core import signing
from core.evidence import EvidenceStore, HashChainBackend
from core.router import ToolRouter

KEYS = signing.generate_keypair()


def _router(scope, tmp_path):
    store = EvidenceStore(backend=HashChainBackend(log_dir=tmp_path))
    return ToolRouter(scope, dry_run=True, evidence_store=store)


def test_signed_execution_succeeds_and_records_evidence(staging_scope, tmp_path):
    router = _router(staging_scope, tmp_path)
    auth = router.authorize_capability(
        "static_code", target="github.com/invisable/app", repo="github.com/invisable/app",
        signer_private_key=KEYS.private, approver="ciso",
    )
    result = router.execute_capability("static_code", auth, verify_key=KEYS.public)
    assert result.allowed, result.refusal_reason
    assert result.output["approver"] == "ciso"
    # Evidence was written and the chain verifies.
    assert (tmp_path / "guardian-audit.jsonl").exists()
    assert EvidenceStore(backend=HashChainBackend(log_dir=tmp_path)).verify()


def test_forged_authorization_is_refused(staging_scope, tmp_path):
    router = _router(staging_scope, tmp_path)
    attacker = signing.generate_keypair()
    auth = router.authorize_capability(
        "static_code", target="github.com/invisable/app",
        signer_private_key=attacker.private, approver="mallory",
    )
    # Verified against the TRUSTED key, the attacker's signature fails.
    result = router.execute_capability("static_code", auth, verify_key=KEYS.public)
    assert not result.allowed
    assert "signature is invalid" in result.refusal_reason


def test_replayed_authorization_for_other_request_is_refused(staging_scope, tmp_path):
    router = _router(staging_scope, tmp_path)
    # Sign an authorization for one target, then try to use it for another.
    req = ActionRequest(action="scan", target="github.com/invisable/app")
    auth = sign_authorization(req, signer_private_key=KEYS.private, approver="ciso")
    tampered = auth.__class__(
        request=ActionRequest(action="scan", target="evil.example.com"),
        approver=auth.approver, signature=auth.signature, expires_at=auth.expires_at,
    )
    result = router.execute_capability("static_code", tampered, verify_key=KEYS.public)
    assert not result.allowed


def test_expired_authorization_is_refused(staging_scope, tmp_path):
    router = _router(staging_scope, tmp_path)
    req = ActionRequest(action="scan", target="github.com/invisable/app",
                        repo="github.com/invisable/app")
    auth = sign_authorization(req, signer_private_key=KEYS.private, approver="ciso",
                              ttl_s=1, now=time() - 10)
    result = router.execute_capability("static_code", auth, verify_key=KEYS.public)
    assert not result.allowed
    assert "expired" in result.refusal_reason


def test_off_allowlist_target_is_refused(staging_scope, tmp_path):
    router = _router(staging_scope, tmp_path)
    auth = router.authorize_capability(
        "static_code", target="evil.example.com",
        signer_private_key=KEYS.private, approver="ciso",
    )
    result = router.execute_capability("static_code", auth, verify_key=KEYS.public)
    assert not result.allowed


def test_simulator_capability_rejected_for_contract_execution(staging_scope, tmp_path):
    router = _router(staging_scope, tmp_path)
    req = ActionRequest(action="run", target="staging.invisable.co.uk")
    auth = sign_authorization(req, signer_private_key=KEYS.private, approver="ciso")
    result = router.execute_capability("privacy_simulation", auth, verify_key=KEYS.public)
    assert not result.allowed
