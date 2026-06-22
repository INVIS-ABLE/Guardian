"""The Guardian Verifier detects key-directory tampering using public data only."""

from __future__ import annotations

import pytest

from core.verifier import (
    GuardianVerifier,
    KeyLeaf,
    KeyTransparencyLog,
    VerifierBoundaryError,
)

SIGNER = b"trusted-checkpoint-key"


def _log(*leaves: KeyLeaf) -> KeyTransparencyLog:
    log = KeyTransparencyLog()
    for leaf in leaves:
        log.append(leaf)
    return log


def test_clean_log_passes_with_valid_checkpoint():
    log = _log(
        KeyLeaf("alice", "phone", "pkA1", epoch=1),
        KeyLeaf("bob", "phone", "pkB1", epoch=1),
    )
    v = GuardianVerifier(SIGNER)
    cp = log.checkpoint(SIGNER, epoch=1)
    report = v.monitor(log, current_checkpoint=cp)
    assert report.ok
    assert v.verify_checkpoint(log, cp)


def test_forged_checkpoint_is_rejected():
    log = _log(KeyLeaf("alice", "phone", "pkA1", epoch=1))
    v = GuardianVerifier(SIGNER)
    # A checkpoint signed with the wrong key must not verify against our trusted signer.
    bad_cp = _log(KeyLeaf("alice", "phone", "pkA1", epoch=1)).checkpoint(b"attacker-key", epoch=1)
    assert not v.verify_checkpoint(log, bad_cp)
    assert "checkpoint_invalid" in v.monitor(log, current_checkpoint=bad_cp).alerts


def test_silent_key_replacement_is_detected():
    # alice's phone key changes WITHOUT a recovery event -> alert.
    log = _log(
        KeyLeaf("alice", "phone", "pkA1", epoch=1),
        KeyLeaf("alice", "phone", "pkA2", epoch=2, recovery=False),
    )
    v = GuardianVerifier(SIGNER)
    report = v.monitor(log)
    assert not report.ok
    assert any(a.startswith("silent_key_replacement:alice/phone") for a in report.alerts)


def test_recovery_key_change_is_not_flagged():
    log = _log(
        KeyLeaf("alice", "phone", "pkA1", epoch=1),
        KeyLeaf("alice", "phone", "pkA2", epoch=2, recovery=True),
    )
    v = GuardianVerifier(SIGNER)
    assert v.monitor(log).ok


def test_consistency_detects_history_rewrite():
    v = GuardianVerifier(SIGNER)
    log = _log(KeyLeaf("alice", "phone", "pkA1", epoch=1))
    earlier = log.checkpoint(SIGNER, epoch=1)
    # Extend honestly: consistency holds.
    log.append(KeyLeaf("bob", "phone", "pkB1", epoch=2))
    assert v.verify_consistency(log, earlier)
    # A log whose first leaf differs from the earlier checkpoint is inconsistent.
    rewritten = _log(KeyLeaf("alice", "phone", "EVIL", epoch=1), KeyLeaf("bob", "phone", "pkB1", epoch=2))
    assert not v.verify_consistency(rewritten, earlier)
    assert "checkpoint_inconsistency" in v.monitor(rewritten, previous_checkpoint=earlier).alerts


def test_inclusion_check():
    leaf = KeyLeaf("alice", "phone", "pkA1", epoch=1)
    log = _log(leaf)
    v = GuardianVerifier(SIGNER)
    assert v.verify_inclusion(log, leaf)
    assert not v.verify_inclusion(log, KeyLeaf("mallory", "phone", "pk", epoch=1))


def test_verifier_refuses_private_content():
    # The Verifier may never ingest private fields — boundary is enforced.
    log = KeyTransparencyLog()
    with pytest.raises(VerifierBoundaryError):
        log.append({"identity": "alice", "device": "phone", "public_key": "pk",
                    "epoch": 1, "private_key": "LEAK"})
    with pytest.raises(VerifierBoundaryError):
        log.append({"identity": "alice", "device": "phone", "public_key": "pk",
                    "epoch": 1, "plaintext": "secret message"})
