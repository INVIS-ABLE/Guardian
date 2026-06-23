"""Production-hardening: Ed25519 is mandatory in staging/production (no silent HMAC fallback).

Characterization first (the behaviour we are pinning), then the new fail-closed enforcement.
"""

from __future__ import annotations

import pytest

from core import signing


# --- characterization: existing behaviour is unchanged in development -----------
def test_development_still_signs_and_verifies(monkeypatch):
    monkeypatch.delenv("GUARDIAN_ENV", raising=False)
    monkeypatch.delenv("GUARDIAN_REQUIRE_ED25519", raising=False)
    kp = signing.generate_keypair()
    sig = signing.sign(kp.private, b"msg")
    assert signing.verify(kp.public, b"msg", sig) is True


def test_require_ed25519_default_off_in_development(monkeypatch):
    monkeypatch.delenv("GUARDIAN_ENV", raising=False)
    monkeypatch.delenv("GUARDIAN_REQUIRE_ED25519", raising=False)
    assert signing.require_ed25519() is False


# --- the requirement is on for a deployed posture -------------------------------
@pytest.mark.parametrize("env", ["staging", "production", "STAGING", " Production "])
def test_require_ed25519_on_in_staging_production(monkeypatch, env):
    monkeypatch.setenv("GUARDIAN_ENV", env)
    assert signing.require_ed25519() is True


def test_require_ed25519_forced_on_by_flag_in_any_posture(monkeypatch):
    monkeypatch.setenv("GUARDIAN_ENV", "development")
    monkeypatch.setenv("GUARDIAN_REQUIRE_ED25519", "1")
    assert signing.require_ed25519() is True


# --- fail-closed when the asymmetric backend is unavailable in a hardened posture -
def test_sign_refuses_hmac_fallback_in_staging(monkeypatch):
    monkeypatch.setenv("GUARDIAN_ENV", "staging")
    monkeypatch.setattr(signing, "_HAVE_ED25519", False)
    with pytest.raises(signing.SigningError):
        signing.sign("00" * 32, b"msg")
    with pytest.raises(signing.SigningError):
        signing.generate_keypair()


def test_verify_fails_closed_in_staging_without_ed25519(monkeypatch):
    # A symmetric HMAC signature is not an acceptable asymmetric proof in production.
    monkeypatch.setenv("GUARDIAN_ENV", "production")
    monkeypatch.setattr(signing, "_HAVE_ED25519", False)
    assert signing.verify("00" * 32, b"msg", "ab" * 32) is False


def test_fallback_still_allowed_in_development(monkeypatch):
    # The offline HMAC fallback remains available for development/CI when not required.
    monkeypatch.setenv("GUARDIAN_ENV", "development")
    monkeypatch.delenv("GUARDIAN_REQUIRE_ED25519", raising=False)
    monkeypatch.setattr(signing, "_HAVE_ED25519", False)
    kp = signing.generate_keypair()              # does not raise
    sig = signing.sign(kp.private, b"msg")
    assert signing.verify(kp.public, b"msg", sig) is True
