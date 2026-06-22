"""Central signing — Ed25519 when functional, deterministic HMAC fallback otherwise."""

from __future__ import annotations

from core import signing


def test_algorithm_is_known():
    assert signing.ALGORITHM in {"ed25519", "hmac-sha256"}


def test_sign_verify_roundtrip():
    kp = signing.generate_keypair()
    sig = signing.sign(kp.private, b"guardian evidence")
    assert signing.verify(kp.public, b"guardian evidence", sig)


def test_tampered_message_fails():
    kp = signing.generate_keypair()
    sig = signing.sign(kp.private, b"original")
    assert not signing.verify(kp.public, b"tampered", sig)


def test_wrong_key_fails():
    kp = signing.generate_keypair()
    other = signing.generate_keypair()
    sig = signing.sign(kp.private, b"msg")
    assert not signing.verify(other.public, b"msg", sig)


def test_keys_are_hex_portable():
    kp = signing.generate_keypair()
    bytes.fromhex(kp.private)   # must not raise
    bytes.fromhex(kp.public)
