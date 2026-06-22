"""Attestation signing (Phase 2).

Signed attestations give evidence non-repudiation. We prefer Ed25519 (asymmetric — a holder
of the public key can verify without being able to forge), lazily importing `cryptography`,
and fall back to HMAC-SHA256 when it isn't available so the core has no hard dependency.

In deployment, artifact/release signing is performed by cosign and pipeline attestations by
in-toto/witness (blueprint area 9). This module signs Guardian's own evidence records so the
audit system of record carries a verifiable signature.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Protocol


def canonical(record: object) -> bytes:
    """Deterministic bytes for signing/hashing (sorted keys)."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class Signer(Protocol):
    algorithm: str

    def sign(self, record: object) -> str: ...
    def verify(self, record: object, signature: str) -> bool: ...


class HmacSigner:
    """Symmetric keyed signature. Dependency-free fallback (shared-secret, not non-repudiable)."""

    algorithm = "hmac-sha256"

    def __init__(self, key: bytes) -> None:
        self._key = key

    def sign(self, record: object) -> str:
        return hmac.new(self._key, canonical(record), hashlib.sha256).hexdigest()

    def verify(self, record: object, signature: str) -> bool:
        return hmac.compare_digest(self.sign(record), signature)


class Ed25519Signer:
    """Asymmetric Ed25519 signature (non-repudiable). Requires `cryptography`."""

    algorithm = "ed25519"

    def __init__(self, private_key: object | None = None) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._sk = private_key or Ed25519PrivateKey.generate()
        self._pk = self._sk.public_key()  # type: ignore[union-attr]

    def sign(self, record: object) -> str:
        return self._sk.sign(canonical(record)).hex()  # type: ignore[union-attr]

    def verify(self, record: object, signature: str) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            self._pk.verify(bytes.fromhex(signature), canonical(record))
            return True
        except (InvalidSignature, ValueError):
            return False

    @property
    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization

        raw = self._pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return raw.hex()


def ed25519_available() -> bool:
    # A broken `cryptography` (e.g. missing _cffi_backend) raises a Rust PanicException, which
    # is NOT an Exception subclass — catch BaseException so we cleanly fall back to HMAC.
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: F401
            Ed25519PrivateKey,
        )

        Ed25519PrivateKey.generate()  # ensure the backend actually works
        return True
    except BaseException:
        return False


def default_signer(hmac_key: bytes = b"guardian-dev-attestation-key-change-me") -> Signer:
    """Ed25519 if available (preferred), else HMAC. Production injects KMS/OpenBao keys."""
    if ed25519_available():
        return Ed25519Signer()
    return HmacSigner(hmac_key)
