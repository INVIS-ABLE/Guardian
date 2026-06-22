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

    def sign(self, record: object) -> str:
        """Return a signature string for the canonicalised record."""

    def verify(self, record: object, signature: str) -> bool:
        """Return True if the signature is valid for the record."""


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
    """True if the cryptography package is importable (Ed25519 signing usable)."""
    import importlib.util

    return importlib.util.find_spec("cryptography") is not None


def default_signer(hmac_key: bytes = b"guardian-dev-attestation-key-change-me") -> Signer:
    """In-process default is HMAC — dependency-free and deterministic.

    For non-repudiable signing, production injects an Ed25519 signer backed by a KMS/OpenBao
    key (``Ed25519Signer(private_key=...)``), and cosign/witness sign release artifacts and
    pipeline attestations (blueprint area 9).
    """
    return HmacSigner(hmac_key)
