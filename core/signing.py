"""Central signing — Ed25519 with a deterministic HMAC fallback.

One module produces and verifies the signatures Guardian relies on:

  * **key-transparency checkpoints** (``core/verifier.py``), and
  * **connector execution authorizations** (``connectors/contract.py``).

Ed25519 (via ``cryptography``) is used when available — the production posture from
ADR 0002. When it is not installed, a deterministic HMAC-SHA256 fallback keeps the logic
working offline/in CI (the *primitive* is swappable; the verification logic is the point).
Keys and signatures are hex strings so they are portable across both backends.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

def _ed25519_works() -> bool:
    """Import AND functionally exercise Ed25519.

    ``cryptography`` can import yet *panic* at runtime if its native backend (cffi) is
    missing. Rather than catch that panic (a ``BaseException``), we first confirm the
    ``_cffi_backend`` extension is importable — its absence is exactly what makes Ed25519
    panic — and only then exercise the primitive, catching ordinary exceptions.
    """
    import importlib.util

    if importlib.util.find_spec("_cffi_backend") is None:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        sk = Ed25519PrivateKey.generate()
        sk.public_key().verify(sk.sign(b"selftest"), b"selftest")
        return True
    except Exception:
        return False


_HAVE_ED25519 = _ed25519_works()

if _HAVE_ED25519:  # pragma: no cover - depends on the runtime backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

ALGORITHM = "ed25519" if _HAVE_ED25519 else "hmac-sha256"


@dataclass(frozen=True)
class KeyPair:
    """A signing keypair as hex strings. For the HMAC fallback, public == private (symmetric)."""

    private: str
    public: str


def generate_keypair() -> KeyPair:
    if _HAVE_ED25519:
        sk = Ed25519PrivateKey.generate()
        priv = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return KeyPair(private=priv.hex(), public=pub.hex())
    # HMAC fallback: a single symmetric secret used as both "private" and "public".
    secret = os.urandom(32).hex()
    return KeyPair(private=secret, public=secret)


def sign(private_hex: str, message: bytes) -> str:
    if _HAVE_ED25519:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
        return sk.sign(message).hex()
    return hmac.new(bytes.fromhex(private_hex), message, hashlib.sha256).hexdigest()


def verify(public_hex: str, message: bytes, signature_hex: str) -> bool:
    if _HAVE_ED25519:
        try:
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
            pk.verify(bytes.fromhex(signature_hex), message)
            return True
        except Exception:
            return False
    expected = hmac.new(bytes.fromhex(public_hex), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex)
