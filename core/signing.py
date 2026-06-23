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


class SigningError(RuntimeError):
    """The mandatory asymmetric backend is unavailable in a hardened posture. Fail closed."""


def require_ed25519() -> bool:
    """Whether asymmetric (Ed25519) signing is MANDATORY in the current posture (fail closed).

    Staging and production must never silently fall back to the symmetric HMAC primitive
    (ADR 0002): a deployment that cannot do Ed25519 must refuse to sign rather than issue a
    weaker capability. ``GUARDIAN_REQUIRE_ED25519=1`` forces the requirement on in any posture
    (so it can be exercised in development/CI); otherwise it is on for staging/production and
    off for development/ci — preserving the offline HMAC fallback for tests and local runs.
    """
    if os.environ.get("GUARDIAN_REQUIRE_ED25519", "").strip().lower() in {"1", "true", "yes"}:
        return True
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}


def _assert_asymmetric_available() -> None:
    """Refuse to operate on the HMAC fallback when Ed25519 is mandatory (staging/production)."""
    if not _HAVE_ED25519 and require_ed25519():
        raise SigningError(
            "Ed25519 signing is mandatory in staging/production but its backend is "
            "unavailable; refusing to fall back to HMAC-SHA256. Install a working "
            "'cryptography' backend, or run with GUARDIAN_ENV=development for the fallback."
        )


@dataclass(frozen=True)
class KeyPair:
    """A signing keypair as hex strings. For the HMAC fallback, public == private (symmetric)."""

    private: str
    public: str


def generate_keypair() -> KeyPair:
    _assert_asymmetric_available()
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
    _assert_asymmetric_available()
    if _HAVE_ED25519:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
        return sk.sign(message).hex()
    return hmac.new(bytes.fromhex(private_hex), message, hashlib.sha256).hexdigest()


def verify(public_hex: str, message: bytes, signature_hex: str) -> bool:
    # Fail closed in a hardened posture: a symmetric HMAC signature is not an acceptable
    # asymmetric proof in staging/production, so do not validate one there.
    if not _HAVE_ED25519 and require_ed25519():
        return False
    if _HAVE_ED25519:
        try:
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
            pk.verify(bytes.fromhex(signature_hex), message)
            return True
        except Exception:
            return False
    expected = hmac.new(bytes.fromhex(public_hex), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex)
