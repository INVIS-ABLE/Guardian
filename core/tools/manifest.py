"""Signed, versioned tool manifests (target architecture §13).

The legacy router maps a capability straight to a tool *name* with a hard-coded dict
(``core.router.CAPABILITY_MAP``). That is unversioned and unsigned: nothing pins the
tool image, declares its schemas, or bounds its blast radius. A manifest replaces that
with a signed, content-addressed description of exactly *what* a capability runs and
under *what* limits:

    capability: static_code_scan
    tool: semgrep
    manifest_version: 1
    image_digest: sha256:...
    input_schema / output_schema: pinned schema ids
    allowed_environments: [development, staging]
    requires_approval: false
    network: deny_all
    filesystem: input read_only, output ephemeral
    limits: cpu / memory / runtime / output bytes

Manifests are HMAC-signed; the registry refuses an unsigned/forged manifest in a
staging/production posture (fail closed), exactly like the policy gate and memory.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

MANIFEST_KEY_ENV = "GUARDIAN_MANIFEST_KEY"
# A non-secret default key used only in development; signatures made with it are NOT
# accepted in staging/production (see require_signed_manifests()).
_DEV_KEY = b"guardian-dev-manifest-key"


def _guardian_env() -> str:
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower()


def require_signed_manifests() -> bool:
    """Whether a verified signature is mandatory in the current posture (fail closed)."""
    return _guardian_env() in {"staging", "production"}


def _signing_key() -> bytes:
    key = os.environ.get(MANIFEST_KEY_ENV)
    if key:
        return key.encode("utf-8")
    if require_signed_manifests():
        # No key in a posture that demands one — callers must treat signing as impossible.
        raise RuntimeError(
            f"{MANIFEST_KEY_ENV} must be set in a staging/production posture"
        )
    return _DEV_KEY


class NetworkMode(str, Enum):
    DENY_ALL = "deny_all"
    EGRESS_ALLOWLIST = "egress_allowlist"


class FsAccess(str, Enum):
    NONE = "none"
    READ_ONLY = "read_only"
    EPHEMERAL = "ephemeral"


class FilesystemPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input: FsAccess = FsAccess.READ_ONLY
    output: FsAccess = FsAccess.EPHEMERAL


class ResourceLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cpu: float = Field(gt=0, default=2.0)
    memory_mb: int = Field(gt=0, default=4096)
    runtime_seconds: int = Field(gt=0, default=1200)
    output_bytes: int = Field(gt=0, default=50_000_000)


class ToolManifest(BaseModel):
    """A pinned, bounded description of what a capability runs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str
    tool: str
    manifest_version: int = Field(ge=1, default=1)
    image_digest: str  # sha256:... of the pinned tool image
    input_schema: str   # pinned schema id/path
    output_schema: str
    allowed_environments: tuple[str, ...] = ()
    requires_approval: bool = False
    network: NetworkMode = NetworkMode.DENY_ALL
    filesystem: FilesystemPolicy = Field(default_factory=FilesystemPolicy)
    limits: ResourceLimits = Field(default_factory=ResourceLimits)

    def canonical_bytes(self) -> bytes:
        """Deterministic serialisation used for signing and content-addressing."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    def manifest_hash(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()

    def allows_environment(self, environment: str) -> bool:
        return environment in self.allowed_environments


class SignedManifest(BaseModel):
    """A manifest plus its HMAC signature."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest: ToolManifest
    signature: str  # hex HMAC-SHA256 over manifest.canonical_bytes()

    def verify(self) -> bool:
        """Constant-time signature check against the configured key."""
        try:
            key = _signing_key()
        except RuntimeError:
            return False
        expected = hmac.new(key, self.manifest.canonical_bytes(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)


def sign_manifest(manifest: ToolManifest) -> SignedManifest:
    """Sign a manifest with the configured key (HMAC-SHA256)."""
    key = _signing_key()
    sig = hmac.new(key, manifest.canonical_bytes(), hashlib.sha256).hexdigest()
    return SignedManifest(manifest=manifest, signature=sig)


__all__ = [
    "MANIFEST_KEY_ENV",
    "require_signed_manifests",
    "NetworkMode",
    "FsAccess",
    "FilesystemPolicy",
    "ResourceLimits",
    "ToolManifest",
    "SignedManifest",
    "sign_manifest",
]
