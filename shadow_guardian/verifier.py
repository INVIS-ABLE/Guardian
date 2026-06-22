"""Independent re-verification of capability transitions, with a freeze latch."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from core.tools.capability import CapabilityToken
from core.tools.manifest import ResourceLimits, SignedManifest


class ShadowError(PermissionError):
    """Base error for Shadow Guardian refusals."""


class CapabilityFrozen(ShadowError):
    """Raised when capability issuance is frozen (divergence or Shadow unavailable)."""


def _independent_args_hash(args: dict) -> str:
    """Recompute the call's args hash WITHOUT importing the primary's helper.

    Intentionally a separate implementation of the same canonical form, so the Shadow
    does not inherit a bug (or a compromise) in ``core.tools.capability.hash_args``.
    """
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _limits_not_increased(token: ResourceLimits, manifest: ResourceLimits) -> bool:
    """A token may never grant MORE than its manifest allows on any budget axis."""
    return (
        token.cpu <= manifest.cpu
        and token.memory_mb <= manifest.memory_mb
        and token.runtime_seconds <= manifest.runtime_seconds
        and token.output_bytes <= manifest.output_bytes
    )


class ObservedCall(BaseModel):
    """The call as actually observed at execution time — what the token must bind to."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: UUID
    tool_digest: str
    args: dict
    environment: str


class ShadowFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    check: str
    ok: bool
    detail: str = ""


class ShadowReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    frozen: bool
    findings: list[ShadowFinding]

    def failures(self) -> list[ShadowFinding]:
        return [f for f in self.findings if not f.ok]


class FreezeLatch:
    """A one-way latch: once tripped, capability issuance stays frozen until the Sovereign
    Root explicitly clears it. The primary Guardian cannot clear its own freeze."""

    def __init__(self) -> None:
        self._frozen = False
        self.reasons: list[str] = []

    @property
    def frozen(self) -> bool:
        return self._frozen

    def trip(self, reason: str) -> None:
        self._frozen = True
        self.reasons.append(reason)

    def clear_by_sovereign_root(self, *, authorized: bool) -> None:
        # Only the Sovereign Root may clear a freeze; ordinary Guardian workflows cannot.
        if not authorized:
            raise ShadowError("only the Sovereign Root may clear a Shadow freeze")
        self._frozen = False
        self.reasons.clear()


class ShadowGate:
    """The capability issuer consults this BEFORE minting a high-risk capability.

    Fails closed: a frozen latch OR an unavailable Shadow Guardian denies issuance.
    """

    def __init__(self, latch: FreezeLatch, *, shadow_available: bool = True) -> None:
        self.latch = latch
        self.shadow_available = shadow_available

    def assert_issuable(self) -> None:
        if not self.shadow_available:
            raise CapabilityFrozen("Shadow Guardian unavailable — high-risk issuance frozen")
        if self.latch.frozen:
            raise CapabilityFrozen(f"capability issuance frozen: {self.latch.reasons}")


class ShadowGuardian:
    """Re-verifies a capability transition independently. Read-only; no execution power."""

    def __init__(self, *, manifest_key: bytes | None = None, latch: FreezeLatch | None = None) -> None:
        # An independent copy of the trusted manifest-signing key. In production this lives
        # in the Shadow's own account/secret store, separate from the primary's.
        self._manifest_key = manifest_key
        self.latch = latch or FreezeLatch()

    def gate(self) -> ShadowGate:
        return ShadowGate(self.latch)

    def _verify_manifest(self, signed: SignedManifest) -> bool:
        if self._manifest_key is not None:
            expected = hmac.new(
                self._manifest_key, signed.manifest.canonical_bytes(), hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, signed.signature)
        # No independent key injected: fall back to the manifest's own verification.
        return signed.verify()

    def verify_transition(
        self,
        *,
        token: CapabilityToken,
        signed_manifest: SignedManifest,
        observed: ObservedCall,
        evidence_receipt: str | None,
        now: datetime | None = None,
    ) -> ShadowReport:
        """Independently re-check every binding of a high-risk transition. Any failure
        trips the freeze latch (which then blocks further capability issuance)."""
        manifest = signed_manifest.manifest
        rehash = _independent_args_hash(observed.args)
        findings = [
            ShadowFinding(check="manifest_signature", ok=self._verify_manifest(signed_manifest)),
            ShadowFinding(check="token_unexpired", ok=not token.is_expired(now)),
            ShadowFinding(
                check="tool_digest_matches_manifest",
                ok=token.tool_digest == manifest.image_digest,
                detail=f"token={token.tool_digest} manifest={manifest.image_digest}",
            ),
            ShadowFinding(
                check="args_hash_matches_observed",
                ok=token.args_hash == rehash,
                detail="observed args differ from the token's bound args"
                if token.args_hash != rehash else "",
            ),
            ShadowFinding(
                check="token_binds_observed_call",
                ok=token.matches(
                    case_id=observed.case_id, tool_digest=observed.tool_digest,
                    args_hash=rehash, environment=observed.environment,
                ),
            ),
            ShadowFinding(
                check="limits_not_increased",
                ok=_limits_not_increased(token.limits, manifest.limits),
            ),
            ShadowFinding(check="network_matches_manifest", ok=token.network == manifest.network),
            ShadowFinding(check="evidence_receipt_present", ok=bool(evidence_receipt)),
        ]
        ok = all(f.ok for f in findings)
        if not ok:
            failed = [f.check for f in findings if not f.ok]
            self.latch.trip(f"shadow divergence on {observed.tool_digest}: {failed}")
        return ShadowReport(ok=ok, frozen=self.latch.frozen, findings=findings)
