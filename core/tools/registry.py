"""Tool registry — resolve a capability to a verified, environment-permitted manifest.

Resolution is a *structured* operation: an unknown or hallucinated capability, a forged
signature, or a capability not permitted in the current environment yields a
:class:`ToolRefusal` with a machine-readable reason — never an uncaught exception
(target architecture §13). The registry verifies the manifest signature and, in a
staging/production posture, refuses anything not validly signed (fail closed).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict

from .manifest import (
    NetworkMode,
    ResourceLimits,
    SignedManifest,
    ToolManifest,
    require_signed_manifests,
    sign_manifest,
)


class RefusalReason(str, Enum):
    UNKNOWN_CAPABILITY = "unknown_capability"
    SIGNATURE_INVALID = "signature_invalid"
    ENVIRONMENT_NOT_ALLOWED = "environment_not_allowed"
    APPROVAL_REQUIRED = "approval_required"
    TOKEN_REJECTED = "token_rejected"


class ToolRefusal(BaseModel):
    """A structured refusal — the safe alternative to raising on bad input."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str
    reason: RefusalReason
    detail: str = ""


class ToolRegistry:
    """An allow-list of signed manifests, indexed by capability."""

    def __init__(self, signed: list[SignedManifest] | None = None) -> None:
        self._by_capability: dict[str, SignedManifest] = {}
        for sm in signed or []:
            self.register(sm)

    def register(self, signed: SignedManifest) -> None:
        self._by_capability[signed.manifest.capability] = signed

    def resolve(self, capability: str, *, environment: str) -> ToolManifest | ToolRefusal:
        """Resolve a capability to a verified, environment-permitted manifest."""
        signed = self._by_capability.get(capability)
        if signed is None:
            return ToolRefusal(
                capability=capability, reason=RefusalReason.UNKNOWN_CAPABILITY,
                detail="no manifest registered for this capability",
            )
        # Verify signature; fail closed in staging/production if not validly signed.
        if not signed.verify() and require_signed_manifests():
            return ToolRefusal(
                capability=capability, reason=RefusalReason.SIGNATURE_INVALID,
                detail="manifest signature did not verify",
            )
        if not signed.manifest.allows_environment(environment):
            return ToolRefusal(
                capability=capability, reason=RefusalReason.ENVIRONMENT_NOT_ALLOWED,
                detail=f"capability not permitted in environment '{environment}'",
            )
        return signed.manifest


# Default manifests for the existing connector capabilities. image_digest values are
# placeholders pinned per environment in real deployment; the point is that they are
# *pinned and signed*, not resolved from a moving tag.
def _m(capability: str, tool: str, *, envs: tuple[str, ...],
       approval: bool = False, network: NetworkMode = NetworkMode.DENY_ALL,
       limits: ResourceLimits | None = None) -> ToolManifest:
    return ToolManifest(
        capability=capability,
        tool=tool,
        image_digest=f"sha256:{'0' * 64}",
        input_schema=f"schemas/{capability}-input-v1.json",
        output_schema=f"schemas/{capability}-output-v1.json",
        allowed_environments=envs,
        requires_approval=approval,
        network=network,
        limits=limits or ResourceLimits(),
    )


def default_registry() -> ToolRegistry:
    """Signed manifests mirroring the legacy CAPABILITY_MAP, now pinned and bounded."""
    dev_stg = ("development", "staging")
    manifests = [
        _m("static_code_scan", "semgrep", envs=dev_stg),
        _m("code_analysis", "codeql", envs=dev_stg),
        _m("secrets_scan", "gitleaks", envs=dev_stg),
        _m("dependency_scan", "trivy", envs=dev_stg),
        _m("container_scan", "trivy", envs=dev_stg),
        # DAST touches a running target — egress allow-list, staging only.
        _m("dast", "zap", envs=("staging",), network=NetworkMode.EGRESS_ALLOWLIST),
        # Credential-resilience capabilities are approval-gated, owned staging only.
        _m("password_strength", "hashcat", envs=("staging",), approval=True),
        _m("login_resilience", "hydra", envs=("staging",), approval=True,
           network=NetworkMode.EGRESS_ALLOWLIST),
    ]
    return ToolRegistry([sign_manifest(m) for m in manifests])


__all__ = ["RefusalReason", "ToolRefusal", "ToolRegistry", "default_registry"]
