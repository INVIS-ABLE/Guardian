"""Bounded tool executor (target architecture §13).

The executor is the only path from a capability to a running tool. For each call it:

1. resolves the capability to a verified, environment-permitted manifest (structured
   refusal on anything unknown/forged/disallowed — never an exception),
2. enforces the manifest's approval requirement,
3. mints a **one-use capability token** bound to the case, tool digest, exact args,
   environment, network policy and resource budget, and consumes it,
4. invokes a pluggable runner under the manifest's limits, and
5. returns a typed result whose output is bounded and hashed for provenance.

The default runner does **not** execute a real container: real isolated execution needs
a configured sandbox backend, so without one the executor fails closed to a dry-run
plan rather than shelling out unbounded. A real sandbox runner slots in behind the same
``ToolRunner`` interface.
"""

from __future__ import annotations

import hashlib
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from .capability import CapabilityToken, TokenStore, hash_args, issue_token
from .manifest import ToolManifest
from .registry import RefusalReason, ToolRefusal, ToolRegistry


class RunOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = ""
    executed: bool = False  # True only for a real sandboxed run


class ToolRunner(Protocol):
    def run(self, manifest: ToolManifest, token: CapabilityToken, args: dict) -> RunOutput:
        ...


class DryRunRunner:
    """Fail-closed default: describes the bounded call without executing it."""

    def run(self, manifest: ToolManifest, token: CapabilityToken, args: dict) -> RunOutput:
        return RunOutput(
            text=(
                f"[dry-run] would run {manifest.tool} ({manifest.image_digest}) "
                f"under network={manifest.network.value}, cpu={manifest.limits.cpu}, "
                f"mem={manifest.limits.memory_mb}MB, timeout={manifest.limits.runtime_seconds}s"
            ),
            executed=False,
        )


class ToolExecution(BaseModel):
    """The typed outcome of a permitted tool call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str
    tool: str
    image_digest: str
    token_id: UUID
    environment: str
    executed: bool
    output: str
    output_hash: str
    truncated: bool = False


class ToolExecutor:
    """Resolves, authorises, tokenises and runs a capability under its manifest."""

    def __init__(self, registry: ToolRegistry, *, token_store: TokenStore | None = None,
                 runner: ToolRunner | None = None) -> None:
        self._registry = registry
        self._tokens = token_store or TokenStore()
        self._runner = runner or DryRunRunner()

    def execute(
        self,
        capability: str,
        *,
        case_id: UUID,
        args: dict,
        environment: str,
        approved: bool = False,
        input_artifact_hashes: tuple[str, ...] = (),
    ) -> ToolExecution | ToolRefusal:
        resolved = self._registry.resolve(capability, environment=environment)
        if isinstance(resolved, ToolRefusal):
            return resolved
        manifest = resolved

        if manifest.requires_approval and not approved:
            return ToolRefusal(
                capability=capability, reason=RefusalReason.APPROVAL_REQUIRED,
                detail="capability requires a recorded human approval",
            )

        token = issue_token(
            manifest, case_id=case_id, args=args, environment=environment,
            input_artifact_hashes=input_artifact_hashes,
        )
        # Re-verify the binding and consume the token exactly once (fail closed).
        if not token.matches(case_id=case_id, tool_digest=manifest.image_digest,
                             args_hash=hash_args(args), environment=environment):
            return ToolRefusal(capability=capability, reason=RefusalReason.TOKEN_REJECTED,
                              detail="token binding mismatch")
        if not self._tokens.consume(token):
            return ToolRefusal(capability=capability, reason=RefusalReason.TOKEN_REJECTED,
                              detail="token expired or already used")

        out = self._runner.run(manifest, token, args)
        text, truncated = _bound(out.text, manifest.limits.output_bytes)
        return ToolExecution(
            capability=manifest.capability,
            tool=manifest.tool,
            image_digest=manifest.image_digest,
            token_id=token.token_id,
            environment=environment,
            executed=out.executed,
            output=text,
            output_hash="sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
            truncated=truncated,
        )


def _bound(text: str, max_bytes: int) -> tuple[str, bool]:
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text, False
    return raw[:max_bytes].decode("utf-8", errors="ignore"), True


__all__ = ["RunOutput", "ToolRunner", "DryRunRunner", "ToolExecution", "ToolExecutor"]
