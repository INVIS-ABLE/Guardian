"""The Guardian connector contract.

Every defensive bolt-on (scanner, firewall manager, IR tool, …) sits behind ONE common
interface so Guardian stays a *control plane* with a single chain of authority — not a pile
of ad-hoc shell-outs. The contract makes the dangerous things structurally impossible:

  * **No raw command strings.** A connector exposes *enumerated actions* with *typed args*
    and a *fixed executable path*; it never accepts ``command``/``shell``/``script`` or args
    containing shell metacharacters.
  * **Targets are allowlisted.** A request must name a target that is explicitly permitted.
  * **Execution requires a signed authorization** bound to the request (action, target,
    commit) and not expired — mirroring the production approval model in ``core.policy_gate``.
  * **Evidence is mandatory and cleanup always runs.**

``core.connectors.base.BaseConnector`` is the current concrete scanner-wrapper; this module
is the higher-level lifecycle contract those connectors are migrated onto. The safety
helpers here (:func:`validate_request`, :func:`authorize_execution`) are enforced and tested
independently of any one connector.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from time import time
from typing import Any, Protocol, runtime_checkable

from core import signing


class ContractViolation(PermissionError):
    """Raised when a connector interaction breaks the contract. Always fail closed."""


# --- lifecycle value types -----------------------------------------------------
@dataclass(frozen=True)
class ConnectorInventory:
    """What a connector is and what it can do — discovered, never assumed."""

    connector: str
    version: str
    actions: tuple[str, ...]          # the ONLY actions this connector will perform
    fixed_binary: str                 # fixed executable path; never user-supplied
    trust_zone: str


@dataclass
class ValidationResult:
    ok: bool
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ResourceLimits:
    timeout_s: int = 300
    max_output_bytes: int = 5_000_000
    max_cpu: float = 1.0
    max_memory_mb: int = 1024
    max_processes: int = 64


@dataclass(frozen=True)
class ActionRequest:
    """A typed request for one enumerated action. Never carries a raw command."""

    action: str                       # must be one of the connector's enumerated actions
    target: str                       # must be allowlisted
    args: dict[str, Any] = field(default_factory=dict)  # typed args only
    repo: str | None = None
    commit: str | None = None


@dataclass(frozen=True)
class Permission:
    name: str


@dataclass(frozen=True)
class ApprovalPolicy:
    required_actions: tuple[str, ...] = ()   # actions needing a recorded human approval
    min_reviewers: int = 1


@dataclass(frozen=True)
class ExecutionPlan:
    """The exact, fixed argv that *would* run — reviewable before authorization."""

    action: str
    argv: tuple[str, ...]             # fixed argument array, executed without a shell
    target: str
    limits: ResourceLimits = ResourceLimits()
    egress_allowlist: tuple[str, ...] = ()


@dataclass(frozen=True)
class SignedAuthorization:
    """A signed capability to execute a SPECIFIC request. Expires; bound to the change."""

    request: ActionRequest
    approver: str
    signature: str                    # detached signature over the request (verified upstream)
    expires_at: float | None = None
    commit: str | None = None
    workflow_run: str | None = None


@dataclass
class ExecutionResult:
    action: str
    returncode: int | None
    output_hash: str                  # hash of output; raw output is redacted before storage
    evidence_ref: str | None = None
    redacted: bool = True


@dataclass
class EvidenceBundle:
    events: list[dict[str, Any]] = field(default_factory=list)
    signed: bool = False


@dataclass
class CleanupResult:
    destroyed: bool
    notes: str = ""


# --- the contract --------------------------------------------------------------
@runtime_checkable
class GuardianConnector(Protocol):
    """One interface for every bolt-on. Implementations must enforce the safety helpers."""

    def inventory(self) -> ConnectorInventory: ...

    def validate_configuration(self) -> ValidationResult: ...

    def calculate_plan(self, request: ActionRequest) -> ExecutionPlan: ...

    def required_permissions(self) -> list[Permission]: ...

    def required_approvals(self) -> ApprovalPolicy: ...

    def execute(self, authorization: SignedAuthorization) -> ExecutionResult: ...

    def collect_evidence(self) -> EvidenceBundle: ...

    def cleanup(self) -> CleanupResult: ...


# --- enforced safety helpers ---------------------------------------------------
# Keys that would smuggle a raw command into a connector. Forbidden.
_RAW_COMMAND_KEYS = frozenset({"command", "cmd", "shell", "script", "exec", "eval"})
# Shell metacharacters that have no place in a typed argument value.
_SHELL_METACHARS = re.compile(r"[;&|`$><\n\r\\]")


def assert_no_raw_command(args: dict[str, Any]) -> None:
    """Reject raw command strings and shell-metacharacter injection in typed args."""
    for key, value in args.items():
        if key.lower() in _RAW_COMMAND_KEYS:
            raise ContractViolation(
                f"connectors must not accept raw command strings (arg {key!r}); "
                "use enumerated actions + typed args."
            )
        if isinstance(value, str) and _SHELL_METACHARS.search(value):
            raise ContractViolation(
                f"arg {key!r} contains shell metacharacters; typed args only, no shell."
            )


def target_allowed(target: str, allowlist: tuple[str, ...]) -> bool:
    """A target is allowed if it equals or is a subdomain/subpath of an allowlist entry."""
    t = target.lower().strip().rstrip("/.")
    for entry in allowlist:
        e = entry.lower().strip().rstrip("/.")
        if t == e or t.endswith("." + e) or t.startswith(e + "/"):
            return True
    return False


def validate_request(
    request: ActionRequest,
    *,
    allowed_actions: tuple[str, ...],
    target_allowlist: tuple[str, ...],
) -> None:
    """Gate a request before any plan is built. Fail closed on anything unexpected."""
    if request.action not in allowed_actions:
        raise ContractViolation(
            f"action {request.action!r} is not one of the connector's enumerated actions "
            f"{allowed_actions}."
        )
    if not target_allowed(request.target, target_allowlist):
        raise ContractViolation(f"target {request.target!r} is not allowlisted.")
    assert_no_raw_command(request.args)


def canonical_request(request: ActionRequest) -> bytes:
    """Stable byte encoding of a request — what an authorization signs over."""
    return json.dumps(
        {
            "action": request.action, "target": request.target,
            "args": request.args, "repo": request.repo, "commit": request.commit,
        },
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def sign_authorization(
    request: ActionRequest,
    *,
    signer_private_key: str,
    approver: str,
    ttl_s: int = 600,
    now: float | None = None,
    workflow_run: str | None = None,
) -> SignedAuthorization:
    """Mint a signed, time-boxed capability to execute exactly this request.

    In production the signer is the human-approval gate's key (Ed25519); the signature
    binds the authorization to the specific action+target+args so it cannot be replayed
    against a different request.
    """
    now = time() if now is None else now
    signature = signing.sign(signer_private_key, canonical_request(request))
    return SignedAuthorization(
        request=request, approver=approver, signature=signature,
        expires_at=now + ttl_s, commit=request.commit, workflow_run=workflow_run,
    )


def authorize_execution(
    authorization: SignedAuthorization, *, verify_key: str | None = None, now: float | None = None
) -> None:
    """Require a present, unexpired authorization; verify its signature when a key is given."""
    if not authorization.signature:
        raise ContractViolation("execute() requires a SignedAuthorization with a signature.")
    now = time() if now is None else now
    if authorization.expires_at is not None and now >= authorization.expires_at:
        raise ContractViolation("authorization has expired; obtain a fresh approval.")
    if verify_key is not None and not signing.verify(
        verify_key, canonical_request(authorization.request), authorization.signature
    ):
        raise ContractViolation("authorization signature is invalid for this request.")
