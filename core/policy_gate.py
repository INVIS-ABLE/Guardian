"""Central authorization gate — the ONE authority that allows or denies any action.

Acceptance-gate #1: every connector, agent, and simulator routes through a single
``authorize()`` path backed by this policy. There is no ``allow_production`` escape
parameter; production is permitted only by recorded, distinct, unexpired approvals.

The canonical policy is expressed twice, identically:
  * ``policies/opa/guardian.rego`` — the external Open Policy Agent authority used in
    deployment (and by ``conftest`` in CI).
  * ``decide()`` here — an in-process evaluator mirroring the Rego, so enforcement holds
    even before OPA is wired and so unit/property tests can prove the rules.

If the ``opa`` binary + bundle are present and ``GUARDIAN_USE_OPA=1``, ``evaluate()``
delegates to OPA. Otherwise the embedded evaluator is used **only** where the runtime
posture allows it: in ``development``/``ci`` (set via ``GUARDIAN_ENV``). In
``staging``/``production`` — or for any production *target* — OPA is mandatory and its
absence means deny; the embedded mirror is a testing oracle, not a production
authority. In ``ci`` with OPA present, the OPA and embedded decisions must agree.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from time import time
from typing import Any

from core.tenancy import (
    INVISABLE_TENANT_ID,
    AuthorisationGrant,
    TenantRegistry,
    authorise_target,
    load_tenant_registry,
)

# Globally blocked actions — denied in every mode and scope; a scope cannot re-enable them.
BLOCKED_ACTIONS: frozenset[str] = frozenset(
    {
        "third_party_scan",
        "real_user_data_access",
        "credential_theft",
        "stealth",
        "persistence",
        "exploit_deployment",
        "hack_back",
        "destructive_testing",
        # --- Privacy Fabric invariants -------------------------------------------------
        # Guardian protects the cryptographic system; it is NEVER a reader inside it.
        # Globally blocked so no scope, model, or agent can request them. See
        # docs/privacy_fabric/ and policies/privacy_invariants.yaml.
        "decrypt_private_content",
        "access_message_plaintext",
        "copy_private_content_to_memory",
        "send_private_content_to_model",
        "store_decryption_keys",
        "silent_moderation_participant",
        "create_master_access_key",
        "plaintext_in_observability",
        "train_on_user_content",
        # --- AI-agent boundary ---------------------------------------------------------
        # The model recommends; the central policy decides. These agent capabilities are
        # globally blocked so a compromised or over-eager model cannot self-escalate.
        # See policies/agent_boundary.yaml and docs/defence_catalogue.md.
        "expand_scope",
        "change_policy",
        "disable_logging",
        "merge_own_security_patch",
        "resolve_own_finding",
        "unrestricted_secret_access",
        "arbitrary_command_execution",
    }
)

# Actions that always require a recorded human approval (in addition to scope-listed ones).
GLOBAL_APPROVAL_REQUIRED: frozenset[str] = frozenset(
    {
        "production_scan",
        "high_volume_test",
        "account_locking_test",
        "data_export_test",
        "admin_permission_test",
        "credential_audit",
    }
)

# Production requires this many DISTINCT, unexpired reviewers approving production_scan.
PRODUCTION_MIN_REVIEWERS = 2


@dataclass(frozen=True)
class ApprovalLite:
    action: str
    approver: str
    expires_at: float | None = None  # epoch seconds; None = never expires (discouraged)
    # Binding fields — an approval is a capability for a SPECIFIC change, not the action in
    # the abstract. When set, the approval only applies to a request with the same value;
    # changing any bound field invalidates the capability. None = unbound (wildcard).
    target: str | None = None  # exact domain or repo
    commit: str | None = None
    workflow_run: str | None = None

    def is_valid(self, now: float) -> bool:
        return self.expires_at is None or now < self.expires_at

    def applies_to(self, inp: "PolicyInput") -> bool:
        """Whether this approval is bound-compatible with the request."""
        if self.commit is not None and self.commit != inp.commit:
            return False
        if self.workflow_run is not None and self.workflow_run != inp.workflow_run:
            return False
        if self.target is not None and self.target not in (inp.domain, inp.repo):
            return False
        return True


@dataclass
class PolicyInput:
    actor: str
    action: str
    mode: str
    environment: str
    domain: str | None = None
    repo: str | None = None
    test_account: str | None = None
    # Result of a DNS-TXT / GitHub-App ownership check. Fail-closed default: ownership
    # is NOT assumed. A caller must pass evidence of verification; an unverified named
    # target is denied (see ``decide`` rule 3). Previously this defaulted to ``True``,
    # which silently treated every target as owned — a fail-open default.
    ownership_verified: bool = False
    allowed_modes: list[str] = field(default_factory=list)
    blocked_actions: list[str] = field(default_factory=list)
    approval_required: list[str] = field(default_factory=list)
    allowed_test_accounts: list[str] = field(default_factory=list)
    approvals: list[ApprovalLite] = field(default_factory=list)
    commit: str | None = None
    workflow_run: str | None = None
    now: float = field(default_factory=time)
    # --- Tenancy (Phase B) -----------------------------------------------------------
    # The owning tenant and the authorisation context for tenant-aware enforcement. These
    # default to the founding INVISABLE tenant and are INERT unless tenancy enforcement is
    # switched on (GUARDIAN_TENANCY_ENFORCE=1); when off, behaviour is exactly as before.
    # See core/tenancy.py and docs/platform/INVISABLE_TO_MULTI_TENANT_MIGRATION.md.
    tenant_id: str = INVISABLE_TENANT_ID
    capability: str | None = None          # the tool capability being exercised (e.g. static_code)
    asset_id: str | None = None            # the asset under test (defaults to the named target)
    grants: list[AuthorisationGrant] = field(default_factory=list)
    verify_grant_key: str | None = None    # public key; when set, grant signatures must verify
    # Optional tenant registry. When enforcement is on and this is unset, the committed
    # tenants/ profiles are loaded so a suspended/archived/unknown tenant is rejected.
    tenants: TenantRegistry | None = None

    def to_opa_input(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "action": self.action,
            "mode": self.mode,
            "environment": self.environment,
            "domain": self.domain,
            "repo": self.repo,
            "test_account": self.test_account,
            "ownership_verified": self.ownership_verified,
            "allowed_modes": self.allowed_modes,
            "blocked_actions": self.blocked_actions,
            "approval_required": self.approval_required,
            "allowed_test_accounts": self.allowed_test_accounts,
            "approvals": [
                {
                    "action": a.action,
                    "approver": a.approver,
                    "expires_at": a.expires_at,
                    "target": a.target,
                    "commit": a.commit,
                    "workflow_run": a.workflow_run,
                }
                for a in self.approvals
            ],
            "commit": self.commit,
            "workflow_run": self.workflow_run,
            "now": self.now,
        }


@dataclass
class PolicyDecision:
    allow: bool
    denies: list[str] = field(default_factory=list)

    def reason(self) -> str:
        return "; ".join(self.denies) if self.denies else "allowed"


def _valid_approvals_for(inp: PolicyInput, action: str) -> list[ApprovalLite]:
    """Approvals that are for this action, unexpired, AND bound-compatible with the request."""
    return [
        a
        for a in inp.approvals
        if a.action == action and a.is_valid(inp.now) and a.applies_to(inp)
    ]


def decide(inp: PolicyInput) -> PolicyDecision:
    """Embedded evaluator — mirrors policies/opa/guardian.rego. Default deny."""
    denies: list[str] = []

    # 1. Globally + scope-blocked actions are never permitted.
    if inp.action in BLOCKED_ACTIONS or inp.action in set(inp.blocked_actions):
        denies.append(f"blocked_action:{inp.action}")

    # 2. Mode must be permitted by the scope.
    if inp.mode not in set(inp.allowed_modes):
        denies.append(f"mode_not_allowed:{inp.mode}")

    # 3. Ownership of any named target must be verified.
    if (inp.domain or inp.repo) and not inp.ownership_verified:
        denies.append("ownership_unverified")

    # 4. Only registered test accounts (never real users).
    if inp.test_account is not None and inp.test_account not in set(inp.allowed_test_accounts):
        denies.append(f"non_test_account:{inp.test_account}")

    # 5. Approval-gated actions need a valid (unexpired) recorded approval.
    gated = inp.action in GLOBAL_APPROVAL_REQUIRED or inp.action in set(inp.approval_required)
    if gated and not _valid_approvals_for(inp, inp.action):
        denies.append(f"missing_approval:{inp.action}")

    # 6. Production needs >= PRODUCTION_MIN_REVIEWERS distinct, unexpired production_scan
    #    approvers (two-person rule). This replaces the removed allow_production flag.
    if inp.environment == "production":
        approvers = {a.approver for a in _valid_approvals_for(inp, "production_scan")}
        if len(approvers) < PRODUCTION_MIN_REVIEWERS:
            denies.append(
                f"insufficient_production_approvals:{len(approvers)}/{PRODUCTION_MIN_REVIEWERS}"
            )

    return PolicyDecision(allow=len(denies) == 0, denies=denies)


def _opa_available() -> bool:
    return (
        os.environ.get("GUARDIAN_USE_OPA") == "1"
        and shutil.which("opa") is not None
        and _rego_bundle_path() is not None
    )


def _rego_bundle_path() -> str | None:
    from .config import REPO_ROOT

    p = REPO_ROOT / "policies" / "opa"
    return str(p) if p.exists() else None


def _decide_via_opa(inp: PolicyInput) -> PolicyDecision:  # pragma: no cover - needs opa
    bundle = _rego_bundle_path()
    proc = subprocess.run(  # noqa: S603
        ["opa", "eval", "-I", "-d", bundle, "-f", "json", "data.guardian.authz.decision"],
        input=json.dumps(inp.to_opa_input()),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        # Fail closed if OPA errors.
        return PolicyDecision(allow=False, denies=[f"opa_error:{proc.stderr.strip()[:120]}"])
    data = json.loads(proc.stdout)
    result = data["result"][0]["expressions"][0]["value"]
    return PolicyDecision(allow=bool(result.get("allow")), denies=list(result.get("denies", [])))


def _guardian_env() -> str:
    """Runtime deployment posture: development | ci | staging | production.

    Distinct from a *target's* ``PolicyInput.environment`` — this is where Guardian
    itself is running, set by ``GUARDIAN_ENV``. Unset defaults to ``development``.
    """
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower()


# Postures in which the embedded Python evaluator is NOT an acceptable production
# authority — OPA must answer, and its absence means deny.
_OPA_REQUIRED_ENVS: frozenset[str] = frozenset({"staging", "production"})


def _embedded_permitted(inp: PolicyInput) -> bool:
    """Whether the embedded evaluator may decide, given runtime posture + target.

    The embedded evaluator mirrors the Rego as a *testing oracle*, not an alternative
    production authority (target architecture §10):

      * development / ci      → permitted (OPA optional; CI also checks parity below).
      * staging / production  → OPA required; its absence means deny.

    The gate keys off Guardian's deployment *posture* (``GUARDIAN_ENV``), not a
    target's environment: a production *target* is still authorised by the embedded
    mirror during development/test (that is how the two-person production rule is unit
    tested), but a Guardian actually deployed to staging/production must use OPA.
    """
    if _guardian_env() in _OPA_REQUIRED_ENVS:
        return False
    return True


def _tenancy_enforced() -> bool:
    """Whether tenant-aware target authorisation is enforced.

    Fail-closed in a *deployed* posture: tenant enforcement is ON automatically in
    staging/production (the hardened default — a target action must be backed by a valid,
    signed, tenant-bound grant), and can be forced on in any posture with
    ``GUARDIAN_TENANCY_ENFORCE=1`` (used to exercise it in development/CI). It is off only in
    development/ci without that flag, so the founding INVISABLE deployment and the existing
    unit tests behave exactly as before.
    """
    if os.environ.get("GUARDIAN_TENANCY_ENFORCE", "").strip().lower() in {"1", "true", "yes"}:
        return True
    return _guardian_env() in _OPA_REQUIRED_ENVS


_TENANT_REGISTRY_CACHE: TenantRegistry | None = None


def _default_tenant_registry() -> TenantRegistry:
    """The committed tenants/ registry, loaded once and cached.

    Loaded lazily and only when enforcement consults it, so the default (enforcement
    off) path never touches disk. Tests inject their own registry via
    ``PolicyInput.tenants`` and so never hit this.
    """
    global _TENANT_REGISTRY_CACHE
    if _TENANT_REGISTRY_CACHE is None:
        _TENANT_REGISTRY_CACHE = load_tenant_registry()
    return _TENANT_REGISTRY_CACHE


def _tenant_denies(inp: PolicyInput) -> list[str]:
    """Tenant-authorisation denials, applied as an outer AND over the action policy.

    This is the placement from the migration doc: target legitimacy (does a current,
    signed grant for *this tenant* cover this asset/capability/environment?) is decided
    by :func:`core.tenancy.authorise_target` **before** the action policy. It sits
    outside :func:`decide` so the OPA / embedded mirror parity is untouched.

    Inert unless enforcement is on. When on, any action naming a target must be backed
    by a valid grant for an **active, known tenant**; non-target actions (no
    domain/repo/asset) are left to the action policy. Fails closed: an unknown or
    suspended tenant, a missing capability, no grant, or an unauthorised grant denies.
    """
    if not _tenancy_enforced():
        return []
    asset = inp.asset_id or inp.domain or inp.repo
    if asset is None:
        return []  # nothing targeted; action policy alone governs
    if not inp.capability:
        return ["tenant_capability_unspecified"]
    registry = inp.tenants if inp.tenants is not None else _default_tenant_registry()
    decision = authorise_target(
        inp.grants,
        tenant_id=inp.tenant_id,
        asset_id=asset,
        capability=inp.capability,
        environment=inp.environment,
        now=inp.now,
        verify_key=inp.verify_grant_key,
        tenants=registry,
    )
    if not decision.allowed:
        return [f"tenant_unauthorised:{decision.reason}"]
    return []


def evaluate(inp: PolicyInput) -> PolicyDecision:
    """Single entry point. Delegates to OPA when configured.

    Fail-closed: when OPA is unavailable and the embedded evaluator is not an
    acceptable authority for this posture/target, **deny** rather than silently fall
    back to the in-process mirror (target architecture §10). In CI, when OPA *is*
    available, the OPA decision and the embedded mirror must agree.

    Tenant-aware target authorisation (when enforced) is applied as an outer AND: the
    request must satisfy both the tenant grant check and the action policy.
    """
    core = _evaluate_core(inp)
    tenant_denies = _tenant_denies(inp)
    if tenant_denies:
        return PolicyDecision(allow=False, denies=tenant_denies + core.denies)
    return core


def _evaluate_core(inp: PolicyInput) -> PolicyDecision:
    """The action-policy decision (OPA or embedded mirror), unchanged by tenancy."""
    if _opa_available():
        decision = _decide_via_opa(inp)
        if _guardian_env() == "ci":
            mirror = decide(inp)
            if mirror.allow != decision.allow:
                return PolicyDecision(
                    allow=False,
                    denies=[
                        f"opa_embedded_mismatch:opa={decision.allow},embedded={mirror.allow}"
                    ],
                )
        return decision
    if _embedded_permitted(inp):
        return decide(inp)
    return PolicyDecision(
        allow=False,
        denies=[f"opa_required:posture={_guardian_env()},target={inp.environment}"],
    )
