"""The six roots of trust (target architecture §5).

Before any sensitive capability is issued, Guardian must INDEPENDENTLY verify six roots:

    human · workload · machine · software · target · evidence

Failing any required root denies issuance — fail closed. This module is the gate the
capability issuer (``core/tools/executor.py``) consults before minting a token; it is the
"are we even allowed to act?" check that sits in front of the one-use capability.

Every evidence field is a POSITIVE assertion that defaults to its fail-closed value, so an
empty / partially-populated context fails: absence of proof is not proof. Production raises
the bar on the human root (two distinct reviewers, no self-review).
"""

from __future__ import annotations

import os
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Root(str, Enum):
    HUMAN = "human"
    WORKLOAD = "workload"
    MACHINE = "machine"
    SOFTWARE = "software"
    TARGET = "target"
    EVIDENCE = "evidence"


ALL_ROOTS: frozenset[Root] = frozenset(Root)


# --- per-root evidence (positive assertions, fail-closed defaults) -------------
class HumanTrust(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    authenticated: bool = False
    phishing_resistant: bool = False           # passkey / hardware key
    active: bool = False                        # not suspended/compromised
    role: str = ""
    requester: str = ""
    approvers: tuple[str, ...] = ()
    approval_valid: bool = False                # recorded, unexpired
    envelope_bound: bool = False                # bound to the exact action envelope


class WorkloadTrust(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    spiffe_id: str = ""
    namespace: str = ""
    service_account: str = ""
    image_digest: str = ""
    runtime_profile: str = ""
    cert_valid: bool = False
    not_revoked: bool = False


class MachineTrust(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    secure_boot: bool = False
    tpm_attested: bool = False
    measured_boot: bool = False
    ima_ok: bool = False
    approved_firmware: bool = False
    not_quarantined: bool = False


class SoftwareTrust(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    approved_repo: bool = False
    commit: str = ""
    build_verified: bool = False                # reproducible or independently verified
    sbom_present: bool = False
    provenance_valid: bool = False
    signature_valid: bool = False
    approved_builder: bool = False
    deps_approved: bool = False
    policy_connector_digest_ok: bool = False


class TargetTrust(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ownership_verified: bool = False            # fresh GitHub-App / DNS evidence
    environment: str = ""
    resolved_addresses: tuple[str, ...] = ()
    dns_unchanged: bool = False                 # no post-authorisation DNS change
    not_third_party: bool = False


class EvidenceTrust(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    service_available: bool = False
    append_ok: bool = False                     # immutable append succeeds
    attestation_generated: bool = False
    trace_id: str = ""
    case_id: str = ""
    shadow_received: bool = False               # Shadow verification received the event


class TrustContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    human: HumanTrust = Field(default_factory=HumanTrust)
    workload: WorkloadTrust = Field(default_factory=WorkloadTrust)
    machine: MachineTrust = Field(default_factory=MachineTrust)
    software: SoftwareTrust = Field(default_factory=SoftwareTrust)
    target: TargetTrust = Field(default_factory=TargetTrust)
    evidence: EvidenceTrust = Field(default_factory=EvidenceTrust)


# --- results -------------------------------------------------------------------
class RootCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    root: Root
    ok: bool
    reasons: tuple[str, ...] = ()


class RootsReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow: bool
    environment: str
    checks: list[RootCheck]

    def failed_roots(self) -> list[Root]:
        return [c.root for c in self.checks if not c.ok]

    def reasons(self) -> list[str]:
        return [f"{c.root.value}:{r}" for c in self.checks if not c.ok for r in c.reasons]


# --- checkers ------------------------------------------------------------------
def _check_human(h: HumanTrust, *, production: bool) -> RootCheck:
    reasons: list[str] = []
    if not h.authenticated:
        reasons.append("not_authenticated")
    if not h.phishing_resistant:
        reasons.append("not_phishing_resistant")
    if not h.active:
        reasons.append("inactive_or_suspended")
    if not h.role:
        reasons.append("no_role")
    if not h.requester:
        reasons.append("no_requester")
    if not h.approval_valid:
        reasons.append("approval_invalid_or_expired")
    if not h.envelope_bound:
        reasons.append("approval_not_envelope_bound")
    distinct = {a for a in h.approvers if a and a != h.requester}
    if h.requester and h.requester in set(h.approvers):
        reasons.append("self_review")
    needed = 2 if production else 1
    if len(distinct) < needed:
        reasons.append(f"insufficient_reviewers:{len(distinct)}/{needed}")
    return RootCheck(root=Root.HUMAN, ok=not reasons, reasons=tuple(reasons))


def _all_true(model: BaseModel, fields: tuple[str, ...]) -> list[str]:
    return [f"missing_{name}" for name in fields if not getattr(model, name)]


def _check_workload(w: WorkloadTrust) -> RootCheck:
    reasons = _all_true(w, ("spiffe_id", "namespace", "service_account", "image_digest",
                            "runtime_profile", "cert_valid", "not_revoked"))
    return RootCheck(root=Root.WORKLOAD, ok=not reasons, reasons=tuple(reasons))


def _check_machine(m: MachineTrust) -> RootCheck:
    reasons = _all_true(m, ("secure_boot", "tpm_attested", "measured_boot", "ima_ok",
                            "approved_firmware", "not_quarantined"))
    return RootCheck(root=Root.MACHINE, ok=not reasons, reasons=tuple(reasons))


def _check_software(s: SoftwareTrust) -> RootCheck:
    reasons = _all_true(s, ("approved_repo", "commit", "build_verified", "sbom_present",
                            "provenance_valid", "signature_valid", "approved_builder",
                            "deps_approved", "policy_connector_digest_ok"))
    return RootCheck(root=Root.SOFTWARE, ok=not reasons, reasons=tuple(reasons))


def _check_target(t: TargetTrust) -> RootCheck:
    reasons = _all_true(t, ("ownership_verified", "dns_unchanged", "not_third_party"))
    if not t.environment:
        reasons.append("no_environment")
    if not t.resolved_addresses:
        reasons.append("no_resolved_addresses")
    return RootCheck(root=Root.TARGET, ok=not reasons, reasons=tuple(reasons))


def _check_evidence(e: EvidenceTrust) -> RootCheck:
    reasons = _all_true(e, ("service_available", "append_ok", "attestation_generated",
                            "shadow_received"))
    if not e.trace_id:
        reasons.append("no_trace_id")
    if not e.case_id:
        reasons.append("no_case_id")
    return RootCheck(root=Root.EVIDENCE, ok=not reasons, reasons=tuple(reasons))


def require_roots() -> bool:
    """Whether the six-roots gate is mandatory in the current posture (fail closed)."""
    if os.environ.get("GUARDIAN_REQUIRE_ROOTS") == "1":
        return True
    return os.environ.get("GUARDIAN_ENV", "development").strip().lower() in {"staging", "production"}


class RootsOfTrust:
    """Verifies the six roots before a sensitive capability is issued. Fail closed."""

    def verify(
        self,
        context: TrustContext,
        *,
        environment: str,
        required: frozenset[Root] | None = None,
    ) -> RootsReport:
        required = required if required is not None else ALL_ROOTS
        production = environment.strip().lower() == "production"
        all_checks = {
            Root.HUMAN: _check_human(context.human, production=production),
            Root.WORKLOAD: _check_workload(context.workload),
            Root.MACHINE: _check_machine(context.machine),
            Root.SOFTWARE: _check_software(context.software),
            Root.TARGET: _check_target(context.target),
            Root.EVIDENCE: _check_evidence(context.evidence),
        }
        checks = [all_checks[r] for r in Root if r in required]
        return RootsReport(allow=all(c.ok for c in checks), environment=environment, checks=checks)


__all__ = [
    "Root", "ALL_ROOTS", "TrustContext",
    "HumanTrust", "WorkloadTrust", "MachineTrust", "SoftwareTrust", "TargetTrust",
    "EvidenceTrust", "RootCheck", "RootsReport", "RootsOfTrust", "require_roots",
]
