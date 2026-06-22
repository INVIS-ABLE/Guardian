"""Trust-context producers — populate the six roots of trust from real evidence.

``core/roots_of_trust.py`` defines *what* must be verified; this module builds a
``TrustContext`` from the concrete evidence sources Guardian already has, so the roots are
populated from facts rather than hand-set booleans:

  * **human**    ← an authenticated ``identity.oidc.Principal`` + recorded approvals
                   (``core.guardrails.Approval``), checking validity and envelope binding.
  * **workload** ← a short-lived ``identity.credentials.Credential`` (its real validity).
  * **evidence** ← an ``core.evidence.store.EvidenceReceipt`` from an actual immutable append.
  * **machine / software / target** ← the verified results of an attestation/provenance/
                   ownership check, mapped through a fail-closed adapter (the integration
                   point for Keylime/TPM, SBOM/provenance, and the ownership verifier).

Everything is **fail closed**: a field is only asserted when the underlying evidence
supports it; anything unknown stays at its negative default. Inputs are duck-typed (read by
attribute) so this module does not hard-import the optional ``identity``/``attestation``
packages.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from .roots_of_trust import (
    EvidenceTrust,
    HumanTrust,
    MachineTrust,
    SoftwareTrust,
    TargetTrust,
    TrustContext,
    WorkloadTrust,
)

if TYPE_CHECKING:  # hints only — no runtime dependency on these packages
    from core.evidence.store import EvidenceReceipt
    from core.guardrails import Approval
    from core.machine_attestation import MachineVerification
    from identity.credentials import Credential
    from identity.oidc import Principal
    from ownership.evidence import OwnershipEvidence
    from supplychain.admission import AdmissionDecision
    from supplychain.provenance import Provenance


def _approval_envelope_bound(approval: Any, envelope: Mapping[str, Any]) -> bool:
    """An approval is envelope-bound when its commit binding is present and matches, and
    no other set binding contradicts the envelope (mirrors ApprovalLite.applies_to)."""
    commit = getattr(approval, "commit", None)
    if not commit or commit != envelope.get("commit"):
        return False
    target = getattr(approval, "target", None)
    if target is not None and target != envelope.get("target"):
        return False
    workflow = getattr(approval, "workflow_run", None)
    if workflow is not None and workflow != envelope.get("workflow_run"):
        return False
    return True


def human_trust_from(
    principal: "Principal",
    approvals: "Sequence[Approval]",
    *,
    requester: str,
    envelope: Mapping[str, Any],
    phishing_resistant: bool,
    active: bool,
    now: float | None = None,
) -> HumanTrust:
    """Derive the human root from an authenticated principal + recorded approvals.

    ``phishing_resistant`` (auth method assurance, e.g. an oauth2-proxy AMR header) and
    ``active`` (account-status check) are supplied by the components that verify them.
    """
    approvers = tuple(getattr(a, "approver", "") for a in approvals)
    approval_valid = bool(approvals) and all(a.valid(now) for a in approvals)
    envelope_bound = bool(approvals) and all(
        _approval_envelope_bound(a, envelope) for a in approvals
    )
    roles = sorted(getattr(principal, "roles", frozenset()))
    return HumanTrust(
        authenticated=bool(getattr(principal, "subject", "")),
        phishing_resistant=phishing_resistant,
        active=active,
        role=",".join(roles),
        requester=requester,
        approvers=approvers,
        approval_valid=approval_valid,
        envelope_bound=envelope_bound,
    )


def workload_trust_from(
    credential: "Credential",
    *,
    spiffe_id: str,
    namespace: str,
    service_account: str,
    image_digest: str,
    runtime_profile: str,
    revoked: bool = False,
    now: float | None = None,
) -> WorkloadTrust:
    """Derive the workload root; ``cert_valid`` comes from the credential's real validity."""
    return WorkloadTrust(
        spiffe_id=spiffe_id,
        namespace=namespace,
        service_account=service_account,
        image_digest=image_digest,
        runtime_profile=runtime_profile,
        cert_valid=bool(credential.valid(now)),
        not_revoked=not revoked,
    )


def evidence_trust_from(
    receipt: "EvidenceReceipt | None",
    *,
    trace_id: str,
    case_id: str,
    shadow_received: bool,
) -> EvidenceTrust:
    """Derive the evidence root from a real append receipt. No receipt ⇒ fail closed."""
    return EvidenceTrust(
        service_available=receipt is not None,
        append_ok=bool(receipt and getattr(receipt, "entry_hash", "")),
        attestation_generated=bool(receipt and getattr(receipt, "verifiable", False)),
        trace_id=trace_id,
        case_id=case_id,
        shadow_received=shadow_received,
    )


def machine_trust_from(report: Mapping[str, Any]) -> MachineTrust:
    """Map a verified machine-attestation result (Keylime/TPM) to the machine root.
    Missing keys default to their fail-closed value."""
    g = lambda k: bool(report.get(k, False))  # noqa: E731
    return MachineTrust(
        secure_boot=g("secure_boot"), tpm_attested=g("tpm_attested"),
        measured_boot=g("measured_boot"), ima_ok=g("ima_ok"),
        approved_firmware=g("approved_firmware"), not_quarantined=g("not_quarantined"),
    )


def software_trust_from(report: Mapping[str, Any]) -> SoftwareTrust:
    """Map a verified provenance/SBOM/signature result to the software root."""
    g = lambda k: bool(report.get(k, False))  # noqa: E731
    return SoftwareTrust(
        approved_repo=g("approved_repo"), commit=str(report.get("commit", "")),
        build_verified=g("build_verified"), sbom_present=g("sbom_present"),
        provenance_valid=g("provenance_valid"), signature_valid=g("signature_valid"),
        approved_builder=g("approved_builder"), deps_approved=g("deps_approved"),
        policy_connector_digest_ok=g("policy_connector_digest_ok"),
    )


def target_trust_from(report: Mapping[str, Any]) -> TargetTrust:
    """Map a verified ownership/DNS result to the target root."""
    return TargetTrust(
        ownership_verified=bool(report.get("ownership_verified", False)),
        environment=str(report.get("environment", "")),
        resolved_addresses=tuple(report.get("resolved_addresses", ()) or ()),
        dns_unchanged=bool(report.get("dns_unchanged", False)),
        not_third_party=bool(report.get("not_third_party", False)),
    )


def machine_trust_from_verification(verification: "MachineVerification") -> MachineTrust:
    """Map a machine-attestation result (``core.machine_attestation``) to the machine root.

    An invalid AK signature or a replayed nonce means *no* claim in the quote is trustworthy,
    so the whole root fails closed; otherwise each anchor is asserted unless its specific
    check failed.
    """
    reasons = set(getattr(verification, "reasons", ()))
    if "ak_signature_invalid" in reasons or "nonce_mismatch" in reasons:
        return MachineTrust()  # nothing in an unsigned/replayed quote can be trusted
    return MachineTrust(
        secure_boot="secure_boot_off" not in reasons,
        tpm_attested=True,  # AK signature valid + nonce fresh
        measured_boot="pcr_mismatch" not in reasons,
        ima_ok="ima_failed" not in reasons,
        approved_firmware=not ({"firmware_not_approved", "kernel_not_approved"} & reasons),
        not_quarantined="node_quarantined" not in reasons,
    )


def software_trust_from_admission(
    decision: "AdmissionDecision",
    provenance: "Provenance | None" = None,
    *,
    build_verified: bool = False,
    deps_approved: bool = False,
    policy_connector_digest_ok: bool = False,
) -> SoftwareTrust:
    """Map a supply-chain admission decision (``supplychain.verify_artifact``) to the software
    root. Admission proves digest-pinning + signed provenance + allowed signer + SBOM; the
    three orthogonal anchors (reproducible build, dependency policy, policy+connector digest)
    come from their own verifiers as explicit inputs (fail-closed defaults).
    """
    admitted = bool(getattr(decision, "allow", False))
    commit = getattr(provenance, "commit", "") if provenance is not None else ""
    return software_trust_from({
        "approved_repo": admitted,
        "commit": commit if admitted else "",
        "build_verified": admitted and build_verified,
        "sbom_present": admitted,
        "provenance_valid": admitted,
        "signature_valid": admitted,
        "approved_builder": admitted,
        "deps_approved": admitted and deps_approved,
        "policy_connector_digest_ok": admitted and policy_connector_digest_ok,
    })


def target_trust_from_ownership(
    evidence: "OwnershipEvidence | None",
    *,
    environment: str,
    resolved_addresses: Sequence[str] = (),
    authorised_addresses: Sequence[str] | None = None,
) -> TargetTrust:
    """Bridge the ownership verifier (``ownership.OwnershipVerifier.verify``) to the target
    root. A non-None evidence means ownership is currently proven (the verifier returns
    fresh-or-None); ``dns_unchanged`` holds only when the freshly-resolved addresses match
    the recorded authorised baseline — a post-authorisation DNS change is a fail.
    """
    verified = evidence is not None
    resolved = tuple(resolved_addresses)
    dns_unchanged = bool(authorised_addresses) and resolved == tuple(authorised_addresses)
    return target_trust_from({
        "ownership_verified": verified,
        "environment": environment,
        "resolved_addresses": resolved,
        "dns_unchanged": dns_unchanged,
        "not_third_party": verified,
    })


def build_trust_context(
    *,
    human: HumanTrust | None = None,
    workload: WorkloadTrust | None = None,
    machine: MachineTrust | None = None,
    software: SoftwareTrust | None = None,
    target: TargetTrust | None = None,
    evidence: EvidenceTrust | None = None,
) -> TrustContext:
    """Assemble a TrustContext from produced roots; any omitted root stays fail-closed."""
    return TrustContext(
        human=human or HumanTrust(),
        workload=workload or WorkloadTrust(),
        machine=machine or MachineTrust(),
        software=software or SoftwareTrust(),
        target=target or TargetTrust(),
        evidence=evidence or EvidenceTrust(),
    )


__all__ = [
    "human_trust_from", "workload_trust_from", "evidence_trust_from",
    "machine_trust_from", "software_trust_from", "target_trust_from",
    "machine_trust_from_verification", "software_trust_from_admission",
    "target_trust_from_ownership", "build_trust_context",
]
