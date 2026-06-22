"""Trust producers build a TrustContext from real evidence; the gate then accepts/rejects it."""

from __future__ import annotations

from core.evidence.store import EvidenceReceipt, EvidenceStore, HashChainBackend
from core.evidence.store import EvidenceEvent
from core.guardrails import Approval
from core.roots_of_trust import Root, RootsOfTrust
from core.trust_producers import (
    build_trust_context,
    evidence_trust_from,
    human_trust_from,
    machine_trust_from,
    software_trust_from,
    target_trust_from,
    workload_trust_from,
)
from identity.credentials import Credential
from identity.oidc import Principal

NOW = 1_000_000.0
ENVELOPE = {"commit": "abc123", "target": "github.com/invisable/app", "workflow_run": "run-1"}

_MACHINE_OK = {k: True for k in
               ("secure_boot", "tpm_attested", "measured_boot", "ima_ok",
                "approved_firmware", "not_quarantined")}
_SOFTWARE_OK = {**{k: True for k in
                   ("approved_repo", "build_verified", "sbom_present", "provenance_valid",
                    "signature_valid", "approved_builder", "deps_approved",
                    "policy_connector_digest_ok")}, "commit": "abc123"}
_TARGET_OK = {"ownership_verified": True, "environment": "staging",
              "resolved_addresses": ("203.0.113.5",), "dns_unchanged": True,
              "not_third_party": True}


def _principal() -> Principal:
    return Principal(subject="alice", email="alice@invisable", roles=frozenset({"security-analyst"}))


def _approval(*, expires_at: float, commit: str | None = "abc123") -> Approval:
    return Approval(action="static_code_scan", approver="ciso", ticket="OPS-1",
                    expires_at=expires_at, target="github.com/invisable/app",
                    commit=commit, workflow_run="run-1")


def _credential(*, expires_at: float) -> Credential:
    return Credential(id="cred-1", secret="s", scope="connector:semgrep@staging",
                      issued_at=NOW, expires_at=expires_at, workflow_run="run-1")


def _human(approvals):
    return human_trust_from(_principal(), approvals, requester="alice", envelope=ENVELOPE,
                            phishing_resistant=True, active=True, now=NOW)


def _workload(credential):
    return workload_trust_from(credential, spiffe_id="spiffe://guardian/exec",
                               namespace="guardian", service_account="exec",
                               image_digest="sha256:" + "b" * 64, runtime_profile="restricted",
                               now=NOW)


def _full_context(*, approval_exp=NOW + 600, cred_exp=NOW + 600,
                  receipt: EvidenceReceipt | None = EvidenceReceipt("e", "h", "hash_chain", True)):
    return build_trust_context(
        human=_human([_approval(expires_at=approval_exp)]),
        workload=_workload(_credential(expires_at=cred_exp)),
        machine=machine_trust_from(_MACHINE_OK),
        software=software_trust_from(_SOFTWARE_OK),
        target=target_trust_from(_TARGET_OK),
        evidence=evidence_trust_from(receipt, trace_id="t-1", case_id="case-1", shadow_received=True),
    )


def test_full_evidence_produces_passing_context():
    report = RootsOfTrust().verify(_full_context(), environment="staging")
    assert report.allow, report.reasons()


def test_expired_credential_fails_workload_root():
    report = RootsOfTrust().verify(_full_context(cred_exp=NOW - 1), environment="staging")
    assert not report.allow
    assert report.failed_roots() == [Root.WORKLOAD]


def test_expired_approval_fails_human_root():
    report = RootsOfTrust().verify(_full_context(approval_exp=NOW - 1), environment="staging")
    assert not report.allow
    assert Root.HUMAN in report.failed_roots()


def test_unbound_approval_fails_envelope_binding():
    ctx = build_trust_context(human=_human([_approval(expires_at=NOW + 600, commit=None)]))
    report = RootsOfTrust().verify(ctx, environment="staging", required=frozenset({Root.HUMAN}))
    assert not report.allow
    assert any("envelope" in r for r in report.reasons())


def test_missing_receipt_fails_evidence_root():
    report = RootsOfTrust().verify(_full_context(receipt=None), environment="staging")
    assert not report.allow
    assert Root.EVIDENCE in report.failed_roots()


def test_partial_machine_report_fails_machine_root():
    ctx = build_trust_context(machine=machine_trust_from({"secure_boot": True}))
    report = RootsOfTrust().verify(ctx, environment="staging", required=frozenset({Root.MACHINE}))
    assert not report.allow


def test_evidence_root_from_a_real_store_receipt(tmp_path):
    # Integration: a receipt from the actual evidence ledger satisfies the evidence root.
    store = EvidenceStore(backend=HashChainBackend(log_dir=tmp_path))
    receipt = store.record(EvidenceEvent(actor="guardian", command_id="semgrep:scan", result="completed"))
    ev = evidence_trust_from(receipt, trace_id="t", case_id="c", shadow_received=True)
    report = RootsOfTrust().verify(build_trust_context(evidence=ev), environment="staging",
                                   required=frozenset({Root.EVIDENCE}))
    assert report.allow


def test_omitted_roots_stay_fail_closed():
    # build_trust_context with only the human root → the other five fail.
    ctx = build_trust_context(human=_human([_approval(expires_at=NOW + 600)]))
    report = RootsOfTrust().verify(ctx, environment="staging")
    assert not report.allow
    assert Root.HUMAN not in report.failed_roots()
    assert {Root.WORKLOAD, Root.MACHINE, Root.SOFTWARE, Root.TARGET, Root.EVIDENCE} <= set(report.failed_roots())
