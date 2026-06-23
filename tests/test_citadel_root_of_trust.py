"""Wave 21 acceptance — Citadel Root-of-Trust Fabric (System 21).

Acceptance criteria (docs: CITADEL Wave 21):
  * an unknown platform cannot receive a production capability,
  * attestation evidence attaches to execution,
  * drift creates a durable event and a case.

Plus the Citadel rule: the independent verifier (citadel.root_of_trust.verifier) agrees with the
authoritative owner (core.machine_attestation) — divergence is caught and fails closed.
"""

from __future__ import annotations

from core import signing
from core.machine_attestation import MachineAttestationVerifier
from core.roots_of_trust import Root, RootsOfTrust, TrustContext
from citadel.root_of_trust import (
    AttestationPolicy,
    BootMeasurement,
    PlatformInventory,
    RootOfTrustVerifier,
    RuntimeMeasurement,
    SoftwareTpm,
    StaticKeylimeClient,
    attest_via_keylime,
    build_report,
    enrol_platform,
)

GOLDEN_PCRS = {"0": "a" * 64, "7": "b" * 64}
FIRMWARE = "edk2-2024.05"
KERNEL = "linux-6.6.30-hardened"
NOW = 1_000_000.0


def _good_boot(node_id: str) -> BootMeasurement:
    return BootMeasurement(node_id, dict(GOLDEN_PCRS), FIRMWARE, KERNEL, secure_boot=True)


def _good_runtime(node_id: str) -> RuntimeMeasurement:
    return RuntimeMeasurement(node_id, ima_ok=True, ima_log_hash="c" * 64)


def _enrolled_verifier(node_id="node-a"):
    kp = signing.generate_keypair()
    inv = PlatformInventory()
    enrol_platform(
        inv, node_id=node_id, ak_public_key=kp.public, golden_pcrs=dict(GOLDEN_PCRS),
        approved_firmware={FIRMWARE}, approved_kernels={KERNEL}, enrolled_at=NOW,
        attestation_max_age_seconds=900,
    )
    events: list = []
    cases: list = []
    verifier = RootOfTrustVerifier(
        inventory=inv, policy=AttestationPolicy(),
        event_sink=events.append, case_sink=cases.append,
    )
    tpm = SoftwareTpm(node_id, kp.private, _good_boot(node_id), _good_runtime(node_id))
    return verifier, tpm, events, cases, node_id


# --- acceptance 1: unknown platform gets no capability -----------------------------------------
def test_unknown_platform_is_denied_and_yields_no_machine_trust():
    verifier = RootOfTrustVerifier(inventory=PlatformInventory())
    kp = signing.generate_keypair()
    report = build_report(_good_boot("ghost"), _good_runtime("ghost"), nonce="x")
    sig = signing.sign(kp.private, report.canonical())

    attestation = verifier.attest(report, sig, now=NOW)
    assert attestation.ok is False
    assert "unknown_platform" in attestation.reasons

    # Bridge to the existing six-roots capability gate: machine root must fail for production.
    mt = verifier.machine_trust(report, sig, now=NOW)
    report_roots = RootsOfTrust().verify(
        TrustContext(machine=mt), environment="production", required=frozenset({Root.MACHINE}),
    )
    assert report_roots.allow is False, "unknown platform must not pass the machine root"


def test_enrolled_clean_platform_passes_the_machine_root():
    verifier, tpm, _, _, node_id = _enrolled_verifier()
    nonce = verifier.issue_nonce(node_id)
    report, sig = tpm.quote(node_id, nonce)
    mt = verifier.machine_trust(report, sig, now=NOW)
    report_roots = RootsOfTrust().verify(
        TrustContext(machine=mt), environment="production", required=frozenset({Root.MACHINE}),
    )
    assert report_roots.allow is True, "a clean, attested, enrolled platform must pass"


# --- acceptance 2: attestation evidence attaches to execution ----------------------------------
def test_attestation_produces_attachable_evidence():
    verifier, tpm, _, _, node_id = _enrolled_verifier()
    nonce = verifier.issue_nonce(node_id)
    report, sig = tpm.quote(node_id, nonce)
    attestation = verifier.attest(report, sig, now=NOW)
    assert attestation.ok is True
    # A stable, content-addressable digest that can be recorded against the case/execution.
    assert len(attestation.evidence_digest) == 64
    assert attestation.attested_at == NOW
    assert attestation.expires_at == NOW + 900
    assert verifier.gate(attestation, now=NOW).allow is True


# --- acceptance 3: drift creates a durable event and a case ------------------------------------
def test_drift_emits_event_opens_case_and_quarantines():
    verifier, _, events, cases, node_id = _enrolled_verifier()
    # Build a drifted quote: a changed PCR (measured-boot drift), correctly signed + fresh nonce.
    identity = verifier.inventory.get(node_id)
    # Recreate a TPM whose boot PCRs drifted from the golden baseline.
    drifted_boot = BootMeasurement(node_id, {"0": "dead" + "0" * 60, "7": "b" * 64}, FIRMWARE, KERNEL, True)
    # Reuse the same AK by re-enrolling a known keypair.
    kp = signing.generate_keypair()
    verifier.inventory.add(  # rebind identity to a key we hold the private half of
        type(identity)(
            node_id=node_id, ak_public_key=kp.public, golden_pcrs=dict(GOLDEN_PCRS),
            approved_firmware=identity.approved_firmware, approved_kernels=identity.approved_kernels,
            enrolled_at=identity.enrolled_at, status=identity.status,
            attestation_max_age_seconds=identity.attestation_max_age_seconds,
        )
    )
    tpm = SoftwareTpm(node_id, kp.private, drifted_boot, _good_runtime(node_id))
    nonce = verifier.issue_nonce(node_id)
    report, sig = tpm.quote(node_id, nonce)

    attestation = verifier.attest(report, sig, now=NOW)
    assert attestation.ok is False
    assert "pcr_mismatch" in attestation.reasons
    # Durable event + case were raised...
    assert len(events) == 1 and events[0].event_type == "guardian.boot.drift"
    assert len(cases) == 1 and cases[0].node_id == node_id
    # ...and the platform is now quarantined, so it is denied even with a clean quote next round.
    assert verifier.inventory.get(node_id).active is False
    good = SoftwareTpm(node_id, kp.private, _good_boot(node_id), _good_runtime(node_id))
    n2 = verifier.issue_nonce(node_id)
    rep2, sig2 = good.quote(node_id, n2)
    follow = verifier.attest(rep2, sig2, now=NOW)
    assert follow.ok is False and "platform_quarantined" in follow.reasons


# --- replay + freshness ------------------------------------------------------------------------
def test_replayed_nonce_is_rejected():
    verifier, tpm, _, _, node_id = _enrolled_verifier()
    nonce = verifier.issue_nonce(node_id)
    report, sig = tpm.quote(node_id, nonce)
    assert verifier.attest(report, sig, now=NOW).ok is True
    # Re-presenting the same quote without a freshly issued nonce is a replay → denied.
    replay = verifier.attest(report, sig, now=NOW)
    assert replay.ok is False and "nonce_mismatch" in replay.reasons


def test_stale_attestation_is_not_valid_for_a_capability():
    verifier, tpm, _, _, node_id = _enrolled_verifier()
    nonce = verifier.issue_nonce(node_id)
    report, sig = tpm.quote(node_id, nonce)
    attestation = verifier.attest(report, sig, now=NOW)
    assert verifier.gate(attestation, now=NOW + 901).allow is False  # past the 900s max age


# --- end-to-end via the Keylime seam -----------------------------------------------------------
def test_keylime_end_to_end_clean_attestation():
    verifier, tpm, _, _, node_id = _enrolled_verifier()
    client = StaticKeylimeClient({node_id: tpm})
    attestation = attest_via_keylime(verifier, client, node_id, now=NOW)
    assert attestation.ok is True


# --- Citadel rule: independent verifier agrees with the authoritative owner --------------------
def test_independent_verifier_matches_authoritative_owner():
    verifier, tpm, _, _, node_id = _enrolled_verifier()
    identity = verifier.inventory.get(node_id)
    nonce = verifier.issue_nonce(node_id)
    report, sig = tpm.quote(node_id, nonce)

    owner = MachineAttestationVerifier(
        ak_public_keys={node_id: identity.ak_public_key},
        golden_pcrs={node_id: dict(GOLDEN_PCRS)},
        approved_firmware={FIRMWARE}, approved_kernels={KERNEL},
    )
    owner_result = owner.verify(report, sig, expected_nonce=nonce)
    citadel_attestation = verifier.attest(report, sig, now=NOW)
    # Both agree the clean quote is valid, and the independent path never flags divergence.
    assert owner_result.ok is True and citadel_attestation.ok is True
    assert "verifier_divergence" not in citadel_attestation.reasons


# --- PWA platform-integrity screen -------------------------------------------------------------
def test_platform_integrity_summary_reports_inventory_and_drift():
    from citadel.root_of_trust import platform_integrity_summary

    verifier, _, _, _, node_id = _enrolled_verifier()
    att = verifier.attest(*_enrolled_quote(verifier, node_id), now=NOW)
    summary = platform_integrity_summary(verifier.inventory, attestations=[att], now=NOW)
    assert summary["total_platforms"] == 1
    assert summary["enrolled"] == 1
    assert summary["quarantined"] == 0
    assert summary["platforms"][0]["node_id"] == node_id
    assert summary["platforms"][0]["golden_pcr_count"] == 2
    assert summary["attestations"][0]["node_id"] == node_id
    assert summary["attestations"][0]["expired"] is False


def test_dashboard_platform_integrity_endpoint_uses_live_inventory():
    import pytest

    pytest.importorskip("fastapi")  # dashboard needs FastAPI (a core dep; present in CI)
    from dashboard import app as dashboard_app

    verifier, _, _, _, node_id = _enrolled_verifier()
    dashboard_app.set_platform_inventory(verifier.inventory)
    try:
        summary = dashboard_app.platform_integrity()
        assert summary["total_platforms"] == 1
        assert summary["platforms"][0]["node_id"] == node_id
    finally:
        dashboard_app.set_platform_inventory(PlatformInventory())  # reset shared state


def _enrolled_quote(verifier, node_id):
    # helper: issue a nonce and produce a clean quote from a fresh AK bound into the inventory
    identity = verifier.inventory.get(node_id)
    kp = signing.generate_keypair()
    verifier.inventory.add(type(identity)(
        node_id=node_id, ak_public_key=kp.public, golden_pcrs=dict(GOLDEN_PCRS),
        approved_firmware=identity.approved_firmware, approved_kernels=identity.approved_kernels,
        enrolled_at=identity.enrolled_at, status=identity.status,
        attestation_max_age_seconds=identity.attestation_max_age_seconds,
    ))
    tpm = SoftwareTpm(node_id, kp.private, _good_boot(node_id), _good_runtime(node_id))
    nonce = verifier.issue_nonce(node_id)
    return tpm.quote(node_id, nonce)
