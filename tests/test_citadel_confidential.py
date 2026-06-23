"""Wave 22 acceptance — Citadel Confidential Execution Fabric (System 22).

Acceptance criteria (CITADEL Wave 22):
  * failed attestation prevents secret release,
  * secret release is tied to the exact workload measurement,
  * sensitive worker evidence is independently committed.

Plus: confidential worker classes require attestation, and a confidential worker is verified to be
destroyed after its job (it must not outlive it).
"""

from __future__ import annotations

from citadel.confidential import (
    ConfidentialVerifier,
    EnarxKeep,
    GramineEnclave,
    KataConfidentialContainers,
    SecretBroker,
    SecretReleaseDenied,
    WorkerClass,
    attest_workload,
    profile_for,
    workload_measurement,
)
from citadel.root_of_trust import PlatformAttestation

NOW = 2_000_000.0
IMAGE = "sha256:" + "f" * 64
CONFIG = "cfg-1"


def _platform(ok: bool) -> PlatformAttestation:
    reasons = () if ok else ("pcr_mismatch",)
    return PlatformAttestation(
        node_id="node-a", ok=ok, reasons=reasons, attested_at=NOW, expires_at=NOW + 900,
    )


def _attest(ok_platform=True, worker_class=WorkerClass.CONFIDENTIAL_WORKER, image=IMAGE, signed=True):
    profile = profile_for(worker_class)
    return attest_workload(
        worker_id="cw-1", profile=profile, platform=_platform(ok_platform),
        image_digest=image, image_signed=signed, config_digest=CONFIG,
    )


# --- profiles ----------------------------------------------------------------------------------
def test_confidential_classes_require_attestation_sandbox_classes_do_not():
    assert profile_for(WorkerClass.CONFIDENTIAL_WORKER).requires_attestation is True
    assert profile_for(WorkerClass.FORENSIC_CONFIDENTIAL_WORKER).requires_attestation is True
    assert profile_for(WorkerClass.STANDARD_SANDBOX).requires_attestation is False
    # confidential profiles demand the strict, ephemeral, externally-committed-evidence posture
    p = profile_for(WorkerClass.RECOVERY_CONFIDENTIAL_WORKER)
    assert p.measured_workload and p.ephemeral_storage and p.evidence_outside_worker
    assert p.sandbox.require_gvisor is True


# --- acceptance 1: failed attestation prevents secret release ----------------------------------
def test_failed_platform_attestation_prevents_secret_release():
    attestation = _attest(ok_platform=False)
    assert attestation.ok is False
    broker = SecretBroker()
    broker.seal("db-key", bound_measurement=attestation.measurement, material="s3cr3t")
    result = broker.evaluate("db-key", attestation)
    assert result.allowed is False
    assert "platform_attestation_failed" in result.reasons
    try:
        broker.release("db-key", attestation)
        raise AssertionError("must not release on failed attestation")
    except SecretReleaseDenied as exc:
        assert exc.secret_id == "db-key"


def test_unsigned_image_prevents_secret_release():
    attestation = _attest(signed=False)
    assert "image_not_signed" in attestation.reasons and attestation.ok is False


# --- acceptance 2: secret release tied to the exact workload measurement ------------------------
def test_secret_release_bound_to_exact_measurement():
    good = _attest()
    broker = SecretBroker()
    broker.seal("api-key", bound_measurement=good.measurement, material="released-material")
    # correct workload measurement → released
    assert broker.release("api-key", good) == "released-material"

    # a different workload (different image) measures differently → mismatch → denied
    other = _attest(image="sha256:" + "a" * 64)
    assert other.measurement != good.measurement
    res = broker.evaluate("api-key", other)
    assert res.allowed is False and "measurement_mismatch" in res.reasons


def test_workload_measurement_is_deterministic_and_class_bound():
    m1 = workload_measurement(IMAGE, WorkerClass.CONFIDENTIAL_WORKER, CONFIG)
    m2 = workload_measurement(IMAGE, WorkerClass.CONFIDENTIAL_WORKER, CONFIG)
    m3 = workload_measurement(IMAGE, WorkerClass.FORENSIC_CONFIDENTIAL_WORKER, CONFIG)
    assert m1 == m2 and m1 != m3 and len(m1) == 64


# --- acceptance 3: sensitive worker evidence is independently committed -------------------------
def test_worker_evidence_is_committed_to_an_independent_sink():
    committed: list = []
    broker = SecretBroker()
    good = _attest()
    broker.seal("k", bound_measurement=good.measurement, material="m")
    verifier = ConfidentialVerifier(broker=broker, evidence_sink=committed.append)

    result = verifier.release_secret("k", good, at=NOW)
    assert result.allowed is True
    # Evidence committed by the verifier (NOT the worker) — outside the worker's sole control.
    assert len(committed) == 1
    ev = committed[0]
    assert ev.worker_id == good.worker_id
    assert ev.measurement == good.measurement
    assert ev.attestation_ok is True and ev.secret_released is True
    assert len(ev.evidence_digest) == 64


def test_denied_release_is_also_independently_recorded():
    committed: list = []
    broker = SecretBroker()
    bad = _attest(ok_platform=False)
    broker.seal("k", bound_measurement=bad.measurement, material="m")
    verifier = ConfidentialVerifier(broker=broker, evidence_sink=committed.append)
    result = verifier.release_secret("k", bad, at=NOW)
    assert result.allowed is False
    assert len(committed) == 1 and committed[0].secret_released is False


# --- worker destruction (ephemeral; must not outlive the job) ----------------------------------
def test_confidential_worker_destruction_is_verified():
    runtime = KataConfidentialContainers()
    handle = runtime.launch(IMAGE, WorkerClass.CONFIDENTIAL_WORKER, at=NOW)
    assert runtime.is_live(handle.worker_id) is True

    receipt = runtime.destroy(handle.worker_id, at=NOW + 10)
    assert ConfidentialVerifier.verify_destroyed(runtime, receipt) is True
    assert runtime.is_live(handle.worker_id) is False


def test_worker_still_live_fails_destruction_verification():
    runtime = KataConfidentialContainers()
    handle = runtime.launch(IMAGE, WorkerClass.CONFIDENTIAL_WORKER, at=NOW)
    # Forge a "complete" receipt while the worker is still live — verification must catch it.
    from citadel.confidential import DestructionReceipt

    fake = DestructionReceipt(worker_id=handle.worker_id, destroyed_at=NOW,
                              ephemeral_storage_wiped=True, identity_revoked=True)
    assert ConfidentialVerifier.verify_destroyed(runtime, fake) is False


def test_specialist_runtimes_share_the_contract():
    for runtime in (KataConfidentialContainers(), GramineEnclave(), EnarxKeep()):
        h = runtime.launch(IMAGE, WorkerClass.CONFIDENTIAL_WORKER, at=NOW)
        r = runtime.destroy(h.worker_id, at=NOW + 1)
        assert r.complete and not runtime.is_live(h.worker_id)
