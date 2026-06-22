"""Machine attestation: a TPM-quote-style verifier feeds the machine root, fail closed."""

from __future__ import annotations

from core import signing
from core.machine_attestation import AttestationReport, MachineAttestationVerifier
from core.roots_of_trust import Root, RootsOfTrust
from core.trust_producers import build_trust_context, machine_trust_from_verification

NODE = "node-1"
NONCE = "challenge-abc"
GOLDEN = {"0": "sha256:pcr0", "7": "sha256:pcr7"}
FW = "edk2-2026.02"
KERNEL = "6.8.0-guardian"
_AK = signing.generate_keypair()


def _report(**over) -> AttestationReport:
    base = dict(node_id=NODE, nonce=NONCE, pcrs=dict(GOLDEN), firmware=FW, kernel=KERNEL,
                secure_boot=True, ima_ok=True, quarantined=False)
    base.update(over)
    return AttestationReport(**base)


def _verifier(**over) -> MachineAttestationVerifier:
    base = dict(ak_public_keys={NODE: _AK.public}, golden_pcrs={NODE: dict(GOLDEN)},
                approved_firmware={FW}, approved_kernels={KERNEL})
    base.update(over)
    return MachineAttestationVerifier(**base)


def _sign(report: AttestationReport, key: str = _AK.private) -> str:
    return signing.sign(key, report.canonical())


def test_valid_quote_passes_and_feeds_machine_root():
    report = _report()
    res = _verifier().verify(report, _sign(report), expected_nonce=NONCE)
    assert res.ok, res.reasons
    ctx = build_trust_context(machine=machine_trust_from_verification(res))
    assert RootsOfTrust().verify(ctx, environment="staging",
                                 required=frozenset({Root.MACHINE})).allow


def test_forged_signature_rejected():
    attacker = signing.generate_keypair()
    report = _report()
    res = _verifier().verify(report, _sign(report, attacker.private), expected_nonce=NONCE)
    assert not res.ok and "ak_signature_invalid" in res.reasons
    # nothing in an unsigned quote is trusted → machine root fails closed
    assert not machine_trust_from_verification(res).tpm_attested


def test_replayed_nonce_rejected():
    report = _report(nonce="stale-nonce")
    res = _verifier().verify(report, _sign(report), expected_nonce=NONCE)
    assert not res.ok and "nonce_mismatch" in res.reasons


def test_pcr_mismatch_detected():
    report = _report(pcrs={"0": "sha256:TAMPERED", "7": "sha256:pcr7"})
    res = _verifier().verify(report, _sign(report), expected_nonce=NONCE)
    assert not res.ok and "pcr_mismatch" in res.reasons
    assert not machine_trust_from_verification(res).measured_boot


def test_unapproved_firmware_and_kernel():
    r1 = _report(firmware="evil-fw")
    assert "firmware_not_approved" in _verifier().verify(r1, _sign(r1), expected_nonce=NONCE).reasons
    r2 = _report(kernel="rootkit-kernel")
    assert "kernel_not_approved" in _verifier().verify(r2, _sign(r2), expected_nonce=NONCE).reasons


def test_quarantined_or_ima_failure_blocks():
    rq = _report(quarantined=True)
    assert "node_quarantined" in _verifier().verify(rq, _sign(rq), expected_nonce=NONCE).reasons
    ri = _report(ima_ok=False)
    assert "ima_failed" in _verifier().verify(ri, _sign(ri), expected_nonce=NONCE).reasons


def test_unknown_node_has_no_enrolled_key():
    report = _report(node_id="rogue-node")
    res = _verifier().verify(report, _sign(report), expected_nonce=NONCE)
    assert not res.ok and "ak_signature_invalid" in res.reasons


def test_bridge_fails_machine_root_on_any_divergence():
    report = _report(secure_boot=False)
    res = _verifier().verify(report, _sign(report), expected_nonce=NONCE)
    ctx = build_trust_context(machine=machine_trust_from_verification(res))
    assert not RootsOfTrust().verify(ctx, environment="staging",
                                     required=frozenset({Root.MACHINE})).allow
