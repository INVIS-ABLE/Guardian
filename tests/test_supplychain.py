"""Phase 4 — supply-chain admission, provenance, SBOM/VEX prioritisation."""

from __future__ import annotations

from attestation.signing import HmacSigner
from supplychain import (
    AdmissionPolicy,
    ArtifactBundle,
    Provenance,
    RiskContext,
    VexStatement,
    VexStatus,
    Vulnerability,
    is_exploitable,
    prioritise,
    sign_provenance,
    verify_artifact,
    verify_provenance,
)

DIGEST = "sha256:" + "a" * 64
IMAGE = f"registry.invisable/app@{DIGEST}"
SIGNER = HmacSigner(b"builder-key")
IDENTITY = "https://github.com/invisable/app/.github/workflows/release.yml@refs/heads/main"


def _bundle(**over) -> ArtifactBundle:
    prov = Provenance(
        subject_digest=DIGEST,
        source_repo="github.com/invisable/app",
        commit="abc123",
        builder_id="github-actions",
        build_workflow="release.yml",
        materials=["sha256:deadbeef"],
    )
    base = dict(
        image_ref=IMAGE,
        signed_provenance=sign_provenance(prov, IDENTITY, SIGNER),
        sbom={"components": [{"name": "lib", "version": "1.0"}]},
    )
    base.update(over)
    return ArtifactBundle(**base)


def _policy(**over) -> AdmissionPolicy:
    base = dict(allowed_identities={IDENTITY})
    base.update(over)
    return AdmissionPolicy(**base)


# ----------------------------------------------------------------------- admission
def test_signed_digest_pinned_artifact_admitted():
    d = verify_artifact(_bundle(), _policy(), SIGNER)
    assert d.allow is True, d.reasons


def test_tag_only_image_refused():
    d = verify_artifact(_bundle(image_ref="registry.invisable/app:latest"), _policy(), SIGNER)
    assert d.allow is False
    assert any("digest" in r for r in d.reasons)


def test_missing_provenance_fails_closed():
    d = verify_artifact(_bundle(signed_provenance=None), _policy(), SIGNER)
    assert d.allow is False
    assert any("fail closed" in r for r in d.reasons)


def test_forged_signature_refused():
    d = verify_artifact(_bundle(), _policy(), HmacSigner(b"attacker-key"))
    assert d.allow is False
    assert any("signature is invalid" in r for r in d.reasons)


def test_untrusted_identity_refused():
    d = verify_artifact(_bundle(), _policy(allowed_identities={"someone-else"}), SIGNER)
    assert d.allow is False
    assert any("identity" in r for r in d.reasons)


def test_provenance_subject_must_match_image():
    other = f"registry.invisable/app@sha256:{'b' * 64}"
    d = verify_artifact(_bundle(image_ref=other), _policy(), SIGNER)
    assert d.allow is False
    assert any("subject digest" in r for r in d.reasons)


def test_missing_sbom_refused():
    d = verify_artifact(_bundle(sbom=None), _policy(), SIGNER)
    assert d.allow is False
    assert any("SBOM" in r for r in d.reasons)


def test_expired_attestation_refused():
    d = verify_artifact(_bundle(expires_at=0.0), _policy(), SIGNER, now=10_000.0)
    assert d.allow is False
    assert any("expired" in r for r in d.reasons)


def test_provenance_roundtrip_verifies():
    b = _bundle()
    assert verify_provenance(b.signed_provenance, SIGNER) is True


# ----------------------------------------------------------------------------- VEX
def test_vex_not_affected_is_not_exploitable():
    vex = [VexStatement("CVE-1", VexStatus.NOT_AFFECTED, "code path not reachable")]
    assert is_exploitable("CVE-1", vex) is False
    assert is_exploitable("CVE-unknown", vex) is True  # no statement → assume exploitable


def test_prioritisation_combines_signals():
    vuln = Vulnerability("CVE-9", "lib", "high", cvss=8.1)
    # KEV + internet exposed + user safety → escalated, short SLA.
    hot = prioritise(vuln, RiskContext(internet_exposed=True, kev=True, epss=0.9, user_safety_impact=True))
    assert hot.tier in ("critical", "high") and hot.remediation_days <= 7

    # Not reachable / VEX not_affected → strongly de-prioritised.
    cold = prioritise(
        vuln,
        RiskContext(runtime_loaded=False),
        [VexStatement("CVE-9", VexStatus.NOT_AFFECTED)],
    )
    assert cold.exploitable is False
    assert cold.score < hot.score
