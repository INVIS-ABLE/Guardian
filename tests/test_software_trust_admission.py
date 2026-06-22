"""Bridge: the real supply-chain admission decision feeds the software root."""

from __future__ import annotations

from attestation.signing import HmacSigner
from core.roots_of_trust import Root, RootsOfTrust
from core.trust_producers import build_trust_context, software_trust_from_admission
from supplychain import AdmissionPolicy, ArtifactBundle, Provenance, sign_provenance, verify_artifact

DIGEST = "sha256:" + "a" * 64
IMAGE = f"registry.invisable/app@{DIGEST}"
SIGNER = HmacSigner(b"builder-key")
IDENTITY = "https://github.com/invisable/app/.github/workflows/release.yml@refs/heads/main"

PROV = Provenance(subject_digest=DIGEST, source_repo="github.com/invisable/app", commit="abc123",
                  builder_id="github-actions", build_workflow="release.yml",
                  materials=["sha256:deadbeef"])


def _bundle(**over) -> ArtifactBundle:
    base = dict(image_ref=IMAGE, signed_provenance=sign_provenance(PROV, IDENTITY, SIGNER),
                sbom={"components": [{"name": "lib", "version": "1.0"}]})
    base.update(over)
    return ArtifactBundle(**base)


def _software_root_ok(ctx) -> bool:
    return RootsOfTrust().verify(ctx, environment="staging",
                                 required=frozenset({Root.SOFTWARE})).allow


def test_admitted_artifact_with_extra_anchors_passes_software_root():
    decision = verify_artifact(_bundle(), AdmissionPolicy(allowed_identities={IDENTITY}), SIGNER)
    assert decision.allow, decision.reasons
    tgt = software_trust_from_admission(decision, PROV, build_verified=True,
                                        deps_approved=True, policy_connector_digest_ok=True)
    assert tgt.commit == "abc123"
    assert _software_root_ok(build_trust_context(software=tgt))


def test_denied_admission_fails_software_root():
    # An unsigned (no provenance) artifact is refused admission -> software root fails.
    decision = verify_artifact(_bundle(signed_provenance=None),
                               AdmissionPolicy(allowed_identities={IDENTITY}), SIGNER)
    assert not decision.allow
    sw = software_trust_from_admission(decision, PROV, build_verified=True,
                                       deps_approved=True, policy_connector_digest_ok=True)
    assert not _software_root_ok(build_trust_context(software=sw))


def test_admission_alone_is_insufficient_without_orthogonal_anchors():
    # Admission proves provenance/SBOM/signature, but reproducible-build / dependency-policy /
    # policy+connector-digest are separate anchors — without them the software root fails closed.
    decision = verify_artifact(_bundle(), AdmissionPolicy(allowed_identities={IDENTITY}), SIGNER)
    sw = software_trust_from_admission(decision, PROV)  # extra anchors default False
    report = RootsOfTrust().verify(build_trust_context(software=sw), environment="staging",
                                   required=frozenset({Root.SOFTWARE}))
    assert not report.allow
    assert any("build_verified" in r or "deps_approved" in r or "policy_connector" in r
               for r in report.reasons())
