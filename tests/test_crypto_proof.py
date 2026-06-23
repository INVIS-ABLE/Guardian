"""Tests for the cryptographic protocol proof lab (Sovereign plane, Wave 3, system #15)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.crypto_proof import (
    CryptoProofError,
    CryptoProofLab,
    ProofResult,
    ProofStatus,
    PropertyKind,
    Protocol,
    SecurityProperty,
    build_from_spec,
    from_provers,
    load_proofs,
)

PROTOCOLS = Path(__file__).resolve().parent.parent / "crypto_proof" / "invisable-protocols.yaml"


def _prop(kind=PropertyKind.SECRECY, critical=True) -> SecurityProperty:
    return SecurityProperty(kind=kind, description="abstract property", critical=critical)


# --- privacy boundary: symbolic only -------------------------------------------
def test_property_refuses_real_content():
    with pytest.raises(ValueError):
        SecurityProperty(kind=PropertyKind.SECRECY, description="the message_body must stay secret")


def test_trace_refuses_key_material():
    with pytest.raises(ValueError):
        ProofResult(protocol_id="p", property=_prop(), status=ProofStatus.FALSIFIED,
                    attack_trace=("attacker reads the private_key",))


# --- break detection -----------------------------------------------------------
def test_falsified_critical_is_a_break():
    lab = CryptoProofLab([Protocol(id="p", name="P")])
    report = lab.report([
        ProofResult(protocol_id="p", property=_prop(critical=True), status=ProofStatus.FALSIFIED,
                    attack_trace=("step one", "step two")),
    ])
    assert report.has_break
    assert len(report.breaks) == 1


def test_falsified_noncritical_is_not_a_break():
    lab = CryptoProofLab([Protocol(id="p", name="P")])
    report = lab.report([
        ProofResult(protocol_id="p", property=_prop(critical=False), status=ProofStatus.FALSIFIED),
    ])
    assert not report.has_break


def test_unknown_is_separated_from_break():
    lab = CryptoProofLab([Protocol(id="p", name="P")])
    report = lab.report([ProofResult(protocol_id="p", property=_prop(), status=ProofStatus.UNKNOWN)])
    assert not report.has_break
    assert len(report.unknowns) == 1


def test_result_for_unknown_protocol_refused():
    lab = CryptoProofLab([Protocol(id="p", name="P")])
    with pytest.raises(CryptoProofError):
        lab.report([ProofResult(protocol_id="ghost", property=_prop(), status=ProofStatus.PROVED)])


# --- sample --------------------------------------------------------------------
def test_sample_finds_recovery_break():
    report = load_proofs(PROTOCOLS)
    assert report.proved() == 3
    assert report.has_break
    brk = report.breaks[0]
    assert brk.protocol_id == "proto:account-recovery"
    assert brk.property.kind is PropertyKind.RECOVERY_SOUNDNESS
    assert len(brk.attack_trace) == 3
    assert len(report.unknowns) == 1


def test_build_from_spec_roundtrip():
    report = build_from_spec({
        "protocols": [{"id": "p", "name": "P"}],
        "results": [{"protocol_id": "p", "status": "proved",
                     "property": {"kind": "authentication", "description": "abstract"}}],
    })
    assert report.proved() == 1


def test_from_provers_fails_closed():
    with pytest.raises(NotImplementedError):
        from_provers()


def test_load_proofs_missing_file():
    with pytest.raises(FileNotFoundError):
        load_proofs(Path("/no/such/p.yaml"))
