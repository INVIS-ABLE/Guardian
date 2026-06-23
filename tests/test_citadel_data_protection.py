"""Wave 31 acceptance — Citadel Data-Exfiltration Detection Fabric (System 31)."""

from __future__ import annotations

from citadel.data_protection import (
    Sensitivity,
    barrier_violation,
    classify,
    egress_decision,
    model_io_check,
)


def test_classifies_secrets_and_pii():
    assert classify("AKIAABCDEFGHIJKLMNOP").sensitivity is Sensitivity.SECRET
    assert classify("reach me at a@b.com").sensitivity is Sensitivity.PII
    assert classify("just an ordinary log line").sensitivity is Sensitivity.INTERNAL


def test_protected_data_to_untrusted_destination_is_blocked():
    d = egress_decision("AKIAABCDEFGHIJKLMNOP", destination_trusted=False)
    assert d.allow is False and d.reasons
    # same secret to a trusted internal destination is allowed
    assert egress_decision("AKIAABCDEFGHIJKLMNOP", destination_trusted=True).allow is True


def test_private_plaintext_barrier_is_structural():
    payload = {"message": "hello", "classification": "MESSAGE_PLAINTEXT"}
    violations = barrier_violation(payload)
    assert "forbidden_field:message" in violations
    assert any("denylisted_classification" in v for v in violations)
    assert barrier_violation({"summary": "ok", "classification": "INTERNAL"}) == []


def test_model_io_check_is_traceable():
    out = model_io_check("card 4111 1111 1111 1111", direction="model_output",
                         destination_trusted=False)
    assert out.direction == "model_output" and out.allow is False
    assert out.sensitivity == "pii" and out.reasons
