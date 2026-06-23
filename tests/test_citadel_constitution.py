"""Wave 40 acceptance — Citadel Guardian Integrity Constitution (System 40)."""

from __future__ import annotations

import pytest

from citadel.constitution import (
    ComponentBinding,
    Constitution,
    assert_permitted,
    enforce,
    validate_bindings,
)


def test_prohibited_actions_are_always_denied():
    assert enforce("access_message_plaintext") is False
    assert enforce("bypass_approval") is False
    assert enforce("run_an_approved_scan") is True
    with pytest.raises(PermissionError):
        assert_permitted("model_grants_production_authority")


def test_bindings_must_reference_known_clauses_with_proving_tests():
    con = Constitution.default()
    ok = [ComponentBinding(component="citadel.root_of_trust",
                           implements=("C-AUTH-1",), proving_tests=("tests/test_citadel_root_of_trust.py",))]
    assert validate_bindings(con, ok) == []

    # implements an unknown clause -> error
    bad_clause = [ComponentBinding(component="x", implements=("C-NOPE",),
                                   proving_tests=("t.py",))]
    assert any("unknown clause" in e for e in validate_bindings(con, bad_clause))

    # implements a real clause but cites no proving test -> error
    no_test = [ComponentBinding(component="y", implements=("C-PRIV-1",))]
    assert any("no proving test" in e for e in validate_bindings(con, no_test))


def test_default_constitution_has_core_clauses():
    con = Constitution.default()
    for cid in ("C-PRIV-1", "C-AUTH-1", "C-EVID-1", "C-REC-1", "C-KEY-1", "C-PROH-1"):
        assert con.has(cid)
