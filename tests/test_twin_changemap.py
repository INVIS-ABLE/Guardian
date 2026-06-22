"""Tests for changed-file → asset resolution and the ambient twin-gate (core/twin)."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from core.cli import main
from core.twin import Severity, assess_change, load_twin, resolve_changed_assets

REPO_TWIN = Path(__file__).resolve().parent.parent / "twin" / "guardian-repo.yaml"


@pytest.fixture()
def repo_twin():
    return load_twin(REPO_TWIN)


# --- path resolution -----------------------------------------------------------
def test_glob_dir_wildcard_matches(repo_twin):
    assets = resolve_changed_assets(repo_twin, ["security/crypto/e2eeMessaging.ts"])
    assert assets == ["ctrl:crypto"]


def test_exact_path_matches(repo_twin):
    assert resolve_changed_assets(repo_twin, ["core/policy_gate.py"]) == ["ctrl:policy-authority"]


def test_unmapped_paths_resolve_to_nothing(repo_twin):
    assert resolve_changed_assets(repo_twin, ["docs/brain.md", "README.md"]) == []


def test_multiple_files_resolve_to_multiple_assets(repo_twin):
    assets = resolve_changed_assets(repo_twin, ["core/signing.py", "core/audit.py"])
    assert assets == ["data:audit-evidence", "key:signing"]


# --- assessment uses the repo twin sensibly -----------------------------------
def test_crypto_change_is_critical(repo_twin):
    result = assess_change(repo_twin, ["ctrl:crypto"])
    assert result.severity == Severity.CRITICAL  # reaches health user content


def test_signing_change_flags_directly(repo_twin):
    # The signing-key module has no downstream sink, but touching it is HIGH on its own.
    result = assess_change(repo_twin, ["key:signing"])
    assert result.severity == Severity.HIGH
    assert any("directly modifies" in h.reason for h in result.assessments[0].hits)


# --- the CLI gate --------------------------------------------------------------
def _run(args, stdin):
    return CliRunner().invoke(main, args, input=stdin)


def test_gate_fails_on_critical_reach():
    r = _run(["twin-gate", str(REPO_TWIN), "--fail-on", "critical"],
             "security/crypto/x.ts\n")
    assert r.exit_code == 1
    assert "FAIL" in r.output and "ctrl:crypto" in r.output


def test_gate_passes_for_unmapped_changes():
    r = _run(["twin-gate", str(REPO_TWIN), "--fail-on", "critical"], "docs/x.md\nREADME.md\n")
    assert r.exit_code == 0
    assert "no twin assets" in r.output


def test_gate_high_passes_at_critical_threshold():
    # A policy change reaches confidential evidence (HIGH) — visible but below the critical gate.
    r = _run(["twin-gate", str(REPO_TWIN), "--fail-on", "critical"], "core/policy_gate.py\n")
    assert r.exit_code == 0
    assert "PASS" in r.output
