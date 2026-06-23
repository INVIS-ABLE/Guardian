"""Tests for the non-merging repository-governor watchdog.

Detectors are validated on synthetic input (so they cannot silently rot), and the
governance-file check is validated against the real repository tree.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "repository_governor", REPO_ROOT / "scripts" / "repository_governor.py"
)
assert _SPEC and _SPEC.loader
governor = importlib.util.module_from_spec(_SPEC)
# Register before exec so dataclass type resolution can find the module.
sys.modules["repository_governor"] = governor
_SPEC.loader.exec_module(governor)


def test_classify_action_ref() -> None:
    sha = "a" * 40
    assert governor.classify_action_ref(f"actions/checkout@{sha}") == "hash-pin"
    assert governor.classify_action_ref("actions/checkout@v4") == "mutable"
    assert governor.classify_action_ref("actions/checkout") == "mutable"
    assert governor.classify_action_ref("./.github/actions/local") == "local"
    assert governor.classify_action_ref("docker://alpine@sha256:" + "b" * 64) == "docker-pinned"


def test_scan_workflow_action_pins_flags_tag_not_sha() -> None:
    sha = "c" * 40
    text = "\n".join(
        [
            "jobs:",
            "  build:",
            "    steps:",
            "      - uses: actions/checkout@v4",
            f"      - uses: actions/setup-python@{sha}",
        ]
    )
    findings = governor.scan_workflow_action_pins(text, "wf.yml")
    refs = [f.detail for f in findings]
    assert len(findings) == 1, refs
    assert "actions/checkout@v4" in findings[0].detail
    assert findings[0].check == "mutable_action_ref"


def test_scan_nonblocking_security_flags_continue_on_error_and_or_true() -> None:
    text = "\n".join(
        [
            "    steps:",
            "      - name: bandit",
            "        continue-on-error: true",
            "      - run: semgrep ci || true",
            "      - run: pytest -q",
        ]
    )
    findings = governor.scan_nonblocking_security(text, "wf.yml")
    checks = [f.check for f in findings]
    assert checks.count("nonblocking_security") == 2
    assert all(f.severity == "medium" for f in findings)


def test_scan_nonblocking_security_clean_passes() -> None:
    text = "      - run: pytest -q\n      - run: ruff check ."
    assert governor.scan_nonblocking_security(text, "wf.yml") == []


def test_check_pr_base() -> None:
    assert governor.check_pr_base("main") == []
    bad = governor.check_pr_base("claude/laughing-ptolemy-zfeiiu")
    assert len(bad) == 1
    assert bad[0].severity == "high"
    assert bad[0].check == "pr_base_not_canonical"


def test_required_governance_files_present_in_repo() -> None:
    # The baseline PR adds all of these; the check must pass on the real tree.
    findings = governor.check_governance_files(REPO_ROOT)
    missing = [f.location for f in findings]
    assert not missing, f"missing governance files: {missing}"


def test_build_report_is_json_serialisable() -> None:
    report = governor.build_report(REPO_ROOT, pr_base="main")
    payload = report.to_dict()
    assert set(payload) == {"ok", "finding_count", "findings"}
    # round-trips through JSON (the workflow uploads this as an artifact)
    assert json.loads(json.dumps(payload))["finding_count"] == len(report.findings)


def test_report_ok_ignores_low_severity_only() -> None:
    r = governor.GovernorReport(
        findings=[governor.Finding("mutable_action_ref", "low", "wf.yml:1", "tag")]
    )
    assert r.ok is True
    r.findings.append(governor.Finding("nonblocking_security", "medium", "wf.yml:2", "x"))
    assert r.ok is False


def test_blocking_findings_filters_by_check_name() -> None:
    report = governor.GovernorReport(
        findings=[
            governor.Finding("pr_base_not_canonical", "high", "base=x", "wrong base"),
            governor.Finding("mutable_action_ref", "low", "wf.yml:1", "tag"),
        ]
    )
    blocking = governor.blocking_findings(report, frozenset({"pr_base_not_canonical"}))
    assert [f.check for f in blocking] == ["pr_base_not_canonical"]


def test_fail_on_checks_blocks_wrong_base_pr() -> None:
    # base != main with the check named -> non-zero exit (the workflow's blocking gate).
    rc = governor.main(
        ["--pr-base", "claude/laughing-ptolemy-zfeiiu", "--fail-on-checks", "pr_base_not_canonical"]
    )
    assert rc == 1


def test_fail_on_checks_passes_canonical_base() -> None:
    rc = governor.main(["--pr-base", "main", "--fail-on-checks", "pr_base_not_canonical"])
    assert rc == 0


def test_wrong_base_is_report_only_without_fail_on_checks() -> None:
    # Without the blocking flag the governor stays report-only (exit 0) even on a wrong base,
    # preserving the existing non-blocking default.
    rc = governor.main(["--pr-base", "claude/laughing-ptolemy-zfeiiu"])
    assert rc == 0


def test_all_repo_workflows_are_sha_pinned() -> None:
    # Drift guard: every Action `uses:` in the real workflows must be pinned to an immutable
    # commit SHA (zizmor's unpinned-uses policy is `hash-pin`). A reintroduced tag/branch ref
    # fails here, in the hermetic governor self-tests, before it can reach a release.
    findings = governor.scan_workflows(REPO_ROOT)
    mutable = [f.location for f in findings if f.check == "mutable_action_ref"]
    assert not mutable, f"unpinned Action refs reintroduced: {mutable}"


def test_governor_never_exposes_merge_capability() -> None:
    # Defence-in-depth: the watchdog module must not import or expose merge actions.
    names = dir(governor)
    for forbidden in ("merge", "delete_branch", "push", "set_default_branch"):
        assert not any(forbidden in n.lower() for n in names), f"{forbidden} surfaced"
