"""Guardian repository-governor watchdog (non-merging).

This is the executable half of the Merge Governor charter
(``docs/governance/merge_governor.md``). It performs *detection only* — it never merges,
never changes settings, and never deletes anything. It is safe to run in CI with
read-only permissions; on findings it is intended to upload an artifact, comment, label,
or open/update one deduplicated governance issue (the workflow decides), not to block.

Detectors (all operate on text/paths so they are unit-testable):

* mutable GitHub Action references (``uses:`` without a pinned ref),
* security jobs neutered to non-blocking (``continue-on-error: true`` / ``|| true``),
* a pull request whose base is not the canonical ``main``,
* required governance files missing.

Run ``python scripts/repository_governor.py`` for a JSON report (exit 0, report-only),
or ``--strict`` to exit non-zero when medium+ findings exist (useful locally / in pre-commit).

``--fail-on-checks <names>`` makes the governor *blocking* for a named subset of checks only
(e.g. ``pr_base_not_canonical``), independent of severity. This is how the
``Repository Governor`` workflow enforces rule 3.1 — a PR whose base is not ``main`` fails —
without coupling that enforcement to the current default-branch state or to lower-severity
hygiene findings. It still detects only; it never merges, changes settings, or deletes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CANONICAL_BRANCH = "main"

#: Files the Merge Governor charter requires to exist.
REQUIRED_GOVERNANCE_FILES: tuple[str, ...] = (
    "docs/governance/merge_governor.md",
    "docs/governance/branch_inventory.yaml",
    "docs/governance/reconciliation_baseline.md",
    "docs/governance/branch_reconciliation_plan.md",
    "docs/governance/worker_registry.yaml",
    "docs/governance/path_ownership.yaml",
    "docs/governance/merge_queue.yaml",
    "docs/governance/merge_ledger.yaml",
    "docs/governance/branch_retirement.yaml",
    "docs/governance/emergency_freeze.md",
    ".github/CODEOWNERS",
    ".github/pull_request_template.md",
)

_USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
# A 40-hex commit SHA after the @ is a hash-pin; a tag/branch is mutable.
_SHA_PIN_RE = re.compile(r"@[0-9a-f]{40}$")


@dataclass
class Finding:
    """A single governance finding. ``severity`` is advisory, never auto-blocking."""

    check: str
    severity: str  # info | low | medium | high
    location: str
    detail: str


@dataclass
class GovernorReport:
    """The full report. ``ok`` is True when no findings of medium+ severity exist."""

    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.severity in {"medium", "high"} for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "finding_count": len(self.findings),
            "findings": [asdict(f) for f in self.findings],
        }


def classify_action_ref(ref: str) -> str:
    """Classify a GitHub Action ``uses:`` reference.

    Returns ``"hash-pin"`` (immutable SHA), ``"local"`` (./path or reusable workflow in
    repo), ``"docker-pinned"`` (docker://...@sha256:), or ``"mutable"`` (tag/branch).
    """
    ref = ref.strip().strip('"').strip("'")
    if ref.startswith("./") or ref.startswith(".github/"):
        return "local"
    if ref.startswith("docker://") and "@sha256:" in ref:
        return "docker-pinned"
    if "@" not in ref:
        return "mutable"
    if _SHA_PIN_RE.search(ref):
        return "hash-pin"
    return "mutable"


def scan_workflow_action_pins(text: str, location: str) -> list[Finding]:
    """Find mutable Action references in a workflow file's text."""
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = _USES_RE.match(line)
        if not m:
            continue
        ref = m.group(1)
        if classify_action_ref(ref) == "mutable":
            findings.append(
                Finding(
                    check="mutable_action_ref",
                    severity="low",
                    location=f"{location}:{i}",
                    detail=f"Action '{ref}' is not pinned to an immutable commit SHA.",
                )
            )
    return findings


def scan_nonblocking_security(text: str, location: str) -> list[Finding]:
    """Find security steps neutered to non-blocking within a workflow file's text.

    Flags ``continue-on-error: true`` and ``|| true`` tails on run-step commands, which
    silently turn a mandatory check into a warning.
    """
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if re.match(r"continue-on-error:\s*true\b", stripped):
            findings.append(
                Finding(
                    check="nonblocking_security",
                    severity="medium",
                    location=f"{location}:{i}",
                    detail="continue-on-error: true can hide a failing required check.",
                )
            )
        if re.search(r"\|\|\s*true\s*$", line):
            findings.append(
                Finding(
                    check="nonblocking_security",
                    severity="medium",
                    location=f"{location}:{i}",
                    detail="'|| true' suppresses a non-zero exit; a gate may pass silently.",
                )
            )
    return findings


def check_pr_base(base_ref: str) -> list[Finding]:
    """A PR must target the canonical branch."""
    if base_ref == CANONICAL_BRANCH:
        return []
    return [
        Finding(
            check="pr_base_not_canonical",
            severity="high",
            location=f"base={base_ref}",
            detail=f"PR base '{base_ref}' is not canonical '{CANONICAL_BRANCH}'.",
        )
    ]


def check_governance_files(root: Path = REPO_ROOT) -> list[Finding]:
    """Every required governance file must exist."""
    findings: list[Finding] = []
    for rel in REQUIRED_GOVERNANCE_FILES:
        if not (root / rel).exists():
            findings.append(
                Finding(
                    check="missing_governance_file",
                    severity="medium",
                    location=rel,
                    detail="Required governance file is missing.",
                )
            )
    return findings


def scan_workflows(root: Path = REPO_ROOT) -> list[Finding]:
    """Run the workflow-text detectors over every workflow file."""
    findings: list[Finding] = []
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.exists():
        return findings
    for path in sorted(wf_dir.glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(root).as_posix()
        findings.extend(scan_workflow_action_pins(text, rel))
        findings.extend(scan_nonblocking_security(text, rel))
    return findings


def build_report(root: Path = REPO_ROOT, pr_base: str | None = None) -> GovernorReport:
    """Assemble the full governor report for the repository (and optional PR base)."""
    report = GovernorReport()
    report.findings.extend(check_governance_files(root))
    report.findings.extend(scan_workflows(root))
    if pr_base is not None:
        report.findings.extend(check_pr_base(pr_base))
    return report


def blocking_findings(report: GovernorReport, fail_on_checks: frozenset[str]) -> list[Finding]:
    """The report's findings whose ``check`` is in the blocking allow-list."""
    return [f for f in report.findings if f.check in fail_on_checks]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guardian repository-governor watchdog.")
    parser.add_argument("--pr-base", default=None, help="Base ref of a PR to validate.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when medium+ findings exist (default: report-only).",
    )
    parser.add_argument(
        "--fail-on-checks",
        default="",
        help=(
            "Comma-separated check names that must BLOCK (exit non-zero) when present, "
            "regardless of severity (e.g. 'pr_base_not_canonical'). Decoupled from --strict."
        ),
    )
    args = parser.parse_args(argv)
    report = build_report(pr_base=args.pr_base)
    print(json.dumps(report.to_dict(), indent=2))

    fail_on = frozenset(c.strip() for c in args.fail_on_checks.split(",") if c.strip())
    if fail_on:
        blocking = blocking_findings(report, fail_on)
        if blocking:
            print(
                "BLOCKING governance findings: "
                + ", ".join(sorted({f.check for f in blocking})),
                file=sys.stderr,
            )
            return 1
    if args.strict and not report.ok:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    raise SystemExit(main())
