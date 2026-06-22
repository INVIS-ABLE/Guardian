"""Evidence model + report generator.

Every simulator and connector emits a ``Finding`` / ``SimulatorResult`` that this
module renders into the standard Guardian evidence report (Markdown + JSON), using
reports/templates/report_template.md.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import REPO_ROOT

SEVERITIES = ("info", "low", "medium", "high", "critical")
TEMPLATE_PATH = REPO_ROOT / "reports" / "templates" / "report_template.md"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "reports" / "generated"

# Patterns scrubbed from evidence before it is written to disk.
_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[=:]\s*\S+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub tokens
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]


def scrub(text: str) -> str:
    """Remove obvious secrets/PII tokens from evidence text."""
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


@dataclass
class SimulatorResult:
    """The mandatory output contract every simulator must produce."""

    scenario_name: str
    scope: str
    test_accounts_used: list[str] = field(default_factory=list)
    signals_observed: list[str] = field(default_factory=list)
    detection_result: str = ""          # e.g. "detected" / "missed" / "partial"
    containment_result: str = ""        # e.g. "contained" / "not contained"
    user_safety_impact: str = ""
    evidence: list[str] = field(default_factory=list)
    severity: str = "info"
    recommended_fix: str = ""
    retest_instructions: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {self.severity!r}")
        self.evidence = [scrub(e) for e in self.evidence]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _render_markdown(result: SimulatorResult) -> str:
    """Render via the template if present, else a built-in fallback."""
    generated = datetime.now(timezone.utc).isoformat()
    fields = {
        "scenario_name": result.scenario_name,
        "scope": result.scope,
        "generated": generated,
        "severity": result.severity.upper(),
        "test_accounts": "\n".join(f"- {a}" for a in result.test_accounts_used) or "- none",
        "signals": "\n".join(f"- {s}" for s in result.signals_observed) or "- none",
        "detection_result": result.detection_result or "n/a",
        "containment_result": result.containment_result or "n/a",
        "user_safety_impact": result.user_safety_impact or "n/a",
        "evidence": "\n".join(f"- {e}" for e in result.evidence) or "- none",
        "recommended_fix": result.recommended_fix or "n/a",
        "retest_instructions": result.retest_instructions or "n/a",
    }
    if TEMPLATE_PATH.exists():
        template = TEMPLATE_PATH.read_text(encoding="utf-8")
        for key, val in fields.items():
            template = template.replace("{{" + key + "}}", str(val))
        return template
    # Fallback inline template
    return (
        f"# Guardian Evidence Report — {fields['scenario_name']}\n\n"
        f"- **Scope:** {fields['scope']}\n"
        f"- **Severity:** {fields['severity']}\n"
        f"- **Generated:** {fields['generated']}\n\n"
        f"## Test accounts used\n{fields['test_accounts']}\n\n"
        f"## Signals observed\n{fields['signals']}\n\n"
        f"## Detection result\n{fields['detection_result']}\n\n"
        f"## Containment result\n{fields['containment_result']}\n\n"
        f"## User safety impact\n{fields['user_safety_impact']}\n\n"
        f"## Evidence\n{fields['evidence']}\n\n"
        f"## Recommended fix\n{fields['recommended_fix']}\n\n"
        f"## Retest instructions\n{fields['retest_instructions']}\n"
    )


def write_report(
    result: SimulatorResult,
    output_dir: Path | str = DEFAULT_OUTPUT_DIR,
    formats: tuple[str, ...] = ("markdown", "json"),
) -> dict[str, Path]:
    """Write the evidence report in the requested formats. Returns paths written."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = re.sub(r"[^a-z0-9]+", "-", result.scenario_name.lower()).strip("-")
    base = out / f"{stamp}_{slug}"
    written: dict[str, Path] = {}
    if "markdown" in formats:
        md_path = base.with_suffix(".md")
        md_path.write_text(_render_markdown(result), encoding="utf-8")
        written["markdown"] = md_path
    if "json" in formats:
        json_path = base.with_suffix(".json")
        json_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        written["json"] = json_path
    return written
