"""Output firewall — screen model output before it can influence anything (§8).

Model output is never trusted. Before a response is returned (and certainly before it
could reach a tool), the output firewall scans it for the signatures of a model that
has been steered by injected instructions or is trying to act beyond its remit:
attempts to invoke tools, change scope/policy, grant approvals, exfiltrate secrets, or
override its own instructions. Matches do not silently pass — they flag the response
``high_risk`` so the caller must route it through human/independent verification rather
than acting on it automatically.

This is a heuristic screen, not a guarantee; it complements (never replaces) the
deterministic policy gate, which is the thing that actually authorises any action.
"""

from __future__ import annotations

import re

# Patterns that suggest the output is trying to act, not just analyse. Deliberately
# broad — false positives only cost a verification step; misses can cost an action.
_HIGH_RISK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("instruction_override", re.compile(r"(?i)ignore (all |the )?(previous|above|prior) (instructions|rules)")),
    ("approval_claim", re.compile(r"(?i)\b(approved|auto[- ]?approve|grant(ing)? approval|self[- ]?approve)\b")),
    ("scope_change", re.compile(r"(?i)\b(expand|change|widen|broaden) (the )?scope\b")),
    ("policy_change", re.compile(r"(?i)\b(disable|bypass|skip|override) (the )?(policy|guardrail|gate|logging)\b")),
    ("tool_invocation", re.compile(r"(?i)\b(call|invoke|run|execute) (the )?(tool|connector|command|shell)\b")),
    ("secret_exfil", re.compile(r"(?i)\b(api[_-]?key|secret|password|private[_-]?key|token)\b\s*[:=]")),
    ("merge_self", re.compile(r"(?i)\b(merge|approve|deploy) (my|this|the) (own )?(patch|pr|pull request)\b")),
]


def screen_output(text: str) -> tuple[bool, tuple[str, ...]]:
    """Return ``(high_risk, findings)`` for a model output string."""
    findings = [name for name, pat in _HIGH_RISK_PATTERNS if pat.search(text)]
    return (bool(findings), tuple(findings))


__all__ = ["screen_output"]
