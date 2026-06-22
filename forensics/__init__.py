"""Forensic timeline (target architecture §17).

Reconstructs an ordered incident timeline from heterogeneous security events — correcting
clock skew, removing duplicates, linking causes, detecting missing expected events, and —
the load-bearing check — flagging when a tool **claims success but the expected independent
evidence is absent** (an "unsupported success"). Read-only analysis over a canonical event
envelope; it draws conclusions, it authorises nothing.
"""

from __future__ import annotations

from .timeline import (
    ForensicTimeline,
    TimelineEntry,
    TimelineEvent,
    TimelineReport,
)

__all__ = ["ForensicTimeline", "TimelineEvent", "TimelineEntry", "TimelineReport"]
