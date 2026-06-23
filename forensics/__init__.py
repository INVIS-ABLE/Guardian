"""Forensic timeline (target architecture §17).

Reconstructs an ordered incident timeline from heterogeneous security events — correcting
clock skew, removing duplicates, linking causes, detecting missing expected events, and —
the load-bearing check — flagging when a tool **claims success but the expected independent
evidence is absent** (an "unsupported success"). Read-only analysis over a canonical event
envelope; it draws conclusions, it authorises nothing.
"""

from __future__ import annotations

from .alerting import (
    alerts_from_report,
    anomaly_to_alert,
    raise_forensic_alerts,
    severity_for,
)
from .sources import (
    events_from_audit_log,
    from_audit_entry,
    from_evidence_receipt,
    from_execution,
    from_policy_decision,
    from_shadow_report,
)
from .timeline import (
    ForensicTimeline,
    TimelineEntry,
    TimelineEvent,
    TimelineReport,
)

__all__ = [
    "ForensicTimeline", "TimelineEvent", "TimelineEntry", "TimelineReport",
    "from_audit_entry", "events_from_audit_log", "from_policy_decision",
    "from_evidence_receipt", "from_shadow_report", "from_execution",
    "raise_forensic_alerts", "alerts_from_report", "anomaly_to_alert", "severity_for",
]
