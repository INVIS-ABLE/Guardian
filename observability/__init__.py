"""Guardian observability — trace/correlation IDs + routed alerting (area 12).

Stitches a security case's events together under one correlation id and turns denials /
fail-closed refusals into severity-routed, deduplicated alerts. In-process and dependency-free:
no network calls unless a deployment injects real alert sinks.
"""

from __future__ import annotations

from .alerts import Alert, AlertRouter, Severity, Sink
from .trace import Span, Tracer, current_correlation_id, new_id

__all__ = [
    "Span",
    "Tracer",
    "current_correlation_id",
    "new_id",
    "Alert",
    "AlertRouter",
    "Severity",
    "Sink",
]
