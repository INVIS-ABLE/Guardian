"""Guardian resilience — control-plane health + fail-closed gating (Phase 6 / area 23).

If OPA, OpenBao, immudb, or Temporal are unavailable, sensitive actions stop safely rather
than proceeding in a degraded, unverifiable state.
"""

from __future__ import annotations

from .failclosed import SensitiveActionBlocked, guard_sensitive_action, is_safe_to_proceed
from .health import ControlPlane, DependencyHealth, DependencyState

__all__ = [
    "ControlPlane",
    "DependencyHealth",
    "DependencyState",
    "guard_sensitive_action",
    "is_safe_to_proceed",
    "SensitiveActionBlocked",
]
