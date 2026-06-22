"""Fail-closed gate for control-plane outages (blueprint area 23 / Phase 6).

Before a sensitive action runs, the control plane must be healthy. If any required dependency
(OPA, OpenBao, immudb, Temporal) is unavailable, the action is **refused** and the refusal is
audited — Guardian stops safely; it never proceeds blind. This complements the policy gate's
own OPA-unavailable fail-closed with the rest of the control plane.
"""

from __future__ import annotations

from typing import Any

from .health import ControlPlane


class SensitiveActionBlocked(PermissionError):
    """Raised when the control plane is not healthy enough for a sensitive action."""


def guard_sensitive_action(
    control_plane: ControlPlane,
    *,
    action: str,
    audit: Any | None = None,
    actor: str = "guardian",
) -> None:
    """Refuse (fail closed) if any required control-plane dependency is unavailable."""
    down = control_plane.unavailable_required()
    if down:
        if audit is not None:
            try:
                audit.record(
                    f"failclosed:{action}", actor=actor, decision="denied",
                    detail={"unavailable": down},
                )
            except Exception:  # pragma: no cover - auditing must not crash enforcement
                pass
        raise SensitiveActionBlocked(
            f"sensitive action '{action}' refused: control-plane dependencies down: {down}"
        )


def is_safe_to_proceed(control_plane: ControlPlane) -> bool:
    return control_plane.healthy_for_sensitive()
