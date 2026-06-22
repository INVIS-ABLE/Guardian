"""Control-plane dependency health (blueprint area 23 / Phase 6).

Guardian's sensitive actions depend on a small set of control-plane services. If any REQUIRED
one is unavailable, sensitive actions must **stop safely** rather than proceed in a degraded,
unverifiable state:

  - OPA          — the authority. (Its absence is already fail-closed in core.policy_gate.)
  - OpenBao      — short-lived credentials. No broker ⇒ no credential ⇒ no execution.
  - immudb       — the evidence system of record. No authoritative evidence ⇒ don't act.
  - Temporal     — durable workflow state. Degraded ⇒ pause, don't push ahead.

This models the chaos-test expectation: "OPA/OpenBao/immudb unavailable ⇒ sensitive actions
stop, while evidence and operator visibility remain available."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DependencyState(str, Enum):
    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"


@dataclass
class DependencyHealth:
    name: str
    state: DependencyState = DependencyState.UP
    required_for_sensitive: bool = True

    def usable(self) -> bool:
        return self.state == DependencyState.UP


# The control-plane services Guardian depends on, and whether each is required before a
# sensitive (state-changing / production / execution) action may proceed.
DEFAULT_DEPENDENCIES = ("opa", "openbao", "immudb", "temporal")


@dataclass
class ControlPlane:
    deps: dict[str, DependencyHealth] = field(default_factory=dict)

    @classmethod
    def all_up(cls) -> "ControlPlane":
        return cls(deps={n: DependencyHealth(n) for n in DEFAULT_DEPENDENCIES})

    def set_state(self, name: str, state: DependencyState) -> None:
        dep = self.deps.get(name) or DependencyHealth(name)
        dep.state = state
        self.deps[name] = dep

    def unavailable_required(self) -> list[str]:
        """Names of required dependencies that are not fully UP."""
        return sorted(
            n for n, d in self.deps.items() if d.required_for_sensitive and not d.usable()
        )

    def healthy_for_sensitive(self) -> bool:
        return not self.unavailable_required()
