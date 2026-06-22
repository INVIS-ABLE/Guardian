"""Monotonic security-workflow state machine (blueprint area 3 / Phase 1).

A workflow advances through a fixed set of states with explicit, forward-only transitions.
Illegal transitions raise. Terminal states (DONE/ROLLED_BACK/DENIED/CANCELLED) cannot be
left — a cancelled or denied workflow can never resume into execution. This is the durable
skeleton that Temporal makes restart-safe (orchestration/temporal_backend.py); the in-process
engine here enforces the same invariants and is fully testable without a Temporal server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from time import time


class State(str, Enum):
    CREATED = "created"
    SCOPED = "scoped"
    THREAT_MODELLED = "threat_modelled"
    SCANNED = "scanned"
    PATCH_PROPOSED = "patch_proposed"
    TESTED = "tested"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    DEPLOYED = "deployed"
    MONITORING = "monitoring"
    DONE = "done"
    # terminal off-ramps
    ROLLED_BACK = "rolled_back"
    DENIED = "denied"
    CANCELLED = "cancelled"


TERMINAL: frozenset[State] = frozenset(
    {State.DONE, State.ROLLED_BACK, State.DENIED, State.CANCELLED}
)

# Forward-only allowed transitions. Any state may go to CANCELLED (operator stop) or DENIED
# (a policy/approval refusal); neither can be left.
_FORWARD: dict[State, set[State]] = {
    State.CREATED: {State.SCOPED},
    State.SCOPED: {State.THREAT_MODELLED},
    State.THREAT_MODELLED: {State.SCANNED},
    State.SCANNED: {State.PATCH_PROPOSED},
    State.PATCH_PROPOSED: {State.TESTED},
    State.TESTED: {State.AWAITING_APPROVAL},
    State.AWAITING_APPROVAL: {State.APPROVED},  # DENIED handled separately
    State.APPROVED: {State.EXECUTING},
    State.EXECUTING: {State.DEPLOYED, State.ROLLED_BACK},
    State.DEPLOYED: {State.MONITORING},
    State.MONITORING: {State.DONE, State.ROLLED_BACK},
}


class IllegalTransition(RuntimeError):
    """Raised on any transition not permitted by the monotonic state machine."""


def allowed_transitions(state: State) -> set[State]:
    if state in TERMINAL:
        return set()
    nxt = set(_FORWARD.get(state, set()))
    # Refusal/stop off-ramps are reachable from any non-terminal state.
    nxt.add(State.CANCELLED)
    if state == State.AWAITING_APPROVAL:
        nxt.add(State.DENIED)
    # A pre-execution policy re-check can deny right before EXECUTING.
    if state == State.APPROVED:
        nxt.add(State.DENIED)
    return nxt


@dataclass
class WorkflowMachine:
    """Tracks and enforces a single workflow's state with an append-only history."""

    workflow_id: str
    state: State = State.CREATED
    history: list[tuple[str, float]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.history:
            self.history.append((self.state.value, time()))

    def can_transition(self, to: State) -> bool:
        return to in allowed_transitions(self.state)

    def transition(self, to: State) -> None:
        if self.state in TERMINAL:
            raise IllegalTransition(
                f"workflow {self.workflow_id} is terminal ({self.state.value}); "
                f"cannot move to {to.value}"
            )
        if to not in allowed_transitions(self.state):
            raise IllegalTransition(
                f"workflow {self.workflow_id}: illegal {self.state.value} -> {to.value}"
            )
        self.state = to
        self.history.append((to.value, time()))

    def cancel(self) -> None:
        """Operator stop. Idempotent only in the sense that a terminal workflow refuses."""
        if self.state in TERMINAL:
            raise IllegalTransition(
                f"workflow {self.workflow_id} already terminal ({self.state.value})"
            )
        self.transition(State.CANCELLED)

    def deny(self) -> None:
        if self.state not in (State.AWAITING_APPROVAL, State.APPROVED):
            raise IllegalTransition(
                f"workflow {self.workflow_id}: deny only from awaiting_approval/approved"
            )
        self.transition(State.DENIED)

    def is_terminal(self) -> bool:
        return self.state in TERMINAL

    def reached_execution(self) -> bool:
        return any(s == State.EXECUTING.value for s, _ in self.history)
