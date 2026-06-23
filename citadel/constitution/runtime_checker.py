"""Constitution validator + runtime checker — the independent verifier for System 40.

``validate_bindings`` checks that every component's declared clauses exist and that bindings are
complete (a component implementing a clause must cite a proving test). ``enforce`` denies any
permanently-prohibited action at runtime, fail closed.
"""

from __future__ import annotations

from .model import PROHIBITED_ACTIONS, ComponentBinding, Constitution


def validate_bindings(
    constitution: Constitution, bindings: list[ComponentBinding]
) -> list[str]:
    """Return binding errors: unknown clauses, or an implemented clause with no proving test."""
    errors: list[str] = []
    for b in bindings:
        for clause_id in b.implements:
            if not constitution.has(clause_id):
                errors.append(f"{b.component}: implements unknown clause {clause_id}")
            elif not b.proving_tests:
                errors.append(f"{b.component}: implements {clause_id} with no proving test")
        for clause_id in b.depends_on:
            if not constitution.has(clause_id):
                errors.append(f"{b.component}: depends on unknown clause {clause_id}")
    return errors


def enforce(action: str) -> bool:
    """Return True if the action is permitted. Permanently-prohibited actions are always denied."""
    return action not in PROHIBITED_ACTIONS


def assert_permitted(action: str) -> None:
    if not enforce(action):
        raise PermissionError(f"constitution: '{action}' is permanently prohibited")


__all__ = ["validate_bindings", "enforce", "assert_permitted"]
