"""Citadel System 40 — Guardian Integrity Constitution (Wave 40)."""

from __future__ import annotations

from .model import (
    CORE_CLAUSES,
    PROHIBITED_ACTIONS,
    ClauseCategory,
    ComponentBinding,
    Constitution,
    ConstitutionClause,
)
from .runtime_checker import assert_permitted, enforce, validate_bindings

__all__ = [
    "CORE_CLAUSES", "PROHIBITED_ACTIONS", "ClauseCategory", "ComponentBinding", "Constitution",
    "ConstitutionClause", "assert_permitted", "enforce", "validate_bindings",
]
