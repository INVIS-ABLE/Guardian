"""Guardian core: configuration, scope engine, guardrails, evidence, and audit log.

This package contains the *enforcement* layer. Connectors, simulators, and agents
all route their decisions through here so that the guardrails in GUARDRAILS.md are
applied uniformly and cannot be bypassed.
"""

from __future__ import annotations

__all__ = [
    "config",
    "scope",
    "guardrails",
    "evidence",
    "audit",
    "memory",
    "router",
    "opa",
    "brain",
]

VERSION = "0.1.0"
