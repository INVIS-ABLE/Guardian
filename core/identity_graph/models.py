"""Typed models for the identity & permission attack graph (Sovereign plane, Wave 1, system #2).

The identity graph is the BloodHound-style companion to the live cyber digital twin
([`core/twin/`](../twin)). Where the twin answers *"what is affected if this asset is
compromised?"*, the identity graph answers the four questions the Sovereign doc asks of
principals and permissions (docs/sovereign_ops_plane.md):

  * **effective + transitive permissions** — what can this principal *actually* do, once
    group/role membership is followed to its closure?
  * **privilege-escalation paths** — how could a principal acquire rights it does not hold
    today, by assuming a role or rewriting another principal's grants?
  * **dormant privilege** — which privileged principals have gone quiet (unused standing
    access is a removal candidate and a blast-radius multiplier if the credential leaks)?
  * **separation-of-duties breaks** — which single principal can perform two duties that
    policy requires be held by different people (e.g. author *and* approve a release)?

This module defines the *shapes* only; the graph algorithms live in ``graph.py`` and the
ingestion seam (BloodHound / cloud IAM → store, in production) in ``ingest.py``.

Privacy boundary (same as the twin): this graph holds **identity metadata and permission
relationships, never private content**. A principal is an identifier; a grant names an
*action* on a *resource*, never the data itself. Guardian protects the access-control
system while remaining structurally outside private content.
"""

from __future__ import annotations

from datetime import date
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

SCHEMA_VERSION = 1


class PrincipalKind(str, Enum):
    """The kinds of principal the identity graph models."""

    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    MACHINE = "machine"
    GROUP = "group"
    ROLE = "role"


class EdgeKind(str, Enum):
    """Directed control edges between principals, oriented ``src`` → ``dst``.

    Two families with deliberately different power:

    * **Inheritance** (``MEMBER_OF``): the source *already holds* every grant of the target.
      Following inheritance to its closure yields a principal's effective permissions.
    * **Escalation** (``CAN_ASSUME``, ``CAN_GRANT``): the source can *acquire* the target's
      grants by taking an action — assuming a role, or rewriting the target's permissions.
      These are the edges privilege-escalation paths are made of.
    """

    MEMBER_OF = "member_of"      # principal → group/role : inherits its grants (transitive)
    CAN_ASSUME = "can_assume"    # principal → role : may assume it, gaining its grants
    CAN_GRANT = "can_grant"      # principal → principal/role : may rewrite its grants


# The two edge families, named once so graph.py and tests agree on the semantics.
INHERITANCE_EDGES = frozenset({EdgeKind.MEMBER_OF})
ESCALATION_EDGES = frozenset({EdgeKind.CAN_ASSUME, EdgeKind.CAN_GRANT})


class Principal(BaseModel):
    """One principal (human, service account, machine, group or role). Immutable, strict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    id: str                       # stable identifier, e.g. "id:ci-token" or "role:deployer"
    kind: PrincipalKind
    name: str
    owner: str | None = None      # team/owner, for reporting
    last_active: date | None = None  # last observed activity — drives dormant-privilege

    @field_validator("id", "name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("principal id/name must be non-empty")
        return v


class IdentityEdge(BaseModel):
    """A directed, typed control edge between two principals (by id)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    src: str
    dst: str
    kind: EdgeKind

    @field_validator("src", "dst")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("edge src/dst must be non-empty principal ids")
        return v


class Grant(BaseModel):
    """A permission a principal/role/group *directly* holds: an ``action`` on a ``resource``.

    ``duty`` tags the grant with a separation-of-duties class (e.g. ``"author"`` /
    ``"approve"``) so conflicting duties held by one principal can be detected. ``sensitive``
    marks high-impact rights (key rotation, production deploy) so dormant standing access to
    them is surfaced first.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    holder: str                   # principal/role/group id that directly holds this grant
    action: str                   # e.g. "deploy", "approve_release", "rotate_key"
    resource: str = "*"           # e.g. "svc:messaging-relay" or "*"
    duty: str | None = None       # separation-of-duties class
    sensitive: bool = False

    @field_validator("holder", "action", "resource")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("grant holder/action/resource must be non-empty")
        return v


class EffectivePermission(BaseModel):
    """An action/resource a principal can exercise, with provenance for audit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: str
    resource: str
    via: str                      # the holder whose grant this is (self, group or role)
    inherited: bool               # False = held directly; True = via membership
    duty: str | None = None
    sensitive: bool = False


class PrivilegeStep(BaseModel):
    """One hop on an escalation path: ``via`` edge reaching ``principal``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    via: EdgeKind
    principal: str


class EscalationPath(BaseModel):
    """A route by which ``origin`` could acquire privilege it does not already hold."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    origin: str
    target: str                              # principal reached
    path: tuple[PrivilegeStep, ...]
    gained: tuple[EffectivePermission, ...]  # NEW rights, beyond origin's effective set
    uses_escalation: bool                    # always True (a pure-inheritance route adds nothing)


class DormantPrincipal(BaseModel):
    """A principal with standing permissions that has not been active within the window."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal: Principal
    idle_days: int | None          # None = never observed active
    permissions: int               # size of its effective permission set
    sensitive: bool                # holds at least one sensitive grant


class DutyConflict(BaseModel):
    """A pair of duties policy requires be separated (held by different principals)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    a: str
    b: str

    @field_validator("name", "a", "b")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("duty conflict name/a/b must be non-empty")
        return v


class SoDBreak(BaseModel):
    """A single principal effectively holding both sides of a separation-of-duties conflict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal: str
    conflict: DutyConflict
    action_a: str                  # the concrete action satisfying duty ``a``
    action_b: str                  # the concrete action satisfying duty ``b``
