"""Dashboard/API identity (Phase 2 / blueprint area 7).

The Guardian dashboard is never exposed directly. In deployment it sits behind oauth2-proxy
(OIDC via Keycloak / Entra ID), which authenticates the user and injects identity headers.
This module turns those trusted headers into a `Principal` and enforces role checks. If auth
is required and no authenticated identity is present, access is refused (fail closed).

Security note: the forwarded identity headers are only trustworthy when the request comes
through the trusted proxy on a private network — never accept them from a directly-exposed
port. `trust_forwarded_headers` must be False unless the proxy is in front.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Headers oauth2-proxy injects after a successful OIDC login.
H_USER = "x-forwarded-user"
H_EMAIL = "x-forwarded-email"
H_GROUPS = "x-forwarded-groups"
H_PREFERRED = "x-forwarded-preferred-username"


class Unauthenticated(PermissionError):
    pass


class Forbidden(PermissionError):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str
    email: str | None = None
    roles: frozenset[str] = field(default_factory=frozenset)

    def has_any(self, required: set[str]) -> bool:
        return bool(self.roles & required)


def _lower_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def principal_from_headers(
    headers: dict[str, str], *, trust_forwarded_headers: bool
) -> Principal:
    """Build a Principal from trusted proxy headers. Raises Unauthenticated if absent/untrusted."""
    if not trust_forwarded_headers:
        raise Unauthenticated(
            "forwarded identity headers are not trusted (no proxy configured); refusing"
        )
    h = _lower_headers(headers)
    subject = h.get(H_USER) or h.get(H_PREFERRED)
    if not subject:
        raise Unauthenticated("no authenticated identity present")
    groups = h.get(H_GROUPS, "")
    roles = frozenset(g.strip() for g in groups.split(",") if g.strip())
    return Principal(subject=subject, email=h.get(H_EMAIL), roles=roles)


def require_roles(principal: Principal, required: set[str]) -> None:
    """Raise Forbidden unless the principal holds at least one required role."""
    if required and not principal.has_any(required):
        raise Forbidden(
            f"principal '{principal.subject}' lacks any of required roles {sorted(required)}"
        )
