"""Guardian identity layer (Phase 2 / blueprint areas 4, 7).

Short-lived credential brokering (OpenBao-modeled) and OIDC principal/role enforcement
(oauth2-proxy/Keycloak-modeled). In-process implementations for dev/tests; lazy adapters for
the real services.
"""

from __future__ import annotations

from .credentials import (
    MAX_TTL_SECONDS,
    Credential,
    CredentialBroker,
    CredentialExpired,
    CredentialRevoked,
    InMemoryCredentialBroker,
    OpenBaoBroker,
)
from .oidc import (
    Forbidden,
    Principal,
    Unauthenticated,
    principal_from_headers,
    require_roles,
)

__all__ = [
    "Credential",
    "CredentialBroker",
    "InMemoryCredentialBroker",
    "OpenBaoBroker",
    "CredentialExpired",
    "CredentialRevoked",
    "MAX_TTL_SECONDS",
    "Principal",
    "principal_from_headers",
    "require_roles",
    "Unauthenticated",
    "Forbidden",
]
