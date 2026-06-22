"""Scope engine: load, validate, and reason about Guardian scope files.

A scope file is the single source of truth for what a run may touch. This module
loads it, validates it against SCOPE_SCHEMA.yaml, and exposes ownership / membership
helpers used by the guardrails. Default-deny throughout.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .config import REPO_ROOT

SCHEMA_PATH = REPO_ROOT / "SCOPE_SCHEMA.yaml"
TEST_ACCOUNTS_PATH = REPO_ROOT / "scope" / "test_accounts.yaml"
ASSETS_PATH = REPO_ROOT / "scope" / "assets.yaml"


class ScopeError(ValueError):
    """Raised when a scope file is missing, invalid, or self-inconsistent."""


@dataclass(frozen=True)
class Scope:
    """A validated Guardian scope file."""

    path: Path
    raw: dict[str, Any]

    # --- convenience accessors -------------------------------------------------
    @property
    def asset(self) -> str:
        return self.raw["asset"]

    @property
    def environment(self) -> str:
        return self.raw["environment"]

    @property
    def owner(self) -> str:
        return self.raw.get("owner", "INVISABLE")

    @property
    def allowed_domains(self) -> list[str]:
        return list(self.raw.get("allowed_domains", []))

    @property
    def allowed_repos(self) -> list[str]:
        return list(self.raw.get("allowed_repos", []))

    @property
    def allowed_test_accounts(self) -> list[str]:
        return list(self.raw.get("allowed_test_accounts", []))

    @property
    def allowed_modes(self) -> list[str]:
        return list(self.raw.get("allowed_modes", []))

    @property
    def blocked_actions(self) -> list[str]:
        return list(self.raw.get("blocked_actions", []))

    @property
    def approval_required(self) -> list[str]:
        return list(self.raw.get("approval_required", []))

    @property
    def rate_limits(self) -> dict[str, Any]:
        return dict(self.raw.get("rate_limits", {}))

    def is_production(self) -> bool:
        return self.environment == "production"


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ScopeError(f"File not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ScopeError(f"Expected a mapping at top level of {path}")
    return data


def _validate_against_schema(raw: dict[str, Any]) -> None:
    """Validate the scope dict against SCOPE_SCHEMA.yaml when jsonschema is available."""
    try:
        import jsonschema  # type: ignore
    except Exception:  # pragma: no cover - jsonschema is a declared dependency
        # Fall back to a minimal structural check rather than silently passing.
        _minimal_check(raw)
        return
    schema = yaml.safe_load(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(instance=raw, schema=schema)
    except jsonschema.ValidationError as exc:  # type: ignore[attr-defined]
        raise ScopeError(f"Scope failed schema validation: {exc.message}") from exc


def _minimal_check(raw: dict[str, Any]) -> None:
    required = [
        "asset",
        "environment",
        "allowed_domains",
        "allowed_repos",
        "allowed_test_accounts",
        "allowed_modes",
        "blocked_actions",
        "approval_required",
    ]
    missing = [k for k in required if k not in raw]
    if missing:
        raise ScopeError(f"Scope missing required keys: {', '.join(missing)}")


def load_scope(path: str | Path) -> Scope:
    """Load and validate a scope file. Fails closed on any problem."""
    p = Path(path)
    raw = _load_yaml(p)
    _validate_against_schema(raw)
    scope = Scope(path=p, raw=raw)
    _cross_check_registries(scope)
    return scope


def _cross_check_registries(scope: Scope) -> None:
    """Ensure the scope only references registered assets and test accounts."""
    # Test accounts must be registered (no real users can be referenced).
    if TEST_ACCOUNTS_PATH.exists():
        registry = _load_yaml(TEST_ACCOUNTS_PATH)
        registered = {a["id"] for a in registry.get("test_accounts", []) if "id" in a}
        unknown = set(scope.allowed_test_accounts) - registered
        if unknown:
            raise ScopeError(
                f"Scope references unregistered test accounts: {', '.join(sorted(unknown))}. "
                "Add them to scope/test_accounts.yaml or remove them."
            )
    # Asset group must be registered.
    if ASSETS_PATH.exists():
        assets = _load_yaml(ASSETS_PATH)
        known = {a["id"] for a in assets.get("assets", []) if "id" in a}
        if known and scope.asset not in known:
            raise ScopeError(
                f"Scope asset '{scope.asset}' is not in scope/assets.yaml registry."
            )


# --- ownership verification ----------------------------------------------------
def domain_is_in_scope(scope: Scope, domain: str) -> bool:
    """A domain is in scope if it equals or is a subdomain of an allowed domain."""
    domain = domain.lower().strip().rstrip(".")
    for allowed in scope.allowed_domains:
        allowed = allowed.lower().strip().rstrip(".")
        if domain == allowed or domain.endswith("." + allowed):
            return True
    return False


def repo_is_in_scope(scope: Scope, repo: str) -> bool:
    """Normalise a repo reference and check it against allowed_repos."""
    repo = _normalise_repo(repo)
    return any(repo == _normalise_repo(r) for r in scope.allowed_repos)


def _normalise_repo(repo: str) -> str:
    repo = repo.strip().lower()
    for prefix in ("https://", "http://", "git@"):
        repo = repo.replace(prefix, "")
    repo = repo.replace("github.com:", "github.com/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    return repo
