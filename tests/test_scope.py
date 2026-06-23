"""Scope loading, validation, and ownership-membership tests."""

from __future__ import annotations

import pytest

from core.scope import (
    ScopeError,
    domain_is_in_scope,
    load_scope,
    repo_is_in_scope,
)


def test_example_scope_loads(staging_scope):
    assert staging_scope.asset == "invisable-staging"
    assert staging_scope.environment == "staging"
    assert "safeguarding" in staging_scope.allowed_modes


def test_domain_membership(staging_scope):
    assert domain_is_in_scope(staging_scope, "staging.invisable.co.uk")
    assert domain_is_in_scope(staging_scope, "api.staging.invisable.co.uk")  # subdomain
    assert not domain_is_in_scope(staging_scope, "evil.example.com")
    assert not domain_is_in_scope(staging_scope, "invisable.co.uk")  # prod not in staging scope


def test_repo_membership_normalisation(staging_scope):
    assert repo_is_in_scope(staging_scope, "github.com/invisable/app")
    assert repo_is_in_scope(staging_scope, "https://github.com/invisable/app.git")
    assert repo_is_in_scope(staging_scope, "git@github.com:invisable/app")
    assert not repo_is_in_scope(staging_scope, "github.com/someoneelse/app")


def test_unregistered_test_account_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "asset: invisable-staging\n"
        "environment: staging\n"
        "allowed_domains: [staging.invisable.co.uk]\n"
        "allowed_repos: [github.com/invisable/app]\n"
        "allowed_test_accounts: [not_a_real_test_account]\n"
        "allowed_modes: [code_review]\n"
        "blocked_actions: []\n"
        "approval_required: []\n",
        encoding="utf-8",
    )
    with pytest.raises(ScopeError):
        load_scope(bad)


def test_pre_tenancy_scope_matches_invisable_asset(staging_scope):
    """A scope with no explicit tenant targets an invisable-owned asset cleanly."""
    assert staging_scope.tenant == "invisable"  # default
    # load_scope already cross-checked tenant == asset tenant without raising.


def test_cross_tenant_asset_reference_is_denied(tmp_path):
    """A scope declaring tenant 'globex' may not target an invisable-owned asset."""
    bad = tmp_path / "cross.yaml"
    bad.write_text(
        "asset: invisable-staging\n"
        "environment: staging\n"
        "tenant: globex\n"
        "allowed_domains: [staging.invisable.co.uk]\n"
        "allowed_repos: [github.com/invisable/app]\n"
        "allowed_test_accounts: [standard_user_test]\n"
        "allowed_modes: [code_review]\n"
        "blocked_actions: []\n"
        "approval_required: []\n",
        encoding="utf-8",
    )
    with pytest.raises(ScopeError, match="cross-tenant"):
        load_scope(bad)
