"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.scope import load_scope

REPO_ROOT = Path(__file__).resolve().parent.parent
STAGING_SCOPE = REPO_ROOT / "scope" / "invisable-staging.yaml"


@pytest.fixture()
def staging_scope():
    return load_scope(STAGING_SCOPE)
