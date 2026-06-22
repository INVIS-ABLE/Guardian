"""Load and expose guardian.config.yaml as a typed object."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = REPO_ROOT / "guardian.config.yaml"


@dataclass(frozen=True)
class GuardianConfig:
    """Typed view over guardian.config.yaml (the top-level ``guardian:`` block)."""

    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def version(self) -> str:
        return self._g.get("version", "0.0.0")

    @property
    def environment_default(self) -> str:
        return self._g.get("environment_default", "staging")

    @property
    def dry_run_default(self) -> bool:
        return bool(self._g.get("dry_run_default", True))

    @property
    def fail_closed(self) -> bool:
        return bool(self._g.get("fail_closed", True))

    @property
    def require_human_approval(self) -> bool:
        # This can never be turned off; we hard-default to True regardless of config.
        return True

    @property
    def connectors(self) -> dict[str, Any]:
        return self._g.get("connectors", {})

    @property
    def reporting(self) -> dict[str, Any]:
        return self._g.get("reporting", {})

    @property
    def audit(self) -> dict[str, Any]:
        return self._g.get("audit", {})

    @property
    def _g(self) -> dict[str, Any]:
        return self.raw.get("guardian", {})


@lru_cache(maxsize=8)
def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> GuardianConfig:
    """Load guardian.config.yaml. Fails closed: a missing/invalid file raises."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Guardian config not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if "guardian" not in data:
        raise ValueError(f"Config {p} is missing the top-level 'guardian:' block")
    return GuardianConfig(raw=data)
