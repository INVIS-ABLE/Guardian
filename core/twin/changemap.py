"""Map changed source paths to twin assets (the bridge that makes the gate ambient).

A PR changes files; the blast-radius gate reasons about assets. This module resolves the
former to the latter using the ``paths`` globs each asset declares, so CI can run
``assess_change`` automatically on every pull request (docs/digital_twin.md).
"""

from __future__ import annotations

from fnmatch import fnmatch

from .graph import DigitalTwin


def _path_matches(pattern: str, path: str) -> bool:
    """Glob match supporting a trailing ``/**`` directory wildcard and plain fnmatch."""
    pattern = pattern.strip().strip("/") if pattern.strip().startswith("/") else pattern.strip()
    path = path.strip().lstrip("./")
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return path == prefix or path.startswith(prefix + "/")
    return fnmatch(path, pattern)


def resolve_changed_assets(twin: DigitalTwin, changed_files: list[str]) -> list[str]:
    """Return the sorted, unique asset ids whose ``paths`` match any changed file."""
    files = [f for f in (cf.strip() for cf in changed_files) if f]
    hit: set[str] = set()
    for asset in twin.assets():
        for pattern in asset.paths:
            if any(_path_matches(pattern, f) for f in files):
                hit.add(asset.id)
                break
    return sorted(hit)
