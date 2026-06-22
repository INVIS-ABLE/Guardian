"""Repository inventory — the machine-readable current-state report (Wave 0).

Guardian's Final Power-Up must "not guess what exists" but inspect it. This module is
the single source of truth for that inspection: it introspects the live registries
(agents, connectors, simulators), the router capability vocabulary, the signed
tool-manifest registry, and scans the source tree for direct subprocess use and
placeholder markers. The result is a deterministic, typed report that:

  * documents every registered agent, connector and capability,
  * records the direct-subprocess inventory (the only sanctioned shell-out points),
  * records the placeholder / not-yet-wired inventory honestly,
  * summarises the target-architecture component manifest and its delivery status.

The committed artefact ``reports/audit/current_state.json`` is generated from
:func:`build_inventory`. ``tests/test_repo_inventory.py`` re-runs the inspection and
fails if the report drifts from reality, so the audit can never silently go stale.

Run ``python -m core.inventory --write`` to regenerate the report after changing a
registry, a capability, or adding a subprocess/placeholder site.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Source directories that hold Guardian production/library code (tests excluded — they
#: legitimately exercise subprocess and stub paths). Sorted for deterministic scanning.
SOURCE_DIRS: tuple[str, ...] = (
    "agents",
    "attestation",
    "connectors",
    "containment",
    "core",
    "dashboard",
    "detection",
    "identity",
    "isolation",
    "orchestration",
    "shadow_guardian",
    "simulators",
    "supplychain",
)

#: Markers that indicate an incomplete / not-yet-wired implementation.
_PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "NotImplementedError",
    "TODO",
    "FIXME",
    "XXX",
    "placeholder",
    "deliberately thin",
)

_SUBPROCESS_RE = re.compile(r"\bsubprocess\b|\bos\.system\b|\bos\.popen\b|\bPopen\b")
_PLACEHOLDER_RE = re.compile("|".join(re.escape(m) for m in _PLACEHOLDER_MARKERS))


def _rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


#: Files excluded from the marker/subprocess scan. The inventory module itself defines
#: the marker strings it searches for, so scanning it yields only self-references.
_SCAN_EXCLUSIONS: frozenset[str] = frozenset({"core/inventory.py"})


def _iter_source_files(root: Path = REPO_ROOT) -> list[Path]:
    files: list[Path] = []
    for name in SOURCE_DIRS:
        base = root / name
        if not base.exists():
            continue
        files.extend(sorted(base.rglob("*.py")))
    return [f for f in files if _rel(f) not in _SCAN_EXCLUSIONS]


def _agent_inventory() -> list[dict[str, str]]:
    from agents import REGISTRY

    return [
        {"name": name, "class": cls.__name__, "summary": getattr(cls, "summary", "")}
        for name, cls in sorted(REGISTRY.items())
    ]


def _connector_inventory() -> list[dict[str, Any]]:
    from connectors import REGISTRY

    rows: list[dict[str, Any]] = []
    for name, cls in sorted(REGISTRY.items()):
        actions = getattr(cls, "ACTIONS", ()) or (getattr(cls, "action", name),)
        rows.append(
            {
                "name": name,
                "class": cls.__name__,
                "binary": getattr(cls, "binary", name),
                "mode": getattr(cls, "mode", ""),
                "trust_zone": getattr(cls, "trust_zone", ""),
                "actions": sorted(actions),
            }
        )
    return rows


def _simulator_inventory() -> list[dict[str, str]]:
    from simulators import REGISTRY

    return [
        {"name": name, "class": cls.__name__, "mode": getattr(cls, "mode", "")}
        for name, cls in sorted(REGISTRY.items())
    ]


def _router_capabilities() -> list[dict[str, str]]:
    from core.router import CAPABILITY_MAP

    return [
        {"capability": cap, "kind": kind, "tool": tool}
        for cap, (kind, tool) in sorted(CAPABILITY_MAP.items())
    ]


def _tool_manifest_capabilities() -> list[dict[str, Any]]:
    from core.tools.registry import default_registry

    registry = default_registry()
    rows: list[dict[str, Any]] = []
    for cap, signed in sorted(registry._by_capability.items()):  # noqa: SLF001 - read-only introspection
        manifest = signed.manifest
        rows.append(
            {
                "capability": cap,
                "tool": manifest.tool,
                "allowed_environments": list(manifest.allowed_environments),
                "requires_approval": manifest.requires_approval,
                "network": manifest.network.value,
            }
        )
    return rows


def _subprocess_inventory(root: Path = REPO_ROOT) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in _iter_source_files(root):
        lines = path.read_text(encoding="utf-8").splitlines()
        hits = [i + 1 for i, line in enumerate(lines) if _SUBPROCESS_RE.search(line)]
        if hits:
            rows.append({"file": _rel(path), "lines": hits})
    return rows


def _placeholder_inventory(root: Path = REPO_ROOT) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in _iter_source_files(root):
        lines = path.read_text(encoding="utf-8").splitlines()
        markers: list[dict[str, Any]] = []
        for i, line in enumerate(lines):
            if _PLACEHOLDER_RE.search(line):
                match = _PLACEHOLDER_RE.search(line)
                markers.append({"line": i + 1, "marker": match.group(0)})  # type: ignore[union-attr]
        if markers:
            rows.append({"file": _rel(path), "markers": markers})
    return rows


def _components_summary(root: Path = REPO_ROOT) -> dict[str, Any]:
    import yaml

    manifest_path = root / "docs" / "architecture" / "components.yaml"
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    components = data.get("components", [])
    by_status: dict[str, int] = {}
    by_zone: dict[str, int] = {}
    for c in components:
        by_status[c["status"]] = by_status.get(c["status"], 0) + 1
        by_zone[c["trust_zone"]] = by_zone.get(c["trust_zone"], 0) + 1
    return {
        "total": len(components),
        "by_status": dict(sorted(by_status.items())),
        "by_trust_zone": dict(sorted(by_zone.items())),
        "present": sorted(c["id"] for c in components if c["status"] == "present"),
    }


def _test_inventory(root: Path = REPO_ROOT) -> list[str]:
    tests_dir = root / "tests"
    if not tests_dir.exists():
        return []
    return sorted(_rel(p) for p in tests_dir.glob("test_*.py"))


def build_inventory(root: Path = REPO_ROOT) -> dict[str, Any]:
    """Inspect the live repository and return the typed current-state report.

    The result is deterministic except for ``generated_at``; consumers that compare
    reports for drift should ignore that field.
    """
    agents = _agent_inventory()
    connectors = _connector_inventory()
    simulators = _simulator_inventory()
    router_caps = _router_capabilities()
    manifest_caps = _tool_manifest_capabilities()
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "wave": 0,
        "summary": {
            "agents": len(agents),
            "connectors": len(connectors),
            "simulators": len(simulators),
            "router_capabilities": len(router_caps),
            "tool_manifest_capabilities": len(manifest_caps),
            "tests": len(_test_inventory(root)),
            "source_directories": list(SOURCE_DIRS),
        },
        "agents": agents,
        "connectors": connectors,
        "simulators": simulators,
        "router_capabilities": router_caps,
        "tool_manifest_capabilities": manifest_caps,
        "subprocess_inventory": _subprocess_inventory(root),
        "placeholder_inventory": _placeholder_inventory(root),
        "components": _components_summary(root),
        "tests": _test_inventory(root),
    }


def _stable(report: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``report`` without volatile fields, for drift comparison."""
    stable = dict(report)
    stable.pop("generated_at", None)
    return stable


def render_markdown(report: dict[str, Any]) -> str:
    """Render a human-readable current-state report from the typed inventory."""
    s = report["summary"]
    lines: list[str] = [
        "# Guardian repository inventory — current state",
        "",
        "_Generated by `core/inventory.py` (Wave 0). Do not edit by hand; run "
        "`python -m core.inventory --write` to regenerate._",
        "",
        "## Summary",
        "",
        f"- Agents (ECC command layer): **{s['agents']}**",
        f"- Connectors: **{s['connectors']}**",
        f"- Simulators: **{s['simulators']}**",
        f"- Router capabilities: **{s['router_capabilities']}**",
        f"- Signed tool-manifest capabilities: **{s['tool_manifest_capabilities']}**",
        f"- Test modules: **{s['tests']}**",
        "",
        "## Agents",
        "",
        "| name | class | summary |",
        "| --- | --- | --- |",
    ]
    for a in report["agents"]:
        lines.append(f"| `{a['name']}` | {a['class']} | {a['summary']} |")
    lines += ["", "## Connectors", "", "| name | binary | mode | trust zone | actions |",
              "| --- | --- | --- | --- | --- |"]
    for c in report["connectors"]:
        lines.append(
            f"| `{c['name']}` | `{c['binary']}` | {c['mode']} | {c['trust_zone']} | "
            f"{', '.join(c['actions'])} |"
        )
    lines += ["", "## Router capabilities", "", "| capability | kind | tool |",
              "| --- | --- | --- |"]
    for c in report["router_capabilities"]:
        lines.append(f"| `{c['capability']}` | {c['kind']} | `{c['tool']}` |")
    lines += ["", "## Signed tool-manifest capabilities", "",
              "| capability | tool | environments | approval | network |",
              "| --- | --- | --- | --- | --- |"]
    for c in report["tool_manifest_capabilities"]:
        lines.append(
            f"| `{c['capability']}` | `{c['tool']}` | "
            f"{', '.join(c['allowed_environments'])} | {c['requires_approval']} | "
            f"{c['network']} |"
        )
    lines += ["", "## Direct-subprocess inventory", "",
              "The only sanctioned shell-out points. Every other execution path routes "
              "through the Guardian router / connector contract.", ""]
    for row in report["subprocess_inventory"]:
        lines.append(f"- `{row['file']}` (lines {', '.join(str(n) for n in row['lines'])})")
    lines += ["", "## Placeholder / not-yet-wired inventory", "",
              "Honestly recorded deployment stubs and markers. These raise "
              "`NotImplementedError` rather than fake success.", ""]
    for row in report["placeholder_inventory"]:
        markers = ", ".join(f"{m['marker']}@{m['line']}" for m in row["markers"])
        lines.append(f"- `{row['file']}`: {markers}")
    comp = report["components"]
    lines += ["", "## Target-architecture component manifest", "",
              f"- Total components: **{comp['total']}**",
              f"- By status: {comp['by_status']}",
              f"- By trust zone: {comp['by_trust_zone']}",
              f"- Present (delivered): {', '.join(comp['present'])}", ""]
    return "\n".join(lines)


def write_report(root: Path = REPO_ROOT) -> tuple[Path, Path]:
    """Generate and write both the JSON and Markdown current-state reports."""
    report = build_inventory(root)
    json_path = root / "reports" / "audit" / "current_state.json"
    md_path = root / "reports" / "audit" / "current_state.md"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report) + "\n", encoding="utf-8")
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: ``python -m core.inventory [--write]``."""
    import argparse

    parser = argparse.ArgumentParser(description="Guardian repository inventory (Wave 0).")
    parser.add_argument("--write", action="store_true", help="Write reports/audit/current_state.{json,md}")
    args = parser.parse_args(argv)
    if args.write:
        json_path, md_path = write_report()
        print(f"wrote {_rel(json_path)} and {_rel(md_path)}")
    else:
        print(json.dumps(build_inventory(), indent=2))
    return 0


__all__ = [
    "build_inventory",
    "render_markdown",
    "write_report",
    "REPO_ROOT",
    "SOURCE_DIRS",
]


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    raise SystemExit(main())
