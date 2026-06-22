"""Wave 0 acceptance: the repository inventory must stay truthful.

These tests enforce the Final Power-Up "do not guess what exists — inspect it" rule:

  * every registered agent, connector, simulator and capability is captured by the
    machine-readable current-state report (and documented),
  * the committed ``reports/audit/current_state.json`` does not drift from reality,
  * no NEW direct-subprocess site appears outside the two sanctioned chokepoints
    (``connectors/base.py`` and ``core/policy_gate.py``).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents import REGISTRY as AGENT_REGISTRY
from connectors import REGISTRY as CONNECTOR_REGISTRY
from core import inventory
from core.router import CAPABILITY_MAP
from core.tools.registry import default_registry
from simulators import REGISTRY as SIMULATOR_REGISTRY

REPO_ROOT = inventory.REPO_ROOT
REPORT_JSON = REPO_ROOT / "reports" / "audit" / "current_state.json"

#: The only files permitted to shell out directly. Everything else must route through
#: the Guardian connector contract / router. Adding a new site here is a deliberate,
#: reviewable decision — not an accident.
SANCTIONED_SUBPROCESS_FILES = {"connectors/base.py", "core/policy_gate.py"}


@pytest.fixture(scope="module")
def report() -> dict:
    return inventory.build_inventory()


def test_report_artifact_exists() -> None:
    assert REPORT_JSON.exists(), "run `python -m core.inventory --write` to generate the report"


def test_committed_report_is_fresh(report: dict) -> None:
    committed = json.loads(REPORT_JSON.read_text(encoding="utf-8"))
    assert inventory._stable(committed) == inventory._stable(report), (
        "reports/audit/current_state.json is stale — regenerate with "
        "`python -m core.inventory --write`"
    )


def test_every_agent_is_inventoried(report: dict) -> None:
    documented = {a["name"] for a in report["agents"]}
    assert documented == set(AGENT_REGISTRY), "every registered agent must be inventoried"
    assert len(documented) == 17, "the 17 ECC command agents must remain intact"


def test_every_connector_is_inventoried(report: dict) -> None:
    documented = {c["name"] for c in report["connectors"]}
    assert documented == set(CONNECTOR_REGISTRY)


def test_every_simulator_is_inventoried(report: dict) -> None:
    documented = {s["name"] for s in report["simulators"]}
    assert documented == set(SIMULATOR_REGISTRY)


def test_every_router_capability_is_inventoried(report: dict) -> None:
    documented = {c["capability"] for c in report["router_capabilities"]}
    assert documented == set(CAPABILITY_MAP)


def test_every_manifest_capability_is_inventoried(report: dict) -> None:
    registry = default_registry()
    documented = {c["capability"] for c in report["tool_manifest_capabilities"]}
    assert documented == set(registry._by_capability)  # noqa: SLF001 - read-only check


def test_subprocess_inventory_is_truthful(report: dict) -> None:
    found = {row["file"] for row in report["subprocess_inventory"]}
    assert found == SANCTIONED_SUBPROCESS_FILES, (
        "a new direct-subprocess site appeared — production execution must route "
        f"through the Guardian router/connector contract. Found: {sorted(found)}"
    )


def test_capability_documentation_covers_every_capability(report: dict) -> None:
    doc = (REPO_ROOT / "docs" / "architecture" / "capability_inventory.md").read_text(
        encoding="utf-8"
    )
    for cap in CAPABILITY_MAP:
        assert f"`{cap}`" in doc, f"router capability {cap} is undocumented"
    for c in report["tool_manifest_capabilities"]:
        assert f"`{c['capability']}`" in doc, f"manifest capability {c['capability']} undocumented"


def test_agent_documentation_covers_every_agent() -> None:
    doc = (REPO_ROOT / "docs" / "architecture" / "agent_inventory.md").read_text(encoding="utf-8")
    for name in AGENT_REGISTRY:
        assert f"`{name}`" in doc, f"agent {name} is undocumented"


def test_connector_documentation_covers_every_connector() -> None:
    doc = (REPO_ROOT / "docs" / "architecture" / "connector_inventory.md").read_text(
        encoding="utf-8"
    )
    for name in CONNECTOR_REGISTRY:
        assert f"`{name}`" in doc, f"connector {name} is undocumented"


def test_canonical_powerup_inputs_present() -> None:
    for rel in (
        "docs/architecture/final_powerup_map.md",
        "docs/architecture/build_directive.md",
        "configs/tools/guardian.tool-registry.expanded.yaml",
    ):
        assert (REPO_ROOT / rel).exists(), f"canonical Wave 0 input missing: {rel}"


def test_inventory_render_is_deterministic() -> None:
    a = inventory.build_inventory()
    b = inventory.build_inventory()
    assert inventory._stable(a) == inventory._stable(b)
    assert isinstance(inventory.render_markdown(a), str)


def test_source_dirs_exist() -> None:
    for name in inventory.SOURCE_DIRS:
        assert (REPO_ROOT / name).exists(), f"declared source dir {name} is missing"


def test_no_unsanctioned_subprocess_via_live_scan() -> None:
    # Defence in depth: scan the live tree directly (not via the committed report).
    live = {row["file"] for row in inventory._subprocess_inventory()}  # noqa: SLF001
    assert live <= SANCTIONED_SUBPROCESS_FILES, f"unsanctioned subprocess sites: {live}"


def test_report_path_under_repo() -> None:
    assert REPORT_JSON.is_relative_to(REPO_ROOT)
    assert isinstance(Path(REPORT_JSON), Path)
