"""Guardian dashboard — a small read-only FastAPI app surfacing scope, guardrails,
simulators, agents, and the latest evidence reports + audit-chain status.

Run:  uvicorn dashboard.app:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from agents import REGISTRY as AGENTS
from citadel.root_of_trust import PlatformInventory, platform_integrity_summary
from core.audit import AuditLog
from core.config import REPO_ROOT, load_config
from core.guardrails import BLOCKED_ACTIONS, GLOBAL_APPROVAL_REQUIRED, check_scope
from core.scope import load_scope
from simulators import PLANNED, REGISTRY as SIMULATORS

app = FastAPI(title="INVISABLE Guardian", version="0.1.0")

# Citadel Platform Integrity (Wave 21): the dashboard renders whatever the configured platform
# inventory holds. Default is an empty inventory — honestly "no platforms enrolled here yet" —
# replaced by the live root-of-trust inventory in a deployed environment.
_PLATFORM_INVENTORY = PlatformInventory()


def set_platform_inventory(inventory: PlatformInventory) -> None:
    """Wire a live platform inventory into the Platform Integrity screen."""
    global _PLATFORM_INVENTORY
    _PLATFORM_INVENTORY = inventory

SCOPE_DIR = REPO_ROOT / "scope"
REPORTS_DIR = REPO_ROOT / "reports" / "generated"


def _scopes() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in sorted(SCOPE_DIR.glob("*.yaml")):
        if path.name in {"assets.yaml", "test_accounts.yaml"}:
            continue
        try:
            scope = load_scope(path)
        except Exception as exc:  # surface invalid scopes rather than hide them
            out.append({"file": path.name, "error": str(exc)})
            continue
        out.append(
            {
                "file": path.name,
                "asset": scope.asset,
                "environment": scope.environment,
                "modes": scope.allowed_modes,
                "notes": check_scope(scope),
            }
        )
    return out


def _recent_reports(limit: int = 10) -> list[dict[str, Any]]:
    if not REPORTS_DIR.exists():
        return []
    items = []
    for p in sorted(REPORTS_DIR.glob("*.json"), reverse=True)[:limit]:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        items.append(
            {
                "file": p.name,
                "scenario": data.get("scenario_name"),
                "severity": data.get("severity"),
                "detection": data.get("detection_result"),
            }
        )
    return items


@app.get("/api/status")
def status() -> dict[str, Any]:
    cfg = load_config()
    return {
        "version": cfg.version,
        "dry_run_default": cfg.dry_run_default,
        "fail_closed": cfg.fail_closed,
        "require_human_approval": cfg.require_human_approval,
        "audit_chain_ok": AuditLog().verify(),
        "blocked_actions": sorted(BLOCKED_ACTIONS),
        "approval_required": sorted(GLOBAL_APPROVAL_REQUIRED),
        "agents": sorted(AGENTS),
        "simulators": sorted(SIMULATORS),
        "planned_simulators": list(PLANNED),
        "scopes": _scopes(),
        "recent_reports": _recent_reports(),
    }


@app.get("/api/platform-integrity")
def platform_integrity() -> dict[str, Any]:
    """Citadel Platform Integrity (System 21): platform inventory, attestation + drift state."""
    return platform_integrity_summary(_PLATFORM_INVENTORY)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
