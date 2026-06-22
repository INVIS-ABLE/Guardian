"""CLI for the simulator library.

    python -m simulators list
    python -m simulators run privacy_leak --scope scope/invisable-staging.yaml [--dry-run|--no-dry-run]
"""

from __future__ import annotations

import argparse
import json
import sys

from core.scope import load_scope

from . import PLANNED, REGISTRY


def _cmd_list() -> int:
    print("Available simulators:")
    for name, cls in sorted(REGISTRY.items()):
        doc = (cls.__doc__ or "").strip().splitlines()[0] if cls.__doc__ else ""
        print(f"  {name:24s} {doc}")
    print("\nPlanned (not yet implemented):")
    for name in PLANNED:
        print(f"  {name}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    if args.name not in REGISTRY:
        print(f"Unknown simulator '{args.name}'. Try: python -m simulators list", file=sys.stderr)
        return 2
    scope = load_scope(args.scope)
    sim = REGISTRY[args.name](scope, dry_run=args.dry_run)
    result = sim.run_and_report() if args.report else sim.run()
    print(json.dumps(result.to_dict(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="simulators")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list simulators")

    run = sub.add_parser("run", help="run a simulator")
    run.add_argument("name")
    run.add_argument("--scope", required=True, help="path to a scope file")
    run.add_argument("--report", action="store_true", help="also write an evidence report")
    group = run.add_mutually_exclusive_group()
    group.add_argument("--dry-run", dest="dry_run", action="store_true", default=True)
    group.add_argument("--no-dry-run", dest="dry_run", action="store_false")

    args = parser.parse_args(argv)
    if args.command == "list":
        return _cmd_list()
    if args.command == "run":
        return _cmd_run(args)
    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
