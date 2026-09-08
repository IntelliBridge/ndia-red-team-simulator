"""`redsim verify` — verifies a finding by replaying its PoC."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from redsim.cli import _console, _runstate
from redsim.config import RedsimConfig


def _cmd_verify_api(args: argparse.Namespace, _config: RedsimConfig) -> None:
    from redsim.cli import api_client

    client = api_client.build_client()
    try:
        result = client.verify(finding_id=args.finding_id)
    except api_client.ApiError as exc:
        _console._err(f"verify rejected by API: {exc}")
        sys.exit(1)
    _console._info(f"Job ID: {result.get('job_id')}")


def cmd_verify(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Verify a finding by replaying its PoC — thin shell over the service.

    F4: when ``--api`` / ``REDSIM_MODE=api`` is set, dispatches to the API.
    """
    from redsim.cli import api_client

    if api_client.is_api_mode(args):
        return _cmd_verify_api(args, config)

    from redsim.services.verify import verify as verify_svc

    state = _runstate._resolve_run_state(config, args.run)
    findings = _runstate._load_findings_objects(state)
    target = next((f for f in findings if f.id == args.finding_id), None)
    if target is None:
        _console._err(f"Finding '{args.finding_id}' not found in run {state.run_id}.")
        sys.exit(1)

    repo_path = Path(args.repo) if args.repo else None
    result = verify_svc(
        run_state=state,
        finding=target,
        repo_path=repo_path,
        require_rebuilt=not args.no_provenance_check,
        actor="cli:verify",
        config=config,
    )

    status_color = {
        "verified": _console._GREEN,
        "still_vulnerable": _console._RED,
        "inconclusive": _console._YELLOW,
    }.get(result.status, "")
    print()
    print(f"{_console._BOLD}Verification result{_console._RESET}")
    print(f"  Finding:  {result.finding_id}")
    print(f"  Strategy: {result.strategy}")
    print(f"  Status:   {status_color}{result.status}{_console._RESET}")
    if result.notes:
        print(f"  Notes:    {result.notes}")
    print(f"  Saved to: {state.run_path / 'verify' / (result.finding_id + '.json')}")
