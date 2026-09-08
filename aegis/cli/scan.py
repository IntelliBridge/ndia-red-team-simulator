"""`aegis scan` — thin CLI shell over ``services.scans.start_scan``."""

from __future__ import annotations

import argparse
import sys

from aegis.cli import _console
from aegis.config import AegisConfig


def _cmd_scan_api(args: argparse.Namespace, _config: AegisConfig) -> None:
    from aegis.cli import api_client

    client = api_client.build_client()
    try:
        result = client.start_scan(
            target=args.target_url,
            scanner=args.scanner,
            project_id=getattr(args, "project_id", None) or "default",
            instruction=getattr(args, "instruction", None),
            override_authorized=getattr(args, "override_authorized", False),
        )
    except api_client.ApiError as exc:
        _console._err(f"scan rejected by API: {exc}")
        sys.exit(1)
    _console._info(f"Run ID: {result.get('run_id')}")
    _console._info(f"Job ID: {result.get('job_id')}")
    if result.get("status_url"):
        _console._info(f"Status: {result['status_url']}")


def cmd_scan(args: argparse.Namespace, config: AegisConfig) -> None:
    """Scan a target — thin CLI shell over ``services.scans.start_scan``.

    Every scan dispatches through the scanner-adapter registry
    (``services.scans.start_scan`` -> ``aegis.scanners.dispatch``). The pentest
    engines and the offline events.jsonl loader were removed with the pentest
    domain; the adversarial-ML attack adapters (``aegis.ml.attacks``) register
    in the same registry. When no adapter is registered for ``--scanner`` the
    command fails loudly (exit 1) and writes no findings — never a faked empty
    run that ``aegis report`` would render as clean.

    F4: when ``--api`` / ``AEGIS_MODE=api`` is set, dispatches the scan
    via ``aegis.cli.api_client`` and returns the run handle.
    """
    from aegis.cli import api_client
    from aegis.services.scans import start_scan
    from aegis.state import RunState

    if api_client.is_api_mode(args):
        return _cmd_scan_api(args, config)

    target_url = args.target_url
    scanner = args.scanner

    state = RunState(config.output_dir)
    _console._info(f"Run ID: {state.run_id}")
    _console._info(f"Target: {target_url}")
    _console._info(f"Dispatching {scanner!r} through the scanner-adapter registry")

    try:
        outcome = start_scan(
            run_state=state, target=target_url, scanner=scanner,
            instruction=getattr(args, "instruction", None),
            timeout=getattr(args, "timeout", 1800),
            actor="cli:scan",
            config=config,
            override_authorized=getattr(args, "override_authorized", False),
        )
    except KeyError as exc:
        # Honest failure: no findings.json is written, exit non-zero, so a CI
        # caller cannot mistake "no adapter" for "clean scan".
        _console._err(
            f"No scanner adapter registered for {scanner!r}: {exc}. "
            f"Register an ML attack adapter (aegis.ml.attacks) or run in "
            f"--api mode."
        )
        sys.exit(1)

    findings = outcome.findings
    if outcome.success:
        _console._info(f"Scan completed: {len(findings)} finding(s)")
    elif outcome.partial_success:
        _console._warn(f"Scanner exited rc={outcome.return_code} but emitted "
                       f"{len(findings)} finding(s) — partial success")
    else:
        _console._err(f"Scan failed: {outcome.error or 'unknown error'}")
        sys.exit(1)

    state.save_findings(findings)
    _console._info(f"Saved {len(findings)} finding(s) to {state.findings_path}")

    # Summary
    if findings:
        print()
        print(f"{_console._BOLD}Scan Summary{_console._RESET}")
        print(f"  Findings: {len(findings)}")
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity.lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        for sev in ("critical", "high", "medium", "low"):
            count = sev_counts.get(sev, 0)
            if count:
                print(f"  {_console._colored_severity(sev)}: {count}")
