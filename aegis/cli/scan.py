"""`aegis scan` — thin CLI shell over ``services.scans.start_scan``."""

from __future__ import annotations

import sys

import aegis.cli.main as _main
from aegis.cli import _console


def _cmd_scan_api(args, _config):
    from aegis.cli import api_client

    client = api_client.build_client()
    try:
        result = client.start_scan(
            target=args.target_url,
            project_id=getattr(args, "project_id", None) or "default",
            scanner=getattr(args, "scanner", None) or "strix",
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


def cmd_scan(args, config) -> None:
    """Scan a target — thin CLI shell over ``services.scans.start_scan``.

    Local-only conveniences (loading pre-existing Strix events.jsonl,
    bundled demo fixture) stay at this layer; everything that needs an
    audit event lives behind the service boundary.

    F4: when ``--api`` / ``AEGIS_MODE=api`` is set, dispatches the scan
    via ``aegis.cli.api_client`` and returns the run handle.
    """
    from aegis.cli import api_client
    from aegis.runners.strix_converter import convert_strix_findings, load_strix_events
    from aegis.services.scans import start_scan
    from aegis.state import RunState

    if api_client.is_api_mode(args):
        return _cmd_scan_api(args, config)

    target_url = args.target_url
    repo_path = args.repo

    state = RunState(config.output_dir)
    _console._info(f"Run ID: {state.run_id}")
    _console._info(f"Target: {target_url}")

    findings = []

    if getattr(args, "use_strix", False):
        _console._info("Launching Strix as a subprocess (this may take a while)")
        outcome = start_scan(
            run_state=state, target=target_url, scanner="strix",
            instruction=getattr(args, "instruction", None),
            timeout=getattr(args, "timeout", 1800),
            actor="cli:scan",
            config=config,
            override_authorized=getattr(args, "override_authorized", False),
            use_strix=True,
        )
        findings = outcome.findings
        if outcome.success:
            _console._info(f"Strix completed: {len(findings)} finding(s)")
        elif outcome.partial_success:
            _console._warn(f"Strix exited rc={outcome.return_code} but emitted "
                        f"{len(findings)} finding(s) — partial success")
        else:
            _console._err(f"Strix failed: {outcome.error or 'unknown error'}")

    # Try to load Strix events.jsonl from an explicit path or the repo path.
    events_path = _main.Path(args.events) if getattr(args, "events", None) else None
    if events_path is None and repo_path and not findings:
        events_path = _main.Path(repo_path) / "events.jsonl"

    if not findings and events_path is not None:
        if events_path.exists():
            _console._info(f"Loading Strix events from {events_path}")
            findings = load_strix_events(str(events_path), state.run_id)
        else:
            _console._warn(f"Strix events file not found: {events_path}")

    # Demo mode: load fixture only when explicitly requested.
    if not findings and getattr(args, "demo", False):
        fixture = _main.Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "strix_finding.json"
        if fixture.exists():
            _console._info(f"Loading demo fixture from {fixture}")
            with _main.open(fixture) as fh:
                raw = _main.json.load(fh)
            raw_list = raw if isinstance(raw, list) else [raw]
            findings = convert_strix_findings(raw_list, state.run_id)
        else:
            _console._warn("Demo fixture not found. No findings to process.")
    elif not findings:
        _console._warn("No Strix findings loaded. Provide --events, --repo with events.jsonl, or --demo.")

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
