"""`aegis pipeline` — runs scan -> findings -> export -> report end to end."""

from __future__ import annotations

import argparse
import sys

import aegis.cli.main as _main


def cmd_pipeline(args, config) -> None:
    """Run the full pipeline: scan -> findings -> export -> report."""
    print(f"{_main._BOLD}Aegis Pipeline{_main._RESET}")
    print("=" * 50)

    # Step 1: Scan
    print(f"\n{_main._BOLD}[1/4] Scan{_main._RESET}")
    _main.cmd_scan(args, config)

    # Grab the latest run for subsequent steps
    from aegis.state import RunState

    state = RunState.latest_run(config.output_dir)
    if state is None:
        _main._err("Scan produced no run state.")
        sys.exit(1)

    # Step 2: Findings
    print(f"\n{_main._BOLD}[2/4] Findings{_main._RESET}")
    findings_args = argparse.Namespace(run=state.run_id)
    _main.cmd_findings(findings_args, config)

    # Step 3: Export
    print(f"\n{_main._BOLD}[3/4] Export{_main._RESET}")
    export_args = argparse.Namespace(format="vulnfixer", run=state.run_id)
    _main.cmd_export(export_args, config)

    # Step 4: Report
    print(f"\n{_main._BOLD}[4/4] Report{_main._RESET}")
    report_args = argparse.Namespace(run=state.run_id)
    _main.cmd_report(report_args, config)

    # Final summary
    findings = state.load_findings()
    print()
    print("=" * 50)
    print(f"{_main._BOLD}Pipeline complete.{_main._RESET}")
    print(f"  Run ID:   {state.run_id}")
    print(f"  Findings: {len(findings)}")
    print(f"  Output:   {state.run_path}")
