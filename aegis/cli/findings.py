"""`aegis findings` — displays findings from a run as a table."""

from __future__ import annotations

import argparse

from aegis.cli import _console, _runstate
from aegis.config import AegisConfig


def cmd_findings(args: argparse.Namespace, config: AegisConfig) -> None:
    """Display findings as a table."""
    state = _runstate._resolve_run_state(config, args.run)
    findings = state.load_findings()

    if not findings:
        _console._warn("No findings in this run.")
        return

    _console._info(f"Run: {state.run_id}  ({len(findings)} finding(s))")
    print()

    # Table header
    hdr_fmt = "{:<14}  {:<10}  {:<45}  {:<12}  {:<14}"

    print(hdr_fmt.format("ID", "Severity", "Title", "Type", "Status"))
    print("-" * 100)

    for f in findings:
        sev_raw = f.get("severity", "unknown")
        # For colored severity we need to account for ANSI escape width
        sev_display = _console._colored_severity(sev_raw)
        title = f.get("title", "")
        if len(title) > 45:
            title = title[:42] + "..."
        # Print with manual padding since ANSI codes mess up format widths
        fid = f.get("id", "?")
        ftype = f.get("finding_type", "?")
        status = f.get("status", "?")
        print(f"{fid:<14}  {sev_display}{' ' * max(0, 10 - len(sev_raw.upper()) )}"
              f"  {title:<45}  {ftype:<12}  {status:<14}")
