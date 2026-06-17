"""`aegis report` — generates Markdown / JSON / HTML reports."""

from __future__ import annotations

import argparse

from aegis.cli import _console, _runstate
from aegis.config import AegisConfig


def cmd_report(args: argparse.Namespace, config: AegisConfig) -> None:
    """Generate Markdown / JSON / HTML reports — thin shell over the service."""
    from aegis.services.reports import render_reports

    state = _runstate._resolve_run_state(config, args.run)
    findings = _runstate._load_findings_objects(state)

    if not findings:
        return

    html_flag = not getattr(args, "no_html", False)
    outcome = render_reports(run_state=state, findings=findings, html=html_flag)
    _console._info(f"Report written to {outcome.markdown_path}")
    _console._info(f"JSON report written to {outcome.json_path}")
    if outcome.html_path is not None:
        _console._info(f"HTML report written to {outcome.html_path}")
