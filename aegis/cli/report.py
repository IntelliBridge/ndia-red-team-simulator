"""`aegis report` — generates Markdown / JSON / HTML reports."""

from __future__ import annotations

import aegis.cli.main as _main


def cmd_report(args, config) -> None:
    """Generate Markdown / JSON / HTML reports — thin shell over the service."""
    from aegis.services.reports import render_reports

    state = _main._resolve_run_state(config, args.run)
    findings = _main._load_findings_objects(state)

    if not findings:
        return

    html_flag = not getattr(args, "no_html", False)
    outcome = render_reports(run_state=state, findings=findings, html=html_flag)
    _main._info(f"Report written to {outcome.markdown_path}")
    _main._info(f"JSON report written to {outcome.json_path}")
    if outcome.html_path is not None:
        _main._info(f"HTML report written to {outcome.html_path}")
