"""`aegis export` — exports findings to external tool formats."""

from __future__ import annotations

import sys

from aegis.cli import _console, _runstate


def cmd_export(args, config) -> None:
    """Export findings to vulnerability-fixer format."""
    if args.format != "vulnfixer":
        _console._err(f"Unsupported export format: {args.format}")
        sys.exit(1)

    state = _runstate._resolve_run_state(config, args.run)
    findings = _runstate._load_findings_objects(state)

    if not findings:
        return

    from aegis.runners.vulnfixer_converter import export_findings

    output_path = state.run_path / "vulnfixer-export.json"
    summary = export_findings(findings, output_path)

    _console._info(f"Exported to {output_path}")
    print()
    print(f"{_console._BOLD}Export Summary{_console._RESET}")
    print(f"  Total findings:          {summary['total']}")
    print(f"  Routable to vulnfixer:   {summary['routable_to_vulnfixer']}")
    print(f"  Requires code fix (CAI): {summary['requires_code_fix']}")
