"""``aegis ci-gate`` — pipeline-gating subcommand."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis.config import AegisConfig
from aegis.policy.ci_gate import CIGatePolicy, evaluate


def cmd_ci_gate(args: argparse.Namespace, config: AegisConfig) -> None:
    findings: list[dict] = []
    if args.findings_file:
        path = Path(args.findings_file)
        if not path.exists():
            print(f"findings file not found: {path}", file=sys.stderr)
            sys.exit(2)
        findings = json.loads(path.read_text())
    elif args.run:
        from aegis.state import FilesystemRunState
        state = FilesystemRunState(config.output_dir, run_id=args.run)
        findings = state.load_findings()
    else:
        print("either --findings-file or --run must be provided",
              file=sys.stderr)
        sys.exit(2)

    policy = CIGatePolicy(
        severity_threshold=args.severity_threshold,
        max_findings=args.max_findings,
        require_validated=args.require_validated,
    )
    exit_code, reason = evaluate(findings, policy)
    print(json.dumps({
        "exit_code": exit_code, "reason": reason,
        "evaluated": len(findings),
    }, indent=2))

    if args.junit_xml:
        _write_junit(findings, exit_code, reason, args.junit_xml)
    sys.exit(exit_code)


def _write_junit(findings: list[dict], exit_code: int, reason: str,
                 path: str) -> None:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<testsuite name="aegis-ci-gate" tests="1" failures="{}">'.format(
            1 if exit_code != 0 else 0),
        '  <testcase name="ci-gate">',
    ]
    if exit_code != 0:
        lines.append(f'    <failure message="{reason}"/>')
    lines.append('  </testcase>')
    lines.append('</testsuite>')
    Path(path).write_text("\n".join(lines))
