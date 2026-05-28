"""Aegis CLI package.

The original ``aegis/cli.py`` was promoted to ``aegis/cli/main.py`` so the
package can host additive subcommand modules (``status``, ``audit``,
``migrate``). Tests and tooling that import ``aegis.cli`` keep working via
the re-exports below.
"""

from aegis.cli.main import (
    build_parser,
    main,
    cmd_doctor,
    cmd_init,
    cmd_scan,
    cmd_findings,
    cmd_export,
    cmd_fix,
    cmd_verify,
    cmd_report,
    cmd_pipeline,
    cmd_demo,
    cmd_targets,
)

__all__ = [
    "build_parser", "main",
    "cmd_doctor", "cmd_init", "cmd_scan", "cmd_findings", "cmd_export",
    "cmd_fix", "cmd_verify", "cmd_report", "cmd_pipeline", "cmd_demo",
    "cmd_targets",
]
