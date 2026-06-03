"""Aegis CLI package.

The original ``aegis/cli.py`` was promoted to ``aegis/cli/main.py``, and each
subcommand now lives in its own module (``aegis.cli.scan``, ``aegis.cli.fix``,
…) mirroring the already-extracted ``status`` / ``audit`` / ``migrate`` /
``ci_gate`` siblings. ``main.py`` keeps only the argument-parser builder and
the dispatch loop, and re-exports each ``cmd_*`` from its new per-command
module. Tests and tooling that import ``aegis.cli`` keep working via the
re-exports below; each name resolves to the function defined in its own
``aegis.cli.<command>`` module.
"""

from aegis.cli.main import (
    build_parser,
    cmd_demo,
    cmd_doctor,
    cmd_export,
    cmd_findings,
    cmd_fix,
    cmd_init,
    cmd_pipeline,
    cmd_report,
    cmd_scan,
    cmd_targets,
    cmd_verify,
    main,
)

__all__ = [
    "build_parser", "main",
    "cmd_doctor", "cmd_init", "cmd_scan", "cmd_findings", "cmd_export",
    "cmd_fix", "cmd_verify", "cmd_report", "cmd_pipeline", "cmd_demo",
    "cmd_targets",
]
