"""Redsim CLI package.

The original ``redsim/cli.py`` was promoted to ``redsim/cli/main.py``, and each
subcommand now lives in its own module (``redsim.cli.scan``, ``redsim.cli.verify``,
…) mirroring the already-extracted ``status`` / ``audit`` / ``migrate``
siblings. ``main.py`` keeps only the argument-parser builder and
the dispatch loop, and re-exports each ``cmd_*`` from its new per-command
module. Tests and tooling that import ``redsim.cli`` keep working via the
re-exports below; each name resolves to the function defined in its own
``redsim.cli.<command>`` module.
"""

from redsim.cli.main import (
    build_parser,
    cmd_doctor,
    cmd_findings,
    cmd_init,
    cmd_report,
    cmd_scan,
    cmd_verify,
    main,
)

__all__ = [
    "build_parser", "main",
    "cmd_doctor", "cmd_init", "cmd_scan", "cmd_findings",
    "cmd_verify", "cmd_report",
]
