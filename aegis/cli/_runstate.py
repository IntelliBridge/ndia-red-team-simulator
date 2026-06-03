"""Run-state resolution helpers shared by the read-side command modules.

``export`` / ``fix`` / ``report`` / ``verify`` all begin by resolving a
``RunState`` (specific run id or latest) and loading its findings as
``AegisFinding`` objects. Those two helpers lived on ``aegis.cli.main`` and
were reached via ``_main._resolve_run_state(...)``; hosting them on this peer
lets the command modules depend on a focused helper rather than the CLI entry
point.
"""

from __future__ import annotations

import sys

from aegis.cli._console import _err, _warn


def _resolve_run_state(config, run_id: str | None = None):
    """Return a RunState for the given (or latest) run, or exit with error."""
    from aegis.state import RunState

    if run_id:
        return RunState(config.output_dir, run_id)

    state = RunState.latest_run(config.output_dir)
    if state is None:
        _err("No runs found. Run 'aegis scan' first.")
        sys.exit(1)
    return state


def _load_findings_objects(state):
    """Load findings from state and convert to AegisFinding objects."""
    from aegis.schema import AegisFinding

    raw = state.load_findings()
    if not raw:
        _warn("No findings in this run.")
        return []
    return [AegisFinding.from_dict(f) for f in raw]
