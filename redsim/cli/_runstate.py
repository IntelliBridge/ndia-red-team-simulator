"""Run-state resolution helpers shared by the read-side command modules.

``export`` / ``fix`` / ``report`` all begin by resolving a
``RunState`` (specific run id or latest) and loading its findings as
``RedsimFinding`` objects. Those two helpers lived on ``redsim.cli.main`` and
were reached via ``_main._resolve_run_state(...)``; hosting them on this peer
lets the command modules depend on a focused helper rather than the CLI entry
point.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from redsim.cli._console import _err, _warn

if TYPE_CHECKING:
    from redsim.config import RedsimConfig
    from redsim.schema import RedsimFinding
    from redsim.state import RunState, RunStateAPI


def _resolve_run_state(config: RedsimConfig, run_id: str | None = None) -> RunState:
    """Return a RunState for the given (or latest) run, or exit with error."""
    from redsim.state import RunState

    if run_id:
        return RunState(config.output_dir, run_id)

    state = RunState.latest_run(config.output_dir)
    if state is None:
        _err("No runs found. Run 'redsim scan' first.")
        sys.exit(1)
    return state


def _load_findings_objects(state: RunStateAPI) -> list[RedsimFinding]:
    """Load findings from state and convert to RedsimFinding objects."""
    from redsim.schema import RedsimFinding

    raw = state.load_findings()
    if not raw:
        _warn("No findings in this run.")
        return []
    return [RedsimFinding.from_dict(f) for f in raw]
