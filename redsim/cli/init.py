"""`redsim init` — writes a default redsim.yaml into the current directory."""

from __future__ import annotations

import argparse

import redsim.cli.main as _main
from redsim.cli import _console
from redsim.config import RedsimConfig


def cmd_init(_args: argparse.Namespace, _config: RedsimConfig) -> None:
    """Create a default redsim.yaml in the current directory."""
    target = _main.Path("redsim.yaml")
    if target.exists():
        _console._warn("redsim.yaml already exists — skipping.")
        return

    import dataclasses

    from redsim.config import RedsimConfig

    defaults = RedsimConfig()
    lines = ["# Redsim configuration\n"]
    for f in dataclasses.fields(defaults):
        val = getattr(defaults, f.name)
        if isinstance(val, list):
            lines.append(f"{f.name}:")
            for item in val:
                lines.append(f"  - \"{item}\"")
        elif isinstance(val, str):
            lines.append(f"{f.name}: \"{val}\"")
        else:
            lines.append(f"{f.name}: {val}")
    lines.append("")

    target.write_text("\n".join(lines))
    _console._info(f"Created {target.resolve()}")
