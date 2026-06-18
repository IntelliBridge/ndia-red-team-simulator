"""`aegis init` — writes a default aegis.yaml into the current directory."""

from __future__ import annotations

import argparse

import aegis.cli.main as _main
from aegis.cli import _console
from aegis.config import AegisConfig


def cmd_init(_args: argparse.Namespace, _config: AegisConfig) -> None:
    """Create a default aegis.yaml in the current directory."""
    target = _main.Path("aegis.yaml")
    if target.exists():
        _console._warn("aegis.yaml already exists — skipping.")
        return

    import dataclasses

    from aegis.config import AegisConfig

    defaults = AegisConfig()
    lines = ["# Aegis configuration\n"]
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
