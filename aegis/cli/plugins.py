"""``aegis plugins list`` — inspect the community adapter marketplace.

Surfaces :func:`aegis.plugins.discover_all` (the read-only discovery report) as
either a human-readable table or a ``--json`` array. Discovery is gated by
``AEGIS_PLUGINS=1``; when it's off this command prints a clear hint and exits 0
rather than silently returning nothing.
"""

from __future__ import annotations

import json
import os

from aegis.cli import _console
from aegis.plugins import discover_all


def cmd_plugins(args, config) -> None:
    """Dispatch the ``plugins`` subcommands (currently only ``list``)."""
    action = getattr(args, "plugins_action", None)
    if action == "list":
        _cmd_plugins_list(args, config)
    else:  # pragma: no cover - argparse marks the subparser required
        _console._err(f"Unknown plugins action: {action}")
        raise SystemExit(2)


def _cmd_plugins_list(args, config) -> None:
    discovery_on = os.environ.get("AEGIS_PLUGINS") == "1"
    plugins = discover_all()

    if getattr(args, "json", False):
        print(json.dumps([p.to_dict() for p in plugins], indent=2))
        return

    if not discovery_on:
        _console._warn(
            "plugin discovery is disabled; set AEGIS_PLUGINS=1 to enable "
            "third-party adapter discovery"
        )
        return

    if not plugins:
        _console._info("no third-party plugins discovered")
        return

    _console._info(f"{len(plugins)} third-party plugin(s) discovered")
    print()
    hdr_fmt = "{:<22}  {:<8}  {:<22}  {:<12}  {:<9}  {}"
    print(hdr_fmt.format(
        "NAME", "KIND", "DISTRIBUTION", "VERSION", "STATUS", "DETAIL"))
    print("-" * 100)
    for p in plugins:
        print(hdr_fmt.format(
            _trunc(p.name, 22),
            _trunc(p.kind, 8),
            _trunc(p.distribution or "-", 22),
            _trunc(p.version or "-", 12),
            _trunc(p.status, 9),
            p.detail or "",
        ))


def _trunc(value: str, width: int) -> str:
    if len(value) > width:
        return value[: width - 3] + "..."
    return value
