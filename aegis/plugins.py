"""Community scanner/agent adapter marketplace: discovery + reporting.

The :class:`~aegis.registry.Registry` owns the single discovery code path
(:meth:`~aegis.registry.Registry.scan_entry_points`). This module layers the
public, read-only *report* on top of it: :func:`discover_all` scans both the
``aegis.scanners`` and ``aegis.agents`` entry-point groups and returns a
:class:`PluginInfo` per third-party item, *without* mutating the global
registries (``register=False``). Built-ins never appear because they are
registered eagerly in code, not via entry points — discovery only ever walks
the entry-point groups, so there is no double-counting.

Discovery is gated by ``AEGIS_PLUGINS=1`` and (optionally) the
``AEGIS_PLUGINS_ALLOW`` distribution allowlist; see the README/docs for the
full contract.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass


@dataclass
class PluginInfo:
    """One row of the plugin-discovery report.

    ``status`` is ``"loaded"`` (conformant, registered/registrable),
    ``"rejected"`` (failed to load or non-conformant — never registered), or
    ``"skipped"`` (excluded by ``AEGIS_PLUGINS_ALLOW``). ``detail`` carries the
    reason for rejected/skipped rows and is ``""`` for loaded ones.
    """

    name: str
    kind: str            # "scanner" | "agent"
    group: str           # "aegis.scanners" | "aegis.agents"
    distribution: str | None
    version: str | None
    status: str          # "loaded" | "rejected" | "skipped"
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def discover_all() -> list[PluginInfo]:
    """Report third-party plugins across both groups without registering them.

    Returns ``[]`` when ``AEGIS_PLUGINS != 1`` (discovery disabled). Otherwise
    walks the scanner and agent entry-point groups through the shared
    :meth:`~aegis.registry.Registry.scan_entry_points` path with
    ``register=False`` so the global registries are left untouched.
    """
    if os.environ.get("AEGIS_PLUGINS") != "1":
        return []

    # Imported lazily so importing this module never drags in the scanner/agent
    # subsystems (and their eager built-in registration) until discovery runs.
    from aegis.agents.registry import _agent_registry
    from aegis.scanners.registry import _scanner_registry

    results: list[PluginInfo] = []
    results.extend(_scanner_registry.scan_entry_points("aegis.scanners", register=False))
    results.extend(_agent_registry.scan_entry_points("aegis.agents", register=False))
    return results
