"""Scanner adapter Protocol + registry."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterable, Literal, Protocol

from aegis.schema import AegisFinding
from aegis.state import RunState


Capability = Literal["dast", "sast", "dependency", "iac", "secret", "sbom"]


@dataclass
class ScanOptions:
    target: str
    instruction: str | None = None
    timeout: int = 1800
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    findings: list[AegisFinding]
    adapter_name: str
    adapter_version: str
    command_str: str
    env_keys: list[str] = field(default_factory=list)
    exit_code: int = 0
    duration_s: float = 0.0
    error: str | None = None


class ScannerAdapter(Protocol):
    name: str
    capabilities: set[Capability]
    default_timeout: int

    def adapter_version(self) -> str: ...
    def health_check(self) -> bool: ...
    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult: ...


_REGISTRY: dict[str, ScannerAdapter] = {}


def register(adapter: ScannerAdapter) -> None:
    _REGISTRY[adapter.name] = adapter


def get(name: str) -> ScannerAdapter:
    if name not in _REGISTRY:
        raise KeyError(f"unknown scanner: {name!r}. "
                       f"available: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def list_scanners() -> list[str]:
    return sorted(_REGISTRY)


def dispatch(name_or_capability: str,
             run_state: RunState,
             options: ScanOptions) -> ScanResult:
    """Run a registered scanner by name; otherwise pick the first scanner
    that claims the given capability."""
    if name_or_capability in _REGISTRY:
        return _REGISTRY[name_or_capability].scan(run_state, options)
    for adapter in _REGISTRY.values():
        if name_or_capability in adapter.capabilities:
            return adapter.scan(run_state, options)
    raise KeyError(f"no scanner registered for {name_or_capability!r}")


def maybe_load_entry_points() -> None:
    """Third-party adapter discovery, gated by AEGIS_PLUGINS=1."""
    if os.environ.get("AEGIS_PLUGINS") != "1":
        return
    try:
        from importlib.metadata import entry_points
        eps = entry_points(group="aegis.scanners")
    except Exception:  # pragma: no cover
        return
    for ep in eps:
        try:
            adapter = ep.load()
            register(adapter())
        except Exception:  # pragma: no cover
            continue
