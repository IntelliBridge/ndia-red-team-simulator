"""Scanner adapter Protocol + registry."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

from aegis.registry import Registry
from aegis.schema import AegisFinding
from aegis.state import RunState

logger = logging.getLogger(__name__)

# Open capability vocabulary. Adding a capability is a one-line append here;
# a declared capability outside this set logs a warning but still registers,
# so third-party plugins can introduce their own without patching core.
KNOWN_CAPABILITIES: set[str] = {"dast", "sast", "dependency", "iac", "secret", "sbom", "supply_chain"}
Capability = str  # back-compat alias; validated against KNOWN_CAPABILITIES at register()


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
    capabilities: set[str]
    default_timeout: int

    def adapter_version(self) -> str: ...
    def health_check(self) -> bool: ...
    def scan(self, run_state: RunState, options: ScanOptions) -> ScanResult: ...


def _validate(adapter: ScannerAdapter) -> None:
    unknown = set(adapter.capabilities) - KNOWN_CAPABILITIES
    if unknown:
        logger.warning(
            "scanner %r declares unknown capabilities %s; registering anyway",
            adapter.name, sorted(unknown),
        )


_scanner_registry: Registry[ScannerAdapter] = Registry("scanner", validate=_validate)
# Historical public handle: callers and tests pop/iterate this dict directly,
# so it must stay the live backing store (same object as the registry's).
_REGISTRY: dict[str, ScannerAdapter] = _scanner_registry._items

register = _scanner_registry.register
get = _scanner_registry.get


def list_scanners() -> list[str]:
    return _scanner_registry.list_names()


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
    _scanner_registry.maybe_load_entry_points("aegis.scanners")
