"""Run-state persistence package.

Public surface for both backends and the selector live here so call sites
keep importing ``from aegis.state import ...`` regardless of internal layout:

  - ``RunStateAPI``      shared Protocol every backend implements (facade)
  - ``ArtifactRef``      content-addressable artifact handle (facade)
  - ``FilesystemRunState`` / ``RunState`` (alias)  offline default backend
  - ``PostgresRunState``  DB-backed backend used by the API/workers
  - ``open_run_state``    per-environment backend selector

``PostgresRunState`` is resolved lazily (PEP 562): importing it pulls in
SQLAlchemy, which only ships in the ``api``/``worker`` extras. Eagerly
importing it here would break the offline/base install (and the lightweight
``unit`` CI job) for callers that only need the filesystem backend.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from aegis.state.facade import ArtifactRef, RunStateAPI
from aegis.state.factory import open_run_state
from aegis.state.filesystem import FilesystemRunState, RunState

if TYPE_CHECKING:
    from aegis.state.postgres import PostgresRunState

__all__ = [
    "ArtifactRef",
    "FilesystemRunState",
    "PostgresRunState",
    "RunState",
    "RunStateAPI",
    "open_run_state",
]


def __getattr__(name: str) -> Any:
    if name == "PostgresRunState":
        from aegis.state.postgres import PostgresRunState

        return PostgresRunState
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
