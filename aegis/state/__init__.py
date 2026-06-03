"""Run-state persistence package.

Public surface for both backends and the selector live here so call sites
keep importing ``from aegis.state import ...`` regardless of internal layout:

  - ``RunStateAPI``      shared Protocol every backend implements (facade)
  - ``ArtifactRef``      content-addressable artifact handle (facade)
  - ``FilesystemRunState`` / ``RunState`` (alias)  offline default backend
  - ``PostgresRunState``  DB-backed backend used by the API/workers
  - ``open_run_state``    per-environment backend selector
"""

from __future__ import annotations

from aegis.state.facade import ArtifactRef, RunStateAPI
from aegis.state.factory import open_run_state
from aegis.state.filesystem import FilesystemRunState, RunState
from aegis.state.postgres import PostgresRunState

__all__ = [
    "ArtifactRef",
    "FilesystemRunState",
    "PostgresRunState",
    "RunState",
    "RunStateAPI",
    "open_run_state",
]
