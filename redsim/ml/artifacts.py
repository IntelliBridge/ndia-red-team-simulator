"""Artifact sink used by the pure ML modules.

The platform adapts ``RunStateAPI`` / the blob store to this protocol inside
the Celery task; tests use ``FilesystemSink``. Paths returned are run-relative
(e.g. ``artifacts/obs_003/shap_adv.png``) so they can be cited in Observations
and rendered by ``GET /v1/runs/{id}/artifacts/{path}``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class ArtifactSink(Protocol):
    def put(self, name: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        """Store ``data`` under run-relative ``name``; return the run-relative path."""
        ...

    def sha256(self, name: str) -> str: ...


class FilesystemSink:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._hashes: dict[str, str] = {}

    def put(self, name: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        rel = f"artifacts/{name}".replace("//", "/")
        target = (self.root / rel).resolve()
        if self.root.resolve() not in target.parents:
            raise ValueError(f"artifact path escapes run dir: {name!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        self._hashes[rel] = hashlib.sha256(data).hexdigest()
        return rel

    def sha256(self, name: str) -> str:
        return self._hashes[name]
