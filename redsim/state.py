"""Filesystem run store (pattern inherited from aegis/state/filesystem.py).

Layout::

    <output_dir>/runs/<run_id>/
        run.json            RunRecord, rewritten after every stage
        artifacts/...       PNGs / JSON written through record_artifact()

Persistence is pure: no auditing, no DB. ``record_artifact`` returns a
content hash so every observation in the report can cite a verifiable file.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

DEFAULT_OUTPUT_DIR = os.environ.get("REDSIM_OUTPUT_DIR", "./redsim_output")


@dataclass(frozen=True)
class ArtifactRef:
    name: str            # run-relative path, e.g. "artifacts/obs_003/shap_adv.png"
    sha256: str
    size_bytes: int
    content_type: str = "application/octet-stream"


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]


class RunStore:
    """Per-run directory under ``output_dir/runs/<run_id>/``."""

    def __init__(self, output_dir: str | Path = DEFAULT_OUTPUT_DIR, run_id: str | None = None):
        self.output_dir = Path(output_dir)
        self.run_id = run_id or new_run_id()
        self.run_path = self.output_dir / "runs" / self.run_id
        self.run_path.mkdir(parents=True, exist_ok=True)

    # -- run record -------------------------------------------------------
    @property
    def record_path(self) -> Path:
        return self.run_path / "run.json"

    def save_record(self, record: dict[str, Any]) -> None:
        tmp = self.record_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(record, indent=2, default=str))
        tmp.replace(self.record_path)

    def load_record(self) -> dict[str, Any] | None:
        if not self.record_path.exists():
            return None
        return json.loads(self.record_path.read_text())

    # -- artifacts --------------------------------------------------------
    @property
    def artifacts_path(self) -> Path:
        return self.run_path / "artifacts"

    def record_artifact(self, name: str, content: bytes | str,
                        content_type: str = "application/octet-stream") -> ArtifactRef:
        data = content.encode("utf-8") if isinstance(content, str) else content
        rel = Path("artifacts") / name
        target = self.resolve(str(rel))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return ArtifactRef(
            name=str(rel), sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data), content_type=content_type,
        )

    def resolve(self, rel_path: str) -> Path:
        """Resolve a run-relative path, refusing anything that escapes the run dir."""
        candidate = (self.run_path / rel_path).resolve()
        root = self.run_path.resolve()
        if root != candidate and root not in candidate.parents:
            raise ValueError(f"path escapes run directory: {rel_path!r}")
        return candidate

    # -- listing ----------------------------------------------------------
    @classmethod
    def list_run_ids(cls, output_dir: str | Path = DEFAULT_OUTPUT_DIR) -> list[str]:
        runs_dir = Path(output_dir) / "runs"
        if not runs_dir.exists():
            return []
        return sorted((d.name for d in runs_dir.iterdir() if d.is_dir()), reverse=True)

    @classmethod
    def open(cls, run_id: str, output_dir: str | Path = DEFAULT_OUTPUT_DIR) -> "RunStore | None":
        path = Path(output_dir) / "runs" / run_id
        if not path.is_dir():
            return None
        return cls(output_dir, run_id)
