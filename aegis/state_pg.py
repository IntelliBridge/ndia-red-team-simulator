"""Postgres-backed implementation of ``RunStateAPI``.

Writes are pure persistence — no audit events emitted here. The service
layer is the only place audit events are written (Phase 3 M2).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.db.models import Artifact, Finding, RemediationAttempt, Run
from aegis.state_facade import ArtifactRef


def _now() -> datetime:
    return datetime.now(timezone.utc)


class PostgresRunState:
    """``RunStateAPI`` over Postgres + a pluggable blob backend.

    ``blob_store`` defaults to a filesystem backend; M9 swaps in S3.
    """

    def __init__(self, session: Session, *, run_id: str,
                 project_id: str, output_dir: str | Path,
                 blob_store=None, created_by: str | None = None):
        self.session = session
        self.run_id = run_id
        self.project_id = project_id
        self.run_path = Path(output_dir) / "runs" / run_id
        self.run_path.mkdir(parents=True, exist_ok=True)
        self.created_by = created_by
        if blob_store is None:
            from aegis.blobs import FilesystemBlobStore
            blob_store = FilesystemBlobStore(Path(output_dir) / "blobs")
        self.blob_store = blob_store

        existing = session.get(Run, run_id)
        if existing is None:
            session.add(Run(
                id=run_id, project_id=project_id, mode="live",
                status="running", created_by=created_by, stage_table={},
            ))
            session.flush()

    # ---- Phase 2 path properties (still useful for offline interop) -------

    @property
    def findings_path(self) -> Path:
        return self.run_path / "findings.json"

    @property
    def artifacts_path(self) -> Path:
        return self.run_path / "artifacts"

    @property
    def remediation_log_path(self) -> Path:
        return self.run_path / "remediation-log.json"

    @property
    def report_path(self) -> Path:
        return self.run_path / "report.md"

    # ---- Findings ---------------------------------------------------------

    def save_findings(self, findings: list) -> None:
        existing = self.session.execute(
            select(Finding).where(Finding.run_id == self.run_id)
        ).scalars().all()
        existing_ids = {f.id for f in existing}
        for raw in findings:
            data = raw.to_dict() if hasattr(raw, "to_dict") else dict(raw)
            fid = data["id"]
            if fid in existing_ids:
                row = next(f for f in existing if f.id == fid)
                row.schema_blob = data
                row.status = data.get("status", row.status)
                row.severity = data.get("severity", row.severity)
                row.updated_at = _now()
            else:
                self.session.add(Finding(
                    id=fid, run_id=self.run_id, project_id=self.project_id,
                    schema_blob=data, status=data.get("status", "open"),
                    severity=data.get("severity", "low"),
                    source_tool=data.get("source_tool"),
                ))
        self.session.flush()

    def load_findings(self) -> list[dict]:
        rows = self.session.execute(
            select(Finding).where(Finding.run_id == self.run_id)
            .order_by(Finding.created_at)
        ).scalars().all()
        return [r.schema_blob for r in rows]

    def update_finding_status(self, finding_id: str, status: str) -> None:
        row = self.session.get(Finding, finding_id)
        if row is not None:
            row.status = status
            row.schema_blob = {**row.schema_blob, "status": status,
                               "updated_at": _now().isoformat()}
            row.updated_at = _now()
            self.session.flush()

    # ---- Artifacts --------------------------------------------------------

    def save_artifact(self, name: str, content) -> Path:
        """Phase 2-style artifact write under run_path/artifacts/. Kept for
        backwards compatibility; ``record_artifact`` is the canonical path
        in Phase 3."""
        self.artifacts_path.mkdir(exist_ok=True)
        artifact_file = self.artifacts_path / name
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(artifact_file, mode) as fh:
            fh.write(content)
        return artifact_file

    def record_artifact(self, name: str, content,
                        content_type: str = "application/octet-stream") -> ArtifactRef:
        data = content.encode("utf-8") if isinstance(content, str) else content
        digest = hashlib.sha256(data).hexdigest()
        key = f"{self.project_id}/{self.run_id}/{name}/{digest}"
        ref = self.blob_store.put(key, data, content_type=content_type)
        self.session.add(Artifact(
            id=str(uuid4()), run_id=self.run_id, project_id=self.project_id,
            kind=name, sha256=digest, location=ref.location,
            content_type=content_type, size_bytes=len(data),
        ))
        self.session.flush()
        return ArtifactRef(
            sha256=digest, location=ref.location,
            size_bytes=len(data), content_type=content_type,
        )

    # ---- Remediation log --------------------------------------------------

    def append_remediation_log(self, finding_id: str, action: str,
                               result: str, success: bool) -> None:
        self.session.add(RemediationAttempt(
            finding_id=finding_id, project_id=self.project_id,
            action=action, success=success,
            detail={"result": result},
        ))
        self.session.flush()
