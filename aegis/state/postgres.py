"""Postgres-backed implementation of ``RunStateAPI``.

Writes are pure persistence — no audit events emitted here. The service
layer is the only place audit events are written (Phase 3 M2).
"""

from __future__ import annotations

import hashlib
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.db.models import Artifact, Finding, RemediationAttempt, Run
from aegis.state.facade import ArtifactRef


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
        # Set by ``open_run_state`` when it hands us a session it entered on
        # our behalf; ``close()`` then exits it (commit + release). Stays None
        # when the caller owns the session (e.g. the worker's ``with`` block).
        self._session_ctx: AbstractContextManager[Session] | None = None
        if blob_store is None:
            from aegis.storage import FilesystemBlobStore
            blob_store = FilesystemBlobStore(Path(output_dir) / "blobs")
        self.blob_store = blob_store

        existing = session.get(Run, run_id)
        if existing is None:
            session.add(Run(
                id=run_id, project_id=project_id, mode="live",
                status="running", created_by=created_by, stage_table={},
            ))
            session.flush()

    def close(self) -> None:
        """Release a session this state owns (commit + close).

        Only the ``open_run_state`` factory path stashes a session context
        for us to own; the worker's ``with get_session()`` block owns its own
        session, leaves ``_session_ctx`` None, and this is a no-op there.
        """
        ctx, self._session_ctx = self._session_ctx, None
        if ctx is not None:
            ctx.__exit__(None, None, None)

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
        """Phase 4 v0.3.1 F9: rows are keyed by an internal UUID; the
        scanner's upstream identifier goes into ``scanner_finding_id``,
        which is uniquely constrained per-run. ``schema_blob["id"]``
        keeps the scanner's identifier so downstream consumers (exports,
        report HTML, deps_workflow) see the contract they expect.
        """
        existing = self.session.execute(
            select(Finding).where(Finding.run_id == self.run_id)
        ).scalars().all()
        by_scanner_id = {f.scanner_finding_id: f for f in existing}

        for raw in findings:
            data = raw.to_dict() if hasattr(raw, "to_dict") else dict(raw)
            scanner_id = data["id"]
            existing_row = by_scanner_id.get(scanner_id)
            if existing_row is not None:
                existing_row.schema_blob = data
                existing_row.status = data.get("status", existing_row.status)
                existing_row.severity = data.get("severity", existing_row.severity)
                existing_row.updated_at = _now()
            else:
                self.session.add(Finding(
                    id=str(uuid4()),
                    scanner_finding_id=scanner_id,
                    run_id=self.run_id, project_id=self.project_id,
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
        # schema_blob already carries the scanner's original ``id``; the DB
        # UUID stays internal.
        return [r.schema_blob for r in rows]

    def update_finding_status(self, finding_id: str, status: str) -> None:
        """Update finding status. ``finding_id`` accepts either the internal
        UUID or the upstream ``scanner_finding_id`` for this run."""
        row = self.session.get(Finding, finding_id)
        if row is None:
            # Fall back to looking up by scanner_finding_id within this run.
            row = self.session.execute(
                select(Finding).where(
                    Finding.run_id == self.run_id,
                    Finding.scanner_finding_id == finding_id,
                )
            ).scalar_one_or_none()
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
