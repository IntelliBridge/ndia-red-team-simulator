"""Walk ``redsim_output/runs/`` and upsert into Postgres.

Idempotent: re-running on the same source is a no-op. Audit events from
the old flat ``audit.jsonl`` are re-anchored as a fresh chain in Postgres
with a single ``audit.reanchored`` marker at the head.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.storage.blobs import BlobStore


@dataclass
class MigrationSummary:
    runs_imported: int = 0
    findings_imported: int = 0
    remediation_attempts_imported: int = 0
    artifacts_imported: int = 0
    audit_events_reanchored: int = 0
    skipped_duplicates: int = 0
    failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _ensure_project(sess: Session, project_id: str) -> None:
    from redsim.db.models import Organization, Project
    if sess.get(Project, project_id) is not None:
        return
    org = sess.get(Organization, "default-org")
    if org is None:
        sess.add(Organization(id="default-org", name="Default", slug="default"))
        sess.flush()
    sess.add(Project(id=project_id, org_id="default-org",
                     name=project_id, slug=project_id))
    sess.flush()


def _import_run(sess: Session, run_dir: Path, project_id: str,
                summary: MigrationSummary, blob_store: BlobStore,
                dry_run: bool) -> None:
    from redsim.db.models import (
        Artifact,
        Finding,
        RemediationAttempt,
        Run,
    )
    run_id = run_dir.name
    if sess.get(Run, run_id):
        summary.skipped_duplicates += 1
        return

    stage_table = {}
    stage_path = run_dir / "stage_table.json"
    if stage_path.exists():
        try:
            stage_table = json.loads(stage_path.read_text())
        except json.JSONDecodeError:
            stage_table = {}

    if not dry_run:
        sess.add(Run(
            id=run_id, project_id=project_id, mode="imported",
            status="completed", stage_table=stage_table,
            created_at=datetime.now(timezone.utc),
        ))
        sess.flush()
    summary.runs_imported += 1

    # Findings
    findings_path = run_dir / "findings.json"
    if findings_path.exists():
        for f in json.loads(findings_path.read_text()):
            fid = f.get("id")
            if not fid or sess.get(Finding, fid) is not None:
                summary.skipped_duplicates += 1
                continue
            if not dry_run:
                sess.add(Finding(
                    id=fid, run_id=run_id, project_id=project_id,
                    schema_blob=f, status=f.get("status", "open"),
                    severity=f.get("severity", "low"),
                    source_tool=f.get("source_tool"),
                ))
            summary.findings_imported += 1

    # Remediation log entries
    rem_path = run_dir / "remediation-log.json"
    if rem_path.exists():
        try:
            entries = json.loads(rem_path.read_text())
        except json.JSONDecodeError:
            entries = []
        for e in entries:
            if not dry_run:
                sess.add(RemediationAttempt(
                    finding_id=e.get("finding_id") or "unknown",
                    project_id=project_id,
                    action=e.get("action", ""),
                    success=bool(e.get("success", False)),
                    detail={"result": e.get("result", "")},
                ))
            summary.remediation_attempts_imported += 1

    # Artifacts
    artifacts_dir = run_dir / "artifacts"
    if artifacts_dir.exists():
        for path in artifacts_dir.rglob("*"):
            if not path.is_file():
                continue
            content = path.read_bytes()
            digest = _sha256(content)
            kind = path.parent.name if path.parent != artifacts_dir else "misc"
            if not dry_run:
                ref = blob_store.put(
                    f"{project_id}/{run_id}/{kind}/{digest}", content,
                )
                sess.add(Artifact(
                    id=str(uuid4()), run_id=run_id, project_id=project_id,
                    kind=kind, sha256=digest, location=ref.location,
                    size_bytes=len(content),
                ))
            summary.artifacts_imported += 1

    # Audit log re-anchor
    _reanchor_audit(sess, run_dir, run_id, project_id, summary, dry_run)

    if not dry_run:
        sess.flush()


def _reanchor_audit(sess: Session, run_dir: Path, run_id: str, project_id: str,
                    summary: MigrationSummary, dry_run: bool) -> None:
    """Re-anchor the legacy flat ``audit.jsonl`` as a fresh chain.

    Builds one canonical ``record`` dict per event, hashes it, then
    derives the ``AuditEvent`` row from that *same* record (mirroring
    ``JsonlAuditWriter.append`` in ``redsim.audit.chain``) so the field
    set is listed exactly once. ``dry_run`` skips the inserts but still
    advances the chain + counters identically.
    """
    audit_path = run_dir / "audit.jsonl"
    if not audit_path.exists():
        return

    from redsim.audit.chain import compute_hash
    from redsim.db.models import AuditEvent

    columns = AuditEvent.__table__.columns.keys()

    def _emit(record: dict, prev_bytes: bytes | None) -> bytes:
        prev_hex = record["prev_hash"]
        this_hash = bytes.fromhex(compute_hash(prev_hex, record))
        if not dry_run:
            fields = {k: v for k, v in record.items() if k in columns}
            fields["prev_hash"] = prev_bytes
            fields["this_hash"] = this_hash
            sess.add(AuditEvent(**fields))
        summary.audit_events_reanchored += 1
        return this_hash

    chain_id = f"run:{run_id}"
    seq = 1
    # Head marker
    marker_record = {
        "chain_id": chain_id, "seq": seq,
        "ts": datetime.now(timezone.utc).isoformat(),
        "actor": "migrate:fs_to_pg",
        "action": "audit.reanchored",
        "target": None, "allowlist_check": "n/a",
        "override": False, "success": True,
        "detail": {"source": str(audit_path)},
        "schema_version": 1, "prev_hash": None,
        "run_id": run_id, "project_id": project_id,
    }
    prev_hash = _emit(marker_record, None)

    # Replay legacy records as chained events
    for line in audit_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            old = json.loads(line)
        except json.JSONDecodeError:
            continue
        seq += 1
        prev_hex = prev_hash.hex() if prev_hash else None
        record = {
            "chain_id": chain_id, "seq": seq,
            "ts": old.get("ts") or datetime.now(timezone.utc).isoformat(),
            "actor": old.get("actor") or "legacy",
            "action": old.get("action") or "unknown",
            "target": old.get("target"),
            "allowlist_check": old.get("allowlist_check", "n/a"),
            "override": bool(old.get("override", False)),
            "success": bool(old.get("success", True)),
            "detail": old.get("detail", {}),
            "schema_version": 1, "prev_hash": prev_hex,
            "run_id": run_id, "project_id": project_id,
        }
        prev_hash = _emit(record, prev_hash)


def migrate(*, source_dir: str | Path,
            project_id: str = "default",
            db_url: str | None = None,
            dry_run: bool = False) -> MigrationSummary:
    """Migrate filesystem run data into Postgres."""
    source = Path(source_dir)
    runs_dir = source / "runs"
    summary = MigrationSummary()
    if not runs_dir.exists():
        summary.failures.append(f"no runs dir at {runs_dir}")
        return summary

    from redsim.db.session import get_session, init_engine
    from redsim.storage import open_blob_store

    if db_url:
        init_engine(db_url)
    blob_store = open_blob_store()

    try:
        with get_session() as sess:
            _ensure_project(sess, project_id)
            for run_dir in sorted(runs_dir.iterdir()):
                if not run_dir.is_dir():
                    continue
                try:
                    _import_run(sess, run_dir, project_id, summary,
                                blob_store, dry_run)
                except Exception as exc:
                    summary.failures.append(f"{run_dir.name}: {exc}")
    except Exception as exc:  # pragma: no cover — surfaces DB connection issues
        summary.failures.append(f"db error: {exc}")
    return summary
