"""Walk ``aegis_output/runs/`` and upsert into Postgres.

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
from uuid import uuid4


@dataclass
class MigrationSummary:
    runs_imported: int = 0
    findings_imported: int = 0
    remediation_attempts_imported: int = 0
    artifacts_imported: int = 0
    audit_events_reanchored: int = 0
    skipped_duplicates: int = 0
    failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _ensure_project(sess, project_id: str) -> None:
    from aegis.db.models import Organization, Project
    if sess.get(Project, project_id) is not None:
        return
    org = sess.get(Organization, "default-org")
    if org is None:
        sess.add(Organization(id="default-org", name="Default", slug="default"))
        sess.flush()
    sess.add(Project(id=project_id, org_id="default-org",
                     name=project_id, slug=project_id))
    sess.flush()


def _import_run(sess, run_dir: Path, project_id: str,
                summary: MigrationSummary, blob_store, dry_run: bool) -> None:
    from aegis.db.models import (
        Artifact,
        AuditEvent,
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
            if not fid or sess.get(Finding, fid):
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
    audit_path = run_dir / "audit.jsonl"
    if audit_path.exists():
        chain_id = f"run:{run_id}"
        seq = 0
        prev_hash: bytes | None = None
        from aegis.audit.chain import compute_hash

        # Head marker
        seq += 1
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
        marker_hash = compute_hash(None, marker_record)
        if not dry_run:
            sess.add(AuditEvent(
                chain_id=chain_id, seq=seq,
                project_id=project_id, run_id=run_id,
                actor="migrate:fs_to_pg", action="audit.reanchored",
                target=None, allowlist_check="n/a", override=False,
                success=True, detail={"source": str(audit_path)},
                schema_version=1, prev_hash=None,
                this_hash=bytes.fromhex(marker_hash),
            ))
        prev_hash = bytes.fromhex(marker_hash)
        summary.audit_events_reanchored += 1

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
            new_hash = compute_hash(prev_hex, record)
            if not dry_run:
                sess.add(AuditEvent(
                    chain_id=chain_id, seq=seq,
                    project_id=project_id, run_id=run_id,
                    actor=record["actor"], action=record["action"],
                    target=record["target"],
                    allowlist_check=record["allowlist_check"],
                    override=record["override"], success=record["success"],
                    detail=record["detail"],
                    schema_version=1, prev_hash=prev_hash,
                    this_hash=bytes.fromhex(new_hash),
                ))
            prev_hash = bytes.fromhex(new_hash)
            summary.audit_events_reanchored += 1

    if not dry_run:
        sess.flush()


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

    from aegis.blobs import open_blob_store
    from aegis.db.session import get_session, init_engine

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
