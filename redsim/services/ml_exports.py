"""The export inventory behind ``GET /v1/exports`` (the web Exports page).

One row per campaign run of the caller's projects, newest first,
saying what has left the platform for that run and what still can:

* the **reports** in the four formats of spec 14.8 and 17.1 (``md``, ``json``,
  ``html``, ``pdf``): which formats exist as content-addressed ``Artifact`` rows,
  which snapshot they belong to (``report_snapshots``, REVIEW_REPORTS-20) and
  whether a ``report.render`` job is in flight;
* the **adversarial dataset** of spec 27.1 (Croissant manifest over Parquet
  shards plus the template card): ``not_exported``, ``queued``, ``running``,
  ``exported`` or ``failed``, with the manifest digest, the file count and the
  bytes when it exists, the follow-up job when one ran, and the blockers the
  admission would raise when it does not (``not_terminal``, ``run_failed``,
  ``fixture_target``, ``no_slices``).

The module is a read projection over the ``runs``, ``jobs``, ``artifacts``,
``targets`` and ``report_snapshots`` tables. It writes nothing, imports no ML
library, opens no blob, and carries no score: the row names ids, digests,
sizes and counts only (spec 15.7: never a bare MRI in a list).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from redsim.audit.chain import canonical_ts
from redsim.services.ml_datasets_export import DATASET_EXPORT_JOB_TYPE, EXPORT_SLICE_KINDS
from redsim.services.reports import REPORT_RENDER_JOB_TYPE

#: The report formats a run can be exported in, in the order the UI lists them.
REPORT_FORMATS: tuple[str, ...] = ("md", "json", "html", "pdf")
#: The one dataset export format (spec 27.1).
DATASET_FORMAT = "croissant-parquet"
#: The run kind the inventory lists, keyed by the ``Run.scanner`` the admission wrote.
RUN_KINDS: dict[str, str] = {"ml.campaign": "campaign"}
#: ``Job.status`` values that mean the export has not finished.
_ACTIVE = frozenset({"queued", "running"})
_TERMINAL = frozenset({"succeeded", "failed", "cancelled"})
_MANIFEST_KIND = "ml.dataset.manifest"
_PARQUET_KIND = "ml.dataset.parquet"
_CARD_KIND = "ml.dataset.card"
_DATASET_KINDS = (_MANIFEST_KIND, _PARQUET_KIND, _CARD_KIND)


def _iso(value: datetime | None) -> str | None:
    """The UTC ``+00:00`` isoformat the audit chain uses, so sqlite and Postgres rows read the same."""
    return canonical_ts(value) if value is not None else None


def _report_ext(kind: str) -> str | None:
    """``md`` for ``report.md`` or ``ml.report_md``; ``None`` for any other kind."""
    if kind.startswith("report."):
        ext = kind.split(".", 1)[1]
    elif kind.startswith("ml.report_"):
        ext = kind[len("ml.report_"):]
    else:
        return None
    return ext if ext in REPORT_FORMATS else None


def _artifact_view(row: Any, *, source: str, snapshot_version: int | None = None) -> dict[str, Any]:
    view: dict[str, Any] = {
        "artifact_id": str(row.id), "kind": str(row.kind), "sha256": str(row.sha256),
        "size_bytes": int(row.size_bytes or 0), "source": source,
    }
    if snapshot_version is not None:
        view["snapshot_version"] = snapshot_version
    return view


def _model_block(target: Any | None, target_id: str | None) -> dict[str, Any]:
    """The credential-free identity of the run's model: id, a display name, the value and modality.

    For an endpoint target ``Target.value`` is the inference URL, and the models
    route never returns it (a path can carry a tenant's routing). ``value`` is
    therefore the ``host[:port]`` of ``endpoint_host`` for that kind, the same
    projection the campaign record and the audit rows carry.
    """
    from redsim.services.ml_models import ENDPOINT_KIND, endpoint_host

    detail = getattr(target, "detail", None) if target is not None else None
    detail = detail if isinstance(detail, dict) else {}
    raw_manifest = detail.get("manifest")
    manifest: dict[str, Any] = raw_manifest if isinstance(raw_manifest, dict) else {}
    value = str(getattr(target, "value", "") or "") if target is not None else ""
    if target is not None and str(getattr(target, "kind", "")) == ENDPOINT_KIND:
        value = endpoint_host(value)
    name = detail.get("name") or manifest.get("name") or detail.get("bundled_id")
    if not name:
        name = value.split(":", 1)[1] if value.startswith("bundled:") else (value or target_id)
    return {
        "target_id": target_id,
        "name": name,
        "value": value or None,
        "modality": detail.get("modality") or manifest.get("modality"),
        "fixture": _is_fixture(detail, manifest),
    }


def _is_fixture(detail: dict[str, Any], manifest: dict[str, Any]) -> bool:
    return bool(detail.get("fixture_only") or manifest.get("fixture_only")
                or detail.get("fixture") or manifest.get("fixture"))


def _reports_block(run_id: str, artifacts: list[Any], snapshots: list[Any],
                   render_in_flight: bool) -> dict[str, Any]:
    """Formats from the newest non-archived snapshot first, then the newest artifact per kind."""
    by_id = {str(a.id): a for a in artifacts}
    formats: dict[str, dict[str, Any] | None] = {ext: None for ext in REPORT_FORMATS}

    newest: tuple[Any, int] | None = None
    for index in range(len(snapshots) - 1, -1, -1):
        if not bool(snapshots[index].archived):
            newest = (snapshots[index], index + 1)
            break
    if newest is not None:
        snapshot, version = newest
        for artifact_id in snapshot.artifact_ids or []:
            row = by_id.get(str(artifact_id))
            ext = _report_ext(str(row.kind)) if row is not None else None
            if ext is not None and formats[ext] is None:
                formats[ext] = _artifact_view(row, source="snapshot", snapshot_version=version)

    # Newest artifact row per format for anything the snapshot did not name
    # (a completion render on a tree before snapshots, or a legacy kind).
    for row in sorted(artifacts, key=lambda a: (_iso(a.created_at) or "", str(a.id)), reverse=True):
        ext = _report_ext(str(row.kind))
        if ext is not None and formats[ext] is None:
            formats[ext] = _artifact_view(row, source="artifact")

    latest: dict[str, Any] | None = None
    if snapshots:
        last, version = snapshots[-1], len(snapshots)
        latest = {"id": str(last.id), "version": version, "rendered_at": _iso(last.rendered_at),
                  "archived": bool(last.archived)}
    return {
        "run_id": run_id,
        "formats": formats,
        "available": [ext for ext in REPORT_FORMATS if formats[ext] is not None],
        "missing": [ext for ext in REPORT_FORMATS if formats[ext] is None],
        "snapshot_count": len(snapshots),
        "latest_snapshot": latest,
        "render_in_flight": render_in_flight,
    }


def _dataset_block(run: Any, artifacts: list[Any], jobs: list[Any], *, fixture: bool) -> dict[str, Any]:
    """The export state of the run's adversarial dataset, and why one cannot start when it cannot."""
    manifest = next((a for a in sorted(artifacts, key=lambda a: str(a.id), reverse=True)
                     if str(a.kind) == _MANIFEST_KIND), None)
    parquet = [a for a in artifacts if str(a.kind) == _PARQUET_KIND]
    card = any(str(a.kind) == _CARD_KIND for a in artifacts)
    has_slices = any(str(a.kind) in EXPORT_SLICE_KINDS for a in artifacts)

    block: dict[str, Any] = {
        "format": DATASET_FORMAT, "status": "not_exported",
        "manifest_artifact_id": None, "manifest_sha256": None, "files": 0, "bytes": 0, "card": False,
        "job_id": None, "follow_up_run_id": None, "error": None, "blockers": [],
    }
    if manifest is not None:
        block.update({
            "status": "exported", "manifest_artifact_id": str(manifest.id),
            "manifest_sha256": str(manifest.sha256), "files": len(parquet),
            "bytes": int(manifest.size_bytes or 0) + sum(int(a.size_bytes or 0) for a in parquet),
            "card": card,
        })
        return block

    # Newest job first: an active one wins, else the last failure is reported.
    ordered = sorted(jobs, key=lambda j: (_iso(j.created_at) or "", str(j.id)), reverse=True)
    active = next((j for j in ordered if str(j.status) in _ACTIVE), None)
    job = active or (ordered[0] if ordered else None)
    if job is not None:
        block.update({"job_id": str(job.id), "follow_up_run_id": str(job.run_id)})
        if active is not None:
            block["status"] = str(job.status)
            return block
        if str(job.status) in ("failed", "cancelled"):
            block.update({"status": "failed", "error": job.error})

    blockers: list[str] = []
    status = str(run.status)
    if status not in _TERMINAL:
        blockers.append("not_terminal")
    elif status != "succeeded":
        blockers.append("run_failed")
    if fixture:
        blockers.append("fixture_target")
    if not has_slices:
        blockers.append("no_slices")
    block["blockers"] = blockers
    return block


def list_exports(session: Session, *, project_ids: list[str] | None, limit: int) -> list[dict[str, Any]]:
    """The export rows of the campaign runs in ``project_ids`` (``None`` for every project).

    Follow-up runs (the ``ml.dataset_export`` run an export creates), LLM probe
    runs, validation runs and pentest-era runs are not exports of anything and
    are not listed.
    """
    from redsim.db.models import Artifact, Job, ReportSnapshot, Run, Target

    stmt = select(Run).where(Run.scanner.in_(list(RUN_KINDS))).order_by(Run.created_at.desc(), Run.id.desc())
    if project_ids is not None:
        if not project_ids:
            return []
        stmt = stmt.where(Run.project_id.in_(project_ids))
    runs = list(session.execute(stmt.limit(limit)).scalars().all())
    if not runs:
        return []

    run_ids = [str(r.id) for r in runs]
    wanted_kinds = tuple(_DATASET_KINDS) + tuple(EXPORT_SLICE_KINDS)
    artifacts_by_run: dict[str, list[Any]] = defaultdict(list)
    for row in session.execute(select(Artifact).where(Artifact.run_id.in_(run_ids))).scalars():
        if _report_ext(str(row.kind)) is not None or str(row.kind) in wanted_kinds:
            artifacts_by_run[str(row.run_id)].append(row)

    snapshots_by_run: dict[str, list[Any]] = defaultdict(list)
    for snap in session.execute(
        select(ReportSnapshot).where(ReportSnapshot.run_id.in_(run_ids))
        .order_by(ReportSnapshot.rendered_at.asc(), ReportSnapshot.id.asc())
    ).scalars():
        snapshots_by_run[str(snap.run_id)].append(snap)

    render_active: set[str] = set()
    for job in session.execute(
        select(Job).where(Job.run_id.in_(run_ids), Job.type == REPORT_RENDER_JOB_TYPE,
                          Job.status.in_(tuple(_ACTIVE)))
    ).scalars():
        render_active.add(str(job.run_id))

    # A dataset export job sits on its follow-up run and names the source in its
    # detail, so the match is made in Python over the projects' export jobs.
    export_jobs_by_source: dict[str, list[Any]] = defaultdict(list)
    export_stmt = select(Job).where(Job.type == DATASET_EXPORT_JOB_TYPE)
    project_scope = sorted({str(r.project_id) for r in runs})
    export_stmt = export_stmt.where(Job.project_id.in_(project_scope))
    for job in session.execute(export_stmt).scalars():
        source = (job.detail or {}).get("source_run_id")
        if source in run_ids:
            export_jobs_by_source[str(source)].append(job)

    target_ids = sorted({str(r.target_id) for r in runs if r.target_id})
    targets = {str(t.id): t for t in session.execute(
        select(Target).where(Target.id.in_(target_ids))).scalars()} if target_ids else {}

    rows: list[dict[str, Any]] = []
    for run in runs:
        run_id = str(run.id)
        target_id = str(run.target_id) if run.target_id else None
        model = _model_block(targets.get(target_id or ""), target_id)
        artifacts = artifacts_by_run.get(run_id, [])
        rows.append({
            "run_id": run_id,
            "project_id": str(run.project_id),
            "kind": RUN_KINDS.get(str(run.scanner or ""), "campaign"),
            "status": str(run.status),
            "terminal": str(run.status) in _TERMINAL,
            "created_at": _iso(run.created_at),
            "completed_at": _iso(run.completed_at),
            "model": model,
            "reports": _reports_block(run_id, artifacts, snapshots_by_run.get(run_id, []),
                                      run_id in render_active),
            "dataset": _dataset_block(run, artifacts, export_jobs_by_source.get(run_id, []),
                                      fixture=bool(model["fixture"])),
        })
    return rows


__all__ = ["DATASET_FORMAT", "REPORT_FORMATS", "RUN_KINDS", "list_exports"]
