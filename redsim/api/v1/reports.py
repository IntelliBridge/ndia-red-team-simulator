"""Report streaming, on-demand rendering and report snapshots.

Phase 4 v0.4.0 F14d layers CSP + nosniff + Content-Disposition on top
of the F12 project-access gate. HTML responses carry the strict
``default-src 'none'`` policy from
``redsim.api.security_headers.REPORT_CSP``; JSON / Markdown / PDF responses
land as downloads with nosniff. The renderer itself escapes every
interpolation (see ``redsim.report.render_inline_markdown``), so an injected
``<script>…</script>`` payload in finding evidence is double-defended:
escaped before write, and would be blocked at the browser by CSP if
it ever reached the document.

Adversarial-ML campaign reports (spec 14.8, 17.1) are ``Artifact`` rows the
worker writes at run completion and on ``report.render``. Phase B (plan 12 wave
B2, reports-compare-weights; REVIEW_REPORTS-17, -20, -21, -22) adds:

* ``report.pdf`` (``application/pdf``), served like the other formats from the
  newest snapshot's artifact, then the newest ``report.pdf`` artifact; the
  legacy filesystem fallback never serves a PDF no worker produced;
* ``?snapshot=<id|version>`` on the report route to fetch one immutable render;
* ``POST /v1/runs/{id}/report.render`` (gate ``report.render``; audit first, then
  the Job row, then the enqueue of ``redsim.report_render``);
* ``GET /v1/runs/{id}/snapshots`` and ``GET /v1/runs/{id}/snapshots/{ref}``;
* ``POST /v1/runs/{id}/snapshots/{ref}/archive`` and ``/restore``: the admin
  soft flag, audited as ``report.snapshot.archive`` / ``report.snapshot.restore``;
  bytes are never deleted. A non-admin asking for an archived snapshot is
  refused with ``409 snapshot_archived``.

Every digest is checked before bytes are served: a row whose blob no longer
matches its recorded sha256 is a ``409``, never served as if it were the record.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Response, status
from fastapi.responses import FileResponse

import redsim.api.errors as _errors
from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import PARAMS_OUT_OF_RANGE, SNAPSHOT_NOT_FOUND, ApiError, api_error
from redsim.api.policy import Action, check, ensure_run_access
from redsim.api.security_headers import (
    html_report_headers,
    non_html_report_headers,
)
from redsim.config import load_config

router = APIRouter(prefix="/runs", tags=["reports"])
logger = logging.getLogger(__name__)

_CONTENT_TYPES = {
    "md": "text/markdown",
    "json": "application/json",
    "html": "text/html",
    # Phase B (REVIEW_REPORTS-17): the PDF projection, rendered on the worker.
    "pdf": "application/pdf",
}
#: Formats the legacy blob-key / filesystem fallback may serve. A PDF exists
#: only as a worker-written Artifact row (REVIEW_REPORTS-17 risk note).
_LEGACY_FALLBACK_FORMATS = frozenset({"md", "json", "html"})

# ``Action.REPORT_RENDER`` (scanner) is the gate the plan names for an on-demand
# render; resolved by name so the module imports on a tree where policy lags,
# with ``report.export`` (same tier) as the stand-in.
REPORT_RENDER: Action = getattr(Action, "REPORT_RENDER", Action.REPORT_EXPORT)
# ``snapshot_archived`` (409) is a wave B2 code; the fallback keeps the route
# honest (a structured 409) on a tree where errors.py lags.
SNAPSHOT_ARCHIVED: str = getattr(_errors, "SNAPSHOT_ARCHIVED", "snapshot_archived")


def _blob_key(run_id: str, ext: str) -> str:
    return f"runs/{run_id}/report.{ext}"


def _report_kinds(ext: str) -> tuple[str, str]:
    """Both spellings of the report artifact kind: the spec 5.8 name (``report.md``)
    and the name the worker's artifact sink derives from the file (``ml.report_md``)."""
    return (f"ml.report_{ext}", f"report.{ext}")


def _report_headers(run_id: str, ext: str) -> dict[str, str]:
    if ext == "html":
        return html_report_headers()
    return non_html_report_headers(filename=f"redsim-{run_id}-report.{ext}")


def _archived_refusal(snapshot_id: str) -> HTTPException:
    if SNAPSHOT_ARCHIVED in _errors.HTTP_STATUS:
        return api_error(SNAPSHOT_ARCHIVED, "the report snapshot is archived; an admin can restore it",
                         snapshot_id=snapshot_id)
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail={
        "code": SNAPSHOT_ARCHIVED, "message": "the report snapshot is archived; an admin can restore it",
        "snapshot_id": snapshot_id,
    })


def _is_admin(user: CurrentUser, project_id: str) -> bool:
    """Whether the caller passes the admin gate on ``project_id`` (through the policy engine)."""
    try:
        check(user, Action.TARGET_MANAGE, project_id)
    except HTTPException:
        return False
    return True


def _digest_checked(location: str, expected: str) -> bytes:
    """The blob bytes at ``location`` once they match ``expected``; ``409`` otherwise."""
    from redsim.storage.blobs import open_blob_store

    data = open_blob_store().get(location)
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "report_artifact_digest_mismatch",
                    "message": "report artifact bytes do not match the recorded digest"},
        )
    return raw


def _snapshot_report(run_id: str, project_id: str, ext: str, *, snapshot_ref: str | None,
                     admin: bool) -> tuple[bytes, str] | None:
    """Bytes and digest of the format ``ext`` from a snapshot.

    With ``snapshot_ref`` the named snapshot is served (``404 snapshot_not_found`` when
    unknown, ``409 snapshot_archived`` for a non-admin, ``404`` when that render did
    not produce the format); without it the newest non-archived snapshot that
    carries the format, or ``None`` when no snapshot does.
    """
    from redsim.db.session import get_session
    from redsim.services.reports import newest_snapshot, resolve_snapshot, snapshot_artifact

    with get_session() as sess:
        if snapshot_ref is not None:
            resolved = resolve_snapshot(sess, run_id, snapshot_ref)
            if resolved is None:
                raise api_error(SNAPSHOT_NOT_FOUND, "report snapshot not found", snapshot=snapshot_ref)
            snapshot, _version = resolved
            if bool(snapshot.archived) and not admin:
                raise _archived_refusal(str(snapshot.id))
            artifact = snapshot_artifact(sess, snapshot, ext)
            if artifact is None or str(artifact.project_id) != project_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                    detail=f"snapshot {snapshot.id} has no report.{ext}")
        else:
            newest = newest_snapshot(sess, run_id)
            if newest is None:
                return None
            artifact = snapshot_artifact(sess, newest[0], ext)
            if artifact is None or str(artifact.project_id) != project_id:
                return None
        location, expected = str(artifact.location), str(artifact.sha256)
    return _digest_checked(location, expected), expected


def _artifact_report(run_id: str, project_id: str, ext: str) -> tuple[bytes, str] | None:
    """The newest report artifact's bytes and digest, or ``None`` when no row exists.

    A row whose blob no longer matches its recorded digest is a ``409``: the
    report is evidence and a mismatch is never served as if it were the record.
    """
    from sqlalchemy import select

    from redsim.db.models import Artifact
    from redsim.db.session import get_session

    with get_session() as sess:
        artifact = sess.execute(select(Artifact).where(
            Artifact.run_id == run_id,
            Artifact.project_id == project_id,
            Artifact.kind.in_(_report_kinds(ext)),
        ).order_by(Artifact.created_at.desc(), Artifact.id.desc())).scalars().first()
        if artifact is None:
            return None
        location, expected = str(artifact.location), str(artifact.sha256)
    return _digest_checked(location, expected), expected


@router.get("/{run_id}/report.{ext}")
def get_report(run_id: str, ext: str, snapshot: str | None = None,
               user: CurrentUser = Depends(get_current_user)) -> Response:
    if ext not in _CONTENT_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="ext must be one of md|json|html|pdf")
    # F12: project-access gate (also yields 404 for unknown runs), then the
    # REPORT_EXPORT role check (spec 7.3, 17.1) before any format decision.
    project_id = ensure_run_access(user, run_id)
    check(user, Action.REPORT_EXPORT, project_id)

    config = load_config()
    headers = _report_headers(run_id, ext)

    # An explicit snapshot is exactly that render, or a refusal; nothing else is tried.
    if snapshot is not None:
        named = _snapshot_report(run_id, project_id, ext, snapshot_ref=snapshot, admin=_is_admin(user, project_id))
        if named is None:  # pragma: no cover - a named snapshot is served or refused, never skipped
            raise api_error(SNAPSHOT_NOT_FOUND, "report snapshot not found", snapshot=snapshot)
        raw, digest = named
        return Response(content=raw, media_type=_CONTENT_TYPES[ext], headers={**headers, "ETag": f'"{digest}"'})

    # ML campaign reports are authoritative Artifact rows: the newest snapshot's
    # artifact first, then the newest artifact of the kind. Their locations are
    # opaque blob references, not the legacy runs/<id>/report.<ext> key.
    served: tuple[bytes, str] | None
    try:
        served = _snapshot_report(run_id, project_id, ext, snapshot_ref=None, admin=False)
        if served is None:
            served = _artifact_report(run_id, project_id, ext)
    except HTTPException:
        raise
    except Exception:
        served = None
        logger.debug("artifact-backed ML report lookup failed", exc_info=True)
    if served is not None:
        raw, digest = served
        return Response(
            content=raw, media_type=_CONTENT_TYPES[ext],
            headers={**headers, "ETag": f'"{digest}"'},
        )
    if ext not in _LEGACY_FALLBACK_FORMATS:
        # A PDF exists only as a worker-written artifact (spec 17.4): no fallback.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="report not yet rendered")

    # Prefer the blob store when one is configured. Phase 2 / offline
    # callers still have the filesystem path; the worker writes both
    # destinations when a blob backend is wired in.
    try:
        from redsim.storage import open_blob_store
        blob = open_blob_store(config)
        data = blob.get(_blob_key(run_id, ext))
        return Response(content=data, media_type=_CONTENT_TYPES[ext],
                        headers=headers)
    except (FileNotFoundError, KeyError):
        pass
    except Exception:  # blob backend not available, try fs
        logger.debug("blob-backed report lookup failed; trying filesystem", exc_info=True)

    path = Path(config.output_dir) / "runs" / run_id / f"report.{ext}"
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="report not yet rendered")
    return FileResponse(path, media_type=_CONTENT_TYPES[ext], headers=headers)


# --------------------------------------------------------------------------- on-demand render


@router.post("/{run_id}/report.render", status_code=status.HTTP_202_ACCEPTED)
def render_report(run_id: str, body: dict[str, Any] | None = Body(default=None),
                  user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Re-render the campaign reports as a new immutable snapshot (REVIEW_REPORTS-21).

    Gate order: membership (404 for an unknown run), the ``report.render`` role
    check, body validation, then the service: ``report.render`` audit row, Job
    row, enqueue. Body: ``{"formats": [md|json|html|pdf, ...]}`` (optional;
    default every format).
    """
    from redsim.audit.chain import resolve_writer
    from redsim.services.reports import create_report_render_job, validate_render_formats

    project_id = ensure_run_access(user, run_id)
    check(user, REPORT_RENDER, project_id)
    if body is not None and not isinstance(body, dict):
        raise api_error(PARAMS_OUT_OF_RANGE, "the request body must be a JSON object", field="body")
    try:
        formats = validate_render_formats((body or {}).get("formats"))
        handle = create_report_render_job(
            run_id=run_id, actor=f"user:{user.sub}", config=load_config(),
            audit_writer=resolve_writer(load_config()), formats=formats,
        )
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return handle.as_dict()


# --------------------------------------------------------------------------- snapshots


@router.get("/{run_id}/snapshots")
def list_report_snapshots(run_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Every immutable render of the run, newest first, with the soft ``archived`` flag (REVIEW_REPORTS-22)."""
    from redsim.db.session import get_session
    from redsim.services.reports import list_snapshots

    ensure_run_access(user, run_id)
    with get_session() as sess:
        snapshots = list_snapshots(sess, run_id)
    return {"run_id": run_id, "snapshots": snapshots, "count": len(snapshots)}


def _load_snapshot(run_id: str, ref: str) -> tuple[dict[str, Any], str]:
    from redsim.db.session import get_session
    from redsim.services.reports import resolve_snapshot, snapshot_view

    with get_session() as sess:
        resolved = resolve_snapshot(sess, run_id, ref)
        if resolved is None:
            raise api_error(SNAPSHOT_NOT_FOUND, "report snapshot not found", snapshot=ref)
        snapshot, version = resolved
        return snapshot_view(sess, snapshot, version), str(snapshot.id)


@router.get("/{run_id}/snapshots/{ref}")
def get_report_snapshot(run_id: str, ref: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """One snapshot by id or 1-based version; an archived one is admin-only (``409 snapshot_archived``)."""
    project_id = ensure_run_access(user, run_id)
    view, snapshot_id = _load_snapshot(run_id, ref)
    if view["archived"] and not _is_admin(user, project_id):
        raise _archived_refusal(snapshot_id)
    return view


def _set_archived(run_id: str, ref: str, *, archived: bool, user: CurrentUser) -> dict[str, Any]:
    """The shared body of archive and restore: admin gate, lookup, audit row, then the flag."""
    from redsim.audit.chain import resolve_writer
    from redsim.db.session import get_session
    from redsim.safety import authorize
    from redsim.services.reports import (
        SNAPSHOT_ARCHIVE_ACTION,
        SNAPSHOT_RESTORE_ACTION,
        resolve_snapshot,
        set_snapshot_archived,
        snapshot_view,
    )

    project_id = ensure_run_access(user, run_id)
    check(user, Action.TARGET_MANAGE, project_id)
    view, snapshot_id = _load_snapshot(run_id, ref)
    action = SNAPSHOT_ARCHIVE_ACTION if archived else SNAPSHOT_RESTORE_ACTION
    # Audit before the flag changes; digests, ids and counts only.
    authorize(
        action, None, allowlist=[], actor=f"user:{user.sub}", writer=resolve_writer(load_config()),
        project_id=project_id, run_id=run_id,
        detail={"snapshot_id": snapshot_id, "version": view["version"], "record_sha256": view["record_sha256"],
                "artifact_count": len(view["artifact_ids"]), "archived_before": view["archived"],
                "archived_after": archived},
    )
    with get_session() as sess:
        resolved = resolve_snapshot(sess, run_id, snapshot_id)
        if resolved is None:  # pragma: no cover - the row was just read
            raise api_error(SNAPSHOT_NOT_FOUND, "report snapshot not found", snapshot=ref)
        snapshot, version = resolved
        changed = set_snapshot_archived(sess, snapshot, archived)
        out = snapshot_view(sess, snapshot, version)
    out["changed"] = changed
    return out


@router.post("/{run_id}/snapshots/{ref}/archive")
def archive_report_snapshot(run_id: str, ref: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Admin soft-archive of a snapshot (REVIEW_REPORTS-22): audited, nothing deleted."""
    return _set_archived(run_id, ref, archived=True, user=user)


@router.post("/{run_id}/snapshots/{ref}/restore")
def restore_report_snapshot(run_id: str, ref: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Admin restore of an archived snapshot (REVIEW_REPORTS-22): audited."""
    return _set_archived(run_id, ref, archived=False, user=user)
