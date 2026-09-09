"""Dataset catalog, consumed slices and Croissant exports (spec 17.2 ``GET /v1/datasets``, spec 27).

``GET /v1/datasets`` lists the bundled evaluation datasets from
``assets/MANIFEST.json`` as ``redsim ml build-assets`` wrote it (read through
the plain-JSON reader the upload binding uses) beside the consumed slices of
the caller's projects (``role: "consumed"``, INTEROP-16). When no manifest is
built the response says so (``assets.status``) instead of presenting an empty
list as a healthy catalog. CI fixture datasets are listed with ``role:
"ci_fixture"``; they are never demo evidence (spec 11.1).

Phase B interoperability (spec 27.1 to 27.3; plan 12 wave B3, interop-consume):

* ``POST /v1/datasets`` (multipart; membership and ``dataset.register`` on the
  body's ``project_id``) consumes another team's evaluation slice: a Croissant
  JSON-LD ``manifest`` part plus a Parquet ``file`` part, or Parquet alone with
  ``license_statement``, ``modality``, ``class_names`` and the feature or image
  schema declared in the form. The API runs static checks only
  (``services.ml_datasets.prepare_dataset_admission``: Parquet magic at both
  ends, manifest shape, every ``contentUrl`` inside the upload, licence,
  declared schema, size caps) and never opens a Parquet file. The
  ``dataset.register`` audit row precedes the blobs and the ``ml_datasets`` row
  (status ``validating``), its ingest Run and the ``dataset.validate`` Job; the
  worker parses the files inside the sandbox child. Every refusal writes a
  ``success=False`` ``dataset.register`` row first and carries the spec 17.3
  code (``dataset_too_large``, ``unsupported_dataset_format``,
  ``remote_reference_refused``, ``license_required``, ``schema_undeclared``).
* ``GET /v1/datasets/{id}``: a consumed slice's record (membership on its
  project) or, when the id names a campaign run, the Croissant manifest of
  that run's export as ``application/ld+json`` (membership through the run;
  ``404`` until the export exists; ``501`` while the export service of the
  interop-contribute track is not on the tree).
* ``POST /v1/runs/{run_id}/dataset`` (membership, ``dataset.export``): the
  Croissant export job through ``services.ml_datasets_export.admit_export``
  (interop-contribute), ``202`` with the job handle; ``501`` with the reason
  when that service is absent. Nothing is faked.

Nothing here imports an ML library (``tests/test_api_process_has_no_ml.py``).
"""

from __future__ import annotations

import inspect
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import (
    HTTP_STATUS,
    NOT_FOUND,
    NOT_IMPLEMENTED,
    ApiError,
    api_error,
)
from redsim.api.policy import Action, accessible_project_ids, check, ensure_project_access, ensure_run_access
from redsim.api.v1.batches import project_field, project_required
from redsim.api.v1.integrations import not_built, phase_b_action
from redsim.services.ml_datasets import (
    DatasetAdmissionError,
    dataset_record,
    enqueue_dataset_validate,
    get_consumed_dataset,
    list_consumed_datasets,
    prepare_dataset_admission,
    register_consumed_dataset,
    upload_max_bytes,
)
from redsim.services.ml_models import (
    DatasetBindingError,
    assets_root_path,
    audit_refused_admission,
    dataset_entries,
    dataset_modality,
    read_asset_manifest,
)

# No prefix: the router hosts ``/datasets`` and the export route ``/runs/{run_id}/dataset``.
router = APIRouter(tags=["ml-datasets"])
logger = logging.getLogger(__name__)

_MODALITIES = ("image", "tabular", "text", "detection", "llm")

# Phase B gates (``dataset.register`` and ``dataset.export``, both remediator, INTEROP-02), resolved by
# name so this module also imports on a tree where ``policy.py`` lags; the stand-ins are the same tier.
DATASET_REGISTER: Action = phase_b_action("DATASET_REGISTER", Action.MODEL_REGISTER)
DATASET_EXPORT: Action = phase_b_action("DATASET_EXPORT", Action.REPORT_EXPORT)

#: Multipart field names that are not declaration fields.
_FILE_FIELDS = frozenset({"file", "manifest"})
_REGISTER_ACTION = "dataset.register"


# --------------------------------------------------------------------------- bundled catalog (B0)


def _split_items(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        return [value for value in raw.values() if isinstance(value, dict)]
    if isinstance(raw, list):
        return [value for value in raw if isinstance(value, dict)]
    return []


def _row(dataset_id: str, raw: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    splits = _split_items(raw.get("splits"))
    size = raw.get("n_rows")
    if size is None:
        size = sum(int(split.get("n", 0) or 0) for split in splits)
    bundled = [split for split in splits if isinstance(split.get("file"), dict) and split["file"].get("path")]
    source = str(raw.get("source", "local"))
    modality = dataset_modality(raw, dataset_id, document)
    return {
        "id": dataset_id,
        "name": str(raw.get("name") or dataset_id),
        "license": str(raw.get("license") or "not declared"),
        "source_url": str(raw.get("url") or ""),
        "classes": [str(value) for value in (raw.get("class_names") or [])],
        "size": int(size or 0),
        "format": str(raw.get("format") or source),
        "revision": str(raw.get("revision") or raw.get("source_file_sha256") or ""),
        "role": "ci_fixture" if raw.get("fixture_only") else "demo",
        "fixture_only": bool(raw.get("fixture_only", False)),
        "reachability": "bundled" if bundled else "manifest_only",
        "bundled_splits": sorted(str(split.get("name") or "") for split in bundled),
        "compatible_modalities": [modality] if modality in _MODALITIES else [],
    }


def dataset_rows() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """``(rows, assets)``: the bundled catalog and the recorded state of the asset manifest."""
    root = assets_root_path()
    try:
        document = read_asset_manifest(root)
    except DatasetBindingError as exc:
        return [], {"status": "missing", "assets_dir": str(root), "reason": str(exc)}
    rows = [
        _row(dataset_id, raw, document)
        for dataset_id, raw in dataset_entries(document).items()
    ]
    # ``dataset_entries`` maps both the mapping key and the entry's own id; list each entry once.
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for row in rows:
        key = f"{row['id']}|{row['revision']}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique, {"status": "built", "assets_dir": str(root), "built_at": document.get("built_at")}


def _consumed_rows(user: CurrentUser, project: str | None) -> list[dict[str, Any]]:
    """Consumed slices of the named project (membership enforced) or of every project the caller can read."""
    from redsim.db.session import get_session

    if project:
        ensure_project_access(user, project)
        scope: list[str] | None = [project]
    else:
        scope = accessible_project_ids(user)
    with get_session() as sess:
        return list_consumed_datasets(sess, scope)


@router.get("/datasets")
def list_datasets(project: str | None = None, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    datasets, assets = dataset_rows()
    consumed = _consumed_rows(user, project)
    rows = datasets + consumed
    return {"datasets": rows, "count": len(rows), "assets": assets, "consumed_count": len(consumed)}


# --------------------------------------------------------------------------- consume (INTEROP-13)


class _Refusal(Exception):
    """A refusal of ``POST /v1/datasets``: the 17.3 envelope plus what the audit row records."""

    def __init__(self, http: HTTPException, reason: str, **audit: Any) -> None:
        super().__init__(reason)
        self.http = http
        self.reason = reason
        self.audit = audit


def _envelope(code: str, message: str, **fields: Any) -> HTTPException:
    if code == NOT_IMPLEMENTED:
        fields.setdefault("phase", "B")
    if code in HTTP_STATUS:
        return api_error(code, message, **fields)
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                         detail={"code": code, "message": message, **fields})


def _content_length(request: Request, cap: int) -> int:
    """Spec 17.3: ``Content-Length`` is required on uploads; over the cap is 413 before any byte is read."""
    raw = request.headers.get("content-length")
    if raw is None or not raw.strip().isdigit():
        raise _Refusal(
            HTTPException(status_code=status.HTTP_411_LENGTH_REQUIRED,
                          detail="Content-Length is required for dataset uploads"),
            "length_required",
        )
    length = int(raw)
    if length > cap:
        raise _Refusal(
            _envelope("dataset_too_large", f"upload of {length} bytes exceeds the {cap} byte cap", field="file",
                      cap=cap),
            "dataset_too_large", field="file", content_length=length, cap=cap,
        )
    return length


async def _multipart_parts(request: Request) -> tuple[dict[str, Any], list[tuple[str, str, bytes]]]:
    """``(fields, parts)`` of the multipart body; ``parts`` are ``(field, original name, bytes)`` triples."""
    form = await request.form()
    fields: dict[str, Any] = {}
    parts: list[tuple[str, str, bytes]] = []
    for key, value in form.multi_items():
        if hasattr(value, "read"):
            data = await value.read()
            parts.append((str(key), str(getattr(value, "filename", "") or ""), bytes(data)))
        elif key not in _FILE_FIELDS:
            fields[str(key)] = value
    return fields, parts


@router.post("/datasets", status_code=status.HTTP_201_CREATED)
async def register_dataset(request: Request, project: str | None = None,
                           user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Consume an external evaluation slice (spec 27.3): static checks, audit, rows, enqueue, ``201``."""
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.db.session import get_session

    config = load_config()
    writer = resolve_writer(config)
    actor = f"user:{user.sub}"
    content_type = request.headers.get("content-type", "")
    multipart = content_type.startswith("multipart/form-data")
    cap = upload_max_bytes()

    if multipart:
        # Before the body is parsed no project role is known; the refusal is recorded on the chain the
        # query string names, else system (the model upload path does the same).
        try:
            _content_length(request, cap)
        except _Refusal as exc:
            audit_refused_admission(
                writer, action=_REGISTER_ACTION, actor=actor, project_id=project,
                detail={"kind": "ml_dataset", "source": "consumed", "reason": exc.reason,
                        "content_length": request.headers.get("content-length"), **exc.audit},
            )
            raise exc.http from exc

    project_id = await project_field(request, project)
    if project_id is None:
        raise project_required()
    ensure_project_access(user, project_id)
    check(user, DATASET_REGISTER, project_id)

    def refused(exc: _Refusal) -> HTTPException:
        # Spec 9.3 step 2 / 5.11: the refusal is on the project chain before it is raised; ids, counts and
        # field names only.
        audit_refused_admission(
            writer, action=_REGISTER_ACTION, actor=actor, project_id=project_id,
            detail={"kind": "ml_dataset", "source": "consumed", "reason": exc.reason, **exc.audit},
        )
        return exc.http

    if not multipart:
        raise refused(_Refusal(
            _envelope("unsupported_dataset_format",
                      "POST /v1/datasets takes a multipart body: a Parquet 'file' part, an optional Croissant "
                      "'manifest' part and the declaration fields", field="file"),
            "unsupported_dataset_format", field="file",
        ))
    fields, parts = await _multipart_parts(request)
    try:
        admission = prepare_dataset_admission(project_id=project_id, fields=fields, parts=parts, cap_bytes=cap)
    except DatasetAdmissionError as exc:
        extra = {k: v for k, v in exc.extra.items() if k in {"phase", "reason", "cap", "detected_format", "index"}}
        raise refused(_Refusal(
            _envelope(exc.code, str(exc), field=exc.field, **extra), exc.code, field=exc.field,
            **{k: v for k, v in exc.extra.items() if k not in {"phase", "reason"}},
        )) from exc

    with get_session() as sess:
        registered = register_consumed_dataset(sess, admission, actor=actor, audit_writer=writer, config=config)
    task_id = enqueue_dataset_validate(registered.job_id)
    if task_id is not None:
        from redsim.db.models import Job

        with get_session() as sess:
            job = sess.get(Job, registered.job_id)
            if job is not None:
                job.celery_task_id = task_id
    response = dict(registered.response)
    response["enqueued"] = task_id is not None
    return response


# --------------------------------------------------------------------------- manifest reads


def _export_service() -> Any | None:
    """``redsim.services.ml_datasets_export`` when the interop-contribute track has landed it, else ``None``."""
    try:
        import importlib

        return importlib.import_module("redsim.services.ml_datasets_export")
    except ImportError:
        return None


def _run_project(run_id: str) -> str | None:
    from redsim.db.models import Run
    from redsim.db.session import get_session

    with get_session() as sess:
        run = sess.get(Run, run_id)
        return None if run is None else str(run.project_id)


@router.get("/datasets/{dataset_id}")
def get_dataset(dataset_id: str, user: CurrentUser = Depends(get_current_user)) -> Any:
    """A consumed slice's record, or the Croissant manifest of a run's export (spec 27.2)."""
    from redsim.db.session import get_session

    with get_session() as sess:
        row = get_consumed_dataset(sess, dataset_id)
        record = dataset_record(row) if row is not None else None
    if record is not None:
        ensure_project_access(user, str(record["project_id"]))
        return record
    project_id = _run_project(dataset_id)
    if project_id is None:
        raise api_error(NOT_FOUND, "dataset not found")
    ensure_project_access(user, project_id)
    service = _export_service()
    reader = getattr(service, "get_export_manifest", None) if service is not None else None
    if not callable(reader):
        raise not_built("Croissant manifest reads are not implemented", wave="B3", track="interop-contribute")
    with get_session() as sess:
        manifest = reader(sess, dataset_id)
    if not isinstance(manifest, dict):
        raise api_error(NOT_FOUND, "no dataset export exists for this run yet")
    return Response(content=json.dumps(manifest, sort_keys=True), media_type="application/ld+json")


# --------------------------------------------------------------------------- export (INTEROP-05..12 route)


def _handle_to_response(result: Any, run_id: str) -> dict[str, Any]:
    """A ``202`` body from whatever ``admit_export`` returns (a handle with ``to_response``, a Job row or a dict)."""
    if isinstance(result, dict):
        body: dict[str, Any] = dict(result)
    elif hasattr(result, "to_response") and callable(result.to_response):
        value = result.to_response()
        body = dict(value) if isinstance(value, dict) else {"result": str(value)}
    else:
        job_id = getattr(result, "job_id", None) or getattr(result, "id", None)
        body = {
            "run_id": str(getattr(result, "run_id", None) or run_id),
            "job_id": str(job_id) if job_id else None,
            "status": str(getattr(result, "status", None) or "queued"),
        }
    body.setdefault("run_id", run_id)
    body.setdefault("status", "queued")
    body.setdefault("status_url", f"/v1/runs/{body['run_id']}")
    body.setdefault("dataset_url", f"/v1/datasets/{body['run_id']}")
    return body


@router.post("/runs/{run_id}/dataset", status_code=status.HTTP_202_ACCEPTED)
def export_run_dataset(run_id: str, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Croissant export of a campaign run (spec 27.1): membership, ``dataset.export``, then the export job."""
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.db.models import Run
    from redsim.db.session import get_session

    project_id = ensure_run_access(user, run_id)
    check(user, DATASET_EXPORT, project_id)
    service = _export_service()
    admit = getattr(service, "admit_export", None) if service is not None else None
    if not callable(admit):
        raise not_built("Croissant dataset export of a campaign run is not implemented",
                        wave="B3", track="interop-contribute")
    config = load_config()
    writer = resolve_writer(config)
    actor = f"user:{user.sub}"
    try:
        parameters: set[str] = set(inspect.signature(admit).parameters)
    except (TypeError, ValueError):
        parameters = set()
    optional: dict[str, Any] = {}
    for name, value in (("audit_writer", writer), ("config", config)):
        if name in parameters:
            optional[name] = value
    try:
        with get_session() as sess:
            run = sess.get(Run, run_id)
            if run is None:
                raise api_error(NOT_FOUND, "run not found")
            result = admit(sess, run, actor, **optional)
            body = _handle_to_response(result, run_id)
    except ApiError as exc:
        raise exc.as_http_exception() from exc
    return body


__all__ = ["DATASET_EXPORT", "DATASET_REGISTER", "dataset_rows", "router"]
