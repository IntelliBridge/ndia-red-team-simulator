"""Bulk model upload and the ML capacity view (register BULK-13, BULK-22; plan 12 wave B3).

``POST /v1/models/bulk`` takes one multipart request with several ``files`` parts
and one ``manifest`` part (JSON)::

    {"project_id": "...",
     "items": [{"filename": "a.onnx", "name": "a", "modality": "image", "dataset_id": "hf:...",
                "license_statement": "MIT", "declared_format": "onnx", "architecture_id": null,
                "dataset_split": null}, ...]}

The request is admitted in this order: ``Content-Length`` (411 without it, ``413
bulk_too_large`` over ``REDSIM_ML_BULK_UPLOAD_MAX_MB``, default 1024, before any
part is parsed), the project (``422`` without one), membership and the
``model.register`` gate, the manifest shape (``422 params_out_of_range``), the
file-count cap (``422 bulk_too_many_files`` over ``REDSIM_ML_BULK_UPLOAD_MAX_FILES``,
default 10), the filename match between parts and items (``422``), then one
``bulk.upload`` audit row on the project chain (bulk id, counts, sanitised
filenames, digests; never bytes) and one ``ml_batches`` row (``kind: upload``).
Only then does each file go through the **single-upload admission** unchanged:
its own ``model.register`` row (``success=False`` on a refusal, with the same 17.3
code the single route uses and ``bulk_id`` in the detail), its own ``Target``,
``ml.ingest`` Run, ``model.validate`` Job and enqueue. A per-file refusal
(``pickle_refused``, ``unsupported_model_format``, a per-file ``model_too_large``
over ``REDSIM_ML_UPLOAD_MAX_MB``, ...) is a row in the response, never a request
failure: ``201`` when every file is validating, ``207`` when mixed, ``422
batch_member_refused`` when every file was refused. No model bytes are
deserialised in this process; the worker's sandbox child does that.

The admission is the single route's: ``redsim.services.ml_models.admit_model_upload``
when a build exposes it (register BULK-12), else the helpers of
``redsim.api.v1.models`` (``_read_capped`` sniff-and-cap, ``_refuse`` /
``_Refusal``, the format and modality tables, ``_project_model``) driven here
step for step in the single route's order, so the two paths share one set of
codes and one audit shape.

``GET /v1/ml/capacity`` (BULK-22) returns the per-project numbers
``redsim.services.ml_capacity`` derives from the jobs table (caps, live and
deferred runs, budget use, reset time) for ``?project=`` (membership) or every
project the caller can read; the ``global`` block is for system principals only.

Nothing here imports an ML library (``tests/test_api_process_has_no_ml.py``).
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime
from pathlib import PurePath
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import (
    ARCHITECTURE_NOT_ALLOWLISTED,
    ARCHITECTURE_REQUIRED,
    BATCH_MEMBER_REFUSED,
    BULK_TOO_LARGE,
    BULK_TOO_MANY_FILES,
    DATASET_INCOMPATIBLE,
    LICENSE_REQUIRED,
    NOT_FOUND,
    NOT_IMPLEMENTED,
    PARAMS_OUT_OF_RANGE,
    UNSUPPORTED_MODEL_FORMAT,
    api_error,
    error_detail,
)
from redsim.api.policy import Action, accessible_project_ids, check, ensure_project_access
from redsim.api.v1 import models as _single
from redsim.api.v1.ml_capabilities import (
    UPLOAD_FORMATS,
    architecture_allowlist,
    catalog_unavailable,
    upload_max_bytes,
)
from redsim.services.ml_models import (
    DatasetBindingError,
    audit_refused_admission,
    check_upload_dataset,
    safe_filename,
    upload_blob_key,
)

router = APIRouter(tags=["ml-bulk"])
logger = logging.getLogger(__name__)

#: Audit action of the request-level row (<= 64 chars; spec 5.11).
BULK_UPLOAD_ACTION = "bulk.upload"
#: ``ml_batches.kind`` of a bulk upload.
BULK_KIND = "upload"

BULK_MAX_FILES_ENV = "REDSIM_ML_BULK_UPLOAD_MAX_FILES"
DEFAULT_BULK_MAX_FILES = 10
BULK_MAX_MB_ENV = "REDSIM_ML_BULK_UPLOAD_MAX_MB"
DEFAULT_BULK_MAX_MB = 1024

#: Suffix -> declared format when an item omits ``declared_format``.
_SUFFIX_FORMATS: dict[str, str] = {
    ".onnx": "onnx", ".pt": "torch_state_dict", ".pth": "torch_state_dict", ".bin": "torch_state_dict",
    ".safetensors": "safetensors_state_dict",
}
#: The B2 single-upload admission service, when a build exposes it (register BULK-12).
_SERVICE_ADMISSION = ("redsim.services.ml_models", "admit_model_upload")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        value = default
    return max(value, 1)


def bulk_max_files() -> int:
    """``REDSIM_ML_BULK_UPLOAD_MAX_FILES`` (default 10; never below 1)."""
    return _env_int(BULK_MAX_FILES_ENV, DEFAULT_BULK_MAX_FILES)


def bulk_max_bytes() -> int:
    """``REDSIM_ML_BULK_UPLOAD_MAX_MB`` (default 1024) in bytes: the ``Content-Length`` cap of one request."""
    return _env_int(BULK_MAX_MB_ENV, DEFAULT_BULK_MAX_MB) * 1024 * 1024


def bulk_limits() -> dict[str, int]:
    """The caps as the capabilities / capacity views report them."""
    return {"max_files": bulk_max_files(), "max_total_mb": bulk_max_bytes() // (1024 * 1024),
            "per_file_max_mb": upload_max_bytes() // (1024 * 1024)}


class BulkItem(BaseModel):
    """One manifest item: what the single-upload form fields say about one file."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    filename: str = Field(min_length=1, max_length=512)
    name: str | None = None
    declared_format: str | None = None
    modality: str = "image"
    architecture_id: str | None = Field(default=None, alias="architecture")
    dataset_id: str | None = None
    dataset_split: str | None = None
    license_statement: str | None = None


class BulkManifest(BaseModel):
    """The ``manifest`` part."""

    model_config = ConfigDict(extra="forbid")

    project_id: str | None = None
    items: list[BulkItem] = Field(min_length=1)


def project_required() -> HTTPException:
    """``422 params_out_of_range`` for a request that names no project (same envelope as the B0 stub)."""
    return api_error(PARAMS_OUT_OF_RANGE, "project_id is required", field="project_id")


def _manifest_text(value: Any) -> str | None:
    """The raw manifest part as text (a string field or an uploaded JSON file)."""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return None


async def _read_part_text(value: Any) -> str | None:
    text = _manifest_text(value)
    if text is not None:
        return text
    if value is not None and hasattr(value, "read"):
        data = await value.read()
        return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
    return None


def _validation_reasons(exc: ValidationError) -> list[str]:
    reasons: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err.get("loc", ()))
        reasons.append(f"{loc or 'manifest'}: {err.get('msg', 'invalid')}")
    return reasons


def _service_admission() -> Any | None:
    """``redsim.services.ml_models.admit_model_upload`` when this build exposes it, else ``None``."""
    import importlib

    module_name, name = _SERVICE_ADMISSION
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        return None
    fn = getattr(module, name, None)
    return fn if callable(fn) else None


# ---------------------------------------------------------------------------
# Per-file admission (the single route's steps, in its order)
# ---------------------------------------------------------------------------


async def admit_upload_file(
    item: BulkItem,
    upload: Any,
    *,
    index: int,
    project_id: str,
    actor: str,
    writer: Any,
    config: Any,
    bulk_id: str,
    per_file_cap: int | None = None,
) -> dict[str, Any]:
    """Admit one file exactly as ``POST /v1/models`` (``source=upload``) does; the result row for the response.

    Every refusal writes the ``model.register`` ``success=False`` row first (the
    single route's codes and fields plus ``bulk_id`` and ``index``) and comes back as
    ``{"index", "filename", "status": "refused", "code", "field", "message"}``; a
    success writes the ``model.register`` row, the Target, the ``ml.ingest`` Run and the
    ``model.validate`` Job, enqueues the validation and comes back ``validating`` with
    the three ids. Model bytes are hashed and stored, never deserialised.
    """
    from redsim.db.session import get_session

    cap = per_file_cap if per_file_cap is not None else upload_max_bytes()
    filename = str(item.filename)
    declared = str(item.declared_format or _SUFFIX_FORMATS.get(PurePath(filename).suffix.lower(), "") or "")
    architecture_id = str(item.architecture_id or "").strip() or None
    modality = str(item.modality or "image").strip().lower()
    license_statement = str(item.license_statement or "").strip()
    dataset_id = str(item.dataset_id or "").strip()
    dataset_split = str(item.dataset_split or "").strip() or None
    audit_base: dict[str, Any] = {
        "kind": "ml_model_artifact", "source": "upload", "bulk_id": bulk_id, "bulk_index": index,
        "declared_format": declared or None, "architecture_id": architecture_id, "modality": modality,
        "filename": safe_filename(filename, ""), "dataset_id": dataset_id or None, "dataset_split": dataset_split,
    }

    def refused(exc: Any, **extra: Any) -> dict[str, Any]:
        # Spec 9.3 step 2 / 5.11: the per-file refusal is on the project chain before it is reported.
        audit_refused_admission(
            writer, action="model.register", actor=actor, project_id=project_id,
            detail={**audit_base, **extra, "reason": exc.reason, **exc.audit},
        )
        detail = exc.http.detail if isinstance(exc.http.detail, dict) else {"message": str(exc.http.detail)}
        return {
            "index": index, "filename": filename, "status": "refused",
            "code": detail.get("code", exc.reason), "field": detail.get("field"),
            "message": detail.get("message"), "http_status": exc.http.status_code,
            **({"phase": detail["phase"]} if detail.get("phase") else {}),
        }

    _refuse = _single._refuse
    _Refusal = _single._Refusal
    try:
        if upload is None or not hasattr(upload, "read"):
            raise _refuse(UNSUPPORTED_MODEL_FORMAT, f"no files part named {filename!r}", field="files")
        if declared not in UPLOAD_FORMATS:
            raise _refuse(UNSUPPORTED_MODEL_FORMAT,
                          f"declared_format must be one of {list(UPLOAD_FORMATS)} (or a .onnx / .pt / .safetensors "
                          "filename)", field="declared_format")
        if modality not in _single._PHASE_A_MODALITIES:
            raise _Refusal(api_error(
                NOT_IMPLEMENTED,
                f"{modality!r} model uploads are not implemented; Phase A evaluates "
                f"{sorted(_single._PHASE_A_MODALITIES)} classifiers", phase="B", field="modality"),
                NOT_IMPLEMENTED, field="modality")
        if architecture_id is None and declared in _single._STATE_DICT_FORMATS:
            raise _refuse(ARCHITECTURE_REQUIRED,
                          "state_dict uploads declare an architecture_id from the in-tree catalog",
                          field="architecture_id")
        if architecture_id is not None:
            try:
                allowed = architecture_allowlist()
            except ImportError as exc:
                raise catalog_unavailable(exc, "architecture") from exc
            if architecture_id not in allowed:
                raise _refuse(ARCHITECTURE_NOT_ALLOWLISTED,
                              f"architecture_id {architecture_id!r} is not in the catalog {allowed}",
                              field="architecture_id", allowed=allowed)
        if not license_statement:
            raise _refuse(LICENSE_REQUIRED,
                          "license_statement is required: only models with a declared licence are registered",
                          field="license_statement")
        try:
            binding = check_upload_dataset(dataset_id, modality=modality, dataset_split=dataset_split)
        except DatasetBindingError as exc:
            raise _refuse(DATASET_INCOMPATIBLE, str(exc), field=exc.field) from exc
        # Sniff the first bytes and enforce the per-file cap while reading (spec 9.2 / 9.3 step 2).
        data, digest, detected, size = await _single._read_capped(upload, filename, declared, cap)
    except _Refusal as exc:
        return refused(exc)

    from redsim.storage.blobs import open_blob_store

    model_id = uuid.uuid4().hex
    blob_key = upload_blob_key(project_id, model_id, filename)
    ref = open_blob_store().put(blob_key, data, content_type="application/octet-stream")
    manifest = {
        "name": str(item.name or filename), "modality": modality,
        "format": detected, "sha256": digest, "size_bytes": size,
        "architecture_id": architecture_id, "dataset_id": binding.dataset_id,
        "dataset_split": binding.split, "dataset_revision": binding.revision,
        "n_classes": len(binding.class_names), "class_names": list(binding.class_names),
        "status": "validating", "license": license_statement,
        "bundled": False,
    }
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    detail = {
        **manifest,
        "source": "upload",
        "original_filename": filename,
        "bulk_id": bulk_id,
        "blob": {"key": blob_key, "location": ref.location, "sha256": ref.sha256, "size_bytes": ref.size_bytes},
        "manifest": manifest,
        "validation": {"ingest_job_id": job_id, "ingest_run_id": run_id},
    }
    from redsim.safety import authorize

    # Spec 9.3 step 4: the chained event precedes the Target / Run / Job rows and the enqueue.
    authorize(
        "model.register", None, allowlist=config.target_allowlist, actor=actor, writer=writer,
        project_id=project_id, run_id=run_id,
        detail={
            **audit_base, "target_id": model_id, "detected_format": detected, "sha256": digest,
            "size_bytes": size, "dataset_id": binding.dataset_id, "dataset_split": binding.split,
            "dataset_revision": binding.revision, "blob_key": blob_key,
            "ingest_run_id": run_id, "ingest_job_id": job_id,
        },
    )
    from redsim.db.models import Job, Run, Target

    with get_session() as sess:
        target = Target(id=model_id, project_id=project_id, kind="ml_model_artifact", value=ref.location,
                        verified=True)
        target.detail = detail
        sess.add(target)
        sess.flush()
        sess.add(Run(
            id=run_id, project_id=project_id, target_id=model_id, mode="api", status="queued",
            scanner="ml.ingest", created_by=actor,
            stage_table={"stage": None, "stages_done": [], "jobs": {}, "bulk_id": bulk_id},
        ))
        sess.flush()
        sess.add(Job(
            id=job_id, run_id=run_id, project_id=project_id, type="model.validate", status="queued",
            created_by=actor, detail={"target_id": model_id, "bulk_id": bulk_id},
        ))
        sess.flush()
        response = _single._project_model(target)
    enqueued = False
    try:
        from redsim.workers.tasks.ml_model import ml_model_validate

        queued = ml_model_validate.delay(job_id)
        with get_session() as sess:
            row = sess.get(Job, job_id)
            if row is not None:
                row.celery_task_id = str(queued.id)
        enqueued = True
    except Exception:  # noqa: BLE001 - the durable queued row survives a broker outage; the reaper picks it up
        logger.warning("enqueue failed for bulk model validation job %s", job_id, exc_info=True)
    return {
        "index": index, "filename": filename, "status": "validating",
        "target_id": model_id, "ingest_run_id": run_id, "ingest_job_id": job_id,
        "sha256": digest, "detected_format": detected, "size_bytes": size, "enqueued": enqueued,
        "name": response["name"], "modality": response["modality"],
    }


# ---------------------------------------------------------------------------
# POST /v1/models/bulk
# ---------------------------------------------------------------------------


def _bulk_content_length(request: Request, cap: int) -> int:
    raw = request.headers.get("content-length")
    if raw is None or not raw.strip().isdigit():
        raise _single._Refusal(
            HTTPException(status_code=status.HTTP_411_LENGTH_REQUIRED,
                          detail="Content-Length is required for bulk model uploads"),
            "length_required",
        )
    length = int(raw)
    if length > cap:
        raise _single._refuse(BULK_TOO_LARGE, f"bulk upload of {length} bytes exceeds the {cap} byte total cap "
                              f"({BULK_MAX_MB_ENV})", field="files", total_bytes=length, cap_bytes=cap)
    return length


async def _json_project(request: Request) -> str | None:
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - a malformed body is a 422 at the caller
        return None
    value = body.get("project_id") if isinstance(body, dict) else None
    return str(value) if isinstance(value, str) and value else None


@router.post("/models/bulk", status_code=status.HTTP_201_CREATED)
async def bulk_upload(
    request: Request,
    project: str | None = None,
    user: CurrentUser = Depends(get_current_user),
) -> Any:
    """Several model files in one request; each keeps its own admission (module docstring)."""
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.db.session import get_session

    config = load_config()
    writer = resolve_writer(config)
    actor = f"user:{user.sub}"
    content_type = request.headers.get("content-type", "")
    multipart = content_type.startswith("multipart/form-data")

    def refuse_request(reason: str, http: HTTPException, project_id: str | None, **extra: Any) -> HTTPException:
        # Spec 5.11 / 9.5: a refused bulk admission is on the chain (the project's when one is named).
        audit_refused_admission(
            writer, action=BULK_UPLOAD_ACTION, actor=actor, project_id=project_id,
            detail={"kind": "ml_model_artifact", "source": "bulk_upload", "reason": reason, **extra},
        )
        return http

    if not multipart:
        # The JSON shape gates like the B0 stub did, then says what the real route takes.
        project_id = await _json_project(request) or project
        if project_id is None:
            raise project_required()
        ensure_project_access(user, project_id)
        check(user, Action.MODEL_REGISTER, project_id)
        raise refuse_request(PARAMS_OUT_OF_RANGE, api_error(
            PARAMS_OUT_OF_RANGE, "bulk upload is multipart/form-data: one or more 'files' parts plus one "
            "'manifest' JSON part ({project_id, items: [{filename, name, modality, dataset_id, "
            "license_statement, declared_format?, architecture_id?, dataset_split?}]})", field="files",
        ), project_id)

    total_cap = bulk_max_bytes()
    try:
        content_length = _bulk_content_length(request, total_cap)
    except _single._Refusal as exc:
        raise refuse_request(exc.reason, exc.http, project,
                             content_length=request.headers.get("content-length"), cap_bytes=total_cap) from exc

    form = await request.form()
    manifest_text = await _read_part_text(form.get("manifest"))
    manifest_doc: Any = None
    manifest_error: str | None = None
    if manifest_text is not None:
        try:
            manifest_doc = json.loads(manifest_text)
        except ValueError as exc:
            manifest_error = f"manifest is not valid JSON: {exc}"
    form_project = form.get("project_id")
    project_id = (
        (str(form_project) if isinstance(form_project, str) and form_project else None)
        or (str(manifest_doc.get("project_id")) if isinstance(manifest_doc, dict) and manifest_doc.get("project_id")
            else None)
        or project
    )
    if project_id is None:
        raise project_required()
    ensure_project_access(user, project_id)
    check(user, Action.MODEL_REGISTER, project_id)

    if manifest_text is None:
        raise refuse_request(PARAMS_OUT_OF_RANGE, api_error(
            PARAMS_OUT_OF_RANGE, "a 'manifest' JSON part is required ({project_id, items: [...]})", field="manifest",
        ), project_id)
    if manifest_error is not None or not isinstance(manifest_doc, dict):
        raise refuse_request(PARAMS_OUT_OF_RANGE, api_error(
            PARAMS_OUT_OF_RANGE, manifest_error or "manifest must be a JSON object", field="manifest",
        ), project_id)
    try:
        manifest = BulkManifest.model_validate(manifest_doc)
    except ValidationError as exc:
        reasons = _validation_reasons(exc)
        raise refuse_request(PARAMS_OUT_OF_RANGE, api_error(
            PARAMS_OUT_OF_RANGE, "manifest is invalid", field="manifest", reasons=reasons,
        ), project_id, n_reasons=len(reasons)) from exc
    if manifest.project_id is not None and manifest.project_id != project_id:
        raise refuse_request(PARAMS_OUT_OF_RANGE, api_error(
            PARAMS_OUT_OF_RANGE, "manifest.project_id disagrees with the request's project", field="manifest.project_id",
        ), project_id)

    uploads = [part for part in form.getlist("files") if hasattr(part, "read")]
    if not uploads:
        uploads = [part for part in form.getlist("file") if hasattr(part, "read")]
    max_files = bulk_max_files()
    if len(uploads) > max_files or len(manifest.items) > max_files:
        raise refuse_request(BULK_TOO_MANY_FILES, api_error(
            BULK_TOO_MANY_FILES, f"{max(len(uploads), len(manifest.items))} files exceed the {max_files} file cap "
            f"({BULK_MAX_FILES_ENV})", field="files", n_files=len(uploads), n_items=len(manifest.items),
            max_files=max_files,
        ), project_id, n_files=len(uploads), n_items=len(manifest.items), max_files=max_files)
    if not uploads:
        raise refuse_request(PARAMS_OUT_OF_RANGE, api_error(
            PARAMS_OUT_OF_RANGE, "at least one 'files' part is required", field="files",
        ), project_id)

    # Filename matching is exact and one-to-one; duplicates and strays are refused with the field named.
    by_name: dict[str, Any] = {}
    duplicates: list[str] = []
    for part in uploads:
        name = str(getattr(part, "filename", "") or "")
        if name in by_name:
            duplicates.append(name)
        by_name[name] = part
    item_names = [item.filename for item in manifest.items]
    dup_items = sorted({n for n in item_names if item_names.count(n) > 1})
    unmatched_items = [n for n in item_names if n not in by_name]
    unmatched_files = sorted(set(by_name) - set(item_names))
    if duplicates or dup_items or unmatched_items or unmatched_files:
        reasons = (
            [f"duplicate files part {n!r}" for n in sorted(set(duplicates))]
            + [f"duplicate manifest item {n!r}" for n in dup_items]
            + [f"manifest item {n!r} has no files part" for n in unmatched_items]
            + [f"files part {n!r} has no manifest item" for n in unmatched_files]
        )
        raise refuse_request(PARAMS_OUT_OF_RANGE, api_error(
            PARAMS_OUT_OF_RANGE, "files parts and manifest items must match one-to-one by filename",
            field="items.filename", reasons=reasons,
        ), project_id, n_files=len(uploads), n_items=len(manifest.items), n_reasons=len(reasons))

    from redsim.safety import authorize

    bulk_id = f"bulk-{uuid.uuid4().hex[:12]}"
    safe_names = [safe_filename(n, "") for n in item_names]
    # One request-level row before any member row, batch row or enqueue (spec 5.11 / 10.5).
    authorize(
        BULK_UPLOAD_ACTION, None, allowlist=config.target_allowlist, actor=actor, writer=writer,
        project_id=project_id,
        detail={
            "bulk_id": bulk_id, "kind": BULK_KIND, "n_files": len(uploads), "filenames": safe_names,
            "content_length": content_length, "declared_formats": [
                item.declared_format or _SUFFIX_FORMATS.get(PurePath(item.filename).suffix.lower())
                for item in manifest.items],
            "modalities": sorted({item.modality for item in manifest.items}),
            "dataset_ids": sorted({str(item.dataset_id) for item in manifest.items if item.dataset_id}),
        },
    )
    from redsim.db.models import MlBatch

    with get_session() as sess:
        sess.add(MlBatch(
            id=bulk_id, project_id=project_id, kind=BULK_KIND, status="accepted", created_by=actor,
            config={"n_files": len(uploads), "filenames": safe_names, "content_length": content_length,
                    "items": [item.model_dump(mode="json", exclude={"license_statement"}) for item in manifest.items]},
        ))
        sess.flush()

    service = _service_admission()
    results: list[dict[str, Any]] = []
    for index, item in enumerate(manifest.items):
        if service is not None:
            try:
                row = service(item=item.model_dump(mode="json"), upload=by_name[item.filename], index=index,
                              project_id=project_id, actor=actor, writer=writer, config=config, bulk_id=bulk_id)
                if hasattr(row, "__await__"):
                    row = await row
                results.append(dict(row))
                continue
            except TypeError:
                # A service with another signature: fall back to the route's helpers below.
                service = None
        results.append(await admit_upload_file(
            item, by_name[item.filename], index=index, project_id=project_id, actor=actor, writer=writer,
            config=config, bulk_id=bulk_id,
        ))

    admitted = [r for r in results if r.get("status") == "validating"]
    refused_rows = [r for r in results if r.get("status") == "refused"]
    with get_session() as sess:
        batch = sess.get(MlBatch, bulk_id)
        if batch is not None:
            batch.config = {
                **dict(batch.config or {}),
                "n_admitted": len(admitted), "n_refused": len(refused_rows),
                "target_ids": [r["target_id"] for r in admitted],
                "ingest_run_ids": [r["ingest_run_id"] for r in admitted],
                "refused": [{"index": r["index"], "filename": safe_filename(str(r["filename"]), ""),
                             "code": r.get("code")} for r in refused_rows],
                "completed_at": datetime.now(UTC).isoformat(),
            }
    body: dict[str, Any] = {
        "bulk_id": bulk_id, "project_id": project_id, "kind": BULK_KIND,
        "n_files": len(results), "n_admitted": len(admitted), "n_refused": len(refused_rows),
        "results": results, "status_url": f"/v1/ml/capacity?project={project_id}",
    }
    if not admitted:
        detail = error_detail(
            BATCH_MEMBER_REFUSED, "every file of the bulk upload was refused; see results",
            members=[{"index": r["index"], "filename": r["filename"], "code": r.get("code"), "message": r.get("message")}
                     for r in refused_rows],
            **body,
        )
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": detail})
    if refused_rows:
        return JSONResponse(status_code=status.HTTP_207_MULTI_STATUS, content=body)
    return body


# ---------------------------------------------------------------------------
# GET /v1/ml/capacity
# ---------------------------------------------------------------------------


def _batch_limits() -> dict[str, Any] | None:
    """The batch caps of ``redsim.services.ml_batches`` when that track has landed them, else ``None``."""
    import importlib

    try:
        module = importlib.import_module("redsim.services.ml_batches")
    except ImportError:
        return None
    fn = getattr(module, "batch_limits", None)
    if callable(fn):
        try:
            value = fn()
            return dict(value) if isinstance(value, dict) else None
        except Exception:  # noqa: BLE001 - the capacity view never fails on a sibling's helper
            return None
    limits = {key: getattr(module, name) for key, name in (
        ("max_members", "DEFAULT_MAX_MEMBERS"), ("max_parallel_default", "DEFAULT_MAX_PARALLEL"),
    ) if isinstance(getattr(module, name, None), int)}
    return limits or None


@router.get("/ml/capacity")
def ml_capacity(project: str | None = None, user: CurrentUser = Depends(get_current_user)) -> dict[str, Any]:
    """Per-project capacity numbers (BULK-22): ``?project=`` (membership) or every readable project."""
    from sqlalchemy import select

    from redsim.db.models import Project
    from redsim.db.session import get_session
    from redsim.services import ml_capacity as capacity
    from redsim.services.llm_capacity import gateway_cap

    if project is not None:
        ensure_project_access(user, project)
        wanted: list[str] | None = [project]
    else:
        wanted = accessible_project_ids(user)
    with get_session() as sess:
        if wanted is None:
            rows = list(sess.execute(select(Project).order_by(Project.id)).scalars().all())
        else:
            rows = [row for pid in wanted if (row := sess.get(Project, pid)) is not None]
            if project is not None and not rows:
                raise api_error(NOT_FOUND, "project not found")
        projects = [capacity.project_capacity(sess, row) for row in rows]
        global_block = capacity.global_capacity(sess) if user.is_system else None
    body: dict[str, Any] = {
        "projects": projects,
        "limits": {
            "max_concurrent_runs_default": capacity.default_max_concurrent_runs(),
            "llm_probe_max_concurrent_per_gateway": gateway_cap(),
            "daily_run_budget_default": capacity.default_daily_run_budget(),
            "env": {"max_concurrent_runs": capacity.MAX_CONCURRENT_ENV,
                    "daily_run_budget": [capacity.DAILY_BUDGET_ENV, capacity.DAILY_BUDGET_ENV_ALIAS],
                    "bulk_upload": [BULK_MAX_FILES_ENV, BULK_MAX_MB_ENV]},
            "bulk_upload": bulk_limits(),
            "batch": _batch_limits(),
        },
        "source": "jobs table (never broker inspection); dispatch continues at the end of every campaign run and "
                  "every 60 s from beat",
    }
    if project is not None and projects:
        body["project"] = projects[0]
    if global_block is not None:
        body["global"] = global_block
    return body


__all__ = [
    "BULK_KIND",
    "BULK_MAX_FILES_ENV",
    "BULK_MAX_MB_ENV",
    "BULK_UPLOAD_ACTION",
    "DEFAULT_BULK_MAX_FILES",
    "DEFAULT_BULK_MAX_MB",
    "BulkItem",
    "BulkManifest",
    "admit_upload_file",
    "bulk_limits",
    "bulk_max_bytes",
    "bulk_max_files",
    "router",
]
