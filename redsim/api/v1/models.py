"""Model catalog and static-only model upload admission."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from pathlib import PurePath
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.policy import Action, check, ensure_project_access

router = APIRouter(prefix="/models", tags=["ml-models"])
logger = logging.getLogger(__name__)

_ML_KINDS = {"ml_model_artifact", "ml_model_endpoint"}
_FORMATS = {"onnx", "torch_state_dict", "safetensors_state_dict"}
_PICKLE_SUFFIXES = {".pkl", ".pickle", ".joblib", ".sav", ".dill"}


def _error(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"code": code, "message": message, **extra}


def _detail(target: Any) -> dict[str, Any]:
    value = getattr(target, "detail", None)
    return dict(value) if isinstance(value, dict) else {}


def _project_model(target: Any) -> dict[str, Any]:
    detail = _detail(target)
    if not detail and str(target.value).startswith("bundled:"):
        bundled_id = str(target.value).split(":", 1)[1]
        bundled = next(
            (row for row in _bundled_rows(target.project_id) if row["id"] == bundled_id),
            None,
        )
        if bundled is not None:
            return bundled
    manifest_value = detail.get("manifest")
    manifest: dict[str, Any] = (
        manifest_value if isinstance(manifest_value, dict) else detail
    )
    source = detail.get("source")
    if source not in {"bundled", "upload", "endpoint"}:
        source = "endpoint" if target.kind == "ml_model_endpoint" else (
            "bundled" if str(target.value).startswith("bundled:") else "upload")
    return {
        "id": target.id,
        "project_id": target.project_id,
        "name": str(detail.get("name") or manifest.get("name") or target.id),
        "source": source,
        "modality": str(detail.get("modality") or manifest.get("modality") or "image"),
        "format": str(detail.get("format") or manifest.get("format") or
                      ("endpoint" if source == "endpoint" else "onnx")),
        "sha256": detail.get("sha256", manifest.get("sha256")),
        "manifest": manifest,
        "status": str(detail.get("status") or manifest.get("status") or
                      ("not_implemented" if source == "endpoint" else "registered")),
        "refusal_reason": detail.get("refusal_reason") or manifest.get("refusal_reason"),
        "reason": detail.get("reason"),
        "validation": detail.get("validation"),
    }


def _bundled_rows(project_id: str) -> list[dict[str, Any]]:
    try:
        from redsim.ml.targets import list_targets

        entries = list_targets()
    except ImportError:
        return []
    rows = []
    for info in entries:
        if info.metadata.get("source") != "bundled":
            continue
        metadata = dict(info.metadata)
        rows.append({
            "id": info.id, "project_id": project_id, "name": info.name,
            "source": "bundled", "modality": info.domain,
            "format": metadata.get("format", "torch_state_dict"),
            "sha256": metadata.get("sha256"), "manifest": metadata,
            "status": "available" if info.status == "available" else "not_implemented",
            "refusal_reason": None, "reason": info.reason, "validation": None,
        })
    return rows


def _get_registered(model_id: str) -> Any | None:
    from redsim.db.models import Target
    from redsim.db.session import get_session

    with get_session() as sess:
        target = sess.get(Target, model_id)
        if target is None or target.kind not in _ML_KINDS:
            return None
        sess.expunge(target)
        return target


@router.get("")
def list_models(
    project: str = "default",
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    from sqlalchemy import select

    from redsim.db.models import Target
    from redsim.db.session import get_session

    ensure_project_access(user, project)
    with get_session() as sess:
        targets = sess.execute(
            select(Target).where(Target.project_id == project, Target.kind.in_(_ML_KINDS))
        ).scalars().all()
        models = [_project_model(row) for row in targets]
    known = {row["id"] for row in models}
    models.extend(row for row in _bundled_rows(project) if row["id"] not in known)
    return {"models": models, "count": len(models)}


@router.get("/{model_id}")
def get_model(
    model_id: str,
    project: str = "default",
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    target = _get_registered(model_id)
    if target is not None:
        ensure_project_access(user, target.project_id)
        model = _project_model(target)
        # Campaign history remains an optional projection until the campaign
        # ORM is present; never invent history from unrelated run types.
        model["campaign_history"] = []
        return model
    ensure_project_access(user, project)
    for model in _bundled_rows(project):
        if model["id"] == model_id:
            model["campaign_history"] = []
            return model
    raise HTTPException(status_code=404, detail=_error("model_not_found", "model not found"))


def _sniff(filename: str, data: bytes, declared: str) -> str:
    suffix = PurePath(filename).suffix.lower()
    head = data[:16]
    if suffix in _PICKLE_SUFFIXES or (head and head[0] == 0x80):
        raise HTTPException(status_code=415, detail=_error(
            "pickle_refused", "pickle and joblib model artifacts are never accepted"))
    if not data:
        raise HTTPException(status_code=422, detail=_error(
            "unsupported_format", "the uploaded model is empty", field="file"))
    if head.startswith(b"PK\x03\x04"):
        detected = "torch_state_dict"
    elif suffix == ".onnx" and head[0] == 0x08:
        detected = "onnx"
    elif suffix == ".safetensors" and len(data) >= 9:
        header_size = int.from_bytes(data[:8], "little")
        detected = "safetensors_state_dict" if 0 < header_size <= len(data) - 8 and data[8:9] == b"{" else ""
    else:
        detected = ""
    if not detected:
        raise HTTPException(status_code=422, detail=_error(
            "unsupported_format", "file magic does not match an accepted model format", field="file"))
    if detected != declared:
        raise HTTPException(status_code=422, detail=_error(
            "format_mismatch", f"declared {declared}, but file magic indicates {detected}",
            field="declared_format"))
    return detected


async def _request_fields(request: Request) -> tuple[dict[str, Any], Any | None]:
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        try:
            value = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HTTPException(status_code=400, detail=_error(
                "invalid_request", "request body is not valid JSON")) from None
        if not isinstance(value, dict):
            raise HTTPException(status_code=400, detail=_error(
                "invalid_request", "request body must be an object"))
        return value, None
    form = await request.form()
    return {key: value for key, value in form.items() if key != "file"}, form.get("file")


@router.post("", status_code=status.HTTP_201_CREATED)
async def register_model(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    fields, upload = await _request_fields(request)
    source = str(fields.get("source") or ("upload" if upload is not None else "bundled"))
    project_id = str(fields.get("project_id") or "default")
    ensure_project_access(user, project_id)
    check(user, Action.MODEL_REGISTER, project_id)
    if source == "endpoint":
        raise HTTPException(status_code=501, detail=_error(
            "not_implemented", "black-box endpoint registration is not implemented", phase="B"))

    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.db.models import Target
    from redsim.db.session import get_session
    from redsim.safety import authorize

    config = load_config()

    if source == "bundled":
        bundled_id = str(fields.get("bundled_id") or "")
        bundled = next((row for row in _bundled_rows(project_id) if row["id"] == bundled_id), None)
        if bundled is None:
            raise HTTPException(status_code=422, detail=_error(
                "unknown_bundled_model", "bundled_id is not in the target registry", field="bundled_id"))
        with get_session() as sess:
            existing = sess.get(Target, bundled_id)
            if existing is not None:
                if existing.project_id != project_id or existing.kind not in _ML_KINDS:
                    raise HTTPException(status_code=409, detail=_error(
                        "model_id_conflict", "the bundled model id is already in use"))
                return _project_model(existing)
        manifest = bundled["manifest"]
        authorize(
            "model.register",
            None,
            allowlist=config.target_allowlist,
            actor=f"user:{user.sub}",
            writer=resolve_writer(config),
            project_id=project_id,
            detail={
                "actor": f"user:{user.sub}",
                "model_id": bundled_id,
                "format": manifest.get("format"),
                "sha256": manifest.get("sha256"),
                "bundled": True,
            },
        )
        with get_session() as sess:
            detail = {**bundled, "manifest": bundled["manifest"]}
            target = Target(id=bundled_id, project_id=project_id, kind="ml_model_artifact",
                            value=f"bundled:{bundled_id}", verified=True)
            # Migration 0010 supplies this mapped field in the merged P4 ORM.
            # Assignment is also harmless on an older ORM during a rolling
            # deployment and keeps the response faithful.
            target.detail = detail
            sess.add(target)
            sess.flush()
            return _project_model(target)

    if source != "upload" or upload is None or not hasattr(upload, "read"):
        raise HTTPException(status_code=400, detail=_error(
            "upload_missing_file", "a multipart file is required for source=upload", field="file"))
    declared = str(fields.get("declared_format") or "")
    if declared not in _FORMATS:
        raise HTTPException(status_code=422, detail=_error(
            "unsupported_format", f"declared_format must be one of {sorted(_FORMATS)}",
            field="declared_format"))
    architecture_id = str(fields.get("architecture_id") or "").strip() or None
    if declared in {"torch_state_dict", "safetensors_state_dict"}:
        try:
            from redsim.ml.targets.artifact import architecture_ids

            allowed = architecture_ids()
        except ImportError:
            allowed = ["smallcnn"]
        if architecture_id not in allowed:
            raise HTTPException(status_code=422, detail=_error(
                "architecture_missing" if architecture_id is None else "architecture_not_allowlisted",
                f"state_dict uploads require architecture_id from {allowed}", field="architecture_id"))

    cap = int(os.environ.get("REDSIM_ML_UPLOAD_MAX_MB", "512")) * 1024 * 1024
    length = request.headers.get("content-length")
    if length and int(length) > cap:
        raise HTTPException(status_code=413, detail=_error(
            "size_limit", f"upload exceeds the {cap} byte limit", field="file"))
    chunks: list[bytes] = []
    size = 0
    while chunk := await upload.read(1024 * 1024):
        size += len(chunk)
        if size > cap:
            raise HTTPException(status_code=413, detail=_error(
                "size_limit", f"upload exceeds the {cap} byte limit", field="file"))
        chunks.append(chunk)
    data = b"".join(chunks)
    filename = str(getattr(upload, "filename", "") or "model")
    detected = _sniff(filename, data, declared)
    digest = hashlib.sha256(data).hexdigest()
    model_id = uuid.uuid4().hex
    from redsim.storage.blobs import open_blob_store

    ref = open_blob_store().put(
        f"{project_id}/models/{model_id}", data, content_type="application/octet-stream")
    manifest = {
        "name": str(fields.get("name") or filename), "modality": str(fields.get("modality") or "image"),
        "format": detected, "sha256": digest, "size_bytes": size,
        "architecture_id": architecture_id, "dataset_id": str(fields.get("dataset_id") or ""),
        "dataset_split": str(fields.get("dataset_split") or "test"),
        "status": "validating", "license": str(fields.get("license_statement") or ""),
        "bundled": False,
    }
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    detail = {
        **manifest,
        "source": "upload",
        "original_filename": filename,
        "manifest": manifest,
        "validation": {"ingest_job_id": job_id},
    }
    authorize(
        "model.register",
        None,
        allowlist=config.target_allowlist,
        actor=f"user:{user.sub}",
        writer=resolve_writer(config),
        project_id=project_id,
        run_id=run_id,
        detail={
            "actor": f"user:{user.sub}",
            "model_id": model_id,
            "format": detected,
            "sha256": digest,
            "size_bytes": size,
        },
    )
    with get_session() as sess:
        from redsim.db.models import Job, Run

        target = Target(id=model_id, project_id=project_id, kind="ml_model_artifact",
                        value=ref.location, verified=True)
        target.detail = detail
        sess.add(target)
        sess.flush()
        sess.add(Run(
            id=run_id,
            project_id=project_id,
            target_id=model_id,
            mode="api",
            status="queued",
            scanner="ml.ingest",
            created_by=f"user:{user.sub}",
            stage_table={"stage": None, "stages_done": [], "jobs": {}},
        ))
        sess.flush()
        sess.add(Job(
            id=job_id,
            run_id=run_id,
            project_id=project_id,
            type="model.validate",
            status="queued",
            created_by=f"user:{user.sub}",
            detail={"target_id": model_id},
        ))
        sess.flush()
        response = _project_model(target)
        response["ingest_run_id"] = run_id
    try:
        from redsim.workers.tasks.ml_model import ml_model_validate

        queued = ml_model_validate.delay(job_id)
        with get_session() as sess:
            from redsim.db.models import Job

            row = sess.get(Job, job_id)
            if row is not None:
                row.celery_task_id = str(queued.id)
    except Exception:  # durable queued row survives broker outages
        logger.warning("enqueue failed for model validation job %s", job_id, exc_info=True)
    return response


@router.delete("/{model_id}")
def delete_model(
    model_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    from sqlalchemy import select

    from redsim.db.models import Run, Target
    from redsim.db.session import get_session

    with get_session() as sess:
        target = sess.get(Target, model_id)
        if target is None or target.kind not in _ML_KINDS:
            raise HTTPException(status_code=404, detail=_error("model_not_found", "model not found"))
        project_id = target.project_id
    ensure_project_access(user, project_id)
    check(user, Action.TARGET_MANAGE, project_id)
    with get_session() as sess:
        active = sess.execute(select(Run.id).where(
            Run.target_id == model_id, Run.status.in_(["queued", "running"])).limit(1)).first()
        if active:
            raise HTTPException(status_code=409, detail=_error(
                "campaign_in_flight", "an active campaign references this model"))
        target = sess.get(Target, model_id)
        if target is None:
            raise HTTPException(status_code=404, detail=_error("model_not_found", "model not found"))
        sess.delete(target)
    return {"deleted": model_id}