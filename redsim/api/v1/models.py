"""Model catalog and static-only model admission (spec 9.3, 17.2 "Models").

Three sources share ``POST /v1/models``:

* ``source: "bundled"`` (JSON ``{project_id, bundled_id}``) goes through
  ``services.ml_models.register_bundled_model``: per-project ``Target`` ids,
  ``409 already_registered`` on a live duplicate, ``404`` for an unknown or
  fixture-only id.
* ``source: "upload"`` (multipart) performs the static checks of spec 9.3 in
  this process and nothing more: ``Content-Length`` is required (411), the
  ``REDSIM_ML_UPLOAD_MAX_MB`` cap is enforced while the stream is read, the
  first bytes are sniffed against the declared format, the sha256 is computed,
  the bytes go to the blob store under ``{project}/models/{target_id}/{name}``
  and the ``Target`` plus its ``ml.ingest`` Run and ``model.validate`` Job are
  written after the ``model.register`` audit row. Every refusal writes a
  ``model.register`` ``success=False`` row before it is raised and carries the
  spec 17.3 code (``model_too_large``, ``unsupported_model_format``,
  ``pickle_refused``, ``architecture_required``, ``architecture_not_allowlisted``,
  ``dataset_incompatible``). Model bytes are never deserialised here.
* ``source: "endpoint"`` (JSON, Phase B; ENDPOINT-01, -07, -19, -20, -31)
  registers a black-box predict endpoint. The gate is ``TARGET_MANAGE``
  (admin): the registration authorises queries against a host, so the bar is
  the one for managing targets, not ``MODEL_REGISTER``. The static checks run
  in ``services.ml_models.admit_endpoint_registration``: the body through
  ``EndpointRegistration`` (URL shape, modality, dataset, class list, the D3
  ``evaluation_instance_attestation``), the URL through the egress policy
  (``endpoint_url_invalid`` / ``endpoint_not_allowlisted`` / ``egress_refused``),
  the AuthProfile by id (same project or ``404 not_found``; kind ``bearer`` or
  ``header`` or ``auth_profile_kind_unsupported``), the dataset binding
  (``dataset_incompatible``). Then ``authorize("model.register", url, ...)``
  writes the chained row with the allowlist verdict, the ``Target`` (kind
  ``ml_model_endpoint``, value the URL, detail an ``MLModelManifest`` with
  ``format: "endpoint"`` and the ``EndpointSpec`` block, ``sha256`` the
  descriptor digest), the ``ml.ingest`` Run and the ``model.validate`` Job are
  committed and the job is enqueued; a broker outage withdraws the three rows,
  records the withdrawal on the chain and answers ``503 queue_unavailable``
  (an endpoint registration is never left waiting for the reaper). Nothing is
  resolved, connected or queried from this process; the worker probes the
  endpoint through the predict broker. ``endpoint_kind: "llm"`` is delegated to
  ``redsim.services.ml_llm.register_llm_target`` when that module is present
  and answers ``501 not_implemented`` with the reason otherwise.

``GET /v1/models`` lists the project's registered targets (soft-deleted rows
hidden), the unregistered bundled catalog entries (fixture-only targets are
never listed) and the LLM domain as a ``not_implemented`` row with its reason.
Endpoint rows carry the host only (never the URL, never a credential), the
response fingerprint and the black-box attacks that can launch on them. The
catalog registries are imported lazily and never pull torch, ART or ONNX into
this process (``tests/test_api_process_has_no_ml.py``); when a registry cannot
be imported the route answers ``503 ml_catalog_unavailable`` rather than an
empty list.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import PurePath
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from redsim.api import errors as _errors
from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import (
    ARCHITECTURE_NOT_ALLOWLISTED,
    ARCHITECTURE_REQUIRED,
    CAMPAIGN_IN_FLIGHT,
    DATASET_INCOMPATIBLE,
    ENDPOINT_NOT_ALLOWLISTED,
    HTTP_STATUS,
    LICENSE_REQUIRED,
    MODEL_TOO_LARGE,
    NOT_FOUND,
    NOT_IMPLEMENTED,
    PICKLE_REFUSED,
    QUEUE_UNAVAILABLE,
    UNSUPPORTED_MODEL_FORMAT,
    ApiError,
    api_error,
)
from redsim.api.policy import Action, check, ensure_project_access
from redsim.api.v1.ml_capabilities import (
    UPLOAD_FORMATS,
    architecture_allowlist,
    catalog_unavailable,
    upload_max_bytes,
)

# Light service module: manifest JSON reads and the ORM only, no ML imports
# (tests/test_api_process_has_no_ml.py).
from redsim.services.ml_models import (
    DELETED_STATUS,
    ENDPOINT_KIND,
    DatasetBindingError,
    EndpointAdmissionError,
    MlCatalogUnavailable,
    admit_endpoint_registration,
    audit_refused_admission,
    campaign_history,
    check_upload_dataset,
    delete_model_target,
    endpoint_auth_profile_id,
    endpoint_host,
    is_deleted,
    is_endpoint_target,
    last_run_ids,
    register_bundled_model,
    safe_filename,
    upload_blob_key,
)

router = APIRouter(prefix="/models", tags=["ml-models"])
logger = logging.getLogger(__name__)

_ML_KINDS = {"ml_model_artifact", "ml_model_endpoint"}
_STATE_DICT_FORMATS = {"torch_state_dict", "safetensors_state_dict"}
_PICKLE_SUFFIXES = {".pkl", ".pickle", ".joblib", ".sav", ".dill"}
# Phase A evaluates image and tabular classifiers; every other modality is a
# named Phase B route (spec 17.3 ``not_implemented``, always with ``phase``).
_PHASE_A_MODALITIES = {"image", "tabular"}
_CHUNK = 1024 * 1024

# Phase B addendum codes the endpoint branch needs that the errors table may not
# carry yet: resolved by name with a fallback to the addendum spelling, as the
# wave brief allows. ``auth_profile_required`` (422) is the missing-profile
# refusal of ENDPOINT-06; ``attestation_required`` would be the D3 attestation's
# own code (ENDPOINT-31) and ``license_required`` stands in for it until then.
AUTH_PROFILE_REQUIRED: str = getattr(_errors, "AUTH_PROFILE_REQUIRED", "auth_profile_required")
ATTESTATION_REQUIRED: str = getattr(_errors, "ATTESTATION_REQUIRED", LICENSE_REQUIRED)
#: Body keys of ``POST /v1/models`` that are not part of the ``EndpointRegistration`` contract.
_ENDPOINT_ROUTE_KEYS = frozenset({"source", "project_id", "endpoint_kind"})
#: Keys of the endpoint projection that name what the worker's probe recorded (never a credential).
_PROBE_KEYS = ("http_status", "latency_ms", "n_rows", "output_kind", "tls_mode", "checked_at", "reason",
               "error_class", "code", "rule", "rows", "requests")


class _Refusal(Exception):
    """An upload refusal: the 17.3 envelope plus the reason the audit row records."""

    def __init__(self, http: HTTPException, reason: str, **audit: Any) -> None:
        super().__init__(reason)
        self.http = http
        self.reason = reason
        self.audit = audit


def _refuse(code: str, message: str, **fields: Any) -> _Refusal:
    return _Refusal(api_error(code, message, **fields), code, **{k: v for k, v in fields.items() if k == "field"})


def _detail(target: Any) -> dict[str, Any]:
    value = getattr(target, "detail", None)
    return dict(value) if isinstance(value, dict) else {}


def _is_deleted(target: Any) -> bool:
    """A soft-deleted model target: hidden from the catalog, 404 by id."""
    return is_deleted(getattr(target, "detail", None))


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------


def _black_box_attacks(modality: str) -> list[str] | None:
    """Evasion adapters that launch on a target without gradients (``black_box`` and ``modality:<m>`` tags).

    ``None`` when the attack registry cannot be imported in this process: the
    row then says nothing rather than an empty list (spec 18.5 honest states).
    """
    try:
        from redsim.ml.attacks import ATTACKS, attack_capabilities
    except ImportError:
        return None
    wanted = {"black_box", "family:evasion", f"modality:{modality}"}
    out: list[str] = []
    for attack_id in ATTACKS.ids():
        adapter = ATTACKS.maybe_get(attack_id)
        if adapter is None:
            continue
        if wanted <= set(attack_capabilities(adapter)):
            out.append(str(attack_id))
    return sorted(out)


def _endpoint_projection(target: Any, detail: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """The ``endpoint`` block of a model row (ENDPOINT-17): host, ids, contract, probe summary, fingerprint.

    Never the URL (the path could carry a tenant's routing), never the
    credential or its ciphertext: the AuthProfile is named by id only.
    """
    spec_value = detail.get("endpoint") if isinstance(detail.get("endpoint"), dict) else manifest.get("endpoint")
    spec: dict[str, Any] = dict(spec_value) if isinstance(spec_value, dict) else {}
    validation_value = detail.get("validation")
    validation: dict[str, Any] = validation_value if isinstance(validation_value, dict) else {}
    probe_value = detail.get("endpoint_probe")
    if not isinstance(probe_value, dict):
        probe_value = validation.get("probe")
    probe_source: dict[str, Any] = probe_value if isinstance(probe_value, dict) else {}
    probe = {key: probe_source.get(key) for key in _PROBE_KEYS if probe_source.get(key) is not None}
    fingerprint_value = detail.get("endpoint_fingerprint")
    fingerprint: dict[str, Any] = dict(fingerprint_value) if isinstance(fingerprint_value, dict) else {}
    attestation = detail.get("attestation") if isinstance(detail.get("attestation"), dict) else None
    return {
        "host": str(spec.get("url_host") or endpoint_host(str(target.value))),
        "scheme": detail.get("scheme"),
        "plaintext": detail.get("plaintext"),
        "auth_profile_id": endpoint_auth_profile_id(detail),
        "auth_kind": detail.get("auth_kind"),
        "contract_version": spec.get("contract_version"),
        "input_format": detail.get("input_format"),
        "batch_rows": spec.get("batch_rows"),
        "timeout_s": spec.get("timeout_s"),
        "fingerprint_sha256": fingerprint.get("sha256") or probe_source.get("fingerprint_sha256"),
        "fingerprint_label": fingerprint.get("label"),
        "output_kind": fingerprint.get("output_kind") or probe_source.get("output_kind"),
        "probe": probe or None,
        "attestation": attestation,
        "verified": False,   # ownership verification is not built (ENDPOINT-26, option a)
    }


def _project_model(target: Any) -> dict[str, Any]:
    """The list/detail row of a registered ``Target`` (spec 17.2 ``GET /v1/models``)."""
    detail = _detail(target)
    manifest_value = detail.get("manifest")
    manifest: dict[str, Any] = manifest_value if isinstance(manifest_value, dict) else detail
    value = str(target.value)
    endpoint = target.kind == ENDPOINT_KIND or is_endpoint_target(detail)
    source = detail.get("source")
    if source not in {"bundled", "upload", "endpoint"}:
        source = "endpoint" if endpoint else ("bundled" if value.startswith("bundled:") else "upload")
    bundled_id = detail.get("bundled_id") or (value.split(":", 1)[1] if value.startswith("bundled:") else None)
    modality = str(detail.get("modality") or manifest.get("modality") or "image")
    row: dict[str, Any] = {
        "id": target.id,
        "project_id": target.project_id,
        "registered": True,
        "bundled_id": bundled_id,
        "name": str(detail.get("name") or manifest.get("name") or target.id),
        "source": source,
        "modality": modality,
        "format": detail.get("format") or manifest.get("format") or ("endpoint" if endpoint else None),
        "sha256": detail.get("sha256", manifest.get("sha256")),
        "manifest": manifest,
        # Status comes from the manifest for every kind (registered -> validating -> available | refused).
        "status": str(detail.get("status") or manifest.get("status") or "registered"),
        "refusal_reason": detail.get("refusal_reason") or manifest.get("refusal_reason"),
        "reason": detail.get("reason"),
        "validation": detail.get("validation"),
        "last_run_id": None,
    }
    if endpoint:
        row["gradients"] = False
        row["endpoint"] = _endpoint_projection(target, detail, manifest)
        row["available_attacks"] = _black_box_attacks(modality)
    return row


def _registry_infos() -> list[Any]:
    """Every registry entry; ``503 ml_catalog_unavailable`` when the registry cannot be imported."""
    try:
        from redsim.ml.targets import list_targets

        return list(list_targets())
    except ImportError as exc:
        raise catalog_unavailable(exc, "bundled model") from exc


def _bundled_row(info: Any, project_id: str) -> dict[str, Any]:
    metadata = dict(info.metadata)
    return {
        "id": info.id, "project_id": project_id, "registered": False, "bundled_id": info.id,
        "name": info.name, "source": "bundled", "modality": info.domain,
        "format": metadata.get("format"), "sha256": metadata.get("sha256"), "manifest": metadata,
        "status": "available" if info.status == "available" else "not_implemented",
        "refusal_reason": None, "reason": info.reason, "validation": None, "last_run_id": None,
    }


def _llm_row(info: Any, project_id: str) -> dict[str, Any]:
    """The LLM domain as a registry entry (spec 6.6, 17.2): ``not_implemented`` with its reason."""
    metadata = dict(info.metadata)
    raw_connection = metadata.get("connection")
    connection: dict[str, Any] = dict(raw_connection) if isinstance(raw_connection, dict) else {}
    return {
        "id": info.id, "project_id": project_id, "registered": False, "bundled_id": None,
        "name": info.name, "source": "endpoint", "modality": info.domain,
        "format": "endpoint", "sha256": None,
        # Env var names and whether they are set; never a value.
        "manifest": {"phase": metadata.get("phase", "B"), "kind": metadata.get("kind", "ml_model_endpoint"),
                     "gateway": connection.get("gateway", "pythia"),
                     "configured": bool(connection.get("configured", False))},
        "status": "not_implemented", "phase": metadata.get("phase", "B"),
        "refusal_reason": None, "reason": info.reason, "validation": None, "last_run_id": None,
    }


def _catalog_rows(project_id: str) -> list[dict[str, Any]]:
    """Unregistered catalog rows: bundled demo models (never fixtures) and the LLM domain."""
    rows: list[dict[str, Any]] = []
    for info in _registry_infos():
        metadata = info.metadata
        if metadata.get("source") == "bundled":
            if metadata.get("fixture_only"):
                continue          # CI fixtures are never demo targets (spec 5.5, 11.1)
            rows.append(_bundled_row(info, project_id))
        elif info.domain == "llm":
            # The LLM domain only: real endpoint targets are Target rows, never registry entries (ENDPOINT-17).
            rows.append(_llm_row(info, project_id))
    return rows


def _get_registered(model_id: str) -> Any | None:
    from redsim.db.models import Target
    from redsim.db.session import get_session

    with get_session() as sess:
        target = sess.get(Target, model_id)
        if target is None or target.kind not in _ML_KINDS or _is_deleted(target):
            return None
        sess.expunge(target)
        return target


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


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
        # Soft-deleted targets keep their row for Run / campaign history but
        # leave the catalog; a deleted bundled registration shows up again as
        # the unregistered catalog entry below.
        live = [row for row in targets if not _is_deleted(row)]
        models = [_project_model(row) for row in live]
        latest = last_run_ids(sess, [row.id for row in live])
    for model in models:
        model["last_run_id"] = latest.get(str(model["id"]))
    registered_bundled = {model["bundled_id"] for model in models if model["bundled_id"]}
    models.extend(
        row for row in _catalog_rows(project)
        if not (row["source"] == "bundled" and row["bundled_id"] in registered_bundled)
    )
    return {"models": models, "count": len(models)}


@router.get("/{model_id}")
def get_model(
    model_id: str,
    project: str = "default",
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    from redsim.db.session import get_session

    target = _get_registered(model_id)
    if target is not None:
        ensure_project_access(user, target.project_id)
        model = _project_model(target)
        with get_session() as sess:
            model["campaign_history"] = campaign_history(sess, target.id)
        model["last_run_id"] = model["campaign_history"][0]["run_id"] if model["campaign_history"] else None
        return model
    ensure_project_access(user, project)
    for model in _catalog_rows(project):
        if model["id"] == model_id:
            model["campaign_history"] = []
            return model
    raise api_error(NOT_FOUND, "model not found")


# ---------------------------------------------------------------------------
# Admission
# ---------------------------------------------------------------------------


def _sniff(filename: str, head: bytes, declared: str) -> str:
    """Detect the format from the first bytes (spec 9.2 admission sniff); refusals are typed."""
    suffix = PurePath(filename).suffix.lower()
    if suffix in _PICKLE_SUFFIXES or (head and head[0] == 0x80):
        raise _refuse(PICKLE_REFUSED, "pickle and joblib model artifacts are never accepted", field="file")
    if not head:
        raise _refuse(UNSUPPORTED_MODEL_FORMAT, "the uploaded model is empty", field="file")
    if head.startswith(b"PK\x03\x04"):
        detected = "torch_state_dict"
    elif suffix == ".onnx" and head[0] == 0x08:
        detected = "onnx"
    elif suffix == ".safetensors" and len(head) >= 9:
        header_size = int.from_bytes(head[:8], "little")
        detected = "safetensors_state_dict" if 0 < header_size and head[8:9] == b"{" else ""
    else:
        detected = ""
    if not detected:
        raise _refuse(UNSUPPORTED_MODEL_FORMAT, "file magic does not match an accepted model format", field="file")
    if detected != declared:
        raise _refuse(UNSUPPORTED_MODEL_FORMAT,
                      f"declared {declared}, but file magic indicates {detected}",
                      field="declared_format", detected_format=detected)
    return detected


async def _request_fields(request: Request) -> tuple[dict[str, Any], Any | None]:
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        try:
            value = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HTTPException(status_code=400, detail="request body is not valid JSON") from None
        if not isinstance(value, dict):
            raise HTTPException(status_code=400, detail="request body must be an object")
        return value, None
    form = await request.form()
    return {key: value for key, value in form.items() if key != "file"}, form.get("file")


def _content_length(request: Request, cap: int) -> int:
    """Spec 17.3: ``Content-Length`` is required on uploads; over the cap is 413 before any byte is read."""
    raw = request.headers.get("content-length")
    if raw is None or not raw.strip().isdigit():
        raise _Refusal(
            HTTPException(status_code=status.HTTP_411_LENGTH_REQUIRED,
                          detail="Content-Length is required for model uploads"),
            "length_required",
        )
    length = int(raw)
    if length > cap:
        raise _refuse(MODEL_TOO_LARGE, f"upload of {length} bytes exceeds the {cap} byte cap", field="file")
    return length


async def _read_capped(upload: Any, filename: str, declared: str, cap: int) -> tuple[bytes, str, str, int]:
    """Read the upload in chunks, sniffing the first and refusing past ``cap``; ``(data, sha256, format, n)``."""
    hasher = hashlib.sha256()
    chunks: list[bytes] = []
    size = 0
    detected: str | None = None
    while chunk := await upload.read(_CHUNK):
        if detected is None:
            detected = _sniff(filename, chunk[:16], declared)
        size += len(chunk)
        if size > cap:
            raise _refuse(MODEL_TOO_LARGE, f"upload exceeds the {cap} byte cap", field="file")
        hasher.update(chunk)
        chunks.append(chunk)
    if detected is None:
        detected = _sniff(filename, b"", declared)
    return b"".join(chunks), hasher.hexdigest(), detected, size


@router.post("", status_code=status.HTTP_201_CREATED)
async def register_model(
    request: Request,
    project: str | None = None,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
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
        # Before the body is parsed: no project role is known yet, so the
        # refusal is recorded on the chain the query string names, else system.
        try:
            _content_length(request, cap)
        except _Refusal as exc:
            audit_refused_admission(
                writer, action="model.register", actor=actor, project_id=project,
                detail={"kind": "ml_model_artifact", "source": "upload", "reason": exc.reason,
                        "content_length": request.headers.get("content-length")},
            )
            raise exc.http from exc

    fields, upload = await _request_fields(request)
    source = str(fields.get("source") or ("upload" if upload is not None else "bundled"))
    project_id = str(fields.get("project_id") or project or "default")
    ensure_project_access(user, project_id)

    if source == "endpoint":
        # Spec 7.3 / 7.4 (ENDPOINT-20): registering a host to query is TARGET_MANAGE (admin), gated
        # before any field is read. A denied role is the policy layer's 403; nothing is written.
        check(user, Action.TARGET_MANAGE, project_id)
        return _register_endpoint(fields, actor=actor, project_id=project_id, writer=writer, config=config)

    check(user, Action.MODEL_REGISTER, project_id)

    if source == "bundled":
        bundled_id = str(fields.get("bundled_id") or "")
        try:
            with get_session() as sess:
                target = register_bundled_model(
                    sess, project_id, bundled_id, actor, audit_writer=writer, config=config,
                )
                response = _project_model(target)
        except ApiError as exc:
            audit_refused_admission(
                writer, action="model.register", actor=actor, project_id=project_id,
                detail={"kind": "ml_model_artifact", "source": "bundled", "bundled_id": bundled_id,
                        "reason": exc.code, **{k: v for k, v in exc.detail.items()
                                               if k in {"reason", "refusal_reason", "status", "target_id"}}},
            )
            raise exc.as_http_exception() from exc
        except MlCatalogUnavailable as exc:
            raise catalog_unavailable(exc.reason, exc.what) from exc
        response["campaign_history"] = []
        return response

    if source != "upload":
        raise api_error(UNSUPPORTED_MODEL_FORMAT, f"unknown source {source!r}; use bundled or upload",
                        field="source")

    declared = str(fields.get("declared_format") or "")
    architecture_id = str(fields.get("architecture_id") or "").strip() or None
    modality = str(fields.get("modality") or "image").strip().lower()
    license_statement = str(fields.get("license_statement") or "").strip()
    dataset_id = str(fields.get("dataset_id") or "").strip()
    dataset_split = str(fields.get("dataset_split") or "").strip() or None
    filename = str(getattr(upload, "filename", "") or "") if upload is not None else ""
    audit_base = {
        "kind": "ml_model_artifact", "source": "upload", "declared_format": declared or None,
        "architecture_id": architecture_id, "modality": modality, "filename": safe_filename(filename, ""),
        "dataset_id": dataset_id or None, "dataset_split": dataset_split,
    }

    def refused(exc: _Refusal, **extra: Any) -> HTTPException:
        # Spec 9.3 step 2 / 5.11: the refusal is on the project chain before it is raised.
        audit_refused_admission(
            writer, action="model.register", actor=actor, project_id=project_id,
            detail={**audit_base, **extra, "reason": exc.reason, **exc.audit},
        )
        return exc.http

    try:
        if upload is None or not hasattr(upload, "read"):
            raise _refuse(UNSUPPORTED_MODEL_FORMAT, "a multipart file is required for source=upload", field="file")
        if declared not in UPLOAD_FORMATS:
            raise _refuse(UNSUPPORTED_MODEL_FORMAT, f"declared_format must be one of {list(UPLOAD_FORMATS)}",
                          field="declared_format")
        if modality not in _PHASE_A_MODALITIES:
            raise _Refusal(api_error(
                NOT_IMPLEMENTED,
                f"{modality!r} model uploads are not implemented; Phase A evaluates "
                f"{sorted(_PHASE_A_MODALITIES)} classifiers", phase="B", field="modality"),
                NOT_IMPLEMENTED, field="modality")
        if architecture_id is None and declared in _STATE_DICT_FORMATS:
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
        # Declared licence and dataset binding are validated here, before a
        # single byte is read towards the blob store and before any Target /
        # Run / Job row exists (spec 9.3 steps 1 to 3, 11.1, 17.3
        # ``dataset_incompatible``). The manifest is read as JSON only; shape
        # and class-count checks stay on the worker.
        if not license_statement:
            raise _refuse(LICENSE_REQUIRED,
                          "license_statement is required: only models with a declared licence are registered",
                          field="license_statement")
        try:
            binding = check_upload_dataset(dataset_id, modality=modality, dataset_split=dataset_split)
        except DatasetBindingError as exc:
            raise _refuse(DATASET_INCOMPATIBLE, str(exc), field=exc.field) from exc
    except _Refusal as exc:
        raise refused(exc) from exc

    filename = filename or "model"
    try:
        data, digest, detected, size = await _read_capped(upload, filename, declared, cap)
    except _Refusal as exc:
        raise refused(exc, size_bytes=None) from exc

    from redsim.storage.blobs import open_blob_store

    model_id = uuid.uuid4().hex
    blob_key = upload_blob_key(project_id, model_id, filename)
    ref = open_blob_store().put(blob_key, data, content_type="application/octet-stream")
    manifest = {
        "name": str(fields.get("name") or filename), "modality": modality,
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
        "blob": {"key": blob_key, "location": ref.location, "sha256": ref.sha256, "size_bytes": ref.size_bytes},
        "manifest": manifest,
        "validation": {"ingest_job_id": job_id, "ingest_run_id": run_id},
    }
    from redsim.safety import authorize

    # Spec 9.3 step 4: the chained event precedes the Target / Run / Job rows
    # and the enqueue. Spec 5.11 detail: refs and digests only, never bytes.
    authorize(
        "model.register",
        None,
        allowlist=config.target_allowlist,
        actor=actor,
        writer=writer,
        project_id=project_id,
        run_id=run_id,
        detail={
            **audit_base,
            "target_id": model_id,
            "detected_format": detected,
            "sha256": digest,
            "size_bytes": size,
            "dataset_id": binding.dataset_id,
            "dataset_split": binding.split,
            "dataset_revision": binding.revision,
            "blob_key": blob_key,
            "ingest_run_id": run_id,
            "ingest_job_id": job_id,
        },
    )
    with get_session() as sess:
        from redsim.db.models import Job, Run, Target

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
            created_by=actor,
            stage_table={"stage": None, "stages_done": [], "jobs": {}},
        ))
        sess.flush()
        sess.add(Job(
            id=job_id,
            run_id=run_id,
            project_id=project_id,
            type="model.validate",
            status="queued",
            created_by=actor,
            detail={"target_id": model_id},
        ))
        sess.flush()
        response = _project_model(target)
        response["ingest_run_id"] = run_id
        response["ingest_job_id"] = job_id
        response["campaign_history"] = []
    enqueued = False
    try:
        from redsim.workers.tasks.ml_model import ml_model_validate

        queued = ml_model_validate.delay(job_id)
        with get_session() as sess:
            from redsim.db.models import Job

            row = sess.get(Job, job_id)
            if row is not None:
                row.celery_task_id = str(queued.id)
        enqueued = True
    except Exception:  # durable queued row survives broker outages; the reaper picks it up
        logger.warning("enqueue failed for model validation job %s", job_id, exc_info=True)
    response["enqueued"] = enqueued
    return response


# ---------------------------------------------------------------------------
# Endpoint registration (``source: "endpoint"``; ENDPOINT-01, -07, -19, -20, -29, -31)
# ---------------------------------------------------------------------------


def _endpoint_error(code: str, message: str, **fields: Any) -> HTTPException:
    """The 17.3 envelope for an endpoint refusal; an addendum code the table lacks keeps its 422 shape."""
    if code == NOT_IMPLEMENTED:
        fields.setdefault("phase", "B")
    if code in HTTP_STATUS:
        return api_error(code, message, **fields)
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                         detail={"code": code, "message": message, **fields})


def _resolve_endpoint_code(exc: EndpointAdmissionError) -> str:
    """Swap the service's addendum spellings for the table's names when the table carries them."""
    if exc.code == "auth_profile_required":
        return AUTH_PROFILE_REQUIRED
    if exc.field == "evaluation_instance_attestation":
        return ATTESTATION_REQUIRED
    return exc.code


def _llm_registrar() -> Any | None:
    """``redsim.services.ml_llm.register_llm_target`` when the llm-api track has landed it, else ``None``."""
    try:
        import importlib

        module = importlib.import_module("redsim.services.ml_llm")
    except ImportError:
        return None
    registrar = getattr(module, "register_llm_target", None)
    return registrar if callable(registrar) else None


def _register_endpoint(
    fields: dict[str, Any],
    *,
    actor: str,
    project_id: str,
    writer: Any,
    config: Any,
) -> dict[str, Any]:
    """Admit a black-box predict endpoint (spec 9.3 steps 1 to 4 for the endpoint kind).

    Every refusal writes the ``model.register`` ``success=False`` row first
    (host, ids and the reason only; never the URL's userinfo or query, never a
    credential) and carries the 17.3 code. The successful path writes the
    chained ``model.register`` row with the allowlist verdict, then the Target,
    Run and Job rows and the enqueue in one transaction.
    """
    from redsim.db.session import get_session
    from redsim.safety import AuthorizationError, authorize

    endpoint_kind = str(fields.get("endpoint_kind") or "predict").strip().lower()
    body = {key: value for key, value in fields.items() if key not in _ENDPOINT_ROUTE_KEYS}
    raw_url = fields.get("url")
    raw_profile = fields.get("auth_profile_id")
    audit_base: dict[str, Any] = {
        "kind": ENDPOINT_KIND, "source": "endpoint", "endpoint_kind": endpoint_kind,
        "host": endpoint_host(raw_url) if isinstance(raw_url, str) else None,
        "auth_profile_id": raw_profile if isinstance(raw_profile, str) else None,
        "modality": fields.get("modality") if isinstance(fields.get("modality"), str) else None,
        "dataset_id": fields.get("dataset_id") if isinstance(fields.get("dataset_id"), str) else None,
    }

    def refused(code: str, message: str, *, field: str, target: str | None = None, **extra: Any) -> HTTPException:
        # Spec 9.3 step 2 / 5.11: the refusal is on the project chain before it is raised. A host the
        # allowlist refuses is recorded like every other allowlist refusal: target URL, allowlist_check fail.
        audit_refused_admission(
            writer, action="model.register", actor=actor, project_id=project_id,
            detail={**audit_base, **extra, "reason": code, "field": field},
            target=target, allowlist_check="fail" if target is not None else "n/a",
        )
        return _endpoint_error(code, message, field=field, **extra)

    if endpoint_kind == "llm":
        # LLM-03: ``services.ml_llm.register_llm_target(session, *, project_id, fields, actor, audit_writer,
        # config) -> Target`` writes its own model.register rows (success and refusal) and raises ApiError.
        registrar = _llm_registrar()
        if registrar is None:
            raise refused(NOT_IMPLEMENTED, "LLM target registration lands with the llm-api track (LLM-03); "
                          "only endpoint_kind 'predict' is implemented here", field="endpoint_kind", phase="B")
        try:
            with get_session() as sess:
                result = registrar(sess, project_id=project_id, fields=dict(fields), actor=actor,
                                   audit_writer=writer, config=config)
                llm_row: dict[str, Any] = result if isinstance(result, dict) else _project_model(result)
        except ApiError as exc:
            raise exc.as_http_exception() from exc
        llm_row.setdefault("campaign_history", [])
        return llm_row
    if endpoint_kind != "predict":
        raise refused(NOT_IMPLEMENTED, f"endpoint_kind {endpoint_kind!r} is not implemented; use 'predict'",
                      field="endpoint_kind", phase="B")

    try:
        with get_session() as sess:
            admission = admit_endpoint_registration(
                sess, body, project_id=project_id, allowlist=list(config.target_allowlist),
            )
    except EndpointAdmissionError as exc:
        code = _resolve_endpoint_code(exc)
        # The static egress rules ran before the allowlist rule, so a not-allowlisted URL is already
        # free of userinfo, query and fragment and may be recorded as the refused target.
        refused_url = str(raw_url) if code == ENDPOINT_NOT_ALLOWLISTED and isinstance(raw_url, str) else None
        raise refused(code, str(exc), field=exc.field, target=refused_url, **exc.extra) from exc

    reg = admission.registration
    model_id = uuid.uuid4().hex
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    registered_at = datetime.now(UTC).isoformat()
    manifest = admission.manifest(status="validating")
    detail: dict[str, Any] = {
        **manifest,
        "source": "endpoint",
        "endpoint_kind": "predict",
        "auth_profile_id": reg.auth_profile_id,
        "auth_kind": admission.auth_kind,
        "input_format": reg.resolved_input_format,
        "scheme": admission.scheme,
        "plaintext": admission.plaintext,
        "attestation": {"evaluation_instance": True, "by": actor, "at": registered_at,
                        "statement": "non-operational evaluation instance; no mission system is connected"},
        "registration": {"descriptor_sha256": admission.descriptor_sha256,
                         "allowlist_entry": admission.allowlist_entry, "contract": reg.contract_version},
        "registered_by": actor,
        "registered_at": registered_at,
        "manifest": manifest,
        "validation": {"ingest_job_id": job_id, "ingest_run_id": run_id, "probe": None},
    }
    audit_detail = {
        **admission.audit_detail(), "endpoint_kind": "predict", "target_id": model_id,
        "ingest_run_id": run_id, "ingest_job_id": job_id,
    }
    # Spec 9.3 step 4 / 5.11: the chained event, with the URL as the target so the allowlist verdict
    # is on the row, precedes the Target / Run / Job rows and the enqueue.
    try:
        authorize(
            "model.register", admission.url, allowlist=list(config.target_allowlist), actor=actor,
            writer=writer, project_id=project_id, run_id=run_id, detail=audit_detail,
        )
    except AuthorizationError as exc:
        # The failed row is already on the chain (allowlist_check fail); the egress check and
        # ``is_target_allowed`` disagree only on an allowlist the operator changed mid-request.
        raise _endpoint_error(ENDPOINT_NOT_ALLOWLISTED, str(exc), field="url", host=admission.host) from exc

    from redsim.db.models import Job, Run, Target

    # Rows first, committed, then the enqueue: a worker that picks the job up before the API commits
    # would find no row (the platform's admission order, ``tests/test_admission_audit_before_enqueue.py``).
    with get_session() as sess:
        target = Target(id=model_id, project_id=project_id, kind=ENDPOINT_KIND, value=admission.url, verified=False)
        target.detail = detail
        sess.add(target)
        sess.flush()
        sess.add(Run(
            id=run_id, project_id=project_id, target_id=model_id, mode="api", status="queued",
            scanner="ml.ingest", created_by=actor,
            stage_table={"stage": None, "stages_done": [], "jobs": {}},
        ))
        sess.flush()
        sess.add(Job(
            id=job_id, run_id=run_id, project_id=project_id, type="model.validate", status="queued",
            created_by=actor,
            # Spec 5.10 / ENDPOINT-29: the profile id rides on the job; the worker decrypts at pickup.
            detail={"target_id": model_id, "declared_format": "endpoint", "auth_profile_id": reg.auth_profile_id},
        ))
        sess.flush()
        response = _project_model(target)
    try:
        from redsim.workers.tasks.ml_model import ml_model_validate

        queued = ml_model_validate.delay(job_id)
    except Exception as exc:  # noqa: BLE001 - any broker failure rolls the registration back
        # Unlike an upload (a durable queued row the reaper picks up), an endpoint registration that
        # cannot be validated is withdrawn: the three rows nobody references yet are removed, the chain
        # records the withdrawal and the caller gets 503 queue_unavailable (ENDPOINT-01).
        logger.warning("enqueue failed for endpoint validation job %s; registration rolled back", job_id,
                       exc_info=True)
        with get_session() as sess:
            for model, key in ((Job, job_id), (Run, run_id), (Target, model_id)):
                row = sess.get(model, key)
                if row is not None:
                    sess.delete(row)
                sess.flush()
        audit_refused_admission(
            writer, action="model.register", actor=actor, project_id=project_id, run_id=run_id,
            detail={**audit_base, "host": admission.host, "target_id": model_id, "ingest_run_id": run_id,
                    "ingest_job_id": job_id, "reason": QUEUE_UNAVAILABLE, "rolled_back": True,
                    "error_class": type(exc).__name__},
        )
        raise api_error(QUEUE_UNAVAILABLE, "the validation job could not be enqueued; the registration was "
                        "rolled back and nothing was registered", target_id=model_id) from exc
    with get_session() as sess:
        job = sess.get(Job, job_id)
        if job is not None:
            job.celery_task_id = str(queued.id)
    response["ingest_run_id"] = run_id
    response["ingest_job_id"] = job_id
    response["campaign_history"] = []
    response["enqueued"] = True
    return response


@router.delete("/{model_id}")
def delete_model(
    model_id: str,
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Soft-delete a model target: audit, mark ``status: deleted``, drop the blob.

    The ``ml.ingest`` Run of every upload and the ``ml_campaigns`` rows
    reference the Target, so the row itself is retained for history (spec 17,
    "Run, Finding, Artifact and audit rows are retained"). The catalog hides it,
    ``GET /v1/models/{id}`` answers 404 and campaign admission refuses it. An
    endpoint target has no blob: the row is marked, the credential stays with
    its AuthProfile, and the audit row names the host (ENDPOINT-18).
    """
    from redsim.audit.chain import resolve_writer
    from redsim.config import load_config
    from redsim.db.models import Target
    from redsim.db.session import get_session

    with get_session() as sess:
        target = sess.get(Target, model_id)
        if target is None or target.kind not in _ML_KINDS or _is_deleted(target):
            raise api_error(NOT_FOUND, "model not found")
        project_id = target.project_id
    ensure_project_access(user, project_id)
    check(user, Action.TARGET_MANAGE, project_id)
    config = load_config()
    try:
        result = delete_model_target(
            target_id=model_id,
            actor=f"user:{user.sub}",
            config=config,
            audit_writer=resolve_writer(config),
        )
    except LookupError as exc:
        raise api_error(NOT_FOUND, "model not found") from exc
    except ValueError as exc:
        # The service raises ``campaign_in_flight: ...`` while a Run on the
        # model is queued or running (spec 17.3).
        raise api_error(CAMPAIGN_IN_FLIGHT, "an active campaign references this model",
                        reason=str(exc)) from exc
    return {
        "deleted": model_id,
        "status": DELETED_STATUS,
        "blob_deleted": result["blob_deleted"],
    }
