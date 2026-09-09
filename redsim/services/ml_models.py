"""Uploaded ML model targets: dataset binding, worker-side materialization, soft delete.

Two callers share this module and it stays light for both:

* The API process imports :func:`check_upload_dataset` (the static dataset
  compatibility check of spec 9.3 / 17.3 ``dataset_incompatible``) and
  :func:`delete_model_target`. Both read only ``MANIFEST.json`` and the ORM and
  import no ML library, so ``tests/test_api_process_has_no_ml.py`` holds.
* The worker and the sandbox child import :func:`uploaded_model_file`,
  :func:`uploaded_target` and :func:`artifact_target_from_path`, the only
  helpers that touch model bytes.

Dataset binding. ``redsim ml build-assets`` records evaluation splits under
``datasets[<dataset_id>].splits[<split>].file`` (``redsim.ml.assets.manifest``:
``DatasetEntry`` / ``SplitEntry`` / ``FileEntry``) with the class names and the
resolved revision on the dataset entry. :func:`resolve_dataset_binding` reads
that shape first and still accepts the pre-manifest flat ``models[*].eval_split``
entries, so an upload declared against a bundled dataset binds to the same
slice a bundled model is measured on.

Bundled registration. :func:`register_bundled_model` is the admission boundary
for ``POST /v1/models`` with ``source: "bundled"`` and for the ``redsim ml seed``
CLI (spec 9.3, 17.2): it resolves the bundled id through the target registry
and the asset manifest, refuses fixture-only entries (never a demo target,
spec 5.5), verifies the weights and the bound evaluation split against their
recorded digests, writes the ``model.register`` audit row, copies the weights
into the blob store and only then creates a per-project ``Target`` row whose
``value`` is ``bundled:<id>``. The registry id lives in ``detail.bundled_id``;
the row id is per project so two projects can register the same bundled model.

Refusals. :func:`audit_refused_admission` writes the ``success=False`` audit row
every refused admission carries (spec 5.11, 9.5) through the same writer the
successful path uses; the detail names the reason and never carries payload
bytes.

Deletion. ``DELETE /v1/models/{id}`` is a soft delete: every upload creates an
``ml.ingest`` Run whose ``target_id`` references the Target, and campaigns
reference it from ``ml_campaigns``, so the row must stay for history (spec 17:
"Run, Finding, Artifact and audit rows are retained"). The target's
``detail.status`` becomes ``"deleted"`` (an API-side terminal marker layered
over the frozen ``ModelStatus`` vocabulary; the frozen manifest copy under
``detail.manifest`` keeps its last validated status), the catalog hides it,
campaign admission refuses it (``409 model_load_refused``: status is not
``available``) and the blob is removed unless another live model target shares
the same content-addressed bytes. The ``target.manage`` audit event is written
before the row changes.

Endpoint registration (Phase B, ENDPOINT-01, -18, -29). ``POST /v1/models`` with
``source: "endpoint"`` registers a black-box predict endpoint as a Target of
kind ``ml_model_endpoint`` whose ``value`` is the inference URL (no userinfo,
query or fragment by construction). :func:`admit_endpoint_registration` runs
the static checks that are allowed in the API process: the body through
``redsim.ml.targets.endpoint_contract.EndpointRegistration``, the URL through
the egress policy, the AuthProfile by id (same project, kind ``bearer`` or
``header``), the dataset binding through :func:`check_upload_dataset` and the
class list against the bound split. Nothing is queried here. The worker task
(``redsim.workers.tasks.ml_model``) builds the credential-free
``target_endpoint`` request block with :func:`endpoint_request_block`, resolves
the credential through ``services.auth_profiles.resolve_auth_for_scan`` at
pickup and hands it to the broker in memory only. Soft delete keeps the row,
skips the blob store (the value is a URL) and records the host, never the URL.
Endpoint rows carry ``Target.verified = False``: the pentest-era ownership
check is gone (owner decision ENDPOINT-26, option a), and the compensating
controls are the admin gate, the operator allowlist and the audited attestation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePath
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

# ``redsim.api.errors`` itself is FastAPI-free, but importing it resolves the
# ``redsim.api`` package, whose ``__init__`` builds the app. The worker and the
# sandbox child import this module, so the error table is loaded lazily inside
# :func:`register_bundled_model` and never at import time.

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig
    from redsim.db.models import AuthProfile, Target
    from redsim.ml.schema import Domain, ModelStatus
    from redsim.ml.targets.artifact import ArtifactTarget
    from redsim.ml.targets.endpoint_contract import EndpointRegistration
    from redsim.storage import BlobStore

logger = logging.getLogger(__name__)

ML_KINDS = frozenset({"ml_model_artifact", "ml_model_endpoint"})

#: ``Target.kind`` of a registered black-box inference endpoint (spec 5.2, 9.1 rule 4).
ENDPOINT_KIND = "ml_model_endpoint"

#: AuthProfile kinds the predict broker can present (``Authorization: Bearer`` or a named header).
#: ``form`` and ``cookie`` are login flows for the retired DAST scanners, not API credentials.
SUPPORTED_ENDPOINT_AUTH_KINDS = frozenset({"bearer", "header"})

#: ``targets.detail.status`` of a soft-deleted model target.
DELETED_STATUS = "deleted"

#: ``Run.scanner`` values that make up a model's campaign history (spec 5.2).
CAMPAIGN_SCANNERS = ("ml.campaign", "ml.verify")
#: Run scanners that count as a model's history for ``last_run_id`` (spec 17.2 list row): the campaign
#: scanners plus the LLM probe scanner (``services.ml_llm.LLM_SCANNER``). Probe runs never join
#: ``campaign_history`` (D9: no campaign row, no MRI); ``services.ml_llm.probe_history`` lists them.
LLM_PROBE_SCANNER = "ml.llm_probe"
HISTORY_SCANNERS = (*CAMPAIGN_SCANNERS, LLM_PROBE_SCANNER)

#: Blob key prefix the bundled weights are copied under (gap register G-ASSET4).
BUNDLED_BLOB_PREFIX = "ml/assets/bundled"

#: Detail ``reason`` carried by a 404 for a bundled id outside the demo catalog
#: (spec 17.2 names it ``unknown_bundled_model``; the 17.3 code is ``not_found``).
UNKNOWN_BUNDLED_MODEL = "unknown_bundled_model"


class MlCatalogUnavailable(RuntimeError):
    """The ML target registry could not be imported in this process (503 at the API)."""

    def __init__(self, what: str, exc: ImportError) -> None:
        super().__init__(f"{what} catalog is unavailable in this process: {exc}")
        self.what = what
        self.reason = str(exc)

# Same names ``redsim.ml.targets.bundled`` reads; kept as literals so the API
# process can locate the manifest without importing the ML target package.
ASSETS_DIR_ENV = "REDSIM_ML_ASSETS_DIR"
DEFAULT_ASSETS_DIR = "./assets"
MANIFEST_NAME = "MANIFEST.json"

# Keys the asset builder writes into ``DatasetEntry.preprocessing`` for each
# modality (``redsim/ml/assets/datasets.py``, ``redsim/ml/assets/build.py``).
_TABULAR_PREPROCESSING_KEYS = frozenset({"features", "extractor", "extractor_version"})
_IMAGE_PREPROCESSING_KEYS = frozenset({"layout", "resolution", "channel_order", "resize", "value_range"})


class DatasetBindingError(ValueError):
    """The declared dataset cannot be bound to a bundled evaluation split.

    Maps to ``422 dataset_incompatible`` at the API (spec 17.3) and to
    ``UnsupportedArtifact("dataset_incompatible: ...")`` on the worker.
    ``field`` names the request field the message is about.
    """

    code = "dataset_incompatible"

    def __init__(self, message: str, *, field: str = "dataset_id") -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class DatasetBinding:
    """A bundled evaluation slice an uploaded model is evaluated on."""

    dataset_id: str
    split: str
    file_path: str                  # relative to the assets root
    file_sha256: str | None
    class_names: list[str]
    revision: str | None
    modality: str | None            # None when the manifest does not say
    fixture_only: bool = False
    legacy: bool = False            # resolved from a flat ``models[*].eval_split`` entry


# ---------------------------------------------------------------------------
# Asset manifest reads (plain JSON; no ML imports)
# ---------------------------------------------------------------------------


def assets_root(explicit: str | Path | None = None) -> Path:
    if explicit is not None:
        return Path(explicit).expanduser()
    return Path(os.environ.get(ASSETS_DIR_ENV, "").strip() or DEFAULT_ASSETS_DIR).expanduser()


def read_asset_manifest(root: str | Path | None = None) -> dict[str, Any]:
    """Parse ``<assets root>/MANIFEST.json`` as a plain object."""
    path = assets_root(root) / MANIFEST_NAME
    if not path.is_file():
        raise DatasetBindingError(
            f"bundled asset manifest is missing at {path}; run `redsim ml build-assets` "
            f"or point {ASSETS_DIR_ENV} at a built asset tree"
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DatasetBindingError(f"bundled asset manifest is unreadable: {exc}") from exc
    if not isinstance(document, dict):
        raise DatasetBindingError("bundled asset manifest is not an object")
    return document


def _model_entries(document: dict[str, Any]) -> list[dict[str, Any]]:
    raw = document.get("models")
    if isinstance(raw, dict):
        return [dict(value) for value in raw.values() if isinstance(value, dict)]
    if isinstance(raw, list):
        return [dict(value) for value in raw if isinstance(value, dict)]
    return []


def _dataset_entries(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """``datasets`` keyed by id (the mapping key and the entry's own ``id`` both resolve)."""
    raw = document.get("datasets")
    entries: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if not isinstance(value, dict):
                continue
            entries[str(key)] = dict(value)
            own_id = value.get("id")
            if isinstance(own_id, str) and own_id and own_id != str(key):
                entries.setdefault(own_id, dict(value))
    elif isinstance(raw, list):
        for value in raw:
            if isinstance(value, dict) and isinstance(value.get("id"), str) and value["id"]:
                entries[str(value["id"])] = dict(value)
    return entries


def _entry_dataset_id(entry: dict[str, Any]) -> Any:
    return entry.get("dataset_id") or entry.get("dataset")


def _dataset_modality(
    entry: dict[str, Any], dataset_id: str, models: list[dict[str, Any]],
) -> str | None:
    """The dataset's modality as recorded, or ``None`` when the manifest does not say."""
    preprocessing = entry.get("preprocessing")
    preprocessing = preprocessing if isinstance(preprocessing, dict) else {}
    for candidate in (entry.get("modality"), preprocessing.get("modality")):
        if isinstance(candidate, str) and candidate:
            return candidate
    for model in models:
        if _entry_dataset_id(model) == dataset_id and isinstance(model.get("modality"), str):
            return str(model["modality"])
    keys = set(preprocessing)
    if keys & _TABULAR_PREPROCESSING_KEYS or entry.get("features"):
        return "tabular"
    if keys & _IMAGE_PREPROCESSING_KEYS:
        return "image"
    return None


def _bundled_splits(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Splits that carry a bundled file: the only ones an upload can be evaluated on."""
    raw = entry.get("splits")
    if isinstance(raw, dict):
        items = [(str(key), value) for key, value in raw.items()]
    elif isinstance(raw, list):
        items = [(str(value.get("name")), value) for value in raw if isinstance(value, dict)]
    else:
        items = []
    out: dict[str, dict[str, Any]] = {}
    for name, value in items:
        if not isinstance(value, dict):
            continue
        file_entry = value.get("file")
        if isinstance(file_entry, dict) and file_entry.get("path"):
            out[str(value.get("name") or name)] = value
    return out


def _select_split(dataset_id: str, splits: dict[str, dict[str, Any]], requested: str | None) -> str:
    if requested:
        if requested in splits:
            return requested
        raise DatasetBindingError(
            f"dataset {dataset_id!r} has no bundled evaluation split named {requested!r}; "
            f"bundled splits: {sorted(splits) or 'none'}",
            field="dataset_split",
        )
    if not splits:
        raise DatasetBindingError(f"dataset {dataset_id!r} has no bundled evaluation split")
    if "test" in splits:
        return "test"
    if len(splits) == 1:
        return next(iter(splits))
    raise DatasetBindingError(
        f"dataset {dataset_id!r} has several bundled splits {sorted(splits)}; declare dataset_split",
        field="dataset_split",
    )


def _legacy_binding(
    dataset_id: str, requested: str | None, models: list[dict[str, Any]],
) -> DatasetBinding | None:
    """Pre-manifest layout: a flat ``eval_split`` path on the bundled model entry."""
    for entry in models:
        if _entry_dataset_id(entry) != dataset_id:
            continue
        split = str(entry.get("dataset_split") or entry.get("eval_split_name") or "test")
        if requested and split != requested:
            continue
        relative = entry.get("eval_split")
        class_names = entry.get("class_names")
        if not (isinstance(relative, str) and relative and isinstance(class_names, list) and class_names):
            continue
        digest = entry.get("eval_split_sha256")
        revision = entry.get("dataset_revision")
        modality = entry.get("modality")
        return DatasetBinding(
            dataset_id=dataset_id,
            split=split,
            file_path=relative,
            file_sha256=str(digest) if isinstance(digest, str) and digest else None,
            class_names=[str(value) for value in class_names],
            revision=None if revision is None else str(revision),
            modality=modality if isinstance(modality, str) and modality else None,
            fixture_only=bool(entry.get("fixture_only", False)),
            legacy=True,
        )
    return None


def resolve_dataset_binding(
    dataset_id: str,
    *,
    dataset_split: str | None = None,
    document: dict[str, Any] | None = None,
    root: str | Path | None = None,
) -> DatasetBinding:
    """Bind a declared dataset (and optional split) to a bundled evaluation slice.

    ``datasets[<id>].splits[<split>].file`` is authoritative; class names and the
    revision come from the dataset entry (falling back to a bundled model bound
    to the same dataset for class names). Without ``dataset_split`` the split
    named ``test`` is used, else the dataset's only bundled split; several
    bundled splits must be disambiguated by the caller. Flat legacy
    ``models[*].eval_split`` entries are still honoured. Never guesses: every
    failure is a :class:`DatasetBindingError` naming the field.
    """
    dataset_id = (dataset_id or "").strip()
    if not dataset_id:
        raise DatasetBindingError(
            "dataset_id is required: an uploaded model is evaluated on a bundled dataset only"
        )
    if document is None:
        document = read_asset_manifest(root)
    requested = (dataset_split or "").strip() or None
    models = _model_entries(document)
    datasets = _dataset_entries(document)
    entry = datasets.get(dataset_id)

    if entry is not None:
        splits = _bundled_splits(entry)
        if splits:
            try:
                split_name = _select_split(dataset_id, splits, requested)
            except DatasetBindingError:
                legacy = _legacy_binding(dataset_id, requested, models)
                if legacy is not None:
                    return legacy
                raise
            file_entry = splits[split_name]["file"]
            class_names = [str(value) for value in (entry.get("class_names") or [])]
            if not class_names:
                for model in models:
                    names = model.get("class_names")
                    if _entry_dataset_id(model) == dataset_id and isinstance(names, list) and names:
                        class_names = [str(value) for value in names]
                        break
            if not class_names:
                raise DatasetBindingError(
                    f"dataset {dataset_id!r} records no class names; an upload cannot be bound to it"
                )
            digest = file_entry.get("sha256")
            revision = entry.get("revision")
            return DatasetBinding(
                dataset_id=dataset_id,
                split=split_name,
                file_path=str(file_entry["path"]),
                file_sha256=str(digest) if isinstance(digest, str) and digest else None,
                class_names=class_names,
                revision=None if revision is None else str(revision),
                modality=_dataset_modality(entry, dataset_id, models),
                fixture_only=bool(entry.get("fixture_only", False)),
            )

    legacy = _legacy_binding(dataset_id, requested, models)
    if legacy is not None:
        return legacy
    if entry is None:
        raise DatasetBindingError(
            f"unknown bundled dataset {dataset_id!r}; bundled datasets: {sorted(datasets) or 'none'}"
        )
    raise DatasetBindingError(
        f"dataset {dataset_id!r} has no bundled evaluation split"
        + (f" named {requested!r}" if requested else ""),
        field="dataset_split" if requested else "dataset_id",
    )


def check_upload_dataset(
    dataset_id: str,
    *,
    modality: str,
    dataset_split: str | None = None,
    document: dict[str, Any] | None = None,
    root: str | Path | None = None,
) -> DatasetBinding:
    """The static compatibility check the API runs before any byte is persisted.

    Confirms the dataset is bundled, has an evaluation split, and (when the
    manifest records one) is of the declared modality. Shape and class-count
    checks against the model stay on the worker inside the sandbox.
    """
    binding = resolve_dataset_binding(dataset_id, dataset_split=dataset_split, document=document, root=root)
    if binding.modality is not None and binding.modality != modality:
        raise DatasetBindingError(
            f"dataset {binding.dataset_id!r} is a {binding.modality} dataset; "
            f"the upload declares modality {modality!r}",
            field="dataset_id",
        )
    return binding


# ---------------------------------------------------------------------------
# Worker side: materialize uploaded bytes and bind them to the evaluation slice
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evaluation_binding(
    dataset_id: str,
    *,
    dataset_split: str | None,
) -> tuple[Path, list[str], str | None, str]:
    """Resolve a declared upload dataset to a confined, digest-verified bundled eval split.

    Returns ``(split file path, class names, dataset revision, split name)``.
    """
    from redsim.ml.errors import UnsupportedArtifact
    from redsim.ml.targets.bundled import assets_dir, resolve_asset_path

    root = assets_dir()
    try:
        binding = resolve_dataset_binding(dataset_id, dataset_split=dataset_split, root=root)
    except DatasetBindingError as exc:
        raise UnsupportedArtifact(f"dataset_incompatible: {exc}") from exc
    path = resolve_asset_path(root, binding.file_path)
    if not path.is_file():
        raise UnsupportedArtifact(
            f"dataset_incompatible: bundled split file {binding.file_path!r} is missing under {root}"
        )
    if binding.file_sha256 is not None:
        actual = _sha256_file(path)
        if actual != binding.file_sha256.strip().lower():
            raise UnsupportedArtifact(
                f"dataset_incompatible: bundled split {binding.file_path!r} has sha256 {actual}, "
                f"manifest says {binding.file_sha256}"
            )
    return path, binding.class_names, binding.revision, binding.split


def artifact_target_from_path(
    target_id: str,
    path: Path,
    detail: dict[str, Any],
) -> ArtifactTarget:
    """Build an uploaded target around already-confined model bytes."""
    from redsim.ml.targets.artifact import ArtifactTarget

    manifest = (
        dict(detail["manifest"])
        if isinstance(detail.get("manifest"), dict)
        else dict(detail)
    )
    declared_format = str(manifest.get("format") or detail.get("format") or "")
    dataset_id = str(manifest.get("dataset_id") or "")
    dataset_split = str(manifest.get("dataset_split") or "").strip() or None
    eval_path, class_names, dataset_revision, resolved_split = _evaluation_binding(
        dataset_id, dataset_split=dataset_split,
    )
    return ArtifactTarget(
        target_id,
        path,
        class_names=class_names,
        eval_data=eval_path,
        dataset_id=dataset_id,
        declared_format=declared_format,
        expected_sha256=str(manifest.get("sha256") or "") or None,
        architecture_id=manifest.get("architecture_id"),
        architecture_kwargs=dict(manifest.get("architecture_kwargs") or {}),
        input_shape=tuple(manifest.get("input_shape") or ()) or None,
        name=str(manifest.get("name") or target_id),
        domain=cast("Domain", str(manifest.get("modality") or "image")),
        dataset_split=resolved_split,
        dataset_revision=(
            str(manifest.get("dataset_revision"))
            if manifest.get("dataset_revision") is not None
            else dataset_revision
        ),
        license=manifest.get("license"),
    )


@contextmanager
def uploaded_model_file(
    target: Target,
    blob_store: BlobStore,
) -> Iterator[tuple[Path, dict[str, Any]]]:
    """Materialize opaque uploaded bytes without deserializing them."""
    detail = dict(target.detail or {})
    manifest = (
        dict(detail["manifest"])
        if isinstance(detail.get("manifest"), dict)
        else dict(detail)
    )
    declared_format = str(manifest.get("format") or detail.get("format") or "")
    suffix = {
        "onnx": ".onnx",
        "torch_state_dict": ".pt",
        "safetensors_state_dict": ".safetensors",
    }.get(declared_format, Path(str(detail.get("original_filename") or "")).suffix)
    data = blob_store.get(str(target.value))
    fd, raw_path = tempfile.mkstemp(prefix="redsim-model-", suffix=suffix)
    path = Path(raw_path)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        yield path, detail
    finally:
        path.unlink(missing_ok=True)


@contextmanager
def uploaded_target(target: Target, blob_store: BlobStore) -> Iterator[ArtifactTarget]:
    """Yield an ArtifactTarget for callers already isolated from API processes."""
    with uploaded_model_file(target, blob_store) as (path, detail):
        yield artifact_target_from_path(target.id, path, detail)


# ---------------------------------------------------------------------------
# Refused admissions and upload naming (``POST /v1/models``)
# ---------------------------------------------------------------------------


def audit_refused_admission(
    writer: AuditWriter,
    *,
    action: str,
    actor: str,
    project_id: str | None,
    detail: dict[str, Any],
    run_id: str | None = None,
    target: str | None = None,
    allowlist_check: str = "n/a",
) -> None:
    """Write the ``success=False`` audit row of a refused admission (spec 5.11, 9.5).

    Goes through the same ``AuditWriter`` the successful path uses, so the
    refusal sits on the project chain next to the admissions it precedes.
    ``target`` is ``None`` for an in-boundary artifact (``allowlist_check`` is
    ``n/a``); an endpoint registration refused by the egress allowlist passes
    the URL and ``allowlist_check="fail"`` so the chain reads like every other
    allowlist refusal (ENDPOINT-07). ``detail`` must already be free of payload
    bytes and secrets; the durable writers redact it as they do every other event.
    """
    writer.append(
        action=action, actor=actor, target=target,
        allowlist_check=allowlist_check, override=False, success=False,
        detail={"actor": actor, **detail},
        run_id=run_id, project_id=project_id,
    )


def safe_filename(name: str | None, default: str = "model") -> str:
    """The upload's file name reduced to ``[A-Za-z0-9._-]`` and its last path segment.

    Runs of refused characters collapse to one ``_`` and a ``_`` before an
    extension dot is dropped, so ``my model (v2).onnx`` becomes ``my_model_v2.onnx``.
    """
    base = PurePath(str(name or "").replace("\\", "/")).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    cleaned = re.sub(r"_+", "_", cleaned)
    cleaned = re.sub(r"_(?=\.)", "", cleaned).strip("._")
    return cleaned or default


def upload_blob_key(project_id: str, target_id: str, filename: str) -> str:
    """``{project_id}/models/{target_id}/{safe_filename}`` (spec 9.3 step 3)."""
    return f"{project_id}/models/{target_id}/{safe_filename(filename)}"


def dataset_modality(entry: dict[str, Any], dataset_id: str, document: dict[str, Any]) -> str | None:
    """The modality a manifest dataset entry records, or ``None`` when it does not say."""
    return _dataset_modality(entry, dataset_id, _model_entries(document))


def dataset_entries(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """``datasets`` of an asset manifest keyed by id (public read of :func:`_dataset_entries`)."""
    return _dataset_entries(document)


# ---------------------------------------------------------------------------
# Bundled registration (``POST /v1/models`` source=bundled, ``redsim ml seed``)
# ---------------------------------------------------------------------------


def _confined_asset_path(root: Path, rel: str) -> Path:
    """``root / rel`` resolved inside the asset tree; escapes are refused."""
    from redsim.api.errors import MODEL_LOAD_REFUSED, ApiError

    root_r = root.resolve()
    candidate = (root_r / rel).resolve()
    if candidate != root_r and root_r not in candidate.parents:
        raise ApiError(MODEL_LOAD_REFUSED, f"asset path escapes the asset tree: {rel!r}",
                       refusal_reason="assets_unverified")
    return candidate


def _registry_info(bundled_id: str) -> Any:
    """``TargetInfo`` of a registered bundled target, ``None`` when the id is not registered."""
    try:
        from redsim.ml.targets import TARGETS
    except ImportError as exc:
        raise MlCatalogUnavailable("bundled model", exc) from exc
    target = TARGETS.maybe_get(bundled_id)
    return None if target is None else target.info()


def canonical_bundled_id(bundled_id: str) -> str:
    """The registry id a bundled id (or a legacy build id such as ``url_classifier``) stands for."""
    from redsim.ml.assets import LEGACY_MODEL_IDS

    return LEGACY_MODEL_IDS.get(bundled_id, bundled_id)


def bundled_target_id(bundled_id: str) -> str:
    """A per-project ``Target.id`` for a bundled registration (the registry id stays in ``detail``)."""
    return f"{bundled_id}-{uuid4().hex[:8]}"


def find_bundled_registration(session: Session, project_id: str, bundled_id: str) -> Target | None:
    """The live (not soft-deleted) Target row registering ``bundled_id`` in ``project_id``, if any."""
    from sqlalchemy import select

    from redsim.db.models import Target

    rows = session.execute(
        select(Target).where(
            Target.project_id == project_id,
            Target.kind.in_(ML_KINDS),
            Target.value == f"bundled:{bundled_id}",
        )
    ).scalars().all()
    for row in rows:
        if not is_deleted(row.detail):
            return row
    return None


def register_bundled_model(
    session: Session,
    project_id: str,
    bundled_id: str,
    actor: str,
    *,
    audit_writer: AuditWriter | None = None,
    config: RedsimConfig | None = None,
    blob_store: BlobStore | None = None,
    assets_root: str | Path | None = None,
) -> Target:
    """Admission boundary for registering a bundled model into a project (spec 9.3, 17.2).

    Order: resolve the id through the registry and the asset manifest, refuse
    fixture-only entries, verify the weights and the bound evaluation split
    against the manifest digests, refuse a duplicate in the project, write the
    ``model.register`` audit row (``source=bundled``), copy the weights into the
    blob store, then add the ``Target`` row to ``session`` (the caller owns the
    transaction). Raises :class:`redsim.api.errors.ApiError` with the 17.3 code:
    ``not_found`` (``reason=unknown_bundled_model``) for an unknown or
    fixture-only id, ``model_load_refused`` when the assets are missing or fail
    verification, ``already_registered`` for a live duplicate.
    :class:`MlCatalogUnavailable` when the registry cannot be imported.
    """
    from redsim.api.errors import ALREADY_REGISTERED, MODEL_LOAD_REFUSED, NOT_FOUND, ApiError
    from redsim.ml.assets.manifest import (
        AssetManifest,
        model_entry,
        model_manifest,
        verify_model_assets,
    )
    from redsim.safety import authorize

    requested = (bundled_id or "").strip()
    bundled_id = canonical_bundled_id(requested)
    if not bundled_id:
        raise ApiError(NOT_FOUND, "bundled_id is required", reason=UNKNOWN_BUNDLED_MODEL, field="bundled_id")
    info = _registry_info(bundled_id)
    if info is None or info.metadata.get("source") != "bundled":
        raise ApiError(NOT_FOUND, f"{requested!r} is not a bundled model in the target registry",
                       reason=UNKNOWN_BUNDLED_MODEL, field="bundled_id")
    root = assets_root_path(assets_root)
    try:
        document = read_asset_manifest(root)
    except DatasetBindingError as exc:
        raise ApiError(MODEL_LOAD_REFUSED, f"bundled assets for {bundled_id!r} are not built: {exc}",
                       status="not_implemented", refusal_reason="bundled_assets_missing") from exc
    try:
        manifest = AssetManifest.model_validate(document)
    except ValueError as exc:
        raise ApiError(MODEL_LOAD_REFUSED, f"bundled asset manifest at {root} is invalid: {exc}",
                       status="not_implemented", refusal_reason="bundled_assets_missing") from exc
    entry = model_entry(manifest, bundled_id)
    if entry is None:
        raise ApiError(MODEL_LOAD_REFUSED,
                       f"bundled assets for {bundled_id!r} are missing: no entry in {root / MANIFEST_NAME}",
                       status="not_implemented", refusal_reason="bundled_assets_missing")
    if entry.fixture_only or info.metadata.get("fixture_only"):
        # CI fixtures are never demo targets (spec 5.5, 11.1); the catalog hides them.
        raise ApiError(NOT_FOUND, f"{bundled_id!r} is a CI fixture and is never registered as a model",
                       reason=UNKNOWN_BUNDLED_MODEL, field="bundled_id")
    problems = verify_model_assets(manifest, root, bundled_id)
    if problems:
        raise ApiError(MODEL_LOAD_REFUSED,
                       f"bundled assets for {bundled_id!r} fail verification against the manifest",
                       status="refused", refusal_reason="assets_unverified",
                       reasons=list(problems.model) + list(problems.dataset))
    existing = find_bundled_registration(session, project_id, bundled_id)
    if existing is not None:
        raise ApiError(ALREADY_REGISTERED,
                       f"bundled model {bundled_id!r} is already registered in project {project_id!r}",
                       target_id=existing.id, sha256=entry.sha256)

    weights_path = _confined_asset_path(root, entry.file.path)
    projection = model_manifest(entry).model_dump(mode="json")
    projection["status"] = "available"
    target_id = bundled_target_id(bundled_id)
    filename = PurePath(entry.file.path).name
    blob_key = f"{BUNDLED_BLOB_PREFIX}/{bundled_id}/{safe_filename(filename)}"

    if config is None:
        from redsim.config import load_config

        config = load_config()
    if audit_writer is None:
        from redsim.audit.chain import resolve_writer

        audit_writer = resolve_writer(config)
    # The chained event precedes the blob and the row (spec 6.7 invariant 4, 9.3 step 4).
    authorize(
        "model.register",
        None,
        allowlist=config.target_allowlist,
        actor=actor,
        writer=audit_writer,
        project_id=project_id,
        detail={
            "actor": actor,
            "target_id": target_id,
            "kind": "ml_model_artifact",
            "source": "bundled",
            "bundled_id": bundled_id,
            "declared_format": entry.format,
            "sha256": entry.sha256,
            "size_bytes": entry.size_bytes,
            "architecture_id": entry.architecture_id,
            "modality": entry.modality,
            "filename": filename,
            "dataset_id": entry.dataset_id,
            "dataset_revision": entry.dataset_revision,
            "dataset_split": entry.dataset_split,
            "manifest_sha256": entry.manifest_sha256,
            "blob_key": blob_key,
        },
    )

    data = weights_path.read_bytes()
    if hashlib.sha256(data).hexdigest() != entry.sha256:
        raise ApiError(MODEL_LOAD_REFUSED, f"bundled weights for {bundled_id!r} changed under verification",
                       status="refused", refusal_reason="assets_unverified")
    if blob_store is None:
        from redsim.storage.blobs import open_blob_store

        blob_store = open_blob_store()
    ref = blob_store.put(blob_key, data, content_type="application/octet-stream")

    from redsim.db.models import Target

    registered_at = datetime.now(UTC).isoformat()
    detail: dict[str, Any] = {
        **projection,
        "source": "bundled",
        "bundled_id": bundled_id,
        "status": "available",
        "fixture_only": False,
        "manifest": projection,
        "blob": {"key": blob_key, "location": ref.location, "sha256": ref.sha256, "size_bytes": ref.size_bytes},
        "assets_dir": str(root),
        "validation": {
            "detected_format": entry.format,
            "input_shape": list(entry.input_shape),
            "class_count": entry.n_classes,
            "gradients": entry.gradients,
            "onnx_torch_argmax_agreement": None,
            "refusal_reason": None,
            "ingest_job_id": None,
            "ingest_run_id": None,
            "source": "asset_manifest",
        },
        "registered_by": actor,
        "registered_at": registered_at,
    }
    target = Target(id=target_id, project_id=project_id, kind="ml_model_artifact",
                    value=f"bundled:{bundled_id}", verified=True)
    target.detail = detail
    session.add(target)
    session.flush()
    logger.info("register_bundled_model project_id=%s target_id=%s bundled_id=%s sha256=%s",
                project_id, target_id, bundled_id, entry.sha256)
    return target


def assets_root_path(explicit: str | Path | None = None) -> Path:
    """The asset tree root (``REDSIM_ML_ASSETS_DIR`` or ``./assets``), as :func:`assets_root` resolves it."""
    return assets_root(explicit)


# ---------------------------------------------------------------------------
# Endpoint targets (``POST /v1/models`` source=endpoint; the validate and campaign workers)
# ---------------------------------------------------------------------------


def is_endpoint_target(detail_or_target: Any) -> bool:
    """True for a black-box endpoint model: a Target of kind ``ml_model_endpoint`` or its detail.

    Campaign admission (``services.ml_campaigns``) uses this to force
    ``gradients=False`` (white-box attacks are refused with
    ``attack_requires_gradients``), to pass the URL as the audit target and to
    dispatch the worker onto the broker path. Accepts the ORM row, a
    ``target_snapshot`` mapping (``{"kind", "detail"}``) or the bare detail.
    """
    kind = getattr(detail_or_target, "kind", None)
    if isinstance(kind, str):
        return kind == ENDPOINT_KIND
    if not isinstance(detail_or_target, dict):
        return False
    if detail_or_target.get("kind") == ENDPOINT_KIND:
        return True
    nested = detail_or_target.get("detail")
    detail: dict[str, Any] = nested if isinstance(nested, dict) else detail_or_target
    manifest_value = detail.get("manifest")
    manifest: dict[str, Any] = manifest_value if isinstance(manifest_value, dict) else {}
    return (detail.get("source") == "endpoint" or detail.get("format") == "endpoint"
            or manifest.get("format") == "endpoint" or isinstance(detail.get("endpoint"), dict))


def endpoint_host(url: str) -> str:
    """``host[:port]`` of an endpoint URL: what audit rows, projections and exports may carry (D3).

    Never the scheme, path, userinfo or query. A default port is dropped; an IPv6
    literal keeps its brackets.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(str(url or ""))
    host = parts.hostname or ""
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    default = 443 if parts.scheme.lower() == "https" else 80
    return host if port in (None, default) else f"{host}:{port}"


def endpoint_auth_profile_id(detail: Any, job_detail: Any = None) -> str | None:
    """The AuthProfile id an endpoint job resolves at pickup (spec 5.10, ENDPOINT-29).

    ``Job.detail.auth_profile_id`` (written at admission) wins; the registration
    copy under ``detail.endpoint.auth_profile_id`` / ``detail.auth_profile_id``
    is the fallback. Never a credential: ids only.
    """
    for source in (job_detail, detail):
        if isinstance(source, dict):
            value = source.get("auth_profile_id")
            if isinstance(value, str) and value.strip():
                return value.strip()
    if isinstance(detail, dict):
        for block_name in ("endpoint", "manifest"):
            block = detail.get(block_name)
            if isinstance(block, dict):
                nested = block.get("endpoint") if block_name == "manifest" else block
                if isinstance(nested, dict):
                    value = nested.get("auth_profile_id")
                    if isinstance(value, str) and value.strip():
                        return value.strip()
    return None


def endpoint_request_block(
    value: str,
    detail: dict[str, Any] | None,
    *,
    auth_profile_id: str | None = None,
) -> dict[str, Any]:
    """The ``target_endpoint`` block ``redsim.ml.sandbox`` takes for an endpoint job.

    ``url`` is read by the parent only (the sandbox replaces it by ``url_host`` and
    ``scheme`` before the request file is written); everything else is the binding
    the child needs to build its ``EndpointTarget``. The credential is not here: it
    travels as the separate ``endpoint_auth`` argument, straight into the broker.
    """
    detail = dict(detail or {})
    manifest_value = detail.get("manifest")
    manifest: dict[str, Any] = dict(manifest_value) if isinstance(manifest_value, dict) else {}
    endpoint_value = detail.get("endpoint") if isinstance(detail.get("endpoint"), dict) else manifest.get("endpoint")
    endpoint: dict[str, Any] = dict(endpoint_value) if isinstance(endpoint_value, dict) else {}

    def pick(key: str) -> Any:
        for source in (detail, manifest):
            if source.get(key) is not None:
                return source.get(key)
        return None

    class_names = pick("class_names")
    n_classes = pick("n_classes")
    if n_classes is None and isinstance(class_names, list) and class_names:
        n_classes = len(class_names)
    binding: dict[str, Any] = {
        "modality": pick("modality") or "image",
        "dataset_id": pick("dataset_id"),
        "dataset_split": pick("dataset_split"),
        "dataset_revision": pick("dataset_revision"),
        "n_classes": n_classes,
        "class_names": list(class_names) if isinstance(class_names, list) else None,
        "input_shape": list(pick("input_shape") or endpoint.get("input_shape") or []) or None,
        "features": pick("features"),
        "name": pick("name"),
        "license": pick("license"),
    }
    block: dict[str, Any] = {
        "url": str(value),
        "auth_profile_id": auth_profile_id or endpoint_auth_profile_id(detail) or "",
        "manifest": {k: v for k, v in binding.items() if v is not None},
    }
    batch_rows = endpoint.get("batch_rows")
    if isinstance(batch_rows, int) and not isinstance(batch_rows, bool) and batch_rows > 0:
        block["batch_rows"] = batch_rows
    timeout_s = endpoint.get("timeout_s")
    if isinstance(timeout_s, (int, float)) and not isinstance(timeout_s, bool) and timeout_s > 0:
        block["timeout_s"] = float(timeout_s)
    limits = detail.get("endpoint_limits")
    if isinstance(limits, dict) and limits:
        block["limits"] = dict(limits)
    return block


class EndpointAdmissionError(ValueError):
    """A static refusal of an endpoint registration: ``code`` is the spec 17.3 code, ``field`` the body field.

    ``extra`` carries the audit-safe context of the refusal (an egress rule and
    host, an AuthProfile kind, a dataset id); never a URL with userinfo or query,
    never a credential.
    """

    def __init__(self, code: str, message: str, *, field: str, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.field = field
        self.extra = extra


@dataclass(frozen=True)
class EndpointAdmission:
    """What the static checks of an endpoint registration established (nothing was queried)."""

    registration: EndpointRegistration
    url: str                      # normalised: lower-case host, default port dropped
    host: str                     # host[:port], the only URL fragment that reaches audit and projections
    scheme: str
    plaintext: bool
    allowlist_entry: str
    auth_kind: str
    auth_header_name: str | None
    binding: DatasetBinding
    descriptor_sha256: str

    def manifest(self, *, status: ModelStatus = "validating") -> dict[str, Any]:
        """The ``MLModelManifest`` dump the Target row is created with (ENDPOINT-03 conventions)."""
        from redsim.ml.schema import EndpointSpec, MLModelManifest

        reg = self.registration
        manifest = MLModelManifest(
            name=reg.name, modality=reg.modality, format="endpoint", sha256=self.descriptor_sha256,
            size_bytes=0, input_shape=list(reg.input_shape), n_classes=len(self.binding.class_names),
            class_names=list(self.binding.class_names), dataset_id=self.binding.dataset_id,
            dataset_revision=self.binding.revision, dataset_split=self.binding.split,
            status=status, gradients=False, bundled=False, license=reg.license_statement,
            endpoint=EndpointSpec(
                url_host=self.host, auth_profile_id=reg.auth_profile_id, contract_version=reg.contract_version,
                input_shape=list(reg.input_shape), batch_rows=reg.batch_rows, timeout_s=reg.timeout_s,
            ),
        )
        return manifest.model_dump(mode="json")

    def audit_detail(self) -> dict[str, Any]:
        """Ids, host, digests and counts for the ``model.register`` row (spec 5.11; ENDPOINT-19, -31)."""
        reg = self.registration
        return {
            "kind": ENDPOINT_KIND, "source": "endpoint", "host": self.host, "scheme": self.scheme,
            "plaintext": self.plaintext, "allowlist_entry": self.allowlist_entry,
            "auth_profile_id": reg.auth_profile_id, "auth_kind": self.auth_kind,
            "modality": reg.modality, "input_format": reg.resolved_input_format,
            "dataset_id": self.binding.dataset_id, "dataset_split": self.binding.split,
            "dataset_revision": self.binding.revision, "n_classes": len(self.binding.class_names),
            "input_shape": list(reg.input_shape), "contract": reg.contract_version,
            "descriptor_sha256": self.descriptor_sha256, "sha256": self.descriptor_sha256,
            "batch_rows": reg.batch_rows, "timeout_s": reg.timeout_s,
            "attestation": {"evaluation_instance": bool(reg.evaluation_instance_attestation)},
        }


def load_endpoint_auth_profile(session: Session, profile_id: str, project_id: str) -> AuthProfile:
    """The AuthProfile an endpoint registration names, checked for project and kind (never decrypted).

    Raises :class:`EndpointAdmissionError` with ``not_found`` (unknown id, or a
    profile of another project: the id is not leaked across tenants),
    ``auth_profile_required`` (blank id) or ``auth_profile_kind_unsupported``
    (``form`` / ``cookie``, or ``header`` without ``config.header_name``).
    """
    from redsim.db.models import AuthProfile

    profile_id = (profile_id or "").strip()
    if not profile_id:
        raise EndpointAdmissionError("auth_profile_required", "auth_profile_id is required: the endpoint credential "
                                     "is an AuthProfile of this project", field="auth_profile_id")
    profile = session.get(AuthProfile, profile_id)
    if profile is None or profile.project_id != project_id:
        raise EndpointAdmissionError("not_found", f"auth profile {profile_id!r} not found in project {project_id!r}",
                                     field="auth_profile_id", auth_profile_id=profile_id)
    kind = str(profile.kind or "")
    if kind not in SUPPORTED_ENDPOINT_AUTH_KINDS:
        raise EndpointAdmissionError(
            "auth_profile_kind_unsupported",
            f"auth profile kind {kind!r} cannot authenticate a predict endpoint; "
            f"use one of {sorted(SUPPORTED_ENDPOINT_AUTH_KINDS)}",
            field="auth_profile_id", auth_profile_id=profile_id, auth_kind=kind,
        )
    if kind == "header":
        header_name = str((profile.config or {}).get("header_name") or "").strip()
        if not header_name or any(ch in header_name for ch in " :\r\n"):
            raise EndpointAdmissionError(
                "auth_profile_kind_unsupported",
                "an auth profile of kind 'header' needs a valid config.header_name to carry the credential",
                field="auth_profile_id", auth_profile_id=profile_id, auth_kind=kind,
            )
    return profile


def admit_endpoint_registration(
    session: Session,
    body: dict[str, Any],
    *,
    project_id: str,
    allowlist: Iterable[str],
    assets_root: str | Path | None = None,
) -> EndpointAdmission:
    """Static admission of ``POST /v1/models`` ``source=endpoint`` (spec 9.3 steps 1 to 3; ENDPOINT-01, -07).

    Order: body shape (``EndpointRegistration``), URL and egress policy,
    AuthProfile, dataset binding, declared classes against the bound split.
    Every refusal is an :class:`EndpointAdmissionError` naming the 17.3 code and
    the body field; the route writes the ``success=False`` row and raises the
    envelope. Nothing is resolved, connected or queried.
    """
    from pydantic import ValidationError

    from redsim.ml.endpoint_egress import EgressRefused
    from redsim.ml.targets.endpoint_contract import EndpointRegistration

    try:
        registration = EndpointRegistration.model_validate(body)
    except ValidationError as exc:
        raise _registration_error(exc) from None

    try:
        parsed = registration.check_url(list(allowlist))
    except EgressRefused as exc:
        # ``detail()`` is the audit-safe context (rule, host, address); ``code`` is the constructor's own.
        context = {key: value for key, value in exc.detail().items() if key != "code"}
        raise EndpointAdmissionError(exc.code, str(exc), field="url", **context) from exc

    profile = load_endpoint_auth_profile(session, registration.auth_profile_id, project_id)
    header_name = str((profile.config or {}).get("header_name") or "").strip() or None

    try:
        binding = check_upload_dataset(registration.dataset_id, modality=registration.modality,
                                       dataset_split=registration.dataset_split, root=assets_root)
    except DatasetBindingError as exc:
        raise EndpointAdmissionError(DatasetBindingError.code, str(exc), field=exc.field,
                                     dataset_id=registration.dataset_id) from exc
    if binding.fixture_only:
        raise EndpointAdmissionError(
            DatasetBindingError.code, f"dataset {binding.dataset_id!r} is a CI fixture and never binds a model",
            field="dataset_id", dataset_id=binding.dataset_id,
        )
    declared = registration.resolved_n_classes
    if declared != len(binding.class_names):
        raise EndpointAdmissionError(
            DatasetBindingError.code,
            f"the endpoint declares {declared} classes; the bound split {binding.dataset_id!r}/{binding.split!r} "
            f"has {len(binding.class_names)}",
            field="n_classes" if registration.class_names is None else "class_names",
            dataset_id=binding.dataset_id,
        )
    if registration.class_names is not None and list(registration.class_names) != list(binding.class_names):
        raise EndpointAdmissionError(
            DatasetBindingError.code,
            f"declared class_names differ from the bound split's class order for {binding.dataset_id!r}",
            field="class_names", dataset_id=binding.dataset_id,
        )
    return EndpointAdmission(
        registration=registration, url=parsed.url, host=endpoint_host(parsed.url), scheme=parsed.scheme,
        plaintext=parsed.plaintext, allowlist_entry=parsed.allowlist_entry, auth_kind=str(profile.kind),
        auth_header_name=header_name, binding=binding, descriptor_sha256=registration.descriptor_sha256(),
    )


# Body field -> the spec 17.3 code a shape error on it maps to. ``auth_profile_required`` is
# a Phase B addendum code the errors table may still lack; the route resolves it by name.
_REGISTRATION_FIELD_CODES: dict[str, str] = {
    "url": "endpoint_url_invalid",
    "auth_profile_id": "auth_profile_required",
    "license_statement": "license_required",
    "dataset_id": DatasetBindingError.code,
    "dataset_split": DatasetBindingError.code,
    "modality": "not_implemented",
    "input_format": "not_implemented",
    "input_shape": "schema_undeclared",
    "class_names": "schema_undeclared",
    "n_classes": "schema_undeclared",
    # The D3 attestation is a required statement like the licence (ENDPOINT-31); the route
    # swaps in ``attestation_required`` when the errors table carries it.
    "evaluation_instance_attestation": "license_required",
}


def _registration_error(exc: Any) -> EndpointAdmissionError:
    """Map the first pydantic error of an ``EndpointRegistration`` body onto a code and a field."""
    errors = list(exc.errors()) if hasattr(exc, "errors") else []
    field = "body"
    message = str(exc)
    if errors:
        first = errors[0]
        loc = [str(part) for part in first.get("loc", ()) if not isinstance(part, int)]
        field = loc[0] if loc else "body"
        message = f"{'.'.join(loc) or 'body'}: {first.get('msg', 'invalid')}"
        if not loc:
            # A model-level check names its field in the message ("one of class_names or n_classes is
            # required", "input_shape for modality 'image' must have 3 dimensions"): the first name
            # mentioned is the field the check is about.
            mentioned = [(message.find(name), name) for name in _REGISTRATION_FIELD_CODES if name in message]
            if mentioned:
                field = min(mentioned)[1]
    code = _REGISTRATION_FIELD_CODES.get(field, "params_out_of_range")
    return EndpointAdmissionError(code, message, field=field)


# ---------------------------------------------------------------------------
# Campaign history (``GET /v1/models`` ``last_run_id``, ``GET /v1/models/{id}``)
# ---------------------------------------------------------------------------


def _campaign_rows(session: Session, run_ids: Iterable[str]) -> tuple[dict[str, Any], bool]:
    """``{run_id: ml_campaigns row}`` for the given runs; ``(rows, available)``.

    The table is migration-owned and reflected, never redeclared. When it is
    not present (a harness that only built the ORM metadata) the history is
    served from the Run rows alone and says so, rather than inventing config.
    """
    ids = [rid for rid in run_ids]
    if not ids:
        return {}, True
    try:
        from sqlalchemy import MetaData, Table

        table = Table("ml_campaigns", MetaData(), autoload_with=session.get_bind())
        rows = session.execute(table.select().where(table.c.run_id.in_(ids))).mappings().all()
    except Exception:  # noqa: BLE001 - NoSuchTableError / OperationalError depending on the dialect
        logger.info("ml_campaigns is not readable here; campaign history is served from Run rows only")
        return {}, False
    return {str(row["run_id"]): dict(row) for row in rows}, True


def _campaign_runs(session: Session, target_id: str) -> list[Any]:
    from sqlalchemy import select

    from redsim.db.models import Run

    return list(session.execute(
        select(Run).where(Run.target_id == target_id, Run.scanner.in_(list(CAMPAIGN_SCANNERS)))
        .order_by(Run.created_at.desc(), Run.id.desc())
    ).scalars().all())


def campaign_history(session: Session, target_id: str) -> list[dict[str, Any]]:
    """Campaigns that ran on a model, newest first (spec 17.2 ``GET /v1/models/{id}``).

    One entry per ``ml.campaign`` / ``ml.verify`` Run with the attack ids,
    ``reference_eps`` and ``settings_hash`` from the campaign row and the MRI as
    a link into the full scorecard (``scorecard_url``), never as a bare number
    (spec 15.7). ``score_status`` is ``scored``, ``pending`` (run not terminal)
    or ``unavailable``; ``campaign_record`` is ``"unavailable"`` when the
    ``ml_campaigns`` table cannot be read.
    """
    runs = _campaign_runs(session, target_id)
    campaigns, available = _campaign_rows(session, [run.id for run in runs])
    history: list[dict[str, Any]] = []
    for run in runs:
        row = campaigns.get(run.id, {})
        config = row.get("config") if isinstance(row.get("config"), dict) else {}
        scored = row.get("score") is not None
        if scored:
            score_status = "scored"
        elif run.status in {"queued", "running"}:
            score_status = "pending"
        else:
            score_status = "unavailable"
        entry: dict[str, Any] = {
            "run_id": run.id,
            "kind": "verify" if run.scanner == "ml.verify" else "attack",
            "status": run.status,
            "created_at": run.created_at.isoformat() if run.created_at is not None else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at is not None else None,
            "attack_ids": list(config.get("attack_ids") or []),
            "reference_eps": config.get("reference_eps"),
            "settings_hash": row.get("settings_hash"),
            "baseline_run_id": row.get("baseline_run_id"),
            "score_status": score_status,
            "scorecard_url": f"/v1/runs/{run.id}/campaign" if scored else None,
            "status_url": f"/v1/runs/{run.id}",
        }
        if not available:
            entry["campaign_record"] = "unavailable"
        history.append(entry)
    return history


def last_run_ids(session: Session, target_ids: Iterable[str]) -> dict[str, str]:
    """``{target_id: newest campaign, verify or probe run id}`` for the given targets (spec 17.2 list row)."""
    from sqlalchemy import select

    from redsim.db.models import Run

    ids = list(target_ids)
    if not ids:
        return {}
    rows = session.execute(
        select(Run.target_id, Run.id).where(
            Run.target_id.in_(ids), Run.scanner.in_(list(HISTORY_SCANNERS)),
        ).order_by(Run.created_at.desc(), Run.id.desc())
    ).all()
    out: dict[str, str] = {}
    for target_id, run_id in rows:
        if target_id is not None and target_id not in out:
            out[str(target_id)] = str(run_id)
    return out


# ---------------------------------------------------------------------------
# Soft delete (``DELETE /v1/models/{id}``)
# ---------------------------------------------------------------------------


def is_deleted(detail: Any) -> bool:
    """True for a soft-deleted model target (``detail.status == "deleted"``)."""
    return isinstance(detail, dict) and detail.get("status") == DELETED_STATUS


def _delete_blob(store: Any, location: str) -> bool:
    """Best-effort removal of one content-addressed blob; ``False`` when it stays.

    ``BlobStore`` has no delete operation, so the backends are handled by
    shape: an explicit ``delete``, the S3 client of ``S3BlobStore``, or the
    ``base`` directory of ``FilesystemBlobStore`` (only files under it are
    ever unlinked). Anything else is logged and retained, never pretended.
    """
    try:
        delete = getattr(store, "delete", None)
        if callable(delete):
            delete(location)
            return True
        client, bucket = getattr(store, "client", None), getattr(store, "bucket", None)
        if client is not None and bucket:
            key = location.split("/", 3)[3] if location.startswith("s3://") else location
            client.delete_object(Bucket=bucket, Key=key)
            return True
        base = getattr(store, "base", None)
        if base is not None:
            base_r = Path(base).resolve()
            digest = Path(location).name
            for candidate in (Path(base) / digest[:2] / digest, Path(location), Path(base) / location):
                resolved = candidate.resolve()
                if resolved != base_r and base_r in resolved.parents and resolved.is_file():
                    resolved.unlink()
                    return True
            logger.warning("model blob %s is not a file under the blob root %s; nothing removed",
                           location, base_r)
            return False
    except Exception:  # noqa: BLE001 - the row is already marked deleted; report, do not fake
        logger.warning("model blob %s could not be deleted", location, exc_info=True)
        return False
    logger.warning("blob store %s has no delete operation; model blob %s is retained",
                   type(store).__name__, location)
    return False


def delete_model_target(
    *,
    target_id: str,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
    blob_store: BlobStore | None = None,
) -> dict[str, Any]:
    """Admission boundary for ``DELETE /v1/models/{id}``: audit first, then soft delete.

    Raises ``LookupError`` (``model_not_found``) for an unknown, non-ML or
    already deleted target and ``ValueError("campaign_in_flight: ...")`` while
    a Run on the model is queued or running. Historical Run, Job, Finding,
    Artifact, ``ml_campaigns`` and audit rows are untouched. The blob is
    removed unless another live model target shares the same bytes; the
    outcome is reported in ``blob_deleted`` (``None`` for bundled targets,
    whose assets are shared and never deleted here).
    """
    from sqlalchemy import select

    from redsim.db.models import Run, Target
    from redsim.db.session import get_session
    from redsim.safety import authorize

    with get_session() as sess:
        target = sess.get(Target, target_id)
        if target is None or target.kind not in ML_KINDS or is_deleted(target.detail):
            raise LookupError(f"model_not_found: model not found: {target_id}")
        active = sess.execute(
            select(Run.id).where(
                Run.target_id == target_id, Run.status.in_(["queued", "running"]),
            ).limit(1)
        ).first()
        if active is not None:
            raise ValueError(
                f"campaign_in_flight: run {active[0]} on model {target_id} is queued or running"
            )
        project_id, kind, value = target.project_id, target.kind, str(target.value)
        detail = dict(target.detail or {})
        siblings = sess.execute(
            select(Target).where(
                Target.value == target.value, Target.id != target_id, Target.kind.in_(ML_KINDS),
            )
        ).scalars().all()
        blob_shared = any(not is_deleted(row.detail) for row in siblings)

    manifest_value = detail.get("manifest")
    manifest: dict[str, Any] = manifest_value if isinstance(manifest_value, dict) else {}
    endpoint = kind == ENDPOINT_KIND
    bundled = not endpoint and (value.startswith("bundled:") or detail.get("source") == "bundled")
    source = detail.get("source") or ("endpoint" if endpoint else "bundled" if bundled else "upload")
    previous_status = detail.get("status") or manifest.get("status")

    # The chained event precedes the row change (spec 6.7 invariant 4). ML
    # targets are in-boundary artifacts, not network locations: target=None
    # records allowlist_check "n/a", as model.register does. An endpoint's value
    # is a URL: the row carries the host only (ENDPOINT-18, -19).
    audit_detail: dict[str, Any] = {
        "actor": actor,
        "op": "delete",
        "kind": kind,
        "target_id": target_id,
        "value": endpoint_host(value) if endpoint else value,
        "source": source,
        "sha256": detail.get("sha256") or manifest.get("sha256"),
        "previous_status": previous_status,
        "soft_delete": True,
        "blob_shared": False if endpoint else blob_shared,
    }
    if endpoint:
        audit_detail["host"] = endpoint_host(value)
        audit_detail["auth_profile_id"] = endpoint_auth_profile_id(detail)
    authorize(
        "target.manage",
        None,
        allowlist=config.target_allowlist,
        actor=actor,
        writer=audit_writer,
        project_id=project_id,
        detail=audit_detail,
    )

    deleted_at = datetime.now(UTC).isoformat()
    with get_session() as sess:
        target = sess.get(Target, target_id)
        if target is None:
            raise LookupError(f"model_not_found: model not found: {target_id}")
        target.detail = {
            **detail,
            "status": DELETED_STATUS,
            "previous_status": previous_status,
            "deleted_at": deleted_at,
            "deleted_by": actor,
        }
        sess.add(target)

    blob_deleted: bool | None = None
    if endpoint:
        # The value is a URL, nothing was ever stored for it (ENDPOINT-18).
        blob_deleted = None
    elif not bundled:
        if blob_shared:
            blob_deleted = False
            logger.info("delete_model_target target_id=%s blob %s shared with another live model; retained",
                        target_id, value)
        else:
            if blob_store is None:
                from redsim.storage.blobs import open_blob_store

                blob_store = open_blob_store()
            blob_deleted = _delete_blob(blob_store, value)
    logger.info("delete_model_target project_id=%s target_id=%s kind=%s blob_deleted=%s",
                project_id, target_id, kind, blob_deleted)
    return {
        "deleted": target_id,
        "project_id": project_id,
        "status": DELETED_STATUS,
        "deleted_at": deleted_at,
        "blob_deleted": blob_deleted,
    }


__all__ = [
    "BUNDLED_BLOB_PREFIX",
    "CAMPAIGN_SCANNERS",
    "HISTORY_SCANNERS",
    "LLM_PROBE_SCANNER",
    "DELETED_STATUS",
    "ENDPOINT_KIND",
    "ML_KINDS",
    "SUPPORTED_ENDPOINT_AUTH_KINDS",
    "UNKNOWN_BUNDLED_MODEL",
    "DatasetBinding",
    "DatasetBindingError",
    "EndpointAdmission",
    "EndpointAdmissionError",
    "MlCatalogUnavailable",
    "admit_endpoint_registration",
    "artifact_target_from_path",
    "assets_root_path",
    "audit_refused_admission",
    "bundled_target_id",
    "campaign_history",
    "canonical_bundled_id",
    "check_upload_dataset",
    "dataset_entries",
    "dataset_modality",
    "delete_model_target",
    "endpoint_auth_profile_id",
    "endpoint_host",
    "endpoint_request_block",
    "find_bundled_registration",
    "is_deleted",
    "is_endpoint_target",
    "last_run_ids",
    "load_endpoint_auth_profile",
    "read_asset_manifest",
    "register_bundled_model",
    "resolve_dataset_binding",
    "safe_filename",
    "upload_blob_key",
    "uploaded_model_file",
    "uploaded_target",
]
