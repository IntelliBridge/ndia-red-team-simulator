"""Consumed evaluation slices: static admission, rows, projections and the binding hook.

Spec 27.1 "Consume side" (register INTEROP-13, -15, -16; plan 12 wave B3,
``interop-consume`` track). Another team's evaluation slice arrives through
``POST /v1/datasets`` as a Croissant JSON-LD manifest plus Parquet, or as
Parquet alone with the licence, modality, class names and feature or image
schema declared in the form. This module is the light half of that path and
is what the API process imports:

* :func:`prepare_dataset_admission` runs every check the API is allowed to run
  (spec 21.8 "untrusted input", 9.1): the Parquet magic bytes at both ends of
  the file, the manifest's JSON-LD shape, every ``contentUrl`` a bare filename
  present in the upload (``remote_reference_refused``), a licence statement
  (``license_required``), the declared schema (``schema_undeclared``), the
  size caps (``dataset_too_large``, ``unsupported_dataset_format``). It never
  opens a Parquet file: no ``pyarrow`` here, so
  ``tests/test_api_process_has_no_ml.py`` holds.
* :func:`register_consumed_dataset` is the admission boundary: the
  ``dataset.register`` audit row first, then the bytes into the blob store,
  then the ``ml_datasets`` row (status ``validating``), its ``ml.dataset_ingest``
  Run and the ``dataset.validate`` Job. The route enqueues
  ``redsim.ml_dataset_validate`` after the commit; the worker parses the files
  inside the sandbox child (``redsim.ml.interop.consume``) and moves the row to
  ``available`` or ``refused`` with a typed reason.
* :func:`dataset_record`, :func:`list_consumed_datasets` and
  :func:`get_consumed_dataset` are the read side ``GET /v1/datasets`` and
  ``GET /v1/datasets/{id}`` serve beside the bundled catalog.
* :func:`resolve_consumed_slice` and :func:`consumed_dataset_binding` are the
  binding hook (INTEROP-16): an ``available`` slice of the same project can be
  named as ``dataset_id`` on a model upload or a campaign; the campaign is its
  own D9(i) campaign with the consumed id and the manifest digest as its
  dataset revision, never compared with a bundled-dataset campaign.

Audit detail carries ids, digests, counts and field names only: never a URL
string, never bytes. The declared schema (:class:`DeclaredSchema`) is the one
contract the API, the worker and the sandbox child share; the child re-checks
everything the API took on trust.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig
    from redsim.db.models import MlDataset
    from redsim.services.ml_models import DatasetBinding
    from redsim.storage import BlobStore

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- constants

#: ``Job.type`` of the worker-side parse (spec 27.4 row 5.11 names the admission event only).
DATASET_VALIDATE_JOB_TYPE = "dataset.validate"
#: Celery task name (``redsim.workers.tasks.dataset_validate``, ``scans`` queue).
DATASET_VALIDATE_TASK = "redsim.ml_dataset_validate"
#: ``Run.scanner`` of the ingest run that hosts the validate job (parity with ``ml.ingest``).
INGEST_SCANNER = "ml.dataset_ingest"
#: ``role`` of a consumed slice in the dataset catalog (bundled rows are ``demo`` / ``ci_fixture``).
CONSUMED_ROLE = "consumed"
#: Statuses of an ``ml_datasets`` row.
STATUS_VALIDATING = "validating"
STATUS_AVAILABLE = "available"
STATUS_REFUSED = "refused"
#: The streaming cap of the multipart body (spec 17.3 ``dataset_too_large``).
UPLOAD_MAX_MB_ENV = "REDSIM_ML_DATASET_UPLOAD_MAX_MB"
DEFAULT_UPLOAD_MAX_MB = 256
#: Parse-time row cap the worker hands the child (the child env carries no ``REDSIM_*`` setting).
MAX_ROWS_ENV = "REDSIM_ML_DATASET_MAX_ROWS"
DEFAULT_MAX_ROWS = 200_000
#: A Croissant manifest larger than this is not a manifest.
MANIFEST_MAX_BYTES = 4 * 1024 * 1024
#: Parts per upload (one manifest plus Parquet shards).
MAX_PARTS = 16
#: Parquet files start and end with this marker (the footer length precedes the trailing one).
PARQUET_MAGIC = b"PAR1"
#: Modalities a consumed slice can declare in this wave; text and detection slices are Phase B work
#: their modality tracks did not include (the loaders for a consumed text/detection slice are not built).
SUPPORTED_MODALITIES: tuple[str, ...] = ("image", "tabular")
PHASE_B_MODALITIES: tuple[str, ...] = ("text", "detection")
#: Image dtypes the child accepts for the raw ``image`` column.
IMAGE_DTYPES: tuple[str, ...] = ("uint8", "float16", "float32", "float64", "int32", "int64")
DEFAULT_LABEL_COLUMN = "label"
DEFAULT_IMAGE_COLUMN = "image"
#: Croissant ``@type`` spellings of the dataset node.
_DATASET_TYPES = frozenset({"sc:Dataset", "Dataset", "schema:Dataset", "https://schema.org/Dataset"})
_FILE_TYPES = frozenset({"cr:FileObject", "FileObject", "sc:FileObject"})
#: Suffixes that name pickled objects; never accepted as dataset bytes.
_PICKLE_SUFFIXES = frozenset({".pkl", ".pickle", ".joblib", ".sav", ".dill", ".npy", ".npz"})
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_DATASET_ID = re.compile(r"^ds-[0-9a-f]{12,32}$")


def upload_max_bytes() -> int:
    """``REDSIM_ML_DATASET_UPLOAD_MAX_MB`` (default 256) in bytes; malformed values keep the default."""
    raw = os.environ.get(UPLOAD_MAX_MB_ENV, "").strip()
    try:
        megabytes = int(raw) if raw else DEFAULT_UPLOAD_MAX_MB
    except ValueError:
        megabytes = DEFAULT_UPLOAD_MAX_MB
    return max(megabytes, 1) * 1024 * 1024


def max_rows() -> int:
    """``REDSIM_ML_DATASET_MAX_ROWS`` (default 200000); the parent reads it, the child receives it."""
    raw = os.environ.get(MAX_ROWS_ENV, "").strip()
    try:
        value = int(raw) if raw else DEFAULT_MAX_ROWS
    except ValueError:
        value = DEFAULT_MAX_ROWS
    return max(value, 1)


def new_dataset_id() -> str:
    return f"ds-{uuid.uuid4().hex[:16]}"


def is_dataset_id(value: str) -> bool:
    return bool(_DATASET_ID.match(value or ""))


def safe_part_name(name: str | None, default: str) -> str:
    """The part's file name reduced to ``[A-Za-z0-9._-]`` and its last path segment."""
    base = str(name or "").replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = _SAFE_NAME.sub("_", base)
    cleaned = re.sub(r"_+", "_", cleaned)
    cleaned = re.sub(r"_(?=\.)", "", cleaned).strip("._")
    return cleaned or default


def dataset_blob_key(project_id: str, dataset_id: str, name: str) -> str:
    """``{project_id}/datasets/{dataset_id}/{safe name}`` (mirrors the model upload layout)."""
    return f"{project_id}/datasets/{dataset_id}/{safe_part_name(name, 'part')}"


# --------------------------------------------------------------------------- refusals


class DatasetAdmissionError(ValueError):
    """A static refusal of ``POST /v1/datasets``: ``code`` is the spec 17.3 code, ``field`` the form field.

    ``extra`` is audit-safe context (counts, field names, a detected format);
    never a URL string or bytes.
    """

    def __init__(self, code: str, message: str, *, field: str, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.field = field
        self.extra = extra


# --------------------------------------------------------------------------- declared schema


@dataclass(frozen=True)
class DeclaredSchema:
    """What the uploader declares about the slice; the child verifies every field (spec 5.5, 27.1).

    ``tabular``: ``features`` (column names, numeric) with optional ``feature_ranges``
    ``{name: (min, max)}`` so eps scaling (spec 12.9) has bounds. ``image``: the raw
    ``image_column`` holds one C-order array per row of ``dtype`` at ``input_shape``
    (or a list of that many numbers), with values inside ``value_range``. Both carry
    ``class_names`` and the ``label_column`` (class name strings or 0-based indices).
    """

    modality: str
    class_names: tuple[str, ...]
    label_column: str = DEFAULT_LABEL_COLUMN
    features: tuple[str, ...] | None = None
    feature_ranges: dict[str, tuple[float, float]] | None = None
    input_shape: tuple[int, ...] | None = None
    dtype: str | None = None
    value_range: tuple[float, float] | None = None
    image_column: str = DEFAULT_IMAGE_COLUMN

    @property
    def n_classes(self) -> int:
        return len(self.class_names)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "modality": self.modality,
            "class_names": list(self.class_names),
            "label_column": self.label_column,
            "features": list(self.features) if self.features is not None else None,
            "feature_ranges": (
                {k: [v[0], v[1]] for k, v in self.feature_ranges.items()} if self.feature_ranges else None
            ),
            "input_shape": list(self.input_shape) if self.input_shape is not None else None,
            "dtype": self.dtype,
            "value_range": list(self.value_range) if self.value_range is not None else None,
            "image_column": self.image_column,
        }

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> DeclaredSchema:
        """Rebuild from :meth:`to_mapping` (the request the child reads); ``ValueError`` on a bad shape."""
        modality = str(raw.get("modality") or "")
        class_names = tuple(str(v) for v in (raw.get("class_names") or []))
        if modality not in SUPPORTED_MODALITIES or not class_names:
            raise ValueError("declared schema is missing modality or class_names")
        features_raw = raw.get("features")
        ranges_raw = raw.get("feature_ranges")
        shape_raw = raw.get("input_shape")
        range_raw = raw.get("value_range")
        return cls(
            modality=modality,
            class_names=class_names,
            label_column=str(raw.get("label_column") or DEFAULT_LABEL_COLUMN),
            features=tuple(str(v) for v in features_raw) if isinstance(features_raw, list) else None,
            feature_ranges=(
                {str(k): (float(v[0]), float(v[1])) for k, v in ranges_raw.items()}
                if isinstance(ranges_raw, dict) and ranges_raw else None
            ),
            input_shape=tuple(int(v) for v in shape_raw) if isinstance(shape_raw, list) else None,
            dtype=str(raw["dtype"]) if raw.get("dtype") else None,
            value_range=(float(range_raw[0]), float(range_raw[1])) if isinstance(range_raw, list) else None,
            image_column=str(raw.get("image_column") or DEFAULT_IMAGE_COLUMN),
        )


def _json_or_csv_list(value: Any) -> list[Any] | None:
    """A form field that is a JSON array, a JSON scalar, or a comma-separated string; ``None`` when absent."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return list(value)
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("["):
        try:
            parsed = json.loads(text)
        except ValueError:
            return None
        return list(parsed) if isinstance(parsed, list) else None
    return [item.strip() for item in text.split(",") if item.strip()]


def _numbers(values: list[Any] | None, *, count: int | None = None) -> tuple[float, ...] | None:
    if values is None:
        return None
    out: list[float] = []
    for item in values:
        if isinstance(item, bool):
            return None
        try:
            out.append(float(item))
        except (TypeError, ValueError):
            return None
    if count is not None and len(out) != count:
        return None
    return tuple(out)


def declared_schema_from_fields(
    fields: Mapping[str, Any], *, manifest: Mapping[str, Any] | None = None,
) -> DeclaredSchema:
    """Read and check the declaration (form fields first, the manifest's record set as the fallback).

    Raises :class:`DatasetAdmissionError` ``schema_undeclared`` naming the missing
    or malformed field, and ``not_implemented`` (phase B) for a text or detection
    slice, whose consumed-slice loaders are not built.
    """
    modality = str(fields.get("modality") or "").strip().lower()
    if not modality:
        raise DatasetAdmissionError("schema_undeclared", "modality is required (image or tabular)", field="modality")
    if modality in PHASE_B_MODALITIES:
        raise DatasetAdmissionError(
            "not_implemented",
            f"consuming a {modality} evaluation slice is not implemented; the {modality} modality has no "
            f"consumed-slice loader in this wave",
            field="modality", phase="B", reason=f"{modality} consumed slices are not built",
        )
    if modality not in SUPPORTED_MODALITIES:
        raise DatasetAdmissionError(
            "schema_undeclared", f"modality {modality!r} is not one of {list(SUPPORTED_MODALITIES)}", field="modality",
        )
    names = _json_or_csv_list(fields.get("class_names"))
    if names is None and manifest is not None:
        names = _json_or_csv_list(_manifest_extension(manifest, "class_names"))
    class_names = tuple(str(v).strip() for v in (names or []) if str(v).strip())
    if not class_names or len(set(class_names)) != len(class_names):
        raise DatasetAdmissionError(
            "schema_undeclared", "class_names must be a non-empty list of distinct class names", field="class_names",
        )
    label_column = str(fields.get("label_column") or DEFAULT_LABEL_COLUMN).strip() or DEFAULT_LABEL_COLUMN

    if modality == "tabular":
        raw_features = _json_or_csv_list(fields.get("features"))
        if raw_features is None and manifest is not None:
            raw_features = manifest_record_fields(manifest, exclude=(label_column,))
        features: list[str] = []
        ranges: dict[str, tuple[float, float]] = {}
        for item in raw_features or []:
            if isinstance(item, dict):
                name = str(item.get("name") or "").strip()
                if not name:
                    raise DatasetAdmissionError("schema_undeclared", "a feature entry has no name", field="features")
                features.append(name)
                if item.get("min") is not None or item.get("max") is not None:
                    bounds = _numbers([item.get("min"), item.get("max")], count=2)
                    if bounds is None or bounds[0] > bounds[1]:
                        raise DatasetAdmissionError(
                            "schema_undeclared", f"feature {name!r} declares an invalid min/max", field="features",
                        )
                    ranges[name] = (bounds[0], bounds[1])
            else:
                name = str(item).strip()
                if name:
                    features.append(name)
        if not features or len(set(features)) != len(features) or label_column in features:
            raise DatasetAdmissionError(
                "schema_undeclared",
                "tabular slices declare features: a non-empty list of distinct numeric column names "
                "(the label column excluded)",
                field="features",
            )
        return DeclaredSchema(
            modality="tabular", class_names=class_names, label_column=label_column,
            features=tuple(features), feature_ranges=ranges or None,
        )

    shape = _numbers(_json_or_csv_list(fields.get("input_shape")))
    if shape is None and manifest is not None:
        shape = _numbers(_json_or_csv_list(_manifest_extension(manifest, "input_shape")))
    if shape is None or len(shape) != 3 or any(v <= 0 or int(v) != v for v in shape):
        raise DatasetAdmissionError(
            "schema_undeclared", "image slices declare input_shape as three positive integers [C, H, W]",
            field="input_shape",
        )
    dtype = str(fields.get("dtype") or _manifest_extension(manifest, "dtype") or "").strip().lower()
    if dtype not in IMAGE_DTYPES:
        raise DatasetAdmissionError(
            "schema_undeclared", f"image slices declare dtype as one of {list(IMAGE_DTYPES)}", field="dtype",
        )
    value_range = _numbers(_json_or_csv_list(fields.get("value_range")), count=2)
    if value_range is None and manifest is not None:
        value_range = _numbers(_json_or_csv_list(_manifest_extension(manifest, "value_range")), count=2)
    if value_range is None or value_range[0] >= value_range[1]:
        raise DatasetAdmissionError(
            "schema_undeclared", "image slices declare value_range as [min, max] with min < max", field="value_range",
        )
    image_column = str(fields.get("image_column") or DEFAULT_IMAGE_COLUMN).strip() or DEFAULT_IMAGE_COLUMN
    return DeclaredSchema(
        modality="image", class_names=class_names, label_column=label_column,
        input_shape=tuple(int(v) for v in shape), dtype=dtype,
        value_range=(value_range[0], value_range[1]), image_column=image_column,
    )


# --------------------------------------------------------------------------- upload parts


@dataclass(frozen=True)
class UploadPart:
    """One multipart file part after the static checks: bytes, digest and its role in the upload."""

    name: str                 # safe file name (blob key segment; what a Croissant contentUrl must equal)
    data: bytes
    sha256: str
    role: str                 # "parquet" | "manifest"
    content_type: str = "application/octet-stream"

    @property
    def size_bytes(self) -> int:
        return len(self.data)


def check_parquet_bytes(name: str, data: bytes) -> None:
    """The static Parquet check: ``PAR1`` at both ends, never a pickle-shaped name, never empty (415)."""
    suffix = os.path.splitext(name.lower())[1]
    if suffix in _PICKLE_SUFFIXES or (data[:1] == b"\x80"):
        raise DatasetAdmissionError(
            "unsupported_dataset_format", "pickled or numpy-serialised slices are never accepted; upload Parquet",
            field="file",
        )
    if not data:
        raise DatasetAdmissionError("unsupported_dataset_format", f"part {name!r} is empty", field="file")
    if data[:4] != PARQUET_MAGIC or len(data) < 12 or data[-4:] != PARQUET_MAGIC:
        raise DatasetAdmissionError(
            "unsupported_dataset_format", f"part {name!r} is not a Parquet file (PAR1 magic missing)", field="file",
            detected_format="unknown",
        )


def parse_manifest_bytes(data: bytes) -> dict[str, Any]:
    """Parse the Croissant manifest part and check its JSON-LD shape (415 on any defect)."""
    if len(data) > MANIFEST_MAX_BYTES:
        raise DatasetAdmissionError(
            "unsupported_dataset_format", f"the manifest exceeds {MANIFEST_MAX_BYTES} bytes", field="manifest",
        )
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise DatasetAdmissionError(
            "unsupported_dataset_format", f"the manifest is not JSON: {type(exc).__name__}", field="manifest",
        ) from None
    if not isinstance(document, dict):
        raise DatasetAdmissionError("unsupported_dataset_format", "the manifest is not a JSON object", field="manifest")
    if "@context" not in document:
        raise DatasetAdmissionError(
            "unsupported_dataset_format", "the manifest has no @context (Croissant JSON-LD)", field="manifest",
        )
    types = document.get("@type")
    type_set = set(types) if isinstance(types, list) else {types}
    if not (type_set & _DATASET_TYPES):
        raise DatasetAdmissionError(
            "unsupported_dataset_format", "the manifest @type is not sc:Dataset", field="manifest",
        )
    distribution = document.get("distribution")
    if not isinstance(distribution, list) or not distribution:
        raise DatasetAdmissionError(
            "unsupported_dataset_format", "the manifest declares no distribution (FileObject list)", field="manifest",
        )
    for index, entry in enumerate(distribution):
        if not isinstance(entry, dict) or not isinstance(entry.get("contentUrl"), str):
            raise DatasetAdmissionError(
                "unsupported_dataset_format", f"distribution[{index}] is not a FileObject with a contentUrl",
                field="manifest", index=index,
            )
        entry_type = entry.get("@type")
        entry_types = set(entry_type) if isinstance(entry_type, list) else {entry_type}
        if entry_type is not None and not (entry_types & _FILE_TYPES):
            raise DatasetAdmissionError(
                "unsupported_dataset_format", f"distribution[{index}] is not a cr:FileObject", field="manifest",
                index=index,
            )
    return document


def is_local_reference(content_url: str) -> bool:
    """True when ``content_url`` is a bare file name: no scheme, host, directory or parent segment."""
    text = str(content_url or "").strip()
    if not text or "\\" in text or "/" in text or text in {".", ".."}:
        return False
    parts = urlsplit(text)
    if parts.scheme or parts.netloc:
        return False
    return "\x00" not in text


def check_manifest_references(manifest: Mapping[str, Any], part_names: Iterable[str]) -> list[str]:
    """Every ``contentUrl`` must name a file in this upload (spec 21.8 bullet 3; ``remote_reference_refused``).

    Returns the referenced names. The refusal never echoes the reference: audit
    detail carries the distribution index and a count only.
    """
    names = set(part_names)
    referenced: list[str] = []
    raw_distribution = manifest.get("distribution")
    distribution: list[Any] = list(raw_distribution) if isinstance(raw_distribution, list) else []
    for index, entry in enumerate(distribution):
        content_url = str(entry.get("contentUrl") or "") if isinstance(entry, dict) else ""
        if not is_local_reference(content_url):
            raise DatasetAdmissionError(
                "remote_reference_refused",
                f"distribution[{index}].contentUrl references content outside the upload; every FileObject must "
                "name a file of this upload",
                field="manifest", index=index,
            )
        if content_url not in names and safe_part_name(content_url, "") not in names:
            raise DatasetAdmissionError(
                "remote_reference_refused",
                f"distribution[{index}].contentUrl names a file that is not part of this upload",
                field="manifest", index=index,
            )
        referenced.append(safe_part_name(content_url, content_url))
    return referenced


def manifest_license(manifest: Mapping[str, Any] | None) -> str | None:
    """The manifest's ``license`` (a string or an object with ``name`` / ``@id``), if declared."""
    if manifest is None:
        return None
    value = manifest.get("license")
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        for key in ("name", "@id", "url"):
            inner = value.get(key)
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
    return None


def manifest_record_fields(manifest: Mapping[str, Any], *, exclude: Iterable[str] = ()) -> list[str] | None:
    """Field names of the manifest's first record set (the tabular feature fallback), else ``None``."""
    record_sets = manifest.get("recordSet")
    if not isinstance(record_sets, list) or not record_sets:
        return None
    first = record_sets[0]
    fields = first.get("field") if isinstance(first, dict) else None
    if not isinstance(fields, list):
        return None
    skipped = set(exclude)
    names: list[str] = []
    for entry in fields:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("@id") or "").rsplit("/", 1)[-1].strip()
        if name and name not in skipped:
            names.append(name)
    return names or None


def _manifest_extension(manifest: Mapping[str, Any] | None, key: str) -> Any:
    """``redsim:<key>`` (or bare ``<key>``) on the dataset node: the declaration carried in a manifest."""
    if manifest is None:
        return None
    for spelled in (f"redsim:{key}", key):
        if manifest.get(spelled) is not None:
            return manifest.get(spelled)
    return None


# --------------------------------------------------------------------------- admission


@dataclass(frozen=True)
class DatasetAdmission:
    """What the static checks of ``POST /v1/datasets`` established; nothing was parsed or stored yet."""

    dataset_id: str
    project_id: str
    name: str
    license: str
    schema: DeclaredSchema
    parts: tuple[UploadPart, ...]
    manifest: dict[str, Any] | None
    manifest_sha256: str | None
    revision: str                     # manifest sha256, else the single Parquet part's sha256
    public: bool
    total_bytes: int
    source_label: str = ""            # free text the uploader gives about the slice's origin (no URL check)

    @property
    def parquet_parts(self) -> list[UploadPart]:
        return [part for part in self.parts if part.role == "parquet"]

    @property
    def manifest_part(self) -> UploadPart | None:
        return next((part for part in self.parts if part.role == "manifest"), None)

    def audit_detail(self) -> dict[str, Any]:
        """Ids, digests, counts and declared names only (spec 5.11)."""
        return {
            "kind": "ml_dataset", "source": CONSUMED_ROLE, "dataset_id": self.dataset_id,
            "modality": self.schema.modality, "n_classes": self.schema.n_classes,
            "license": self.license[:256], "public": self.public,
            "n_files": len(self.parts), "n_parquet": len(self.parquet_parts),
            "total_bytes": self.total_bytes, "manifest_sha256": self.manifest_sha256,
            "revision": self.revision,
            "sha256s": {part.name: part.sha256 for part in self.parts},
            "features": list(self.schema.features) if self.schema.features else None,
            "input_shape": list(self.schema.input_shape) if self.schema.input_shape else None,
        }


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def prepare_dataset_admission(
    *, project_id: str, fields: Mapping[str, Any], parts: Iterable[tuple[str, str, bytes]],
    cap_bytes: int | None = None,
) -> DatasetAdmission:
    """Run every API-side static check of INTEROP-13 over the parsed multipart body.

    ``parts`` are ``(form field name, original file name, bytes)`` triples: the
    field ``manifest`` is the Croissant document, every other file part is a
    Parquet shard. Order of refusals: part count and total size, Parquet magic,
    manifest shape, remote references, licence, declared schema. Raises
    :class:`DatasetAdmissionError`; the route writes the ``success=False`` row.
    """
    cap = cap_bytes if cap_bytes is not None else upload_max_bytes()
    triples = list(parts)
    if not triples:
        raise DatasetAdmissionError(
            "unsupported_dataset_format", "a multipart Parquet file part is required", field="file",
        )
    if len(triples) > MAX_PARTS:
        raise DatasetAdmissionError(
            "dataset_too_large", f"at most {MAX_PARTS} file parts per upload", field="file", n_files=len(triples),
        )
    total = sum(len(data) for _f, _n, data in triples)
    if total > cap:
        raise DatasetAdmissionError(
            "dataset_too_large", f"upload of {total} bytes exceeds the {cap} byte cap", field="file",
            total_bytes=total, cap=cap,
        )

    upload_parts: list[UploadPart] = []
    seen: set[str] = set()
    manifest: dict[str, Any] | None = None
    manifest_sha: str | None = None
    for field_name, original, data in triples:
        role = "manifest" if field_name == "manifest" else "parquet"
        default = "manifest.json" if role == "manifest" else "slice.parquet"
        name = safe_part_name(original, default)
        if name in seen:
            raise DatasetAdmissionError(
                "unsupported_dataset_format", f"two parts share the file name {name!r}", field="file",
            )
        seen.add(name)
        digest = hashlib.sha256(data).hexdigest()
        if role == "manifest":
            if manifest is not None:
                raise DatasetAdmissionError(
                    "unsupported_dataset_format", "at most one manifest part per upload", field="manifest",
                )
            manifest = parse_manifest_bytes(data)
            manifest_sha = digest
            upload_parts.append(UploadPart(name=name, data=data, sha256=digest, role=role,
                                           content_type="application/ld+json"))
        else:
            check_parquet_bytes(name, data)
            upload_parts.append(UploadPart(name=name, data=data, sha256=digest, role=role,
                                           content_type="application/vnd.apache.parquet"))
    parquet_names = [part.name for part in upload_parts if part.role == "parquet"]
    if not parquet_names:
        raise DatasetAdmissionError(
            "unsupported_dataset_format", "the upload carries a manifest but no Parquet part", field="file",
        )
    if manifest is not None:
        referenced = check_manifest_references(manifest, parquet_names)
        unreferenced = sorted(set(parquet_names) - set(referenced))
        if unreferenced:
            raise DatasetAdmissionError(
                "unsupported_dataset_format",
                f"{len(unreferenced)} Parquet part(s) are not listed in the manifest's distribution",
                field="manifest", n_unreferenced=len(unreferenced),
            )

    license_statement = str(fields.get("license_statement") or "").strip() or (manifest_license(manifest) or "")
    if not license_statement:
        raise DatasetAdmissionError(
            "license_required",
            "license_statement is required: only licensed datasets are registered (the manifest's license is "
            "accepted in its place)",
            field="license_statement",
        )
    schema = declared_schema_from_fields(fields, manifest=manifest)

    dataset_id = new_dataset_id()
    name = str(fields.get("name") or (manifest.get("name") if manifest else None) or parquet_names[0]).strip()
    revision = manifest_sha or next(part.sha256 for part in upload_parts if part.role == "parquet")
    return DatasetAdmission(
        dataset_id=dataset_id, project_id=project_id, name=name[:256], license=license_statement,
        schema=schema, parts=tuple(upload_parts), manifest=manifest, manifest_sha256=manifest_sha,
        revision=revision, public=_truthy(fields.get("public")), total_bytes=total,
        source_label=str(fields.get("source") or "").strip()[:256],
    )


@dataclass(frozen=True)
class RegisteredDataset:
    """The rows :func:`register_consumed_dataset` wrote (ids only) plus the response projection."""

    dataset_id: str
    run_id: str
    job_id: str
    response: dict[str, Any] = field(default_factory=dict)


def register_consumed_dataset(
    session: Session,
    admission: DatasetAdmission,
    *,
    actor: str,
    audit_writer: AuditWriter,
    config: RedsimConfig,
    blob_store: BlobStore | None = None,
) -> RegisteredDataset:
    """The admission boundary: audit row, then blobs, then the dataset, Run and Job rows (spec 9.3 order).

    The caller owns the transaction (``get_session``) and enqueues
    :data:`DATASET_VALIDATE_TASK` after the commit so a fast worker never finds
    a missing row. Nothing is parsed here.
    """
    from redsim.db.models import Job, MlDataset, Run
    from redsim.safety import authorize

    run_id = f"run-{uuid.uuid4().hex[:12]}"
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    blob_prefix = f"{admission.project_id}/datasets/{admission.dataset_id}"
    # Spec 9.3 step 4 / 5.11: the chained event precedes the blobs and every row.
    authorize(
        "dataset.register", None, allowlist=config.target_allowlist, actor=actor, writer=audit_writer,
        project_id=admission.project_id, run_id=run_id,
        detail={**admission.audit_detail(), "blob_prefix": blob_prefix, "ingest_run_id": run_id,
                "ingest_job_id": job_id, "name": admission.name},
    )
    if blob_store is None:
        from redsim.storage.blobs import open_blob_store

        blob_store = open_blob_store()
    files: list[dict[str, Any]] = []
    for part in admission.parts:
        key = dataset_blob_key(admission.project_id, admission.dataset_id, part.name)
        ref = blob_store.put(key, part.data, content_type=part.content_type)
        files.append({
            "name": part.name, "role": part.role, "key": key, "location": ref.location,
            "sha256": part.sha256, "size_bytes": part.size_bytes, "content_type": part.content_type,
        })
    registered_at = datetime.now(UTC).isoformat()
    detail: dict[str, Any] = {
        "name": admission.name,
        "schema": admission.schema.to_mapping(),
        "files": files,
        "manifest_sha256": admission.manifest_sha256,
        "has_manifest": admission.manifest is not None,
        "public": admission.public,
        "source_label": admission.source_label or None,
        "total_bytes": admission.total_bytes,
        "registered_by": actor,
        "registered_at": registered_at,
        "validation": {"ingest_run_id": run_id, "ingest_job_id": job_id, "parse": None},
    }
    row = MlDataset(
        id=admission.dataset_id, project_id=admission.project_id, status=STATUS_VALIDATING,
        license=admission.license[:256], modality=admission.schema.modality,
        class_names=list(admission.schema.class_names), manifest_sha256=admission.revision,
        blob_location=blob_prefix, detail=detail, created_by=actor,
    )
    session.add(row)
    session.flush()
    session.add(Run(
        id=run_id, project_id=admission.project_id, target_id=None, mode="api", status="queued",
        scanner=INGEST_SCANNER, created_by=actor,
        stage_table={"stage": None, "stages_done": [], "jobs": {}, "dataset_id": admission.dataset_id},
    ))
    session.flush()
    primary = admission.parquet_parts[0]
    session.add(Job(
        id=job_id, run_id=run_id, project_id=admission.project_id, type=DATASET_VALIDATE_JOB_TYPE,
        status="queued", created_by=actor,
        detail={
            # ``DatasetRegisterJobDetail`` keys (redsim/db/models.py) plus the file list the worker materialises.
            "dataset_id": admission.dataset_id, "blob_location": blob_prefix, "declared_format": "parquet",
            "declared_sha256": primary.sha256, "manifest_sha256": admission.manifest_sha256,
            "files": files,
        },
    ))
    session.flush()
    response = dataset_record(row)
    response["ingest_run_id"] = run_id
    response["ingest_job_id"] = job_id
    logger.info("register_consumed_dataset project_id=%s dataset_id=%s revision=%s files=%d",
                admission.project_id, admission.dataset_id, admission.revision, len(files))
    return RegisteredDataset(dataset_id=admission.dataset_id, run_id=run_id, job_id=job_id, response=response)


def enqueue_dataset_validate(job_id: str) -> str | None:
    """Enqueue the worker task; ``None`` when the broker is unavailable (the queued row survives for the reaper)."""
    try:
        from redsim.workers.tasks.dataset_validate import ml_dataset_validate

        queued = ml_dataset_validate.delay(job_id)
    except Exception:  # noqa: BLE001 - durable queued row survives broker outages
        logger.warning("enqueue failed for dataset validation job %s", job_id, exc_info=True)
        return None
    return str(getattr(queued, "id", "") or "") or None


# --------------------------------------------------------------------------- read side


def _detail(row: Any) -> dict[str, Any]:
    value = getattr(row, "detail", None)
    return dict(value) if isinstance(value, dict) else {}


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def dataset_record(row: MlDataset) -> dict[str, Any]:
    """The JSON projection of an ``ml_datasets`` row (never bytes, never a blob URL: names and digests)."""
    detail = _detail(row)
    files_raw = detail.get("files")
    files = [
        {"name": item.get("name"), "role": item.get("role"), "sha256": item.get("sha256"),
         "size_bytes": item.get("size_bytes"), "content_type": item.get("content_type")}
        for item in (files_raw if isinstance(files_raw, list) else []) if isinstance(item, dict)
    ]
    validation = _as_dict(detail.get("validation"))
    parse_value = validation.get("parse")
    parse: dict[str, Any] | None = dict(parse_value) if isinstance(parse_value, dict) else None
    schema = _as_dict(detail.get("schema"))
    class_names = [str(v) for v in (row.class_names or [])]
    created = getattr(row, "created_at", None)
    return {
        "id": row.id,
        "project_id": row.project_id,
        "name": str(detail.get("name") or row.id),
        "role": CONSUMED_ROLE,
        "source": CONSUMED_ROLE,
        "status": row.status,
        "refusal_reason": row.refusal_reason,
        "license": row.license or "not declared",
        "modality": row.modality,
        "compatible_modalities": [row.modality] if row.modality else [],
        "classes": class_names,
        "class_names": class_names,
        "n_classes": len(class_names),
        "size": int(parse.get("n_rows") or 0) if parse else 0,
        "n_rows": parse.get("n_rows") if parse else None,
        "per_class": parse.get("per_class") if parse else None,
        "format": "parquet",
        "revision": row.manifest_sha256 or "",
        "manifest_sha256": detail.get("manifest_sha256"),
        "has_manifest": bool(detail.get("has_manifest")),
        "schema": schema,
        "files": files,
        "fixture_only": False,
        "reachability": "blob",
        "public": bool(detail.get("public", False)),
        "source_label": detail.get("source_label"),
        "created_by": row.created_by,
        "created_at": created.isoformat() if created is not None else None,
        "ingest_run_id": validation.get("ingest_run_id"),
        "ingest_job_id": validation.get("ingest_job_id"),
        "validation": {k: v for k, v in validation.items() if k != "parse"} | {"parse": parse},
    }


def get_consumed_dataset(session: Session, dataset_id: str) -> MlDataset | None:
    from redsim.db.models import MlDataset

    if not dataset_id:
        return None
    return session.get(MlDataset, dataset_id)


def list_consumed_datasets(session: Session, project_ids: Iterable[str] | None) -> list[dict[str, Any]]:
    """Consumed rows of ``project_ids`` (``None`` = every project, for system principals), newest first."""
    from sqlalchemy import select

    from redsim.db.models import MlDataset

    stmt = select(MlDataset).order_by(MlDataset.created_at.desc(), MlDataset.id.desc())
    if project_ids is not None:
        ids = list(project_ids)
        if not ids:
            return []
        stmt = stmt.where(MlDataset.project_id.in_(ids))
    return [dataset_record(row) for row in session.execute(stmt).scalars().all()]


# --------------------------------------------------------------------------- binding hook (INTEROP-16)


@dataclass(frozen=True)
class ConsumedSlice:
    """An ``available`` consumed slice resolved for a model upload or a campaign (never bytes)."""

    dataset_id: str
    project_id: str
    revision: str                       # manifest sha256 (or the Parquet digest of a manifest-less upload)
    modality: str
    class_names: list[str]
    schema: DeclaredSchema
    files: list[dict[str, Any]]         # {name, role, location, sha256, size_bytes}
    n_rows: int | None
    per_class: dict[str, int] | None
    license: str | None

    @property
    def parquet_files(self) -> list[dict[str, Any]]:
        return [item for item in self.files if item.get("role") == "parquet"]


def resolve_consumed_slice(
    session: Session, dataset_id: str, *, project_id: str | None = None,
) -> ConsumedSlice | None:
    """The ``available`` consumed slice ``dataset_id`` names, or ``None``.

    ``None`` for an unknown id, a row of another project when ``project_id`` is
    given, or a row that is still ``validating`` / ``refused`` (a slice binds
    only once the child confirmed the declaration). The one-line hooks for the
    files this track does not own: ``services.ml_models.check_upload_dataset``
    falls back to :func:`consumed_dataset_binding` when the bundled resolution
    raises ``DatasetBindingError``; ``services.ml_campaigns`` accepts a
    ``dataset_id`` that resolves here with ``dataset_revision = slice.revision``.
    """
    row = get_consumed_dataset(session, dataset_id)
    if row is None or row.status != STATUS_AVAILABLE:
        return None
    if project_id is not None and row.project_id != project_id:
        return None
    detail = _detail(row)
    try:
        schema = DeclaredSchema.from_mapping(detail.get("schema") or {})
    except (TypeError, ValueError):
        return None
    validation = _as_dict(detail.get("validation"))
    parse = _as_dict(validation.get("parse"))
    files_raw = detail.get("files")
    files = [dict(item) for item in (files_raw if isinstance(files_raw, list) else []) if isinstance(item, dict)]
    n_rows = parse.get("n_rows")
    per_class = parse.get("per_class")
    return ConsumedSlice(
        dataset_id=row.id, project_id=row.project_id, revision=str(row.manifest_sha256 or ""),
        modality=str(row.modality or schema.modality), class_names=list(schema.class_names), schema=schema,
        files=files, n_rows=int(n_rows) if isinstance(n_rows, int) else None,
        per_class=dict(per_class) if isinstance(per_class, dict) else None, license=row.license,
    )


def consumed_dataset_binding(
    session: Session, dataset_id: str, *, project_id: str, modality: str | None = None,
) -> DatasetBinding:
    """A ``services.ml_models.DatasetBinding`` over a consumed slice (the upload-path hook, INTEROP-16).

    ``file_path`` is the primary Parquet blob location and ``split`` is
    ``"eval"``; the revision is the manifest digest. Raises
    ``DatasetBindingError`` (``422 dataset_incompatible``) when the slice is
    unknown, not available, of another project or of another modality.
    """
    from redsim.services.ml_models import DatasetBinding, DatasetBindingError

    slice_ = resolve_consumed_slice(session, dataset_id, project_id=project_id)
    if slice_ is None:
        row = get_consumed_dataset(session, dataset_id)
        if row is not None and row.project_id == project_id and row.status != STATUS_AVAILABLE:
            raise DatasetBindingError(
                f"consumed dataset {dataset_id!r} is {row.status}; only an available slice binds a model",
            )
        raise DatasetBindingError(f"unknown dataset {dataset_id!r}: neither bundled nor a consumed slice of this project")
    if modality is not None and slice_.modality != modality:
        raise DatasetBindingError(
            f"consumed dataset {dataset_id!r} is a {slice_.modality} slice; the model declares modality {modality!r}",
        )
    parquet = slice_.parquet_files
    if not parquet:
        raise DatasetBindingError(f"consumed dataset {dataset_id!r} records no Parquet part")
    return DatasetBinding(
        dataset_id=slice_.dataset_id, split="eval", file_path=str(parquet[0].get("location") or ""),
        file_sha256=str(parquet[0].get("sha256") or "") or None, class_names=list(slice_.class_names),
        revision=slice_.revision or None, modality=slice_.modality, fixture_only=False,
    )


__all__ = [
    "CONSUMED_ROLE",
    "DATASET_VALIDATE_JOB_TYPE",
    "DATASET_VALIDATE_TASK",
    "DEFAULT_IMAGE_COLUMN",
    "DEFAULT_LABEL_COLUMN",
    "DEFAULT_MAX_ROWS",
    "DEFAULT_UPLOAD_MAX_MB",
    "IMAGE_DTYPES",
    "INGEST_SCANNER",
    "MANIFEST_MAX_BYTES",
    "MAX_PARTS",
    "MAX_ROWS_ENV",
    "PARQUET_MAGIC",
    "PHASE_B_MODALITIES",
    "STATUS_AVAILABLE",
    "STATUS_REFUSED",
    "STATUS_VALIDATING",
    "SUPPORTED_MODALITIES",
    "UPLOAD_MAX_MB_ENV",
    "ConsumedSlice",
    "DatasetAdmission",
    "DatasetAdmissionError",
    "DeclaredSchema",
    "RegisteredDataset",
    "UploadPart",
    "check_manifest_references",
    "check_parquet_bytes",
    "consumed_dataset_binding",
    "dataset_blob_key",
    "dataset_record",
    "declared_schema_from_fields",
    "enqueue_dataset_validate",
    "get_consumed_dataset",
    "is_dataset_id",
    "is_local_reference",
    "list_consumed_datasets",
    "manifest_license",
    "manifest_record_fields",
    "max_rows",
    "new_dataset_id",
    "parse_manifest_bytes",
    "prepare_dataset_admission",
    "register_consumed_dataset",
    "resolve_consumed_slice",
    "safe_part_name",
    "upload_max_bytes",
]
