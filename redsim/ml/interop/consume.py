"""Parse and verify a consumed evaluation slice, inside the sandbox child only (INTEROP-15, -16).

The API (``redsim.services.ml_datasets``) admits another team's slice on static
checks alone; this module is the other half, run as ``python -m
redsim.ml.interop.consume --request <json> --work-dir <dir>`` by
``redsim.workers.tasks.dataset_validate`` under the ML sandbox's rlimits and
credential-free environment. Parquet decoders are an attack surface (spec 21.8
"untrusted input"), so ``pyarrow`` is imported here and nowhere the API or the
worker parent would load it.

What the child establishes, every outcome a typed envelope in ``result.json``
(same shape as ``redsim.ml.sandbox_worker``):

* every materialised file still has the sha256 recorded at admission
  (``artifact_digest_mismatch`` otherwise);
* a Croissant manifest's ``FileObject.sha256`` agrees with the file it names
  (``manifest_digest_mismatch``) and names only files of the upload;
* the Parquet metadata is readable, ``num_rows`` is within the cap
  (``dataset_too_large``), the declared columns exist with numeric types
  (``schema_mismatch``), the ``label`` column resolves onto the declared class
  names or indices (``class_names_mismatch``), image rows have exactly
  ``prod(input_shape)`` elements of the declared dtype inside ``value_range``;
* the report: row count, per-class counts, empty classes, column types, the
  observed value range, digests and the dataset revision.

:func:`load_consumed_slice` is the same reader the evaluation binding uses once a
slice is bound to a model (INTEROP-16): it returns ``x`` and integer ``y`` with
the declared class order, so a campaign on a consumed slice measures the rows
the child validated and nothing else.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from redsim.services.ml_datasets import (
    DEFAULT_MAX_ROWS,
    DeclaredSchema,
    is_local_reference,
    safe_part_name,
)

#: Report schema version (``detail.validation.parse.schema_version``).
REPORT_SCHEMA_VERSION = "consumed-slice-1"
#: Request ``mode`` this child answers.
MODE = "dataset_parse"
#: Exit status for an unreadable request (mirrors ``redsim.ml.sandbox_worker.EXIT_BAD_REQUEST``).
EXIT_BAD_REQUEST = 2
#: Cap on the envelope (spec 9.4).
ENVELOPE_MAX_BYTES = 16 * 1024 * 1024
#: Rows of a Parquet file read per batch when counting labels (bounded memory on a wide slice).
_BATCH_ROWS = 8192


class ConsumeRefused(Exception):
    """A typed refusal of the slice: ``code`` is recorded as the row's ``refusal_reason``."""

    def __init__(self, code: str, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.field = field


@dataclass(frozen=True)
class ConsumedArrays:
    """The slice as arrays: ``x`` (float32; ``(n, F)`` tabular or ``(n, C, H, W)`` image) and ``y`` (int64)."""

    x: Any
    y: Any
    class_names: tuple[str, ...]
    columns: list[dict[str, str]]
    value_range: tuple[float, float]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------- manifest cross-checks


def check_manifest_against_files(manifest: dict[str, Any], digests: dict[str, str]) -> dict[str, str]:
    """Every ``FileObject`` must name an uploaded file and, when it carries ``sha256``, match it.

    Returns ``{file name: declared sha256}`` for the entries that declared one.
    """
    declared: dict[str, str] = {}
    raw_distribution = manifest.get("distribution")
    distribution: list[Any] = list(raw_distribution) if isinstance(raw_distribution, list) else []
    for index, entry in enumerate(distribution):
        if not isinstance(entry, dict):
            raise ConsumeRefused("unsupported_dataset_format", f"distribution[{index}] is not an object",
                                 field="manifest")
        content_url = str(entry.get("contentUrl") or "")
        if not is_local_reference(content_url):
            raise ConsumeRefused("remote_reference_refused",
                                 f"distribution[{index}].contentUrl references content outside the upload",
                                 field="manifest")
        name = content_url if content_url in digests else safe_part_name(content_url, content_url)
        if name not in digests:
            raise ConsumeRefused("remote_reference_refused",
                                 f"distribution[{index}].contentUrl names a file that is not part of the upload",
                                 field="manifest")
        expected = entry.get("sha256")
        if expected is not None:
            expected_text = str(expected).strip().lower()
            if expected_text != digests[name]:
                raise ConsumeRefused(
                    "manifest_digest_mismatch",
                    f"distribution[{index}] declares sha256 {expected_text[:16]}... but the uploaded file "
                    f"{name!r} has {digests[name][:16]}...",
                    field="manifest",
                )
            declared[name] = expected_text
    return declared


# --------------------------------------------------------------------------- parquet reading


def _pyarrow() -> tuple[Any, Any]:
    import pyarrow as pa
    import pyarrow.parquet as pq

    return pa, pq


def _numeric(pa: Any, dtype: Any) -> bool:
    return bool(pa.types.is_integer(dtype) or pa.types.is_floating(dtype))


def _label_indices(labels: list[Any], schema: DeclaredSchema) -> Any:
    """Labels as 0-based class indices in the declared order; a string is looked up, an int range-checked."""
    import numpy as np

    index = {name: i for i, name in enumerate(schema.class_names)}
    out = np.empty(len(labels), dtype=np.int64)
    for position, value in enumerate(labels):
        if value is None:
            raise ConsumeRefused("class_names_mismatch", f"row {position} has a null label",
                                 field=schema.label_column)
        if isinstance(value, bool):
            raise ConsumeRefused("class_names_mismatch", f"row {position} has a boolean label",
                                 field=schema.label_column)
        if isinstance(value, (int,)) or (isinstance(value, float) and float(value).is_integer()):
            number = int(value)
            if not 0 <= number < schema.n_classes:
                raise ConsumeRefused(
                    "class_names_mismatch",
                    f"row {position} has label index {number}, outside the {schema.n_classes} declared classes",
                    field=schema.label_column,
                )
            out[position] = number
            continue
        text = str(value)
        if text not in index:
            raise ConsumeRefused(
                "class_names_mismatch", f"row {position} has label {text!r}, which is not a declared class name",
                field=schema.label_column,
            )
        out[position] = index[text]
    return out


def _check_columns(pa: Any, arrow_schema: Any, schema: DeclaredSchema) -> list[dict[str, str]]:
    names = set(arrow_schema.names)
    if schema.label_column not in names:
        raise ConsumeRefused("schema_mismatch", f"label column {schema.label_column!r} is not in the Parquet schema",
                             field=schema.label_column)
    label_type = arrow_schema.field(schema.label_column).type
    if not (_numeric(pa, label_type) or pa.types.is_string(label_type) or pa.types.is_large_string(label_type)
            or pa.types.is_dictionary(label_type)):
        raise ConsumeRefused("schema_mismatch",
                             f"label column {schema.label_column!r} has type {label_type}; class names or indices "
                             "are expected", field=schema.label_column)
    if schema.modality == "tabular":
        missing = [name for name in (schema.features or ()) if name not in names]
        if missing:
            raise ConsumeRefused("schema_mismatch",
                                 f"{len(missing)} declared feature column(s) are missing: {missing[:8]}",
                                 field="features")
        wrong = [name for name in (schema.features or ()) if not _numeric(pa, arrow_schema.field(name).type)]
        if wrong:
            raise ConsumeRefused("schema_mismatch",
                                 f"{len(wrong)} declared feature column(s) are not numeric: {wrong[:8]}",
                                 field="features")
    else:
        if schema.image_column not in names:
            raise ConsumeRefused("schema_mismatch", f"image column {schema.image_column!r} is not in the Parquet schema",
                                 field=schema.image_column)
        image_type = arrow_schema.field(schema.image_column).type
        if not (pa.types.is_binary(image_type) or pa.types.is_large_binary(image_type)
                or pa.types.is_fixed_size_binary(image_type) or pa.types.is_list(image_type)
                or pa.types.is_large_list(image_type) or pa.types.is_fixed_size_list(image_type)):
            raise ConsumeRefused("schema_mismatch",
                                 f"image column {schema.image_column!r} has type {image_type}; raw bytes or a list "
                                 "of numbers per row are expected", field=schema.image_column)
    return [{"name": str(field.name), "type": str(field.type)} for field in arrow_schema]


def _image_rows(pa: Any, column: Any, schema: DeclaredSchema, offset: int) -> Any:
    """Decode one batch of the image column into ``(n, C, H, W)`` float32; every row must fit the declaration."""
    import numpy as np

    assert schema.input_shape is not None and schema.dtype is not None
    shape = tuple(schema.input_shape)
    count = int(np.prod(shape))
    dtype = np.dtype(schema.dtype)
    values = column.to_pylist()
    out = np.empty((len(values), *shape), dtype=np.float32)
    for i, value in enumerate(values):
        row = offset + i
        if value is None:
            raise ConsumeRefused("schema_mismatch", f"row {row} has a null image", field=schema.image_column)
        if isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            if len(raw) != count * dtype.itemsize:
                raise ConsumeRefused(
                    "schema_mismatch",
                    f"row {row} holds {len(raw)} bytes; {count * dtype.itemsize} are needed for {schema.dtype} at "
                    f"input_shape {list(shape)}",
                    field=schema.image_column,
                )
            array = np.frombuffer(raw, dtype=dtype)
        else:
            try:
                array = np.asarray(value, dtype=np.float64)
            except (TypeError, ValueError) as exc:
                raise ConsumeRefused("schema_mismatch", f"row {row} image is not numeric: {type(exc).__name__}",
                                     field=schema.image_column) from None
            if array.size != count:
                raise ConsumeRefused(
                    "schema_mismatch", f"row {row} holds {array.size} values; {count} are needed for input_shape "
                    f"{list(shape)}", field=schema.image_column,
                )
        out[i] = array.reshape(shape).astype(np.float32)
    return out


def load_consumed_slice(
    path: Path, schema: DeclaredSchema, *, max_rows: int = DEFAULT_MAX_ROWS,
) -> ConsumedArrays:
    """Read a validated (or to-be-validated) Parquet slice into arrays under the declared schema.

    Raises :class:`ConsumeRefused` for every declaration the file does not
    honour. Reads row groups in batches so a wide slice never doubles in memory.
    """
    import numpy as np

    pa, pq = _pyarrow()
    try:
        parquet = pq.ParquetFile(str(path))
    except Exception as exc:  # noqa: BLE001 - the decoder's own errors are the refusal evidence
        raise ConsumeRefused("parse_failed", f"Parquet metadata is unreadable: {type(exc).__name__}: {exc}"[:500],
                             field="file") from None
    n_rows = int(parquet.metadata.num_rows)
    if n_rows <= 0:
        raise ConsumeRefused("schema_mismatch", "the Parquet file holds no rows", field="file")
    if n_rows > max_rows:
        raise ConsumeRefused("dataset_too_large", f"{n_rows} rows exceed the {max_rows} row cap", field="file")
    columns = _check_columns(pa, parquet.schema_arrow, schema)
    wanted = [schema.label_column] + (list(schema.features) if schema.modality == "tabular" and schema.features
                                      else [schema.image_column])
    xs: list[Any] = []
    ys: list[Any] = []
    offset = 0
    for batch in parquet.iter_batches(batch_size=_BATCH_ROWS, columns=wanted):
        labels = batch.column(schema.label_column)
        if pa.types.is_dictionary(labels.type):
            labels = labels.dictionary_decode()
        ys.append(_label_indices(labels.to_pylist(), schema))
        if schema.modality == "tabular":
            assert schema.features is not None
            stacked = np.column_stack([
                np.asarray(batch.column(name).to_numpy(zero_copy_only=False), dtype=np.float64)
                for name in schema.features
            ]) if batch.num_rows else np.empty((0, len(schema.features)))
            if not np.all(np.isfinite(stacked)):
                raise ConsumeRefused("schema_mismatch", f"non-finite feature values in rows {offset}..{offset + batch.num_rows}",
                                     field="features")
            xs.append(stacked.astype(np.float32))
        else:
            xs.append(_image_rows(pa, batch.column(schema.image_column), schema, offset))
        offset += batch.num_rows
    x = np.concatenate(xs, axis=0) if xs else np.empty((0,))
    y = np.concatenate(ys, axis=0) if ys else np.empty((0,), dtype=np.int64)
    if x.shape[0] != n_rows or y.shape[0] != n_rows:
        raise ConsumeRefused("parse_failed", f"read {x.shape[0]} rows, metadata says {n_rows}", field="file")
    observed = (float(np.min(x)), float(np.max(x))) if x.size else (0.0, 0.0)
    if schema.modality == "image" and schema.value_range is not None:
        lo, hi = schema.value_range
        if observed[0] < lo or observed[1] > hi:
            raise ConsumeRefused(
                "schema_mismatch",
                f"image values span [{observed[0]:.6g}, {observed[1]:.6g}], outside the declared value_range "
                f"[{lo:.6g}, {hi:.6g}]", field="value_range",
            )
    if schema.modality == "tabular" and schema.feature_ranges and schema.features:
        for j, name in enumerate(schema.features):
            bounds = schema.feature_ranges.get(name)
            if bounds is None:
                continue
            col_min, col_max = float(np.min(x[:, j])), float(np.max(x[:, j]))
            if col_min < bounds[0] or col_max > bounds[1]:
                raise ConsumeRefused(
                    "schema_mismatch",
                    f"feature {name!r} spans [{col_min:.6g}, {col_max:.6g}], outside its declared range "
                    f"[{bounds[0]:.6g}, {bounds[1]:.6g}]", field="features",
                )
    return ConsumedArrays(x=x, y=y, class_names=tuple(schema.class_names), columns=columns, value_range=observed)


# --------------------------------------------------------------------------- the parse report


def parse_consumed_slice(request: dict[str, Any], work_dir: Path) -> dict[str, Any]:
    """Verify the request's files against the declaration and return the report (INTEROP-15)."""
    import numpy as np

    dataset_id = str(request.get("dataset_id") or "")
    schema = DeclaredSchema.from_mapping(dict(request.get("schema") or {}))
    files = request.get("files")
    if not isinstance(files, list) or not files:
        raise ConsumeRefused("unsupported_dataset_format", "the request names no files", field="file")
    max_rows = int(request.get("max_rows") or DEFAULT_MAX_ROWS)
    input_root = (work_dir / "input").resolve()

    digests: dict[str, str] = {}
    parquet_paths: list[Path] = []
    manifest_path: Path | None = None
    sizes: dict[str, int] = {}
    for item in files:
        name = str(item.get("name") or "")
        path = (input_root / name).resolve()
        if input_root != path.parent or not path.is_file():
            raise ConsumeRefused("artifact_digest_mismatch", f"file {name!r} was not materialised", field="file")
        actual = sha256_file(path)
        expected = str(item.get("sha256") or "").strip().lower()
        if expected and actual != expected:
            raise ConsumeRefused(
                "artifact_digest_mismatch",
                f"file {name!r} has sha256 {actual[:16]}..., admission recorded {expected[:16]}...", field="file",
            )
        digests[name] = actual
        sizes[name] = path.stat().st_size
        if item.get("role") == "manifest":
            manifest_path = path
        else:
            parquet_paths.append(path)
    if not parquet_paths:
        raise ConsumeRefused("unsupported_dataset_format", "no Parquet part to parse", field="file")

    manifest_sha: str | None = None
    declared_digests: dict[str, str] = {}
    if manifest_path is not None:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConsumeRefused("unsupported_dataset_format", f"the manifest is not JSON: {type(exc).__name__}",
                                 field="manifest") from None
        if not isinstance(manifest, dict):
            raise ConsumeRefused("unsupported_dataset_format", "the manifest is not an object", field="manifest")
        manifest_sha = digests[manifest_path.name]
        declared_digests = check_manifest_against_files(
            manifest, {name: digest for name, digest in digests.items() if name != manifest_path.name},
        )

    if len(parquet_paths) > 1:
        raise ConsumeRefused(
            "unsupported_dataset_format",
            f"{len(parquet_paths)} Parquet parts; a consumed slice is one Parquet file in this wave",
            field="file",
        )
    primary = parquet_paths[0]
    arrays = load_consumed_slice(primary, schema, max_rows=max_rows)
    counts = np.bincount(arrays.y, minlength=schema.n_classes)
    per_class = {name: int(counts[i]) for i, name in enumerate(schema.class_names)}
    _pa, pq = _pyarrow()
    metadata = pq.ParquetFile(str(primary)).metadata
    import numpy
    import pyarrow

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "dataset_id": dataset_id,
        "modality": schema.modality,
        "n_rows": int(arrays.y.shape[0]),
        "n_classes": schema.n_classes,
        "class_names": list(schema.class_names),
        "per_class": per_class,
        "empty_classes": [name for name, n in per_class.items() if n == 0],
        "label_column": schema.label_column,
        "columns": arrays.columns,
        "features": list(schema.features) if schema.features else None,
        "input_shape": list(schema.input_shape) if schema.input_shape else None,
        "dtype": schema.dtype,
        "x_shape": [int(v) for v in arrays.x.shape],
        "value_range_declared": list(schema.value_range) if schema.value_range else None,
        "value_range_observed": [arrays.value_range[0], arrays.value_range[1]],
        "parquet": {
            "name": primary.name, "sha256": digests[primary.name], "size_bytes": sizes[primary.name],
            "num_row_groups": int(metadata.num_row_groups), "created_by": str(metadata.created_by or ""),
        },
        "manifest_sha256": manifest_sha,
        "manifest_declared_sha256s": declared_digests,
        "revision": manifest_sha or digests[primary.name],
        "digests": digests,
        "library_versions": {"pyarrow": pyarrow.__version__, "numpy": numpy.__version__},
    }


# --------------------------------------------------------------------------- envelope and entry point


def _write_envelope(work_dir: Path, envelope: dict[str, Any]) -> None:
    data = json.dumps(envelope)
    if len(data.encode("utf-8")) > ENVELOPE_MAX_BYTES:
        envelope = {"ok": False, "error_class": "EnvelopeInvalid", "code": "envelope_invalid",
                    "error": f"parse envelope exceeds {ENVELOPE_MAX_BYTES} bytes"}
        data = json.dumps(envelope)
    tmp = work_dir / "result.json.tmp"
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, work_dir / "result.json")


def run_request(request: dict[str, Any], work_dir: Path) -> dict[str, Any]:
    """Execute one parse request and return the envelope that was written (refusals as data, never stderr)."""
    try:
        report = parse_consumed_slice(request, work_dir)
    except ConsumeRefused as exc:
        envelope: dict[str, Any] = {"ok": False, "error_class": "ConsumeRefused", "code": exc.code,
                                    "error": str(exc)[:4000]}
        if exc.field:
            envelope["field"] = exc.field
    except Exception as exc:  # noqa: BLE001 - a decoder crash is a refusal of the input, reported as data
        envelope = {"ok": False, "error_class": type(exc).__name__, "code": "parse_failed",
                    "error": (str(exc) or type(exc).__name__)[:4000]}
    else:
        envelope = {"ok": True, "result": {"report": report}}
    _write_envelope(work_dir, envelope)
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser(prog="redsim.ml.interop.consume")
    parser.add_argument("--request", required=True)
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()
    work_dir = Path(args.work_dir).resolve()
    try:
        request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"consume request unreadable: {exc}", file=sys.stderr)
        return EXIT_BAD_REQUEST
    if not isinstance(request, dict) or request.get("mode") != MODE:
        print(f"consume request must be an object with mode {MODE!r}", file=sys.stderr)
        return EXIT_BAD_REQUEST
    # The parent hands the child a credential-free environment; scrub the gateway names again in-process
    # so a widened allowlist can never make this child an LLM caller (parity with sandbox_worker).
    for key in [k for k in os.environ if k.startswith("PYTHIA_")]:
        del os.environ[key]
    run_request(request, work_dir)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the worker task
    raise SystemExit(main())


__all__ = [
    "ENVELOPE_MAX_BYTES",
    "EXIT_BAD_REQUEST",
    "MODE",
    "REPORT_SCHEMA_VERSION",
    "ConsumeRefused",
    "ConsumedArrays",
    "check_manifest_against_files",
    "load_consumed_slice",
    "parse_consumed_slice",
    "run_request",
    "sha256_file",
]
