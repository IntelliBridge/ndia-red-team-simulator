"""Black-box endpoint contract ``endpoint-v1`` (register ENDPOINT-02) and the registration body.

Pure Python: pydantic and the standard library only. The API process validates
``POST /v1/models`` (``source="endpoint"``) bodies with :class:`EndpointRegistration`,
and the worker-parent ``PredictBroker`` (ENDPOINT-05, wave B1) encodes requests and
validates responses with :func:`encode_request` / :func:`validate_response`. Neither
side may pull numpy, torch, ART, onnxruntime, shap or sklearn through this module
(``tests/test_api_process_has_no_ml.py``), so arrays are duck-typed: anything with a
``.tolist()`` is accepted on the way out and nested ``list[list[float]]`` come back;
the transport converts with ``np.asarray(rows, dtype=np.float32)``.

Contract ``endpoint-v1``
------------------------

Request — ``POST <url>``, ``Content-Type: application/json``::

    {"contract": "endpoint-v1",
     "input_format": "float32_nchw" | "tabular_features",
     "inputs": [[...], ...]}

* ``inputs`` has ``n`` rows (``1 <= n <= batch_rows <= 1024``); every row has the
  registered ``input_shape`` and every leaf is a finite number (booleans refused).
* ``float32_nchw`` (images): a row is a ``[C][H][W]`` nested list of floats in
  ``[0, 1]``. Preprocessing (resize, normalisation) is the endpoint's job; redsim
  applies no external normalisation (parity with spec 11.3.1).
* ``tabular_features``: a row is the declared feature vector, a flat list of floats.
* The credential is added by the broker per AuthProfile kind (``bearer`` ->
  ``Authorization: Bearer <secret>``; ``header`` -> ``<header_name>: <secret>``),
  never by this module, and never appears in a request body.

Response — ``200 application/json``::

    {"probabilities": [[p_1 .. p_k], ...], "model_id": "optional", "latency_ms": 12.5}

* ``probabilities`` has exactly ``n`` rows of ``n_classes`` finite values in
  ``[0, 1]`` each summing to 1 within :data:`ROW_SUM_TOLERANCE`.
* Alternatively ``{"logits": [[...]]}``: softmax is applied client-side and
  ``output_kind = "logits"`` is recorded on the run. Exactly one of the two keys.
* ``model_id`` and ``latency_ms`` are optional and recorded as provenance.
* Any other status, key, shape, non-finite value, ``NaN``/``Infinity`` token or a
  body over :data:`MAX_RESPONSE_BYTES` is an :class:`EndpointSchemaMismatch` naming
  the offending field. Nothing is coerced.

Versioning: :data:`CONTRACT_VERSION` is the only accepted value of ``contract`` /
``contract_version``. A later contract (for example an ``npz_base64`` encoding for
large image batches) gets a new string and a new validator; ``endpoint-v1`` never
changes shape.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from redsim.ml.endpoint_egress import ParsedEndpoint, check_registration_url
from redsim.ml.errors import MLError

CONTRACT_VERSION: Final = "endpoint-v1"
ContractVersion = Literal["endpoint-v1"]
InputFormat = Literal["float32_nchw", "tabular_features"]
EndpointModality = Literal["image", "tabular"]
OutputKind = Literal["probabilities", "logits"]

#: The one input format per modality; ``EndpointRegistration.input_format`` is derived from it.
MODALITY_INPUT_FORMAT: Final[dict[str, str]] = {"image": "float32_nchw", "tabular": "tabular_features"}
#: Dimensions of one row (without the batch axis) per input format: images are ``[C][H][W]``.
INPUT_FORMAT_RANK: Final[dict[str, int]] = {"float32_nchw": 3, "tabular_features": 1}

MAX_BATCH_ROWS: Final = 1024
#: List-encoded images are large (a 3x128x128 row is ~600 KB of JSON), so the default batch stays small.
DEFAULT_BATCH_ROWS: Final = 32
MAX_TIMEOUT_S: Final = 60.0
DEFAULT_TIMEOUT_S: Final = 30.0
MAX_RESPONSE_BYTES: Final = 16 * 1024 * 1024
MAX_URL_LENGTH: Final = 2048
#: Elements per row; guards the JSON encoder against an absurd declared shape.
MAX_ROW_ELEMENTS: Final = 1 << 24
ROW_SUM_TOLERANCE: Final = 1e-3
PROBABILITY_TOLERANCE: Final = 1e-6


class EndpointSchemaMismatch(MLError):
    """The endpoint's response violates ``endpoint-v1``. Never coerced; ``field`` names the offender.

    Spec 10.6 failure class: an infrastructure state, never a model outcome. The
    endpoint-target track (ENDPOINT-05) may re-home this class in ``redsim.ml.errors``;
    the stable ``code`` is what services and ``Job.error`` record.
    """

    code = "endpoint_schema_mismatch"

    def __init__(self, message: str, *, field: str) -> None:
        super().__init__(f"{field}: {message}")
        self.field = field
        self.reason = message


# ---------------------------------------------------------------------------
# Registration body (ENDPOINT-01 / ENDPOINT-31 fields, validated in the API process)
# ---------------------------------------------------------------------------


def _non_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    return value


class EndpointRegistration(BaseModel):
    """``POST /v1/models`` body for ``source="endpoint"``. Static, pure-Python checks only.

    URL *policy* (scheme, userinfo, query, allowlist, private addresses) lives in
    ``redsim.ml.endpoint_egress``; call :meth:`check_url` with ``config.target_allowlist``
    after validation. This model only refuses URLs that are structurally not URLs.
    """

    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)
    auth_profile_id: str = Field(min_length=1, max_length=200)
    modality: EndpointModality
    dataset_id: str = Field(min_length=1, max_length=200)
    dataset_split: str = Field(default="test", min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=200)
    license_statement: str = Field(min_length=1, max_length=4000)
    #: D3 bound: "this endpoint is a non-operational evaluation instance; no mission system is connected".
    evaluation_instance_attestation: Literal[True]
    input_shape: list[int] = Field(min_length=1, max_length=4)
    class_names: list[str] | None = None
    n_classes: int | None = Field(default=None, ge=2)
    batch_rows: int = Field(default=DEFAULT_BATCH_ROWS, ge=1, le=MAX_BATCH_ROWS)
    timeout_s: float = Field(default=DEFAULT_TIMEOUT_S, gt=0, le=MAX_TIMEOUT_S)
    #: Derived from ``modality`` when omitted; refused when it disagrees.
    input_format: InputFormat | None = None
    contract_version: ContractVersion = CONTRACT_VERSION

    @field_validator("url")
    @classmethod
    def _url_shape(cls, value: str) -> str:
        if not value.isascii() or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise ValueError("url must not contain whitespace, control or non-ASCII characters")
        if "://" not in value:
            raise ValueError("url must be absolute (scheme://host/path)")
        return value

    @field_validator("auth_profile_id", "dataset_id", "dataset_split", "name", "license_statement")
    @classmethod
    def _blank(cls, value: str) -> str:
        return _non_blank(value)

    @field_validator("input_shape")
    @classmethod
    def _shape(cls, value: list[int]) -> list[int]:
        if any(d < 1 for d in value):
            raise ValueError("every input_shape dimension must be >= 1")
        if math.prod(value) > MAX_ROW_ELEMENTS:
            raise ValueError(f"input_shape has more than {MAX_ROW_ELEMENTS} elements per row")
        return value

    @field_validator("class_names")
    @classmethod
    def _names(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        if len(value) < 2:
            raise ValueError("class_names needs at least two classes")
        if any(not name.strip() for name in value):
            raise ValueError("class_names must not contain blank names")
        if len(set(value)) != len(value):
            raise ValueError("class_names must be unique")
        return value

    @model_validator(mode="after")
    def _consistency(self) -> EndpointRegistration:
        if self.class_names is None and self.n_classes is None:
            raise ValueError("one of class_names or n_classes is required")
        if self.class_names is not None and self.n_classes is not None and len(self.class_names) != self.n_classes:
            raise ValueError("class_names length must equal n_classes")
        expected_format = MODALITY_INPUT_FORMAT[self.modality]
        if self.input_format is None:
            self.input_format = expected_format  # type: ignore[assignment]
        elif self.input_format != expected_format:
            raise ValueError(f"input_format {self.input_format!r} does not match modality {self.modality!r}"
                             f" (expected {expected_format!r})")
        rank = INPUT_FORMAT_RANK[expected_format]
        if len(self.input_shape) != rank:
            what = "[C, H, W]" if rank == 3 else "[n_features]"
            raise ValueError(f"input_shape for modality {self.modality!r} must have {rank} dimensions {what}")
        return self

    @property
    def resolved_n_classes(self) -> int:
        if self.n_classes is not None:
            return self.n_classes
        assert self.class_names is not None
        return len(self.class_names)

    @property
    def resolved_input_format(self) -> str:
        return self.input_format or MODALITY_INPUT_FORMAT[self.modality]

    def check_url(self, allowlist: Sequence[str]) -> ParsedEndpoint:
        """Run the egress policy's static check (ENDPOINT-07 a-c) against ``config.target_allowlist``."""
        return check_registration_url(self.url, allowlist)

    def descriptor(self) -> dict[str, Any]:
        """The registration with derived fields filled in; the manifest ``sha256`` is a digest of it."""
        data = self.model_dump(mode="json")
        data["input_format"] = self.resolved_input_format
        data["n_classes"] = self.resolved_n_classes
        return data

    def descriptor_sha256(self) -> str:
        canonical = json.dumps(self.descriptor(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_leaves(seq: Sequence[Any], path: str, *, unit_interval: bool) -> None:
    for i, value in enumerate(seq):
        if not _is_number(value):
            raise ValueError(f"{path}[{i}] must be a number, got {type(value).__name__}")
    if not all(map(math.isfinite, seq)):
        raise ValueError(f"{path} contains a non-finite value")
    if unit_interval and (min(seq) < 0.0 or max(seq) > 1.0):
        raise ValueError(f"{path} has a value outside [0, 1]")


def _row_shape(node: Any, path: str, *, unit_interval: bool) -> tuple[int, ...]:
    """Shape of one nested-list row; refuses ragged, empty, boolean and non-finite content."""
    if not isinstance(node, (list, tuple)):
        raise ValueError(f"{path} must be a nested list of numbers, got {type(node).__name__}")
    if not node:
        raise ValueError(f"{path} has an empty dimension")
    first = node[0]
    if not isinstance(first, (list, tuple)):
        _check_leaves(node, path, unit_interval=unit_interval)
        return (len(node),)
    inner = _row_shape(first, f"{path}[0]", unit_interval=unit_interval)
    for i in range(1, len(node)):
        if _row_shape(node[i], f"{path}[{i}]", unit_interval=unit_interval) != inner:
            raise ValueError(f"{path} is ragged: {path}[{i}] differs in shape from {path}[0]")
    return (len(node), *inner)


class PredictRequest(BaseModel):
    """The ``endpoint-v1`` request body. Built by :func:`encode_request` on the worker side."""

    model_config = ConfigDict(extra="forbid")

    contract: ContractVersion = CONTRACT_VERSION
    input_format: InputFormat
    inputs: list[Any] = Field(min_length=1, max_length=MAX_BATCH_ROWS)

    _row_shape: tuple[int, ...] = PrivateAttr(default=())

    @model_validator(mode="after")
    def _rows(self) -> PredictRequest:
        rank = INPUT_FORMAT_RANK[self.input_format]
        unit = self.input_format == "float32_nchw"
        shape0: tuple[int, ...] | None = None
        for i, row in enumerate(self.inputs):
            shape = _row_shape(row, f"inputs[{i}]", unit_interval=unit)
            if len(shape) != rank:
                what = "[C][H][W]" if rank == 3 else "a flat feature vector"
                raise ValueError(f"inputs[{i}] has {len(shape)} dimensions; {self.input_format} rows are {what}")
            if shape0 is None:
                shape0 = shape
            elif shape != shape0:
                raise ValueError(f"inputs[{i}] has shape {list(shape)}, inputs[0] has shape {list(shape0)}")
        assert shape0 is not None
        self._row_shape = shape0
        return self

    @property
    def row_shape(self) -> tuple[int, ...]:
        """Shape of every row (``input_shape`` without the batch axis)."""
        return self._row_shape

    @property
    def n(self) -> int:
        return len(self.inputs)


def encode_request(x: Any, *, input_format: InputFormat, input_shape: Sequence[int] | None = None) -> dict[str, Any]:
    """Nested-list ``endpoint-v1`` request body for a batch ``x`` of shape ``[n, *input_shape]``.

    ``x`` is anything with a ``.tolist()`` (a numpy array; float32 leaves round-trip through
    JSON exactly) or already nested sequences. Violations raise ``ValueError`` (pydantic's
    ``ValidationError`` is one): a malformed request is the caller's bug, not a contract
    mismatch on the endpoint's side.
    """
    rows = x.tolist() if hasattr(x, "tolist") else x
    request = PredictRequest(input_format=input_format, inputs=rows)
    if input_shape is not None and request.row_shape != tuple(int(d) for d in input_shape):
        raise ValueError(f"batch rows have shape {list(request.row_shape)}, the registered input_shape is "
                         f"{[int(d) for d in input_shape]}")
    return {"contract": CONTRACT_VERSION, "input_format": request.input_format, "inputs": request.inputs}


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------


class PredictResponse(BaseModel):
    """The ``endpoint-v1`` response body. Strict: no extra keys, no string-to-number coercion."""

    model_config = ConfigDict(extra="forbid", strict=True)

    probabilities: list[list[float]] | None = None
    logits: list[list[float]] | None = None
    model_id: str | None = Field(default=None, max_length=200)
    latency_ms: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _exactly_one(self) -> PredictResponse:
        if (self.probabilities is None) == (self.logits is None):
            raise ValueError("exactly one of probabilities or logits is required")
        return self

    @property
    def output_kind(self) -> OutputKind:
        return "probabilities" if self.probabilities is not None else "logits"

    @property
    def matrix(self) -> list[list[float]]:
        rows = self.probabilities if self.probabilities is not None else self.logits
        assert rows is not None
        return rows


@dataclass(frozen=True)
class ValidatedPrediction:
    """A response that passed every ``endpoint-v1`` check: probabilities as ``[n][n_classes]`` floats."""

    probabilities: list[list[float]]
    output_kind: OutputKind
    n: int
    n_classes: int
    model_id: str | None = None
    latency_ms: float | None = None


def _softmax(row: Sequence[float]) -> list[float]:
    top = max(row)
    exps = [math.exp(v - top) for v in row]
    total = math.fsum(exps)
    return [v / total for v in exps]


def _first_error(exc: ValidationError) -> tuple[str, str]:
    errors = exc.errors()
    if not errors:
        return "body", "invalid response body"
    first = errors[0]
    loc = ".".join(str(part) for part in first.get("loc", ()) if not isinstance(part, int)) or "body"
    return loc, str(first.get("msg", "invalid"))


def parse_response(body: Any, *, n: int, n_classes: int, raw_size: int | None = None) -> ValidatedPrediction:
    """Validate a decoded JSON response for a request of ``n`` rows against ``n_classes``.

    ``raw_size`` is the byte length of the response body when the caller has it
    (:func:`validate_response_bytes` supplies it). Raises :class:`EndpointSchemaMismatch`.
    """
    if n < 1 or n_classes < 1:
        raise ValueError("n and n_classes must be >= 1")
    if raw_size is not None and raw_size > MAX_RESPONSE_BYTES:
        raise EndpointSchemaMismatch(f"response is {raw_size} bytes; the cap is {MAX_RESPONSE_BYTES}", field="body")
    if not isinstance(body, dict):
        raise EndpointSchemaMismatch(f"response body must be a JSON object, got {type(body).__name__}",
                                     field="body")
    try:
        parsed = PredictResponse.model_validate(body)
    except ValidationError as exc:
        field, message = _first_error(exc)
        raise EndpointSchemaMismatch(message, field=field) from None
    kind = parsed.output_kind
    matrix = parsed.matrix
    if len(matrix) != n:
        raise EndpointSchemaMismatch(f"expected {n} rows, got {len(matrix)}", field=kind)
    for i, row in enumerate(matrix):
        if len(row) != n_classes:
            raise EndpointSchemaMismatch(f"row {i} has {len(row)} values, n_classes is {n_classes}", field=kind)
        if not all(map(math.isfinite, row)):
            raise EndpointSchemaMismatch(f"row {i} contains a non-finite value", field=kind)
    if kind == "probabilities":
        for i, row in enumerate(matrix):
            if min(row) < -PROBABILITY_TOLERANCE or max(row) > 1.0 + PROBABILITY_TOLERANCE:
                raise EndpointSchemaMismatch(f"row {i} has a value outside [0, 1]", field=kind)
            total = math.fsum(row)
            if abs(total - 1.0) > ROW_SUM_TOLERANCE:
                raise EndpointSchemaMismatch(f"row {i} sums to {total:.6f}, not 1 within {ROW_SUM_TOLERANCE}",
                                             field=kind)
        probabilities = [[float(v) for v in row] for row in matrix]
    else:
        probabilities = [_softmax(row) for row in matrix]
    return ValidatedPrediction(probabilities=probabilities, output_kind=kind, n=n, n_classes=n_classes,
                               model_id=parsed.model_id, latency_ms=parsed.latency_ms)


def validate_response(body: Any, *, n: int, n_classes: int,
                      raw_size: int | None = None) -> tuple[list[list[float]], OutputKind]:
    """``(probabilities, output_kind)`` for a decoded response; see :func:`parse_response`."""
    result = parse_response(body, n=n, n_classes=n_classes, raw_size=raw_size)
    return result.probabilities, result.output_kind


def _refuse_constant(name: str) -> None:
    raise ValueError(f"non-finite JSON constant {name}")


def validate_response_bytes(raw: bytes, *, n: int, n_classes: int) -> ValidatedPrediction:
    """Size cap, UTF-8 and JSON decoding (``NaN``/``Infinity`` tokens refused), then :func:`parse_response`."""
    size = len(raw)
    if size > MAX_RESPONSE_BYTES:
        raise EndpointSchemaMismatch(f"response is {size} bytes; the cap is {MAX_RESPONSE_BYTES}", field="body")
    try:
        body = json.loads(raw.decode("utf-8"), parse_constant=_refuse_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise EndpointSchemaMismatch(f"response is not valid JSON: {exc}", field="body") from None
    return parse_response(body, n=n, n_classes=n_classes, raw_size=size)


def contract_summary() -> dict[str, Any]:
    """JSON-able description of ``endpoint-v1`` for ``/v1/ml/capabilities`` and the docs."""
    return {
        "contract_version": CONTRACT_VERSION,
        "request": {
            "method": "POST",
            "content_type": "application/json",
            "body": {"contract": CONTRACT_VERSION, "input_format": sorted(INPUT_FORMAT_RANK),
                     "inputs": "[n, *input_shape] nested lists of finite numbers; images in [0, 1] NCHW"},
            "auth": {"bearer": "Authorization: Bearer <secret>", "header": "<header_name>: <secret>"},
        },
        "response": {
            "status": 200,
            "content_type": "application/json",
            "body": {"probabilities": "[n, n_classes] finite values in [0, 1], rows summing to 1",
                     "logits": "alternative to probabilities; softmax applied client-side, output_kind recorded",
                     "model_id": "optional", "latency_ms": "optional"},
        },
        "limits": {"batch_rows_max": MAX_BATCH_ROWS, "batch_rows_default": DEFAULT_BATCH_ROWS,
                   "timeout_s_max": MAX_TIMEOUT_S, "timeout_s_default": DEFAULT_TIMEOUT_S,
                   "response_bytes_max": MAX_RESPONSE_BYTES, "row_sum_tolerance": ROW_SUM_TOLERANCE},
        "preprocessing": "the endpoint's job: redsim sends raw [0, 1] NCHW pixels or the declared feature vector",
        "violations": "any other status, key, shape or non-finite value is endpoint_schema_mismatch; nothing is coerced",
    }


__all__ = [
    "CONTRACT_VERSION", "DEFAULT_BATCH_ROWS", "DEFAULT_TIMEOUT_S", "INPUT_FORMAT_RANK", "MAX_BATCH_ROWS",
    "MAX_RESPONSE_BYTES", "MAX_TIMEOUT_S", "MODALITY_INPUT_FORMAT", "PROBABILITY_TOLERANCE",
    "ROW_SUM_TOLERANCE", "EndpointModality", "EndpointRegistration", "EndpointSchemaMismatch", "InputFormat",
    "OutputKind", "PredictRequest", "PredictResponse", "ValidatedPrediction", "contract_summary",
    "encode_request", "parse_response", "validate_response", "validate_response_bytes",
]
