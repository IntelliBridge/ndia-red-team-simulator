"""ENDPOINT-02: the ``endpoint-v1`` predict contract and the endpoint registration body.

Pure Python, no ``ml`` extra, no network: runs on the torch-less lane. The one numpy
round-trip test ``importorskip``s numpy inside the test.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from redsim.ml.errors import MLError
from redsim.ml.targets import endpoint_contract as ec

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]


def _registration(**over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "url": "https://models.example.mil/predict",
        "auth_profile_id": "ap-1",
        "modality": "image",
        "dataset_id": "leibnitz-lab/military_vehicles",
        "name": "vehicle classifier (eval instance)",
        "license_statement": "internal evaluation copy; owner: red team",
        "evaluation_instance_attestation": True,
        "input_shape": [3, 8, 8],
        "class_names": ["tank", "truck", "apc"],
    }
    body.update(over)
    return body


def _errors(exc_info: pytest.ExceptionInfo[ValidationError]) -> set[str]:
    return {".".join(str(p) for p in err["loc"]) for err in exc_info.value.errors()}


# --- constants -----------------------------------------------------------------

def test_contract_constants():
    assert ec.CONTRACT_VERSION == "endpoint-v1"
    assert ec.MAX_BATCH_ROWS == 1024
    assert ec.MAX_TIMEOUT_S == 60
    assert ec.MAX_RESPONSE_BYTES == 16 * 1024 * 1024
    assert ec.MODALITY_INPUT_FORMAT == {"image": "float32_nchw", "tabular": "tabular_features"}
    assert ec.INPUT_FORMAT_RANK == {"float32_nchw": 3, "tabular_features": 1}
    summary = ec.contract_summary()
    assert summary["contract_version"] == "endpoint-v1"
    assert summary["limits"]["batch_rows_max"] == 1024 and summary["limits"]["timeout_s_max"] == 60
    json.dumps(summary)  # JSON-able for /v1/ml/capabilities


def test_schema_mismatch_is_a_typed_ml_error_naming_the_field():
    exc = ec.EndpointSchemaMismatch("row 0 sums to 0.9", field="probabilities")
    assert isinstance(exc, MLError)
    assert exc.code == "endpoint_schema_mismatch"
    assert exc.field == "probabilities" and exc.reason == "row 0 sums to 0.9"
    assert str(exc) == "probabilities: row 0 sums to 0.9"


# --- EndpointRegistration --------------------------------------------------------

def test_registration_image_happy_path_derives_format_and_classes():
    reg = ec.EndpointRegistration(**_registration())
    assert reg.input_format == "float32_nchw" and reg.resolved_input_format == "float32_nchw"
    assert reg.resolved_n_classes == 3 and reg.n_classes is None
    assert reg.batch_rows == ec.DEFAULT_BATCH_ROWS == 32
    assert reg.timeout_s == ec.DEFAULT_TIMEOUT_S == 30.0
    assert reg.dataset_split == "test"
    assert reg.contract_version == "endpoint-v1"
    assert reg.evaluation_instance_attestation is True


def test_registration_tabular_happy_path_with_n_classes_only():
    reg = ec.EndpointRegistration(**_registration(modality="tabular", input_shape=[12], class_names=None,
                                                  n_classes=2, batch_rows=1024, timeout_s=60))
    assert reg.resolved_input_format == "tabular_features"
    assert reg.resolved_n_classes == 2 and reg.class_names is None


def test_registration_explicit_matching_input_format_accepted():
    reg = ec.EndpointRegistration(**_registration(input_format="float32_nchw"))
    assert reg.input_format == "float32_nchw"


@pytest.mark.parametrize("over, field", [
    ({"evaluation_instance_attestation": False}, "evaluation_instance_attestation"),
    ({"evaluation_instance_attestation": "yes"}, "evaluation_instance_attestation"),
    ({"batch_rows": 1025}, "batch_rows"),
    ({"batch_rows": 0}, "batch_rows"),
    ({"timeout_s": 60.5}, "timeout_s"),
    ({"timeout_s": 0}, "timeout_s"),
    ({"modality": "text"}, "modality"),
    ({"contract_version": "endpoint-v2"}, "contract_version"),
    ({"url": "https://models.example.mil/pre dict"}, "url"),
    ({"url": "models.example.mil/predict"}, "url"),
    ({"url": "https://models.example.mil/é"}, "url"),
    ({"license_statement": "   "}, "license_statement"),
    ({"name": ""}, "name"),
    ({"auth_profile_id": " "}, "auth_profile_id"),
    ({"input_shape": []}, "input_shape"),
    ({"input_shape": [3, 0, 8]}, "input_shape"),
    ({"input_shape": [3, 5000, 5000]}, "input_shape"),
    ({"class_names": ["only"]}, "class_names"),
    ({"class_names": ["a", "a", "b"]}, "class_names"),
    ({"class_names": ["a", " ", "b"]}, "class_names"),
    ({"n_classes": 1, "class_names": None}, "n_classes"),
    ({"unexpected": 1}, "unexpected"),
])
def test_registration_field_refusals_name_the_field(over: dict[str, Any], field: str):
    with pytest.raises(ValidationError) as exc_info:
        ec.EndpointRegistration(**_registration(**over))
    assert field in _errors(exc_info), exc_info.value


def test_registration_attestation_is_required_not_defaulted():
    body = _registration()
    del body["evaluation_instance_attestation"]
    with pytest.raises(ValidationError) as exc_info:
        ec.EndpointRegistration(**body)
    assert "evaluation_instance_attestation" in _errors(exc_info)


@pytest.mark.parametrize("over, match", [
    ({"class_names": None}, "class_names or n_classes"),
    ({"n_classes": 4}, "class_names length must equal n_classes"),
    ({"input_format": "tabular_features"}, "does not match modality"),
    ({"input_shape": [8]}, "must have 3 dimensions"),
    ({"modality": "tabular", "input_shape": [3, 8, 8]}, "must have 1 dimensions"),
])
def test_registration_cross_field_refusals(over: dict[str, Any], match: str):
    with pytest.raises(ValidationError, match=match):
        ec.EndpointRegistration(**_registration(**over))


def test_descriptor_digest_is_deterministic_and_covers_derived_fields():
    a = ec.EndpointRegistration(**_registration())
    b = ec.EndpointRegistration(**_registration(input_format="float32_nchw", n_classes=3))
    assert a.descriptor() == b.descriptor()
    assert a.descriptor_sha256() == b.descriptor_sha256()
    assert len(a.descriptor_sha256()) == 64
    c = ec.EndpointRegistration(**_registration(url="https://models.example.mil/predict2"))
    assert c.descriptor_sha256() != a.descriptor_sha256()
    d = a.descriptor()
    assert d["input_format"] == "float32_nchw" and d["n_classes"] == 3 and d["contract_version"] == "endpoint-v1"


def test_registration_check_url_runs_the_egress_policy():
    from redsim.ml import endpoint_egress as eg

    reg = ec.EndpointRegistration(**_registration())
    parsed = reg.check_url(["models.example.mil"])
    assert parsed.host == "models.example.mil" and parsed.plaintext is False
    with pytest.raises(eg.EndpointNotAllowlisted):
        reg.check_url(["127.0.0.1"])
    loop = ec.EndpointRegistration(**_registration(url="http://127.0.0.1:8081/predict"))
    assert loop.check_url(["127.0.0.1"]).plaintext_loopback is True


# --- PredictRequest / encode_request --------------------------------------------

def _image_rows(n: int, c: int = 3, h: int = 2, w: int = 2) -> list[Any]:
    return [[[[((i + ch + y + x) % 7) / 7 for x in range(w)] for y in range(h)] for ch in range(c)] for i in range(n)]


def test_encode_request_nested_lists_image():
    body = ec.encode_request(_image_rows(2), input_format="float32_nchw", input_shape=[3, 2, 2])
    assert body["contract"] == "endpoint-v1"
    assert body["input_format"] == "float32_nchw"
    assert len(body["inputs"]) == 2
    # JSON-serialisable as is.
    assert json.loads(json.dumps(body)) == body
    # And it is itself a valid PredictRequest.
    request = ec.PredictRequest.model_validate(body)
    assert request.row_shape == (3, 2, 2) and request.n == 2


def test_encode_request_tabular_rows():
    body = ec.encode_request([[0.1, 2.5, -3.0], [4.0, 5.0, 6.0]], input_format="tabular_features", input_shape=[3])
    assert body["input_format"] == "tabular_features"
    assert ec.PredictRequest.model_validate(body).row_shape == (3,)


def test_encode_request_round_trips_float32_array_exactly():
    np = pytest.importorskip("numpy")
    rng = np.random.default_rng(0)
    x = rng.random((2, 3, 8, 8), dtype=np.float32)
    body = ec.encode_request(x, input_format="float32_nchw", input_shape=(3, 8, 8))
    back = np.asarray(json.loads(json.dumps(body))["inputs"], dtype=np.float32)
    assert back.shape == (2, 3, 8, 8)
    assert np.max(np.abs(back - x)) < 1e-7
    assert np.array_equal(back, x)  # float32 -> Python float -> JSON -> float32 is exact


@pytest.mark.parametrize("rows, input_format, match", [
    ([], "float32_nchw", "at least 1"),
    ([[0.1, 0.2]], "float32_nchw", "3 dimensions|1 dimensions"),
    ([[[[0.1, 0.2]]]], "tabular_features", "dimensions"),
    ([[[[0.1, 1.5]]]], "float32_nchw", "outside \\[0, 1\\]"),
    ([[[[0.1, -0.1]]]], "float32_nchw", "outside \\[0, 1\\]"),
    ([[[[0.1, float("nan")]]]], "float32_nchw", "non-finite"),
    ([[0.1, float("inf")]], "tabular_features", "non-finite"),
    ([[0.1, True]], "tabular_features", "must be a number"),
    ([[0.1, "0.2"]], "tabular_features", "must be a number"),
    ([[0.1, 0.2], [0.3]], "tabular_features", "shape"),
    ([[[[0.1, 0.2]], [[0.3]]]], "float32_nchw", "ragged"),
    ([[[[]]]], "float32_nchw", "empty dimension"),
    ([0.5], "tabular_features", "nested list"),
])
def test_predict_request_refusals(rows: Any, input_format: str, match: str):
    with pytest.raises(ValueError, match=match):
        ec.encode_request(rows, input_format=input_format)  # type: ignore[arg-type]


def test_encode_request_refuses_a_shape_that_disagrees_with_the_registration():
    with pytest.raises(ValueError, match="registered input_shape"):
        ec.encode_request(_image_rows(1), input_format="float32_nchw", input_shape=[3, 8, 8])


def test_predict_request_batch_cap_and_contract_literal():
    with pytest.raises(ValidationError):
        ec.PredictRequest(input_format="tabular_features", inputs=[[0.0]] * (ec.MAX_BATCH_ROWS + 1))
    assert ec.PredictRequest(input_format="tabular_features", inputs=[[0.0]] * ec.MAX_BATCH_ROWS).n == 1024
    with pytest.raises(ValidationError):
        ec.PredictRequest.model_validate({"contract": "redsim-predict-proba/1", "input_format": "tabular_features",
                                          "inputs": [[0.0]]})
    with pytest.raises(ValidationError):
        ec.PredictRequest.model_validate({"input_format": "tabular_features", "inputs": [[0.0]], "encoding": "list"})


# --- validate_response ----------------------------------------------------------

P3 = [[0.2, 0.3, 0.5], [0.6, 0.3, 0.1], [0.1, 0.1, 0.8]]


def test_validate_response_accepts_probability_matrix():
    probabilities, kind = ec.validate_response({"probabilities": P3}, n=3, n_classes=3)
    assert kind == "probabilities"
    assert probabilities == P3
    assert all(isinstance(v, float) for row in probabilities for v in row)


def test_validate_response_applies_softmax_to_logits_and_records_kind():
    probabilities, kind = ec.validate_response({"logits": [[1.0, 2.0, 3.0], [1000.0, 0.0, -1000.0]]}, n=2, n_classes=3)
    assert kind == "logits"
    for row in probabilities:
        assert math.isclose(sum(row), 1.0, abs_tol=1e-9)
        assert all(0.0 <= v <= 1.0 for v in row)
    assert probabilities[0][2] > probabilities[0][1] > probabilities[0][0]
    assert probabilities[1][0] == pytest.approx(1.0)  # no overflow on large logits


def test_validate_response_tolerances():
    ok = [[0.3334, 0.3333, 0.3333]]
    assert ec.validate_response({"probabilities": ok}, n=1, n_classes=3)[1] == "probabilities"
    assert ec.validate_response({"probabilities": [[1, 0]]}, n=1, n_classes=2)[0] == [[1.0, 0.0]]  # ints are numbers


def test_parse_response_keeps_provenance_fields():
    result = ec.parse_response({"probabilities": [[0.5, 0.5]], "model_id": "resnet18-eval", "latency_ms": 12},
                               n=1, n_classes=2)
    assert isinstance(result, ec.ValidatedPrediction)
    assert result.model_id == "resnet18-eval" and result.latency_ms == 12.0
    assert result.output_kind == "probabilities" and result.n == 1 and result.n_classes == 2


@pytest.mark.parametrize("body, n, k, field, match", [
    ({"probabilities": P3[:2]}, 3, 3, "probabilities", "expected 3 rows, got 2"),
    ({"probabilities": P3 + [P3[0]]}, 3, 3, "probabilities", "expected 3 rows, got 4"),
    ({"probabilities": [[0.5, 0.5]]}, 1, 3, "probabilities", "has 2 values, n_classes is 3"),
    ({"logits": [[0.5, 0.5]]}, 1, 3, "logits", "has 2 values, n_classes is 3"),
    ({"probabilities": [[float("nan"), 0.5, 0.5]]}, 1, 3, "probabilities", "non-finite"),
    ({"probabilities": [[float("inf"), 0.0, 0.0]]}, 1, 3, "probabilities", "non-finite"),
    ({"logits": [[float("inf"), 0.0, 0.0]]}, 1, 3, "logits", "non-finite"),
    ({"probabilities": [[0.2, 0.3, 0.4]]}, 1, 3, "probabilities", "sums to 0.900000"),
    ({"probabilities": [[0.5, 0.6, 0.0]]}, 1, 3, "probabilities", "sums to 1.100000"),
    ({"probabilities": [[1.2, -0.2, 0.0]]}, 1, 3, "probabilities", "outside \\[0, 1\\]"),
    ({"probabilities": [["0.5", "0.5"]]}, 1, 2, "probabilities", "valid number"),
    ({"probabilities": [[True, False]]}, 1, 2, "probabilities", "valid number"),
    ({"probabilities": [0.5, 0.5]}, 1, 2, "probabilities", "valid list"),
    ({"probabilities": [[0.5, 0.5]], "extra": 1}, 1, 2, "extra", "Extra inputs"),
    ({"probabilities": [[0.5, 0.5]], "logits": [[0.0, 0.0]]}, 1, 2, "body", "exactly one"),
    ({"model_id": "m"}, 1, 2, "body", "exactly one"),
    ({}, 1, 2, "body", "exactly one"),
    ({"probabilities": [[0.5, 0.5]], "latency_ms": -1}, 1, 2, "latency_ms", "greater than or equal"),
    ({"probabilities": [[0.5, 0.5]], "model_id": 7}, 1, 2, "model_id", "valid string"),
    ([[0.5, 0.5]], 1, 2, "body", "JSON object, got list"),
    ("[[0.5, 0.5]]", 1, 2, "body", "JSON object, got str"),
    (None, 1, 2, "body", "JSON object, got NoneType"),
])
def test_validate_response_refusals_name_the_field(body: Any, n: int, k: int, field: str, match: str):
    with pytest.raises(ec.EndpointSchemaMismatch, match=match) as exc_info:
        ec.validate_response(body, n=n, n_classes=k)
    assert exc_info.value.field == field
    assert exc_info.value.code == "endpoint_schema_mismatch"


def test_validate_response_size_cap():
    with pytest.raises(ec.EndpointSchemaMismatch, match="cap is 16777216") as exc_info:
        ec.validate_response({"probabilities": [[0.5, 0.5]]}, n=1, n_classes=2, raw_size=ec.MAX_RESPONSE_BYTES + 1)
    assert exc_info.value.field == "body"
    # At the cap exactly is fine.
    ec.validate_response({"probabilities": [[0.5, 0.5]]}, n=1, n_classes=2, raw_size=ec.MAX_RESPONSE_BYTES)


def test_validate_response_bytes_decodes_and_refuses_bad_json_and_nan_tokens():
    result = ec.validate_response_bytes(b'{"probabilities": [[0.25, 0.75]], "latency_ms": 3}', n=1, n_classes=2)
    assert result.probabilities == [[0.25, 0.75]] and result.latency_ms == 3.0
    for raw, match in [
        (b"not json", "not valid JSON"),
        (b'{"probabilities": [[NaN, 0.5]]}', "non-finite JSON constant NaN"),
        (b'{"logits": [[Infinity, 0.5]]}', "non-finite JSON constant Infinity"),
        (b"\xff\xfe", "not valid JSON"),
        (b"[[0.5, 0.5]]", "JSON object, got list"),
    ]:
        with pytest.raises(ec.EndpointSchemaMismatch, match=match) as exc_info:
            ec.validate_response_bytes(raw, n=1, n_classes=2)
        assert exc_info.value.field == "body"
    big = b" " * (ec.MAX_RESPONSE_BYTES + 1)
    with pytest.raises(ec.EndpointSchemaMismatch, match="cap"):
        ec.validate_response_bytes(big, n=1, n_classes=2)


def test_validate_response_rejects_nonsense_expectations():
    with pytest.raises(ValueError):
        ec.validate_response({"probabilities": [[1.0]]}, n=0, n_classes=1)


# --- API-process safety ----------------------------------------------------------

_PROBE = r"""
import json, sys
blocked = %r
for name in blocked:
    sys.modules[name] = None
import redsim.ml.endpoint_egress as eg
import redsim.ml.targets.endpoint_contract as ec
direct = sorted(name for name in ("numpy", "torch", "art", "shap", "sklearn", "onnxruntime")
                if any(getattr(v, "__name__", "") == name for v in vars(ec).values())
                or any(getattr(v, "__name__", "") == name for v in vars(eg).values()))
print(json.dumps({
    "loaded": sorted(m for m in sys.modules if m.split(".")[0] in blocked and sys.modules[m] is not None),
    "direct": direct,
    "contract": ec.CONTRACT_VERSION,
}))
"""

_BLOCKED = ("torch", "torchvision", "art", "onnx", "onnxruntime", "shap", "sklearn", "xgboost")


def test_contract_and_egress_modules_import_without_the_ml_extra():
    """Both modules load in a fresh interpreter with every ML library blocked and import numpy nowhere."""
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    proc = subprocess.run([sys.executable, "-c", _PROBE % (_BLOCKED,)], capture_output=True, text=True,
                          cwd=ROOT, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["loaded"] == []
    assert out["direct"] == []
    assert out["contract"] == "endpoint-v1"
