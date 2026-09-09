"""Black-box inference endpoint as a ``Target`` (spec 9.1 rule 4, 9.2, 12.1, 13.2; ENDPOINT-04, -09).

An :class:`EndpointTarget` is a remote ``predict_proba`` plus the bundled evaluation slice it is
bound to at registration. It exposes no gradients: ``art_classifier()`` is an ART
``BlackBoxClassifier`` over ``predict_proba``, ``torch_model()`` is ``None`` (the image explainer
takes the PartitionExplainer path and the tabular explainer the KernelExplainer path) and
``surrogate_art_classifier()`` is ``None``, so white-box adapters are recorded ``not_run`` (spec 9.5).

Every prediction goes through a :class:`PredictTransport`. Inside the sandbox child that is
:class:`SocketPredictTransport`, a unix-socket client of the worker parent's ``PredictBroker``
(``redsim.ml.endpoint_broker``): the child holds no credential and no network configuration, and the
one socket path it receives is inside the parent's 0700 work directory. Offline tests and the CLI
may hand an ``HttpPredictTransport`` directly.

``load()`` is the connection probe (the endpoint variant of ``validate``): a seeded 8-row batch of
the bound slice is sent with purpose ``probe``, the response is checked against the contract, and
latency, HTTP status, output kind and the broker's response fingerprint (*remote model identity*,
never a weights digest) are recorded on the manifest. Query counts are kept per purpose and are
recorded on ``manifest()`` so the campaign's provenance carries them.
"""

from __future__ import annotations

import hashlib
import json
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

import numpy as np

from redsim.ml.datasets.sampling import (
    as_model_input,
    per_class_counts,
    stratified_indices,
    stratified_sample,
)
from redsim.ml.endpoint_broker import (
    EndpointLimits,
    PredictResult,
    error_from_frame,
    read_frame,
    write_frame,
)
from redsim.ml.errors import EndpointError, EndpointUnreachable, UnsupportedArtifact
from redsim.ml.schema import Domain, TargetInfo
from redsim.ml.targets.artifact import EvalData, _load_eval_data, model_manifest
from redsim.ml.targets.base import Sample
from redsim.ml.targets.endpoint_contract import CONTRACT_VERSION, EndpointSchemaMismatch

#: ``TargetInfo.metadata["access"]`` value the explainer caps key on (ENDPOINT-14).
ACCESS_LABEL = "black-box-endpoint"
#: Rows in the connection probe (ENDPOINT-09).
PROBE_ROWS = 8
DEFAULT_PURPOSE = "predict"

ENDPOINT_CAVEATS: tuple[str, ...] = (
    "The model is a remote inference endpoint: only its predict output was observed; no weights, "
    "architecture or training data were inspected.",
    "Endpoint responses may be nondeterministic across calls (batching, hardware, model updates); the "
    "response fingerprint identifies what the endpoint answered on this job, not the model's bytes.",
)
ENDPOINT_NONDETERMINISM = ("remote endpoint predictions (server-side batching, hardware and model updates are "
                           "outside this process; the response fingerprint is recorded)")


class PredictTransport(Protocol):
    """What :class:`EndpointTarget` needs from a transport (the socket client or the HTTP client)."""

    def predict(self, inputs: list[Any], *, purpose: str = ...) -> PredictResult: ...

    def stats_dict(self) -> dict[str, Any]: ...

    def close(self) -> None: ...


class SocketPredictTransport:
    """Unix-socket client of the worker parent's ``PredictBroker``; one connection per request.

    Runs inside the sandbox child. It knows one thing about the outside world: the socket path the
    parent wrote into the request JSON. No URL, no credential, no HTTP.
    """

    def __init__(self, socket_path: str | Path, *, connect_timeout_s: float = 10.0,
                 request_timeout_s: float | None = None) -> None:
        self.socket_path = Path(socket_path)
        self._connect_timeout = float(connect_timeout_s)
        self._request_timeout = request_timeout_s

    def _roundtrip(self, frame: dict[str, Any]) -> dict[str, Any]:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self._connect_timeout)
            try:
                sock.connect(str(self.socket_path))
            except OSError as exc:
                raise EndpointUnreachable(f"predict broker socket {self.socket_path} is not reachable: {exc}") from exc
            sock.settimeout(self._request_timeout)
            write_frame(sock, frame)
            reply = read_frame(sock)
        finally:
            sock.close()
        if not isinstance(reply, dict):
            raise EndpointSchemaMismatch("predict broker answered with a non-object frame", field="frame")
        if reply.get("ok") is True:
            return reply
        # The broker's typed frame names the class (``redsim.ml.errors`` resolves it by name) and carries the
        # structured detail (egress rule / host, contract field) the class is rebuilt from.
        raise error_from_frame(reply)

    def predict(self, inputs: list[Any], *, purpose: str = DEFAULT_PURPOSE) -> PredictResult:
        reply = self._roundtrip({"op": "predict", "inputs": inputs, "purpose": purpose})
        rows = reply.get("probabilities")
        if not isinstance(rows, list):
            raise EndpointSchemaMismatch("predict broker reply carries no probabilities", field="frame")
        return PredictResult(
            probabilities=rows, output_kind=str(reply.get("output_kind") or "probabilities"),
            http_status=int(reply.get("http_status") or 0), latency_ms=float(reply.get("latency_ms") or 0.0),
        )

    def stats_dict(self) -> dict[str, Any]:
        reply = self._roundtrip({"op": "stats"})
        stats = reply.get("stats")
        return dict(stats) if isinstance(stats, dict) else {}

    def close(self) -> None:
        return None


def descriptor_sha256(descriptor: dict[str, Any]) -> str:
    """``MLModelManifest.sha256`` of an endpoint: the digest of its canonical descriptor (ENDPOINT-03)."""
    canonical = json.dumps(descriptor, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class EndpointTarget:
    """A remote predict endpoint evaluated on a bundled dataset slice; gradients are never available."""

    def __init__(
        self,
        target_id: str,
        *,
        transport: PredictTransport,
        url_host: str,
        auth_profile_id: str,
        class_names: list[str],
        eval_data: EvalData,
        dataset_id: str,
        dataset_split: str | None = None,
        dataset_revision: str | None = None,
        input_shape: tuple[int, ...] | None = None,
        domain: Domain = "image",
        name: str | None = None,
        scheme: str = "https",
        batch_rows: int = 32,
        timeout_s: float = 30.0,
        features: list[dict[str, Any]] | None = None,
        license: str | None = None,
        limits: dict[str, Any] | None = None,
        contract_version: str = CONTRACT_VERSION,
        probe_rows: int = PROBE_ROWS,
    ) -> None:
        if not isinstance(dataset_id, str) or not dataset_id.strip():
            raise ValueError("EndpointTarget needs the dataset_id its evaluation split belongs to")
        if not class_names:
            raise ValueError("EndpointTarget needs the class list the endpoint's columns are declared against")
        self.id = target_id
        self._transport = transport
        self._url_host = url_host
        self._scheme = scheme
        self._auth_profile_id = auth_profile_id
        self._class_names = list(class_names)
        self._eval_source = eval_data
        self._dataset = {"dataset_id": dataset_id, "dataset_split": dataset_split,
                         "dataset_revision": dataset_revision, "license": license}
        self._declared_input_shape = tuple(int(d) for d in input_shape) if input_shape else None
        self._domain = domain
        self._name = name or f"Endpoint model {url_host}"
        self._batch_rows = max(1, int(batch_rows))
        self._timeout_s = float(timeout_s)
        self._features = [dict(f) for f in features] if features else None
        self._limits = dict(limits) if limits else None
        self._contract = contract_version
        self._probe_rows = max(1, int(probe_rows))
        self._x: np.ndarray | None = None
        self._y: np.ndarray | None = None
        self._indices: np.ndarray | None = None
        self._clf: Any = None
        self._manifest: dict[str, Any] | None = None
        self._endpoint_block: dict[str, Any] = {}
        self._probe: dict[str, Any] | None = None
        self._fingerprint: str | None = None
        self._output_kind: str | None = None
        self._purpose = DEFAULT_PURPOSE
        self._queries: dict[str, dict[str, int]] = {}
        self._lock = threading.Lock()

    # -- protocol -------------------------------------------------------------------------------

    def info(self) -> TargetInfo:
        meta: dict[str, Any] = {
            "source": "endpoint", "access": ACCESS_LABEL, "gradients": False, "format": "endpoint",
            "url_host": self._url_host, "scheme": self._scheme, "auth_profile_id": self._auth_profile_id,
            "contract": self._contract, "class_names": self._class_names, "n_classes": len(self._class_names),
            "loaded": self._x is not None, "batch_rows": self._batch_rows, "timeout_s": self._timeout_s,
            **{k: v for k, v in self._dataset.items() if v is not None},
        }
        if self._fingerprint is not None:
            meta["fingerprint_sha256"] = self._fingerprint
        return TargetInfo(id=self.id, name=self._name, domain=self._domain, status="available", metadata=meta)

    def load(self) -> None:
        """Bind the evaluation slice and run the connection probe; idempotent."""
        if self._x is not None:
            return
        x, y, idx = _load_eval_data(self._eval_source)
        if x.shape[0] != y.shape[0] or x.shape[0] == 0:
            raise UnsupportedArtifact("evaluation split is empty or x/y disagree on row count")
        if y.min() < 0 or y.max() >= len(self._class_names):
            raise UnsupportedArtifact("evaluation labels fall outside the declared class list")
        sample_shape = tuple(int(d) for d in x.shape[1:])
        if self._declared_input_shape and self._declared_input_shape != sample_shape:
            raise UnsupportedArtifact(f"shape_mismatch: declared input_shape {self._declared_input_shape} vs "
                                      f"evaluation data {sample_shape}")
        probe_idx = stratified_indices(y, min(self._probe_rows, int(x.shape[0])), 0)
        # The probe rows are scaled exactly as ``sample()`` scales campaign rows (uint8 -> [0, 1]); the
        # endpoint-v1 contract refuses anything outside the unit interval (ENDPOINT-30).
        result = self._call(as_model_input(x[probe_idx]), purpose="probe")
        if result.probabilities.shape[1] != len(self._class_names):
            raise EndpointSchemaMismatch(
                f"probe response has {result.probabilities.shape[1]} columns; the target declares "
                f"{len(self._class_names)} classes", field="probabilities",
            )
        stats = self._safe_stats()
        self._fingerprint = stats.get("fingerprint_sha256") if isinstance(stats.get("fingerprint_sha256"), str) else None
        self._output_kind = result.output_kind
        self._probe = {
            "http_status": result.http_status, "latency_ms": round(result.latency_ms, 3),
            "n_rows": int(probe_idx.shape[0]), "output_kind": result.output_kind,
            "tls_mode": stats.get("tls_mode"), "checked_at": datetime.now(UTC).isoformat(),
        }
        descriptor = {
            "url_host": self._url_host, "scheme": self._scheme, "auth_profile_id": self._auth_profile_id,
            "contract": self._contract, "modality": self._domain, "dataset_id": self._dataset["dataset_id"],
            "dataset_split": self._dataset["dataset_split"], "dataset_revision": self._dataset["dataset_revision"],
            "input_shape": list(sample_shape), "class_names": self._class_names,
        }
        # ``schema.EndpointSpec``: host[:port], the AuthProfile id (never the credential), the contract the probe
        # was validated against and the caps; ``MLModelManifest`` requires it whenever ``format`` is ``endpoint``.
        self._endpoint_block = {
            "url_host": self._url_host, "auth_profile_id": self._auth_profile_id, "contract_version": self._contract,
            "input_shape": list(sample_shape), "batch_rows": self._batch_rows, "timeout_s": self._timeout_s,
        }
        self._manifest = model_manifest(
            f"endpoint model {self._url_host}",
            name=self._name, modality=self._domain, format="endpoint", sha256=descriptor_sha256(descriptor),
            size_bytes=0, input_shape=list(sample_shape), n_classes=len(self._class_names),
            class_names=self._class_names, features=self._features, dataset_id=self._dataset["dataset_id"],
            dataset_revision=self._dataset["dataset_revision"], dataset_split=self._dataset["dataset_split"],
            status="available", gradients=False, bundled=False, license=self._dataset["license"],
            endpoint=dict(self._endpoint_block),
        )
        self._x, self._y, self._indices = x, y.astype(np.int64), idx

    def sample(self, n: int, seed: int) -> Sample:
        self.load()
        assert self._x is not None and self._y is not None
        return stratified_sample(self._x, self._y, n, seed, self._class_names, source_indices=self._indices)

    def _safe_stats(self) -> dict[str, Any]:
        """The transport's counters, or ``{}`` when the broker cannot answer (never fails a manifest)."""
        try:
            return self._transport.stats_dict()
        except (EndpointError, OSError):
            return {}

    def _count(self, purpose: str, rows: int) -> None:
        with self._lock:
            bucket = self._queries.setdefault(purpose, {"requests": 0, "rows": 0})
            bucket["requests"] += 1
            bucket["rows"] += rows

    def _call(self, batch: np.ndarray, *, purpose: str) -> _Rows:
        result = self._transport.predict(batch.tolist(), purpose=purpose)
        self._count(purpose, int(batch.shape[0]))
        proba = np.asarray(result.probabilities, dtype=np.float32)
        if proba.ndim != 2 or proba.shape[0] != batch.shape[0]:
            raise EndpointSchemaMismatch(
                f"response shape {tuple(proba.shape)} does not match {batch.shape[0]} requested rows",
                field="probabilities",
            )
        return _Rows(proba, result.output_kind, result.http_status, result.latency_ms)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        """Class probabilities from the endpoint, ``batch_rows`` rows per request, float32 in and out."""
        self.load()
        xin = np.ascontiguousarray(np.asarray(x), dtype=np.float32)
        if xin.shape[0] == 0:
            return np.empty((0, len(self._class_names)), dtype=np.float32)
        outs: list[np.ndarray] = []
        for start in range(0, xin.shape[0], self._batch_rows):
            result = self._call(xin[start:start + self._batch_rows], purpose=self._purpose)
            if result.probabilities.shape[1] != len(self._class_names):
                raise EndpointSchemaMismatch(
                    f"response has {result.probabilities.shape[1]} columns; the target declares "
                    f"{len(self._class_names)} classes", field="probabilities",
                )
            outs.append(result.probabilities)
        return np.concatenate(outs)

    def art_classifier(self) -> Any:
        """ART ``BlackBoxClassifier`` over ``predict_proba``: predicts, exposes no loss gradient."""
        self.load()
        if self._clf is None:
            from art.estimators.classification import BlackBoxClassifier

            assert self._x is not None
            shape = tuple(int(d) for d in self._x.shape[1:])
            self._clf = BlackBoxClassifier(predict_fn=self.predict_proba, input_shape=shape,
                                           nb_classes=len(self._class_names), clip_values=(0.0, 1.0))
        return self._clf

    def surrogate_art_classifier(self) -> Any:
        return None

    def torch_model(self) -> Any:
        """``None``: a remote endpoint has no differentiable module (model-agnostic explainers only)."""
        return None

    @contextmanager
    def purpose(self, name: str) -> Iterator[None]:
        """Label the queries made inside the block (``attack``, ``control``, ``explain``) for the counters."""
        previous = self._purpose
        self._purpose = str(name) or DEFAULT_PURPOSE
        try:
            yield
        finally:
            self._purpose = previous

    def queries(self) -> dict[str, Any]:
        """Client-side query counters: rows and requests per purpose plus totals."""
        with self._lock:
            by_purpose = {k: dict(v) for k, v in self._queries.items()}
        return {
            "by_purpose": by_purpose,
            "rows": sum(v["rows"] for v in by_purpose.values()),
            "requests": sum(v["requests"] for v in by_purpose.values()),
            "batch_rows": self._batch_rows,
        }

    @property
    def feature_names(self) -> list[str]:
        return [str(f.get("name")) for f in (self._features or [])]

    def manifest(self) -> dict[str, Any]:
        """``schema.MLModelManifest`` fields plus the endpoint block, the probe, the fingerprint and counters."""
        self.load()
        assert self._y is not None and self._manifest is not None
        stats = self._safe_stats()
        # ``endpoint`` is the validated ``schema.EndpointSpec`` block from load(); the endpoint-specific extras
        # (probe, fingerprint, counters, limits) live beside it under their own keys.
        return {
            **self._manifest,
            "source": "endpoint", "access": ACCESS_LABEL, "gradients": False, "torch_model": None,
            "surrogate": None, "scheme": self._scheme,
            "endpoint": dict(self._endpoint_block),
            "endpoint_probe": dict(self._probe or {}),
            "endpoint_fingerprint": {
                "sha256": self._fingerprint, "label": stats.get("fingerprint_label")
                or "remote model identity (first response fingerprint), not a weights digest",
                "output_kind": self._output_kind,
            },
            "endpoint_queries": self.queries(),
            "endpoint_broker": stats or None,
            "endpoint_limits": self._limits or (stats.get("limits") if isinstance(stats.get("limits"), dict) else None),
            "explainer": ("PartitionExplainer over predict_proba (no differentiable module)" if self._domain == "image"
                          else "KernelExplainer over predict_proba (no differentiable module)"),
            "eval_n": int(self._y.shape[0]), "eval_per_class": per_class_counts(self._y, self._class_names),
            "caveats": list(ENDPOINT_CAVEATS),
            "nondeterminism": [ENDPOINT_NONDETERMINISM],
        }


class _Rows:
    __slots__ = ("http_status", "latency_ms", "output_kind", "probabilities")

    def __init__(self, probabilities: np.ndarray, output_kind: str, http_status: int, latency_ms: float) -> None:
        self.probabilities = probabilities
        self.output_kind = output_kind
        self.http_status = http_status
        self.latency_ms = latency_ms


# ---------------------------------------------------------------------------
# Child-side factory (mirrors ``services.ml_models.artifact_target_from_path``)
# ---------------------------------------------------------------------------


def endpoint_target_from_request(target_id: str, spec: dict[str, Any]) -> EndpointTarget:
    """Build the child's :class:`EndpointTarget` from the parent's ``target_endpoint`` request block.

    ``spec`` carries ``socket`` (the broker path inside the work dir), ``url_host``, ``scheme``,
    ``auth_profile_id`` (an id, never the credential), ``batch_rows``, ``timeout_s``, optional ``limits`` and
    ``manifest`` (``modality``, ``dataset_id``, ``dataset_split``, ``dataset_revision``, ``input_shape``,
    ``features``, ``name``, ``license``). The evaluation slice is bound through the bundled asset manifest
    exactly as for uploads; class names come from that binding.
    """
    from redsim.services.ml_models import _evaluation_binding

    socket_path = spec.get("socket")
    if not isinstance(socket_path, str) or not socket_path.strip():
        raise ValueError("target_endpoint.socket (the predict broker path) is required")
    manifest = dict(spec.get("manifest") or {})
    dataset_id = str(manifest.get("dataset_id") or spec.get("dataset_id") or "")
    dataset_split = str(manifest.get("dataset_split") or "").strip() or None
    eval_path, class_names, dataset_revision, resolved_split = _evaluation_binding(
        dataset_id, dataset_split=dataset_split,
    )
    modality = str(manifest.get("modality") or spec.get("modality") or "image")
    limits = EndpointLimits.from_env(modality).merged(spec.get("limits") if isinstance(spec.get("limits"), dict)
                                                       else None)
    batch_rows = spec.get("batch_rows")
    timeout_s = spec.get("timeout_s")
    features = manifest.get("features")
    revision = manifest.get("dataset_revision")
    return EndpointTarget(
        target_id,
        transport=SocketPredictTransport(socket_path, request_timeout_s=limits.timeout_s * 4 + 10),
        url_host=str(spec.get("url_host") or ""),
        scheme=str(spec.get("scheme") or "https"),
        auth_profile_id=str(spec.get("auth_profile_id") or ""),
        class_names=class_names,
        eval_data=eval_path,
        dataset_id=dataset_id,
        dataset_split=resolved_split,
        dataset_revision=str(revision) if revision is not None else dataset_revision,
        input_shape=tuple(manifest.get("input_shape") or ()) or None,
        domain=cast("Domain", modality),
        name=str(manifest.get("name") or target_id),
        batch_rows=int(batch_rows) if isinstance(batch_rows, int) and batch_rows > 0 else limits.batch_rows,
        timeout_s=float(timeout_s) if isinstance(timeout_s, (int, float)) and timeout_s > 0 else limits.timeout_s,
        features=[dict(f) for f in features] if isinstance(features, list) else None,
        license=manifest.get("license"),
        limits=limits.as_dict(),
    )


__all__ = [
    "ACCESS_LABEL",
    "ENDPOINT_CAVEATS",
    "PROBE_ROWS",
    "EndpointTarget",
    "PredictTransport",
    "SocketPredictTransport",
    "descriptor_sha256",
    "endpoint_target_from_request",
]
