"""Model-artifact loading (spec section 9.2) and the ``Target`` over an uploaded artifact.

Accepted formats and what loading means for each:

* ``onnx``              ``onnx.load(load_external_data=False)`` -> refuse external data tensors and
                        custom operator domains -> ``onnx.checker`` -> ``onnxruntime`` CPU session with
                        bounded threads. There is no onnx2torch here, so the ART estimator is a
                        ``BlackBoxClassifier`` over ``predict`` and ``torch_model()`` is ``None``
                        (``gradients=False`` in the manifest; white-box attacks are not run silently).
* ``torch_state_dict``  zip archive, ``torch.load(weights_only=True)``, an architecture id from the
                        in-tree allowlist, ``load_state_dict(strict=True)`` -> ``PyTorchClassifier``.

Everything else is refused with ``UnsupportedArtifact``: legacy pickles and joblib files (by
extension and by the ``\\x80`` PROTO opcode), ``weights_only`` failures (what a "full pickle" means
operationally), unknown signatures, digest mismatches, unknown or missing architecture ids, and
shape or class-count disagreements with the evaluation data. torch, onnx and ART are imported
lazily so importing this module (or the registry) pulls no ML library into the API process.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import platform
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from redsim.ml.datasets.sampling import as_model_input, per_class_counts, stratified_sample
from redsim.ml.errors import UnsupportedArtifact
from redsim.ml.schema import Domain, TargetInfo
from redsim.ml.targets.base import Sample

ArtifactFormat = str  # "onnx" | "torch_state_dict"
ACCEPTED_FORMATS: tuple[str, ...] = ("onnx", "torch_state_dict")
PICKLE_SUFFIXES: tuple[str, ...] = (".pkl", ".pickle", ".joblib", ".sav", ".dill")
ZIP_MAGIC = b"PK\x03\x04"
PICKLE_PROTO_OPCODE = 0x80
_ONNX_IR_VERSION_TAG = 0x08     # field 1 (ir_version), varint: the first byte of every ModelProto
STANDARD_ONNX_DOMAINS: frozenset[str] = frozenset({"", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training"})
_CHUNK = 1 << 20


# --------------------------------------------------------------------------------------
# Architecture allowlist. ``architectures.py`` is owned by the assets branch; import it lazily so a
# missing module is a clear refusal rather than an import error, and so tests can inject tiny modules
# by adding to (or overriding entries of) ``ARCHITECTURES``.
# --------------------------------------------------------------------------------------

def _smallcnn(**kwargs: Any) -> Any:
    from redsim.ml.targets.architectures import SmallCNN

    return SmallCNN(**kwargs)


ARCHITECTURES: dict[str, Callable[..., Any]] = {"smallcnn": _smallcnn}


def architecture_ids() -> list[str]:
    return sorted(ARCHITECTURES)


def resolve_architecture(architecture_id: str | None, kwargs: dict[str, Any] | None = None) -> Any:
    """Instantiate an allowlisted architecture. Free-form code is never accepted."""
    if not architecture_id:
        raise UnsupportedArtifact("architecture_required: a torch state_dict needs an architecture id "
                                  f"from the allowlist {architecture_ids()}")
    factory = ARCHITECTURES.get(architecture_id)
    if factory is None:
        raise UnsupportedArtifact(f"architecture_not_allowlisted: {architecture_id!r} is not one of "
                                  f"{architecture_ids()}")
    try:
        return factory(**(kwargs or {}))
    except ImportError as exc:
        raise UnsupportedArtifact(f"architecture {architecture_id!r} is not available in this build: {exc}") from exc
    except TypeError as exc:
        raise UnsupportedArtifact(f"architecture {architecture_id!r} rejected its kwargs {kwargs!r}: {exc}") from exc


# --------------------------------------------------------------------------------------
# Signature sniffing and digests
# --------------------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_sha256(path: Path, expected: str | None) -> str:
    """Return the file digest; refuse when it disagrees with ``expected``."""
    actual = sha256_file(path)
    if expected is not None and actual != expected.strip().lower():
        raise UnsupportedArtifact(f"hash_mismatch: {Path(path).name} has sha256 {actual}, manifest says {expected}")
    return actual


def sniff_format(path: Path) -> ArtifactFormat:
    """Classify a model file from its name and first bytes, without deserialising anything."""
    p = Path(path)
    if not p.is_file():
        raise UnsupportedArtifact(f"model file not found: {p}")
    suffix = p.suffix.lower()
    if suffix in PICKLE_SUFFIXES:
        raise UnsupportedArtifact(f"pickle_refused: {p.name} has a pickle/joblib extension; Phase A accepts only "
                                  f"{ACCEPTED_FORMATS}")
    with p.open("rb") as fh:
        head = fh.read(16)
    if not head:
        raise UnsupportedArtifact(f"unsupported_model_format: {p.name} is empty")
    if head[0] == PICKLE_PROTO_OPCODE:
        raise UnsupportedArtifact(f"pickle_refused: {p.name} starts with a pickle PROTO opcode")
    if head[:4] == ZIP_MAGIC:
        return "torch_state_dict"
    if head[0] == _ONNX_IR_VERSION_TAG and suffix == ".onnx":
        return "onnx"
    raise UnsupportedArtifact(f"unsupported_model_format: {p.name} matches none of {ACCEPTED_FORMATS} "
                              f"(first bytes {head[:4]!r})")


def detect_format(path: Path, declared: str | None = None) -> ArtifactFormat:
    """Sniff the file and cross-check the declaration; a contradiction is refused, never trusted."""
    if declared is not None and declared not in ACCEPTED_FORMATS:
        raise UnsupportedArtifact(f"unsupported_model_format: declared {declared!r}; accepted {ACCEPTED_FORMATS}")
    sniffed = sniff_format(path)
    if declared is not None and declared != sniffed:
        raise UnsupportedArtifact(f"format_mismatch: declared {declared!r} but the file looks like {sniffed!r}")
    return sniffed


# --------------------------------------------------------------------------------------
# Loaders (worker side only)
# --------------------------------------------------------------------------------------

def load_state_dict_module(path: Path, architecture_id: str | None,
                           architecture_kwargs: dict[str, Any] | None = None) -> Any:
    """``torch.load(weights_only=True)`` + allowlisted architecture + ``load_state_dict(strict=True)``."""
    import torch

    module = resolve_architecture(architecture_id, architecture_kwargs)
    try:
        state = torch.load(str(path), map_location="cpu", weights_only=True)
    except Exception as exc:  # torch raises pickle.UnpicklingError and friends
        raise UnsupportedArtifact("pickle_refused: weights_only load failed (the archive holds objects other "
                                  f"than tensors): {str(exc).splitlines()[0][:200]}") from exc
    if not isinstance(state, dict) or not all(isinstance(v, torch.Tensor) for v in state.values()):
        raise UnsupportedArtifact("unsupported_model_format: the archive is not a state_dict of tensors")
    try:
        module.load_state_dict(state, strict=True)
    except RuntimeError as exc:
        raise UnsupportedArtifact(f"architecture_mismatch: state_dict does not fit {architecture_id!r}: "
                                  f"{str(exc).splitlines()[0][:300]}") from exc
    return module.eval()


@dataclass
class OnnxModel:
    session: Any
    input_name: str
    output_name: str
    input_shape: tuple[int | None, ...]      # without the batch dimension
    n_outputs: int | None
    ir_version: int
    opsets: dict[str, int] = field(default_factory=dict)

    def run(self, x: np.ndarray) -> np.ndarray:
        out = self.session.run([self.output_name], {self.input_name: np.ascontiguousarray(x, dtype=np.float32)})
        return np.asarray(out[0])


def _dims(shape: list[Any]) -> tuple[int | None, ...]:
    return tuple(int(d) if isinstance(d, int) and d > 0 else None for d in shape)


def load_onnx_model(path: Path, *, intra_op_threads: int = 2) -> OnnxModel:
    """Parse, check and open an ONNX model with onnxruntime's default CPU provider."""
    import onnx
    import onnxruntime as ort

    try:
        proto = onnx.load(str(path), load_external_data=False)
    except Exception as exc:
        raise UnsupportedArtifact(f"onnx_parse_failed: {str(exc).splitlines()[0][:200]}") from exc
    external = [t.name for t in proto.graph.initializer if t.data_location == onnx.TensorProto.EXTERNAL]
    if external:
        raise UnsupportedArtifact(f"onnx_external_data: tensors reference external files: {external[:5]}")
    custom = sorted({n.domain for n in proto.graph.node} - STANDARD_ONNX_DOMAINS)
    if custom:
        raise UnsupportedArtifact(f"onnx_custom_op_domain: custom operator domains are refused: {custom}")
    try:
        onnx.checker.check_model(proto)
    except Exception as exc:
        raise UnsupportedArtifact(f"onnx_checker_failed: {str(exc).splitlines()[0][:200]}") from exc
    initializer_names = {t.name for t in proto.graph.initializer}
    graph_inputs = [i for i in proto.graph.input if i.name not in initializer_names]
    if len(graph_inputs) != 1 or len(proto.graph.output) != 1:
        raise UnsupportedArtifact("onnx_signature: exactly one graph input and one output are required "
                                  f"(got {len(graph_inputs)} / {len(proto.graph.output)})")
    so = ort.SessionOptions()
    so.intra_op_num_threads = max(1, int(intra_op_threads))
    so.inter_op_num_threads = 1
    try:
        session = ort.InferenceSession(proto.SerializeToString(), so, providers=["CPUExecutionProvider"])
    except Exception as exc:
        raise UnsupportedArtifact(f"onnx_session_failed: {str(exc).splitlines()[0][:200]}") from exc
    inp, out = session.get_inputs()[0], session.get_outputs()[0]
    in_dims, out_dims = _dims(list(inp.shape)), _dims(list(out.shape))
    n_outputs = out_dims[-1] if len(out_dims) >= 2 else None
    return OnnxModel(session=session, input_name=inp.name, output_name=out.name, input_shape=in_dims[1:],
                     n_outputs=n_outputs, ir_version=int(proto.ir_version),
                     opsets={o.domain or "ai.onnx": int(o.version) for o in proto.opset_import})


def _softmax(z: np.ndarray) -> np.ndarray:
    z = np.asarray(z, dtype=np.float64)
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return (e / e.sum(axis=1, keepdims=True)).astype(np.float32)


def looks_like_probabilities(out: np.ndarray) -> bool:
    arr = np.asarray(out, dtype=np.float64)
    if arr.ndim != 2 or arr.size == 0:
        return False
    return bool(np.all(arr >= -1e-6) and np.all(arr <= 1 + 1e-6) and np.allclose(arr.sum(axis=1), 1.0, atol=1e-3))


def library_versions(*names: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in names:
        try:
            out[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            out[name] = "not installed"
    return out


EvalData = tuple[np.ndarray, np.ndarray] | Callable[[], tuple[np.ndarray, np.ndarray]] | str | Path


def _load_eval_data(source: EvalData) -> tuple[np.ndarray, np.ndarray, np.ndarray | None]:
    if callable(source):
        x, y = source()
        return np.asarray(x), np.asarray(y).reshape(-1), None
    if isinstance(source, (str, Path)):
        with np.load(Path(source), allow_pickle=False) as npz:
            x = np.asarray(npz["x"])
            y = np.asarray(npz["y"]).reshape(-1)
            idx = np.asarray(npz["indices"]) if "indices" in npz else None
        return x, y, idx
    x, y = source
    return np.asarray(x), np.asarray(y).reshape(-1), None


# --------------------------------------------------------------------------------------
# The Target
# --------------------------------------------------------------------------------------

class ArtifactTarget:
    """A caller-supplied model file evaluated on a bundled dataset slice (uploads are never trained on).

    ``eval_data`` is the evaluation split the artifact is bound to: ``(x, y)`` arrays, a zero-arg
    callable returning them, or a path to an ``.npz`` with ``x``, ``y`` and optional ``indices``.
    Images are uint8 or float32 NCHW in [0, 1]; the model must consume x directly (no external
    normalisation, spec section 11.3.1).
    """

    def __init__(
        self,
        target_id: str,
        path: str | Path,
        *,
        class_names: list[str],
        eval_data: EvalData,
        declared_format: str | None = None,
        expected_sha256: str | None = None,
        architecture_id: str | None = None,
        architecture_kwargs: dict[str, Any] | None = None,
        input_shape: tuple[int, ...] | None = None,
        name: str | None = None,
        domain: Domain = "image",
        dataset_id: str | None = None,
        dataset_split: str | None = None,
        dataset_revision: str | None = None,
        license: str | None = None,
        intra_op_threads: int = 2,
    ) -> None:
        self.id = target_id
        self._path = Path(path)
        self._class_names = list(class_names)
        self._eval_source = eval_data
        self._declared = declared_format
        self._expected_sha = expected_sha256
        self._arch_id = architecture_id
        self._arch_kwargs = dict(architecture_kwargs or {})
        self._declared_input_shape = tuple(input_shape) if input_shape else None
        self._name = name or f"Uploaded model {self._path.name}"
        self._domain = domain
        self._dataset = {"dataset_id": dataset_id, "dataset_split": dataset_split,
                         "dataset_revision": dataset_revision, "license": license}
        self._threads = intra_op_threads
        self._format: str | None = None
        self._sha256: str | None = None
        self._module: Any = None
        self._onnx: OnnxModel | None = None
        self._x: np.ndarray | None = None
        self._y: np.ndarray | None = None
        self._indices: np.ndarray | None = None
        self._clf: Any = None
        self._output_kind: str | None = None

    # -- protocol ---------------------------------------------------------------------

    def info(self) -> TargetInfo:
        meta: dict[str, Any] = {
            "source": "uploaded", "format": self._format or self._declared, "sha256": self._sha256,
            "architecture_id": self._arch_id, "class_names": self._class_names,
            "n_classes": len(self._class_names), "loaded": self._x is not None,
            "gradients": None if self._format is None else self._format == "torch_state_dict",
            **{k: v for k, v in self._dataset.items() if v is not None},
        }
        return TargetInfo(id=self.id, name=self._name, domain=self._domain, status="available", metadata=meta)

    def load(self) -> None:
        if self._x is not None:
            return
        self._format = detect_format(self._path, self._declared)
        self._sha256 = verify_sha256(self._path, self._expected_sha)
        x, y, idx = _load_eval_data(self._eval_source)
        if x.shape[0] != y.shape[0] or x.shape[0] == 0:
            raise UnsupportedArtifact("evaluation split is empty or x/y disagree on row count")
        if y.min() < 0 or y.max() >= len(self._class_names):
            raise UnsupportedArtifact("evaluation labels fall outside the declared class list")
        sample_shape = tuple(int(d) for d in x.shape[1:])
        if self._declared_input_shape and self._declared_input_shape != sample_shape:
            raise UnsupportedArtifact(f"shape_mismatch: manifest input_shape {self._declared_input_shape} vs "
                                      f"evaluation data {sample_shape}")
        if self._format == "torch_state_dict":
            self._module = load_state_dict_module(self._path, self._arch_id, self._arch_kwargs)
            probe = self._torch_logits(as_model_input(x[:1]))
        else:
            self._onnx = load_onnx_model(self._path, intra_op_threads=self._threads)
            for want, got in zip(self._onnx.input_shape, sample_shape):
                if want is not None and want != got:
                    raise UnsupportedArtifact(f"shape_mismatch: ONNX input {self._onnx.input_shape} vs "
                                              f"evaluation data {sample_shape}")
            probe = self._onnx.run(as_model_input(x[:1]))
            self._output_kind = "probabilities" if looks_like_probabilities(probe) else "logits"
        if probe.ndim != 2 or probe.shape[1] != len(self._class_names):
            raise UnsupportedArtifact(f"shape_mismatch: model emits {probe.shape[1:]} outputs, manifest declares "
                                      f"{len(self._class_names)} classes")
        self._x, self._y, self._indices = x, y.astype(np.int64), idx

    def sample(self, n: int, seed: int) -> Sample:
        self.load()
        assert self._x is not None and self._y is not None
        return stratified_sample(self._x, self._y, n, seed, self._class_names, source_indices=self._indices)

    def _torch_logits(self, x: np.ndarray) -> np.ndarray:
        import torch

        with torch.no_grad():
            out = self._module(torch.from_numpy(np.ascontiguousarray(x, dtype=np.float32)))
        return np.asarray(out.cpu().numpy())

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        self.load()
        xin = as_model_input(np.asarray(x))
        outs = []
        for start in range(0, xin.shape[0], 256):
            batch = xin[start:start + 256]
            if self._module is not None:
                outs.append(_softmax(self._torch_logits(batch)))
            else:
                assert self._onnx is not None
                raw = self._onnx.run(batch)
                outs.append(raw.astype(np.float32) if self._output_kind == "probabilities" else _softmax(raw))
        return np.concatenate(outs) if outs else np.empty((0, len(self._class_names)), dtype=np.float32)

    def art_classifier(self) -> Any:
        self.load()
        if self._clf is None:
            assert self._x is not None
            shape = tuple(int(d) for d in self._x.shape[1:])
            if self._module is not None:
                from art.estimators.classification import PyTorchClassifier
                from torch import nn

                self._clf = PyTorchClassifier(model=self._module, loss=nn.CrossEntropyLoss(), input_shape=shape,
                                              nb_classes=len(self._class_names), clip_values=(0.0, 1.0),
                                              device_type="cpu")
            else:
                from art.estimators.classification import BlackBoxClassifier

                self._clf = BlackBoxClassifier(predict_fn=self.predict_proba, input_shape=shape,
                                               nb_classes=len(self._class_names), clip_values=(0.0, 1.0))
        return self._clf

    def torch_model(self) -> Any:
        self.load()
        return self._module  # None for ONNX: no differentiable module, never faked

    def manifest(self) -> dict[str, Any]:
        self.load()
        assert self._x is not None and self._y is not None
        m: dict[str, Any] = {
            "source": "uploaded", "file": self._path.name, "format": self._format, "sha256": self._sha256,
            "size_bytes": self._path.stat().st_size, "architecture_id": self._arch_id,
            "architecture_kwargs": self._arch_kwargs or None, "input_shape": list(self._x.shape[1:]),
            "n_classes": len(self._class_names), "class_names": self._class_names,
            "gradients": self._module is not None, "eval_n": int(self._y.shape[0]),
            "eval_per_class": per_class_counts(self._y, self._class_names),
            "library_versions": {**library_versions("torch", "onnx", "onnxruntime", "adversarial-robustness-toolbox"),
                                 "python": platform.python_version()},
            **{k: v for k, v in self._dataset.items() if v is not None},
        }
        if self._onnx is not None:
            m["onnx"] = {"ir_version": self._onnx.ir_version, "opsets": self._onnx.opsets,
                         "output_kind": self._output_kind, "estimator": "BlackBoxClassifier",
                         "note": "no onnx2torch conversion in this build: white-box attacks are not available "
                                 "for ONNX uploads and are reported as not run"}
        return m


__all__ = [
    "ACCEPTED_FORMATS",
    "ARCHITECTURES",
    "PICKLE_SUFFIXES",
    "ArtifactTarget",
    "OnnxModel",
    "architecture_ids",
    "detect_format",
    "library_versions",
    "load_onnx_model",
    "load_state_dict_module",
    "looks_like_probabilities",
    "resolve_architecture",
    "sha256_file",
    "sniff_format",
    "verify_sha256",
]
