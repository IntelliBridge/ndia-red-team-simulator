"""Model-artifact loading (spec section 9.2) and the ``Target`` over an uploaded artifact.

Accepted formats and what loading means for each:

* ``onnx``              ``onnx.load(load_external_data=False)`` -> refuse external data tensors and
                        custom operator domains -> ``onnx.checker`` -> ``onnxruntime`` CPU session with
                        bounded threads. Predictions come from onnxruntime. For gradient attacks the graph
                        is converted with ``onnx2torch``; the converted module's argmax is compared with
                        onnxruntime on the evaluation slice and recorded as ``onnx_torch_argmax_agreement``.
                        When conversion succeeds and agrees, the ART estimator is a ``PyTorchClassifier``
                        over the converted module (``gradients=True``); when onnx2torch is absent, the
                        conversion fails, or the two disagree, it is a ``BlackBoxClassifier`` over
                        ``predict`` and ``torch_model()`` is ``None`` (``gradients=False``; white-box
                        attacks are reported as not run, never silently substituted).
* ``torch_state_dict``  zip archive, ``torch.load(weights_only=True)``, an architecture id from the
                        in-tree allowlist, ``load_state_dict(strict=True)`` -> ``PyTorchClassifier``.
* ``safetensors_state_dict``  safetensors header, ``safetensors.torch.load_file``, the same architecture
                         allowlist and strict state-dict load -> ``PyTorchClassifier``.

Open-weights checkpoints. A state_dict in the bare torchvision / timm key layout (a Hugging Face
``model.safetensors`` of a ResNet) is prefixed onto the catalog architecture's ``backbone.`` and recorded
as ``state_dict_layout: torchvision`` (:func:`adapt_state_dict_layout`); a channels-last ONNX graph is
sniffed (or declared) and served through a permute (``input_layout: NHWC``). The input contract the
uploader declares (``redsim.ml.targets.input_contract``: resize, scale, mean / std, layout) is folded
into the estimator by :func:`make_input_adapter`, so the campaign keeps perturbing [0, 1] NCHW pixels at
the evaluation slice's resolution and eps keeps its meaning. Nothing is guessed: an absent contract is
the identity, and the validate job records the clean accuracy that contract earns.

Everything else is refused with ``UnsupportedArtifact``: legacy pickles and joblib files (by
extension and by the ``\\x80`` PROTO opcode), ``weights_only`` failures (what a "full pickle" means
operationally), unknown signatures, digest mismatches, unknown or missing architecture ids, and
shape or class-count disagreements with the evaluation data. torch, onnx and ART are imported
lazily so importing this module (or the registry) pulls no ML library into the API process.

The architecture allowlist mirrors ``redsim.ml.targets.architectures``: canonical ids ``small_cnn``
and ``resnet18``, alias ``smallcnn`` -> ``small_cnn``. ``ARCHITECTURES`` here maps every accepted
spelling to a factory so tests can inject tiny modules with ``monkeypatch.setitem``.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from pydantic import ValidationError

from redsim.ml.datasets.sampling import as_model_input, per_class_counts, stratified_sample
from redsim.ml.errors import ArtifactDigestMismatch, DatasetUnavailable, UnsupportedArtifact
from redsim.ml.schema import Domain, MLModelManifest, TargetInfo
from redsim.ml.targets.base import Sample
from redsim.ml.targets.input_contract import (
    INPUT_LAYOUTS,
    InputPreprocessing,
    InputPreprocessingError,
    sniff_input_layout,
)
from redsim.ml.targets.input_contract import parse_input_preprocessing as _parse_input_preprocessing

ArtifactFormat = str  # "onnx" | "torch_state_dict" | "safetensors_state_dict"
ACCEPTED_FORMATS: tuple[str, ...] = ("onnx", "torch_state_dict", "safetensors_state_dict")
PICKLE_SUFFIXES: tuple[str, ...] = (".pkl", ".pickle", ".joblib", ".sav", ".dill")
ZIP_MAGIC = b"PK\x03\x04"
PICKLE_PROTO_OPCODE = 0x80
_ONNX_IR_VERSION_TAG = 0x08     # field 1 (ir_version), varint: the first byte of every ModelProto
STANDARD_ONNX_DOMAINS: frozenset[str] = frozenset({"", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training"})
_CHUNK = 1 << 20

# onnx2torch agreement: the converted module must reproduce onnxruntime's argmax on (nearly) every row of the
# evaluation slice before its gradients stand in for the uploaded graph's. The measured rate is recorded
# either way; below the floor the target stays black-box and says why.
MIN_ONNX_TORCH_AGREEMENT = 0.99
AGREEMENT_MAX_N = 1000


# --------------------------------------------------------------------------------------
# Input preprocessing declared at upload (spec 11.3.1: normalisation lives inside the model boundary).
# The campaign perturbs [0, 1] NCHW pixels at the evaluation slice's resolution. An open-weights model
# trained on another input contract (raw 0-255 pixels, ImageNet mean / std, upsampled inputs, a
# channels-last graph) declares that contract here and the loader folds it into the estimator, so eps
# keeps its meaning and the graph is never edited. Every value is recorded in the manifest.
# --------------------------------------------------------------------------------------

def parse_input_preprocessing(block: Mapping[str, Any] | None) -> InputPreprocessing:
    """The contract module's parser, refusing as ``UnsupportedArtifact`` with the ``params_out_of_range`` code."""
    try:
        return _parse_input_preprocessing(block)
    except InputPreprocessingError as exc:
        raise UnsupportedArtifact(f"{exc.code}: {exc}") from exc


def make_input_adapter(prep: InputPreprocessing, *, channels_last: bool = False, inner: Any = None) -> Any:
    """A torch module applying ``prep`` (and the NHWC permute) before ``inner``; ``inner=None`` returns the input.

    Differentiable end to end, so the white-box estimator's gradients reach the [0, 1] NCHW pixels the
    campaign perturbs.
    """
    import torch
    import torch.nn.functional as functional
    from torch import nn

    class _InputAdapter(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.inner = inner
            self.resize = prep.resize
            self.scale = float(prep.scale)
            self.channels_last = channels_last
            if prep.mean is not None and prep.std is not None:
                self.register_buffer("mean", torch.tensor(prep.mean, dtype=torch.float32).view(1, -1, 1, 1))
                self.register_buffer("std", torch.tensor(prep.std, dtype=torch.float32).view(1, -1, 1, 1))
            else:
                self.mean = None
                self.std = None

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            if self.resize is not None and tuple(x.shape[-2:]) != (self.resize, self.resize):
                x = functional.interpolate(x, size=(self.resize, self.resize), mode="bilinear", align_corners=False)
            if self.scale != 1.0:
                x = x * self.scale
            if self.mean is not None:
                x = (x - self.mean) / self.std
            if self.channels_last:
                x = x.permute(0, 2, 3, 1).contiguous()
            return self.inner(x) if self.inner is not None else x

    return _InputAdapter().eval()


def _numpy_preprocess(prep: InputPreprocessing, *, channels_last: bool) -> Callable[[np.ndarray], np.ndarray] | None:
    """The same adapter for onnxruntime input, or ``None`` when nothing has to change."""
    if prep.is_identity and not channels_last:
        return None
    adapter = make_input_adapter(prep, channels_last=channels_last)

    def _apply(x: np.ndarray) -> np.ndarray:
        import torch

        with torch.no_grad():
            out = adapter(torch.from_numpy(np.ascontiguousarray(x, dtype=np.float32)))
        return np.ascontiguousarray(out.numpy(), dtype=np.float32)

    return _apply


# --------------------------------------------------------------------------------------
# Architecture allowlist. ``architectures.py`` imports torch, so it is imported lazily here: a missing
# module is a clear refusal rather than an import error, and the API process never loads torch. Tests
# inject tiny modules by adding to (or overriding entries of) ``ARCHITECTURES``.
# --------------------------------------------------------------------------------------

def _small_cnn(**kwargs: Any) -> Any:
    from redsim.ml.targets.architectures import SmallCNN

    return SmallCNN(**kwargs)


def _resnet18(**kwargs: Any) -> Any:
    from redsim.ml.targets.architectures import ResNet18

    return ResNet18(**kwargs)


# Accepted spellings -> canonical id. Read wherever an id comes in; canonical ids are what gets recorded.
ARCHITECTURE_ALIASES: dict[str, str] = {"smallcnn": "small_cnn"}

ARCHITECTURES: dict[str, Callable[..., Any]] = {
    "small_cnn": _small_cnn,
    "smallcnn": _small_cnn,      # alias, kept as a key so architecture_ids() advertises it
    "resnet18": _resnet18,
}


def canonical_architecture_id(architecture_id: str) -> str:
    return ARCHITECTURE_ALIASES.get(architecture_id, architecture_id)


# Catalog architectures whose constructor is ``(in_channels, n_classes, image_size)``: when an upload names
# one without an ``architecture_kwargs`` block, the loader derives the block from the evaluation binding
# (NCHW sample shape, declared class list) instead of building the catalog defaults, which fit only the
# 10-class 32x32 build (spec 9.2; the manifest records what was built).
CATALOG_SHAPE_ARCHITECTURES: frozenset[str] = frozenset({"small_cnn", "resnet18"})


def derived_architecture_kwargs(architecture_id: str | None, sample_shape: tuple[int, ...],
                                n_classes: int) -> dict[str, Any]:
    """Constructor kwargs implied by the evaluation binding, or ``{}`` when they cannot be derived."""
    if not architecture_id or canonical_architecture_id(architecture_id) not in CATALOG_SHAPE_ARCHITECTURES:
        return {}
    if len(sample_shape) != 3 or sample_shape[1] != sample_shape[2]:
        return {}
    return {"in_channels": int(sample_shape[0]), "n_classes": int(n_classes), "image_size": int(sample_shape[1])}


def architecture_ids() -> list[str]:
    """Every accepted architecture spelling (canonical ids and their aliases)."""
    return sorted(ARCHITECTURES)


def resolve_architecture(architecture_id: str | None, kwargs: dict[str, Any] | None = None) -> Any:
    """Instantiate an allowlisted architecture. Free-form code is never accepted.

    ``kwargs`` are the constructor arguments recorded by the build (``ModelEntry.architecture``); the
    ``architecture_id`` key the builder stores inside that block is checked against the declared id and
    not passed on.
    """
    if not architecture_id:
        raise UnsupportedArtifact("architecture_required: a torch state_dict needs an architecture id "
                                  f"from the allowlist {architecture_ids()}")
    factory = ARCHITECTURES.get(architecture_id) or ARCHITECTURES.get(canonical_architecture_id(architecture_id))
    if factory is None:
        raise UnsupportedArtifact(f"architecture_not_allowlisted: {architecture_id!r} is not one of "
                                  f"{architecture_ids()}")
    ctor = dict(kwargs or {})
    inner = ctor.pop("architecture_id", None)
    if inner is not None and canonical_architecture_id(str(inner)) != canonical_architecture_id(architecture_id):
        raise UnsupportedArtifact(f"architecture_mismatch: the architecture block names {inner!r} but the entry "
                                  f"declares {architecture_id!r}")
    try:
        return factory(**ctor)
    except ImportError as exc:
        raise UnsupportedArtifact(f"architecture {architecture_id!r} is not available in this build: {exc}") from exc
    except (TypeError, ValueError) as exc:
        raise UnsupportedArtifact(f"architecture {architecture_id!r} rejected its kwargs {ctor!r}: {exc}") from exc


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
    """Return the file digest; refuse (``ArtifactDigestMismatch``) when it disagrees with ``expected``."""
    actual = sha256_file(path)
    if expected is not None and actual != expected.strip().lower():
        raise ArtifactDigestMismatch(f"hash_mismatch: {Path(path).name} has sha256 {actual}, manifest says {expected}")
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
    if suffix == ".safetensors" and len(head) >= 9:
        header_size = int.from_bytes(head[:8], "little", signed=False)
        if 0 < header_size <= p.stat().st_size - 8 and head[8:9] == b"{":
            return "safetensors_state_dict"
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

STATE_DICT_LAYOUTS: tuple[str, ...] = ("redsim", "torchvision")
_CATALOG_BUFFERS: frozenset[str] = frozenset({"input_mean", "input_std"})


def adapt_state_dict_layout(module: Any, state: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Accept the bare torchvision / timm key layout for a catalog architecture that wraps a backbone.

    A catalog module stores its backbone under ``backbone.`` and carries the ``input_mean`` /
    ``input_std`` normalisation buffers; open-weights checkpoints (torchvision, timm, the Hugging Face
    ``model.safetensors`` of a ResNet) name the same tensors without the prefix and without the buffers.
    When every key of the file maps one-to-one onto ``backbone.<key>`` and nothing else is missing but
    the two buffers, the keys are prefixed and the buffers keep the module's identity values (the
    uploader declares normalisation through ``input_preprocessing``). Any other shape is returned
    unchanged so the strict load names the mismatch. Returns ``(state, layout)``.
    """
    expected = set(module.state_dict().keys())
    if set(state) == expected:
        return state, "redsim"
    if not hasattr(module, "backbone"):
        return state, "redsim"
    prefixed = {f"backbone.{k}": v for k, v in state.items()}
    if set(prefixed) | (expected & _CATALOG_BUFFERS) != expected:
        return state, "redsim"
    own = module.state_dict()
    for name in expected & _CATALOG_BUFFERS:
        prefixed[name] = own[name]
    return prefixed, "torchvision"


def load_state_dict_module_with_record(
    path: Path,
    architecture_id: str | None,
    architecture_kwargs: dict[str, Any] | None = None,
    *,
    artifact_format: str = "torch_state_dict",
) -> tuple[Any, dict[str, Any]]:
    """Safely load tensors, then apply them strictly to an allowlisted architecture; ``(module, record)``.

    ``record`` carries ``state_dict_layout`` (``redsim`` or ``torchvision``) and ``n_tensors``.
    """
    import torch

    module = resolve_architecture(architecture_id, architecture_kwargs)
    if artifact_format == "safetensors_state_dict":
        try:
            from safetensors.torch import load_file

            state = load_file(str(path), device="cpu")
        except Exception as exc:
            raise UnsupportedArtifact(
                "unsupported_model_format: safetensors load failed: "
                f"{str(exc).splitlines()[0][:200]}"
            ) from exc
    else:
        try:
            state = torch.load(str(path), map_location="cpu", weights_only=True)
        except Exception as exc:  # torch raises pickle.UnpicklingError and friends
            raise UnsupportedArtifact("pickle_refused: weights_only load failed (the archive holds objects other "
                                      f"than tensors): {str(exc).splitlines()[0][:200]}") from exc
    if not isinstance(state, dict) or not all(isinstance(v, torch.Tensor) for v in state.values()):
        raise UnsupportedArtifact("unsupported_model_format: the archive is not a state_dict of tensors")
    state, layout = adapt_state_dict_layout(module, state)
    try:
        module.load_state_dict(state, strict=True)
    except RuntimeError as exc:
        raise UnsupportedArtifact(f"architecture_mismatch: state_dict does not fit {architecture_id!r}: "
                                  f"{str(exc).splitlines()[0][:300]}") from exc
    return module.eval(), {"state_dict_layout": layout, "n_tensors": len(state)}


def load_state_dict_module(
    path: Path,
    architecture_id: str | None,
    architecture_kwargs: dict[str, Any] | None = None,
    *,
    artifact_format: str = "torch_state_dict",
) -> Any:
    """Safely load tensors, then apply them strictly to an allowlisted architecture."""
    module, _record = load_state_dict_module_with_record(
        path, architecture_id, architecture_kwargs, artifact_format=artifact_format,
    )
    return module


@dataclass
class OnnxModel:
    session: Any
    input_name: str
    output_name: str
    input_shape: tuple[int | None, ...]      # without the batch dimension, always as (C, H, W) for images
    n_outputs: int | None
    ir_version: int
    opsets: dict[str, int] = field(default_factory=dict)
    proto: Any = None                        # the checked ``ModelProto`` (for onnx2torch)
    input_layout: str = "NCHW"               # what the graph itself consumes
    graph_input_shape: tuple[int | None, ...] = ()   # the graph's own signature, before any adaptation
    preprocessing: InputPreprocessing = field(default_factory=InputPreprocessing)
    preprocess: Callable[[np.ndarray], np.ndarray] | None = None

    def run(self, x: np.ndarray) -> np.ndarray:
        xin = np.ascontiguousarray(x, dtype=np.float32)
        if self.preprocess is not None:
            xin = self.preprocess(xin)
        out = self.session.run([self.output_name], {self.input_name: xin})
        return np.asarray(out[0])


def _dims(shape: list[Any]) -> tuple[int | None, ...]:
    return tuple(int(d) if isinstance(d, int) and d > 0 else None for d in shape)


def load_onnx_model(path: Path, *, intra_op_threads: int = 2,
                    preprocessing: InputPreprocessing | None = None) -> OnnxModel:
    """Parse, check and open an ONNX model with onnxruntime's default CPU provider.

    ``preprocessing`` is the contract the uploader declared; its ``layout`` overrides the sniffed one.
    A channels-last graph is served through a permute in front of the session, and ``input_shape`` is
    reported as ``(C, H, W)`` so the caller's shape check reads the same for every graph.
    """
    import onnx
    import onnxruntime as ort

    prep = preprocessing or InputPreprocessing()

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
    graph_dims = in_dims[1:]
    layout = prep.layout or sniff_input_layout(graph_dims)
    channels_last = layout == "NHWC"
    if channels_last and len(graph_dims) != 3:
        raise UnsupportedArtifact(f"shape_mismatch: an NHWC graph needs a rank-4 input, got {list(inp.shape)}")
    input_shape = (graph_dims[2], graph_dims[0], graph_dims[1]) if channels_last else graph_dims
    return OnnxModel(session=session, input_name=inp.name, output_name=out.name, input_shape=input_shape,
                     n_outputs=n_outputs, ir_version=int(proto.ir_version),
                     opsets={o.domain or "ai.onnx": int(o.version) for o in proto.opset_import}, proto=proto,
                     input_layout=layout, graph_input_shape=graph_dims, preprocessing=prep,
                     preprocess=_numpy_preprocess(prep, channels_last=channels_last))


def convert_onnx_to_torch(model: OnnxModel) -> tuple[Any, dict[str, Any]]:
    """``(torch module | None, conversion record)`` via onnx2torch. Never raises; failure is recorded.

    ``status`` is ``converted``, ``unavailable`` (onnx2torch not installed) or ``failed`` (the converter
    rejected the graph, typically an unsupported operator). The record is copied into the manifest so
    a black-box outcome always says why.
    """
    try:
        import onnx2torch
    except ImportError:
        return None, {"status": "unavailable", "reason": "onnx2torch is not installed in this build",
                      "converter": "onnx2torch", "version": library_versions("onnx2torch")["onnx2torch"]}
    version = library_versions("onnx2torch")["onnx2torch"]
    try:
        module = onnx2torch.convert(model.proto)
    except Exception as exc:  # noqa: BLE001 - the converter raises many types for unsupported ops
        return None, {"status": "failed", "reason": f"unsupported_onnx_op: {type(exc).__name__}: "
                                                    f"{str(exc).splitlines()[0][:200]}",
                      "converter": "onnx2torch", "version": version}
    module = module.eval()
    channels_last = model.input_layout == "NHWC"
    if channels_last or not model.preprocessing.is_identity:
        # The converted graph consumes what the session consumes; the same adapter sits in front of both.
        module = make_input_adapter(model.preprocessing, channels_last=channels_last, inner=module)
    return module, {"status": "converted", "reason": None, "converter": "onnx2torch", "version": version}


def onnx_torch_argmax_agreement(model: OnnxModel, module: Any, x: np.ndarray, *,
                                max_n: int = AGREEMENT_MAX_N) -> dict[str, Any]:
    """Share of the first ``min(n, max_n)`` evaluation rows on which onnxruntime and the converted module agree.

    Returned with its denominator: ``{"n", "n_agree", "agreement"}``; a runtime error in the converted
    module is recorded as ``error`` with ``agreement=None``, never as a number.
    """
    import torch

    xin = as_model_input(np.asarray(x))[: max(1, int(max_n))]
    n_agree = 0
    try:
        for start in range(0, xin.shape[0], 256):
            batch = xin[start:start + 256]
            ref = model.run(batch).argmax(axis=1)
            with torch.no_grad():
                got = module(torch.from_numpy(np.ascontiguousarray(batch, dtype=np.float32)))
            n_agree += int((np.asarray(got.cpu().numpy()).argmax(axis=1) == ref).sum())
    except Exception as exc:  # noqa: BLE001 - a converted graph can fail at run time on real batches
        return {"n": int(xin.shape[0]), "n_agree": None, "agreement": None,
                "error": f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"}
    n = int(xin.shape[0])
    return {"n": n, "n_agree": n_agree, "agreement": (n_agree / n) if n else None}


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


def model_manifest(what: str, **fields: Any) -> dict[str, Any]:
    """The ``schema.MLModelManifest`` block of a target manifest, validated and stamped with ``manifest_sha256``.

    ``fields`` are the manifest's own field names (spec 5.5); ``None`` values are dropped so the schema
    defaults apply. The digest covers the canonical JSON of every other field. A field set that does not
    form a valid manifest is refused as ``UnsupportedArtifact`` (``what`` names the offending source), so a
    malformed asset entry fails at load time instead of surfacing as a broken record later.
    """
    try:
        manifest = MLModelManifest(**{k: v for k, v in fields.items() if v is not None})
    except ValidationError as exc:
        raise UnsupportedArtifact(f"{what} does not form a valid model manifest: {exc}") from exc
    payload = manifest.model_dump(mode="json", exclude={"manifest_sha256"})
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**payload, "manifest_sha256": hashlib.sha256(canonical).hexdigest()}


EvalData = tuple[np.ndarray, np.ndarray] | Callable[[], tuple[np.ndarray, np.ndarray]] | str | Path


def _load_eval_data(source: EvalData) -> tuple[np.ndarray, np.ndarray, np.ndarray | None]:
    if callable(source):
        x, y = source()
        return np.asarray(x), np.asarray(y).reshape(-1), None
    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.is_file():
            raise DatasetUnavailable(f"evaluation slice not found: {path}")
        try:
            with np.load(path, allow_pickle=False) as npz:
                x = np.asarray(npz["x"])
                y = np.asarray(npz["y"]).reshape(-1)
                idx = np.asarray(npz["indices"]) if "indices" in npz else None
        except (OSError, KeyError, ValueError) as exc:
            raise DatasetUnavailable(f"evaluation slice {path} is unreadable: {exc}") from exc
        return x, y, idx
    x, y = source
    return np.asarray(x), np.asarray(y).reshape(-1), None


def consumed_eval_slice(
    block: Mapping[str, Any],
) -> tuple[Callable[[], tuple[np.ndarray, np.ndarray]], list[str], str | None, str]:
    """The evaluation binding over a consumed Parquet slice the worker parent materialised (INTEROP-16).

    ``block`` is ``target_detail["consumed_slice"]`` as ``services.ml_models.materialize_consumed_slice``
    wrote it: ``file`` (a path inside the work dir), ``sha256``, ``schema`` (the uploader's
    ``DeclaredSchema`` mapping), ``class_names``, ``revision`` (the manifest digest) and ``max_rows``.
    Returns ``(loader, class_names, dataset_revision, split)`` in the shape ``_evaluation_binding``
    returns for a bundled split, with a zero-arg ``loader`` in place of the ``.npz`` path: it reads
    the file with ``redsim.ml.interop.consume.load_consumed_slice`` (the same reader the parse child
    used, so a campaign measures the rows that were validated and nothing else) and refuses every
    declaration the file does not honour as ``UnsupportedArtifact("dataset_incompatible: …")``. Image
    rows are scaled onto [0, 1] from the declared ``value_range`` (uint8 slices by 255) because the
    targets consume unit-interval NCHW (spec 11.3.1); tabular rows pass through. The file's digest is
    checked here again before a byte is parsed; the split of a consumed slice is always ``eval``.
    """
    from redsim.services.ml_datasets import DeclaredSchema

    dataset_id = str(block.get("dataset_id") or "consumed slice")
    file_value = block.get("file")
    if not isinstance(file_value, str) or not file_value:
        raise DatasetUnavailable(f"consumed slice {dataset_id!r}: the request names no materialised file")
    path = Path(file_value)
    if not path.is_file():
        raise DatasetUnavailable(f"consumed slice {dataset_id!r}: evaluation file not found: {path}")
    expected = block.get("sha256")
    verify_sha256(path, str(expected) if isinstance(expected, str) and expected else None)
    schema_value = block.get("schema")
    try:
        schema = DeclaredSchema.from_mapping(schema_value if isinstance(schema_value, Mapping) else {})
    except (TypeError, ValueError) as exc:
        raise UnsupportedArtifact(f"dataset_incompatible: consumed slice {dataset_id!r} declares no readable "
                                  f"schema: {exc}") from exc
    max_rows_value = block.get("max_rows")
    max_rows = int(max_rows_value) if isinstance(max_rows_value, int) and max_rows_value > 0 else None

    def load() -> tuple[np.ndarray, np.ndarray]:
        from redsim.ml.interop.consume import ConsumeRefused, load_consumed_slice

        try:
            arrays = (load_consumed_slice(path, schema, max_rows=max_rows) if max_rows is not None
                      else load_consumed_slice(path, schema))
        except ConsumeRefused as exc:
            raise UnsupportedArtifact(
                f"dataset_incompatible: consumed slice {dataset_id!r} does not honour its declaration "
                f"({exc.code}): {exc}"
            ) from exc
        x = np.asarray(arrays.x, dtype=np.float32)
        if schema.modality == "image":
            top = 255.0 if (schema.dtype or "") == "uint8" else (
                float(schema.value_range[1]) if schema.value_range is not None else 1.0)
            if top > 1.0:
                x = (x / np.float32(top)).astype(np.float32)
        return x, np.asarray(arrays.y).reshape(-1)

    revision = block.get("revision")
    return load, list(schema.class_names), (str(revision) if revision else None), "eval"


# --------------------------------------------------------------------------------------
# The Target
# --------------------------------------------------------------------------------------

class ArtifactTarget:
    """A caller-supplied model file evaluated on a bundled or consumed dataset slice (uploads are never trained on).

    ``eval_data`` is the evaluation split the artifact is bound to: ``(x, y)`` arrays, a zero-arg
    callable returning them (a consumed Parquet slice through :func:`consumed_eval_slice`), or a path
    to an ``.npz`` with ``x``, ``y`` and optional ``indices``.
    ``dataset_id`` names that split's dataset and is required: an upload is bound to a dataset at
    registration (spec 5.5) and the manifest never guesses one. Images are uint8 or float32 NCHW in
    [0, 1]; the model must consume x directly (no external normalisation, spec section 11.3.1).
    """

    def __init__(
        self,
        target_id: str,
        path: str | Path,
        *,
        class_names: list[str],
        eval_data: EvalData,
        dataset_id: str,
        declared_format: str | None = None,
        expected_sha256: str | None = None,
        architecture_id: str | None = None,
        architecture_kwargs: dict[str, Any] | None = None,
        input_shape: tuple[int, ...] | None = None,
        name: str | None = None,
        domain: Domain = "image",
        dataset_split: str | None = None,
        dataset_revision: str | None = None,
        license: str | None = None,
        intra_op_threads: int = 2,
        input_preprocessing: Mapping[str, Any] | None = None,
    ) -> None:
        if not isinstance(dataset_id, str) or not dataset_id.strip():
            raise ValueError("ArtifactTarget needs the dataset_id its evaluation split belongs to")
        self.id = target_id
        self._path = Path(path)
        self._class_names = list(class_names)
        self._eval_source = eval_data
        self._declared = declared_format
        self._expected_sha = expected_sha256
        self._arch_id = architecture_id
        self._arch_kwargs = dict(architecture_kwargs or {})
        self._prep = parse_input_preprocessing(input_preprocessing)
        self._state_dict_record: dict[str, Any] | None = None
        self._declared_input_shape = tuple(input_shape) if input_shape else None
        self._name = name or f"Uploaded model {self._path.name}"
        self._domain = domain
        self._dataset = {"dataset_id": dataset_id, "dataset_split": dataset_split,
                         "dataset_revision": dataset_revision, "license": license}
        self._threads = intra_op_threads
        self._format: str | None = None
        self._sha256: str | None = None
        self._module: Any = None            # state_dict formats: the allowlisted architecture with weights applied
        self._onnx: OnnxModel | None = None
        self._torch_module: Any = None      # onnx: the onnx2torch conversion when it succeeded and agreed
        self._conversion: dict[str, Any] | None = None
        self._agreement: dict[str, Any] | None = None
        self._x: np.ndarray | None = None
        self._y: np.ndarray | None = None
        self._indices: np.ndarray | None = None
        self._clf: Any = None
        self._output_kind: str | None = None
        self._manifest: dict[str, Any] | None = None

    # -- protocol ---------------------------------------------------------------------

    def _gradients(self) -> bool | None:
        """Differentiable estimator available? ``None`` until an ONNX upload has been loaded (spec 5.5)."""
        if self._x is not None:
            return self._module is not None or self._torch_module is not None
        fmt = self._format or self._declared
        if fmt in {"torch_state_dict", "safetensors_state_dict"}:
            return True
        return None

    def info(self) -> TargetInfo:
        meta: dict[str, Any] = {
            "source": "uploaded", "format": self._format or self._declared, "sha256": self._sha256,
            "architecture_id": self._arch_id, "class_names": self._class_names,
            "n_classes": len(self._class_names), "loaded": self._x is not None,
            "gradients": self._gradients(),
            **{k: v for k, v in self._dataset.items() if v is not None},
        }
        if self._agreement is not None:
            meta["onnx_torch_argmax_agreement"] = self._agreement
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
        # What the graph or module sees after the declared preprocessing: the evaluation shape, resized.
        model_shape = sample_shape
        if self._prep.resize is not None:
            if len(sample_shape) != 3:
                raise UnsupportedArtifact("shape_mismatch: input_preprocessing.resize needs image (C, H, W) data")
            model_shape = (sample_shape[0], self._prep.resize, self._prep.resize)
        if self._format in {"torch_state_dict", "safetensors_state_dict"}:
            if self._prep.layout == "NHWC":
                raise UnsupportedArtifact("params_out_of_range: input_preprocessing.layout NHWC applies to ONNX "
                                          "graphs; catalog architectures consume NCHW")
            if not self._arch_kwargs:
                self._arch_kwargs = derived_architecture_kwargs(self._arch_id, model_shape, len(self._class_names))
            module, self._state_dict_record = load_state_dict_module_with_record(
                self._path,
                self._arch_id,
                self._arch_kwargs,
                artifact_format=self._format,
            )
            if not self._prep.is_identity:
                module = make_input_adapter(self._prep, inner=module)
            self._module = module
            probe = self._torch_logits(self._module, as_model_input(x[:1]))
        else:
            self._onnx = load_onnx_model(self._path, intra_op_threads=self._threads, preprocessing=self._prep)
            for want, got in zip(self._onnx.input_shape, model_shape):
                if want is not None and want != got:
                    raise UnsupportedArtifact(f"shape_mismatch: ONNX input {self._onnx.input_shape} "
                                              f"({self._onnx.input_layout} graph) vs evaluation data {model_shape}")
            probe = self._onnx.run(as_model_input(x[:1]))
            self._output_kind = "probabilities" if looks_like_probabilities(probe) else "logits"
        if probe.ndim != 2 or probe.shape[1] != len(self._class_names):
            raise UnsupportedArtifact(f"shape_mismatch: model emits {probe.shape[1:]} outputs, manifest declares "
                                      f"{len(self._class_names)} classes")
        if self._onnx is not None:
            self._convert_onnx(x)
        self._manifest = model_manifest(
            f"uploaded model {self._path.name}",
            name=self._name, modality=self._domain, format=self._format, sha256=self._sha256,
            size_bytes=self._path.stat().st_size, architecture_id=self._arch_id, input_shape=list(sample_shape),
            n_classes=len(self._class_names), class_names=self._class_names,
            dataset_id=self._dataset["dataset_id"], dataset_revision=self._dataset["dataset_revision"],
            dataset_split=self._dataset["dataset_split"], status="available",
            gradients=self._module is not None or self._torch_module is not None, bundled=False,
            license=self._dataset["license"],
        )
        self._x, self._y, self._indices = x, y.astype(np.int64), idx

    def _convert_onnx(self, x: np.ndarray) -> None:
        """onnx2torch conversion + argmax agreement on the evaluation slice (spec 9.2, onnx row)."""
        assert self._onnx is not None
        module, record = convert_onnx_to_torch(self._onnx)
        if module is None:
            self._conversion, self._agreement = record, None
            return
        agreement = onnx_torch_argmax_agreement(self._onnx, module, x)
        self._agreement = agreement
        rate = agreement.get("agreement")
        if rate is None:
            record = {**record, "status": "failed",
                      "reason": f"converted module failed on the evaluation slice: {agreement.get('error')}"}
            module = None
        elif rate < MIN_ONNX_TORCH_AGREEMENT:
            record = {**record, "status": "disagreement",
                      "reason": (f"converted module agrees with onnxruntime on {agreement['n_agree']}/{agreement['n']} "
                                 f"rows ({rate:.4f}), below the {MIN_ONNX_TORCH_AGREEMENT} floor; gradients not offered")}
            module = None
        self._conversion, self._torch_module = record, module

    def sample(self, n: int, seed: int) -> Sample:
        self.load()
        assert self._x is not None and self._y is not None
        return stratified_sample(self._x, self._y, n, seed, self._class_names, source_indices=self._indices)

    @staticmethod
    def _torch_logits(module: Any, x: np.ndarray) -> np.ndarray:
        import torch

        with torch.no_grad():
            out = module(torch.from_numpy(np.ascontiguousarray(x, dtype=np.float32)))
        return np.asarray(out.cpu().numpy())

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        """Class probabilities. ONNX uploads always predict through onnxruntime (the reference runtime)."""
        self.load()
        xin = as_model_input(np.asarray(x))
        outs = []
        for start in range(0, xin.shape[0], 256):
            batch = xin[start:start + 256]
            if self._module is not None:
                outs.append(_softmax(self._torch_logits(self._module, batch)))
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
            module = self._module if self._module is not None else self._torch_module
            if module is not None:
                from art.estimators.classification import PyTorchClassifier
                from torch import nn

                self._clf = PyTorchClassifier(model=module, loss=nn.CrossEntropyLoss(), input_shape=shape,
                                              nb_classes=len(self._class_names), clip_values=(0.0, 1.0),
                                              device_type="cpu")
            else:
                from art.estimators.classification import BlackBoxClassifier

                self._clf = BlackBoxClassifier(predict_fn=self.predict_proba, input_shape=shape,
                                               nb_classes=len(self._class_names), clip_values=(0.0, 1.0))
        return self._clf

    def torch_model(self) -> Any:
        """The differentiable module: the loaded state_dict architecture, or the agreeing onnx2torch conversion.

        ``None`` for an ONNX upload that could not be converted -- never faked.
        """
        self.load()
        return self._module if self._module is not None else self._torch_module

    def manifest(self) -> dict[str, Any]:
        """The ``schema.MLModelManifest`` fields (validated at load) plus upload-specific provenance."""
        self.load()
        assert self._y is not None and self._manifest is not None
        m: dict[str, Any] = {
            "source": "uploaded", "file": self._path.name, "architecture_kwargs": self._arch_kwargs or None,
            "input_preprocessing": None if self._prep.is_identity and self._prep.layout is None else self._prep.record(),
            **(self._state_dict_record or {}),
            "eval_n": int(self._y.shape[0]), "eval_per_class": per_class_counts(self._y, self._class_names),
            "library_versions": {**library_versions(
                "torch", "safetensors", "onnx", "onnxruntime", "onnx2torch", "adversarial-robustness-toolbox",
            ),
                                 "python": platform.python_version()},
            "onnx_torch_argmax_agreement": self._agreement,
            **self._manifest,
        }
        if self._onnx is not None:
            converted = self._torch_module is not None
            m["onnx"] = {"ir_version": self._onnx.ir_version, "opsets": self._onnx.opsets,
                         "output_kind": self._output_kind,
                         "input_layout": self._onnx.input_layout,
                         "graph_input_shape": [d if d is None else int(d) for d in self._onnx.graph_input_shape],
                         "estimator": "PyTorchClassifier" if converted else "BlackBoxClassifier",
                         "predictions": "onnxruntime",
                         "conversion": self._conversion,
                         "onnx_torch_argmax_agreement": self._agreement,
                         "note": ("gradients come from the onnx2torch conversion; its argmax agreement with "
                                  "onnxruntime on the evaluation slice is recorded above" if converted else
                                  "no differentiable module: white-box attacks are not available for this ONNX "
                                  "upload and are reported as not run (unsupported_onnx_op)")}
        return m


__all__ = [
    "ACCEPTED_FORMATS",
    "AGREEMENT_MAX_N",
    "ARCHITECTURES",
    "ARCHITECTURE_ALIASES",
    "MIN_ONNX_TORCH_AGREEMENT",
    "PICKLE_SUFFIXES",
    "INPUT_LAYOUTS",
    "STATE_DICT_LAYOUTS",
    "ArtifactTarget",
    "InputPreprocessing",
    "OnnxModel",
    "adapt_state_dict_layout",
    "architecture_ids",
    "canonical_architecture_id",
    "consumed_eval_slice",
    "convert_onnx_to_torch",
    "detect_format",
    "library_versions",
    "load_onnx_model",
    "load_state_dict_module",
    "load_state_dict_module_with_record",
    "looks_like_probabilities",
    "make_input_adapter",
    "model_manifest",
    "onnx_torch_argmax_agreement",
    "parse_input_preprocessing",
    "resolve_architecture",
    "sha256_file",
    "sniff_format",
    "sniff_input_layout",
    "verify_sha256",
]
