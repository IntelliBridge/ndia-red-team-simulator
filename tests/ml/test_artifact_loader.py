"""Artifact loader refusals and round trips (spec sections 9.2, 9.5, 22.3 ``test_loader_refusals``)."""

from __future__ import annotations

import pickle
from pathlib import Path

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("onnx")
pytest.importorskip("onnxruntime")
pytest.importorskip("art")

import numpy as np
import onnx
import torch
from torch import nn

from redsim.ml.errors import UnsupportedArtifact
from redsim.ml.schema import MLModelManifest
from redsim.ml.targets import artifact
from redsim.ml.targets.artifact import ArtifactTarget
from redsim.ml.targets.base import Target
from tests.ml.fakes import CLASS_NAMES, _TinyNet

DATASET = "synthetic/eval"        # every upload is bound to a dataset slice at registration (spec 5.5)

pytestmark = [
    pytest.mark.ml,
    # The tests export with the TorchScript exporter on purpose (deterministic opset 17 graph); torch 2.9+
    # flags it as legacy.
    pytest.mark.filterwarnings("ignore:.*ONNX export.*:DeprecationWarning"),
    pytest.mark.filterwarnings("ignore:The feature will be removed:DeprecationWarning"),
]


@pytest.fixture
def tinynet_arch(monkeypatch: pytest.MonkeyPatch) -> str:
    """Inject a tiny module into the architecture allowlist for the duration of a test."""
    monkeypatch.setitem(artifact.ARCHITECTURES, "tinynet", lambda **kw: _TinyNet(**kw))
    return "tinynet"


@pytest.fixture
def eval_data() -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(1)
    return rng.random((30, 3, 8, 8), dtype=np.float32), rng.integers(0, 3, size=30)


def _state_dict_file(path: Path, seed: int = 0) -> tuple[Path, _TinyNet]:
    net = _TinyNet(seed).eval()
    torch.save(net.state_dict(), path)
    return path, net


def _onnx_file(path: Path, net: nn.Module) -> Path:
    torch.onnx.export(net, (torch.zeros(1, 3, 8, 8),), str(path), input_names=["input"], output_names=["logits"],
                      dynamic_axes={"input": {0: "n"}, "logits": {0: "n"}}, opset_version=17, dynamo=False)
    return path


# ----------------------------------------------------------------------------------------
# signature sniffing: refused before any deserialisation
# ----------------------------------------------------------------------------------------

def test_pickle_extension_refused(tmp_path: Path) -> None:
    for name in ("model.pkl", "model.joblib", "model.pickle"):
        p = tmp_path / name
        p.write_bytes(b"PK\x03\x04 pretend zip")       # even a zip signature does not rescue a .pkl name
        with pytest.raises(UnsupportedArtifact, match="pickle_refused"):
            artifact.sniff_format(p)


def test_pickle_opcode_refused(tmp_path: Path) -> None:
    p = tmp_path / "model.bin"
    p.write_bytes(pickle.dumps({"a": 1}))
    assert p.read_bytes()[0] == 0x80
    with pytest.raises(UnsupportedArtifact, match="pickle_refused"):
        artifact.sniff_format(p)


def test_unknown_signature_and_declaration_mismatch_refused(tmp_path: Path) -> None:
    p = tmp_path / "model.bin"
    p.write_bytes(b"hello world")
    with pytest.raises(UnsupportedArtifact, match="unsupported_model_format"):
        artifact.sniff_format(p)
    (tmp_path / "empty.onnx").write_bytes(b"")
    with pytest.raises(UnsupportedArtifact, match="unsupported_model_format"):
        artifact.sniff_format(tmp_path / "empty.onnx")
    sd, _ = _state_dict_file(tmp_path / "m.pt")
    assert artifact.detect_format(sd) == "torch_state_dict"
    with pytest.raises(UnsupportedArtifact, match="format_mismatch"):
        artifact.detect_format(sd, "onnx")
    with pytest.raises(UnsupportedArtifact, match="unsupported_model_format"):
        artifact.detect_format(sd, "safetensors_state_dict")
    with pytest.raises(UnsupportedArtifact, match="not found"):
        artifact.sniff_format(tmp_path / "nope.pt")


# ----------------------------------------------------------------------------------------
# torch state_dict path
# ----------------------------------------------------------------------------------------

def test_full_pickled_module_refused_by_weights_only(tmp_path: Path, tinynet_arch: str) -> None:
    p = tmp_path / "full_module.pt"
    torch.save(_TinyNet(0), p)                        # a full pickle inside a zip archive
    assert artifact.sniff_format(p) == "torch_state_dict"   # the signature alone cannot tell
    with pytest.raises(UnsupportedArtifact, match="pickle_refused"):
        artifact.load_state_dict_module(p, tinynet_arch)


def test_state_dict_with_non_tensor_global_refused(tmp_path: Path, tinynet_arch: str) -> None:
    state = dict(_TinyNet(0).state_dict())
    state["extra"] = nn.Linear(2, 2)
    p = tmp_path / "poisoned.pt"
    torch.save(state, p)
    with pytest.raises(UnsupportedArtifact, match="pickle_refused"):
        artifact.load_state_dict_module(p, tinynet_arch)


def test_state_dict_requires_allowlisted_architecture(tmp_path: Path) -> None:
    p, _ = _state_dict_file(tmp_path / "m.pt")
    assert "smallcnn" in artifact.architecture_ids()
    with pytest.raises(UnsupportedArtifact, match="architecture_required"):
        artifact.load_state_dict_module(p, None)
    with pytest.raises(UnsupportedArtifact, match="architecture_not_allowlisted"):
        artifact.load_state_dict_module(p, "resnet_from_the_internet")


def test_state_dict_architecture_mismatch_refused(tmp_path: Path, tinynet_arch: str) -> None:
    p = tmp_path / "linear.pt"
    torch.save(nn.Linear(2, 2).state_dict(), p)
    with pytest.raises(UnsupportedArtifact, match="architecture_mismatch"):
        artifact.load_state_dict_module(p, tinynet_arch)


def test_sha256_mismatch_refused(tmp_path: Path, tinynet_arch: str,
                                 eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    p, _ = _state_dict_file(tmp_path / "m.pt")
    t = ArtifactTarget("up1", p, class_names=list(CLASS_NAMES), eval_data=eval_data, dataset_id=DATASET,
                       architecture_id=tinynet_arch, expected_sha256="00" * 32)
    with pytest.raises(UnsupportedArtifact, match="hash_mismatch"):
        t.load()
    assert artifact.verify_sha256(p, artifact.sha256_file(p)) == artifact.sha256_file(p)
    assert artifact.verify_sha256(p, artifact.sha256_file(p).upper()) == artifact.sha256_file(p)


def test_state_dict_round_trip(tmp_path: Path, tinynet_arch: str, eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    p, net = _state_dict_file(tmp_path / "m.pt", seed=4)
    t = ArtifactTarget("up2", p, class_names=list(CLASS_NAMES), eval_data=eval_data, architecture_id=tinynet_arch,
                       declared_format="torch_state_dict", expected_sha256=artifact.sha256_file(p),
                       dataset_id="synthetic", dataset_split="eval")
    assert isinstance(t, Target)
    t.load()
    t.load()                                          # idempotent
    x, y = eval_data
    proba = t.predict_proba(x)
    with torch.no_grad():
        ref = torch.softmax(net(torch.from_numpy(x)), dim=1).numpy()
    assert proba.shape == (30, 3) and np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)
    assert np.allclose(proba, ref, atol=1e-5)
    s = t.sample(12, seed=0)
    assert s.x.shape == (12, 3, 8, 8) and np.array_equal(s.indices, t.sample(12, seed=0).indices)
    clf = t.art_classifier()
    assert type(clf).__name__ == "PyTorchClassifier" and clf.nb_classes == 3 and clf.input_shape == (3, 8, 8)
    assert tuple(clf.clip_values) == (0.0, 1.0)
    assert isinstance(t.torch_model(), nn.Module)
    m = t.manifest()
    assert m["format"] == "torch_state_dict" and m["gradients"] is True and m["sha256"] == artifact.sha256_file(p)
    assert m["eval_per_class"] == {c: int((y == i).sum()) for i, c in enumerate(CLASS_NAMES)}
    assert "torch" in m["library_versions"]
    mm = MLModelManifest.model_validate(m)                     # the schema block is a valid spec 5.5 manifest
    assert mm.format == "torch_state_dict" and mm.architecture_id == tinynet_arch and mm.bundled is False
    assert mm.size_bytes == p.stat().st_size and mm.input_shape == [3, 8, 8] and mm.n_classes == 3
    assert mm.class_names == list(CLASS_NAMES) and mm.dataset_id == "synthetic" and mm.dataset_split == "eval"
    assert mm.clean_accuracy is None                           # an upload has no build-time accuracy; the campaign measures it
    assert mm.status == "available" and mm.gradients is True and mm.refusal_reason is None
    assert mm.manifest_sha256 and m["manifest_sha256"] == mm.manifest_sha256
    info = t.info()
    assert info.status == "available" and info.metadata["gradients"] is True and info.metadata["loaded"] is True


def test_artifact_target_requires_a_dataset_binding(tmp_path: Path, tinynet_arch: str,
                                                    eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    p, _ = _state_dict_file(tmp_path / "m.pt")
    with pytest.raises(TypeError):
        ArtifactTarget("nods", p, class_names=list(CLASS_NAMES), eval_data=eval_data,  # type: ignore[call-arg]
                       architecture_id=tinynet_arch)
    with pytest.raises(ValueError, match="dataset_id"):
        ArtifactTarget("nods", p, class_names=list(CLASS_NAMES), eval_data=eval_data, architecture_id=tinynet_arch,
                       dataset_id="  ")


def test_eval_data_from_npz_path(tmp_path: Path, tinynet_arch: str, eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    p, _ = _state_dict_file(tmp_path / "m.pt")
    x, y = eval_data
    split = tmp_path / "eval.npz"
    np.savez(split, x=x, y=y, indices=np.arange(100, 130))
    t = ArtifactTarget("up3", p, class_names=list(CLASS_NAMES), eval_data=split, dataset_id=DATASET,
                       architecture_id=tinynet_arch)
    s = t.sample(9, seed=0)
    assert s.indices.min() >= 100 and s.indices.max() < 130


def test_class_count_and_input_shape_mismatch_refused(tmp_path: Path, tinynet_arch: str,
                                                      eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    p, _ = _state_dict_file(tmp_path / "m.pt")
    x, y = eval_data
    with pytest.raises(UnsupportedArtifact, match="shape_mismatch"):
        ArtifactTarget("up4", p, class_names=["a", "b", "c", "d"], eval_data=(x, y), dataset_id=DATASET,
                       architecture_id=tinynet_arch).load()
    with pytest.raises(UnsupportedArtifact, match="shape_mismatch"):
        ArtifactTarget("up5", p, class_names=list(CLASS_NAMES), eval_data=(x, y), dataset_id=DATASET,
                       architecture_id=tinynet_arch, input_shape=(3, 16, 16)).load()
    with pytest.raises(UnsupportedArtifact, match="outside the declared class list"):
        ArtifactTarget("up6", p, class_names=["a", "b"], eval_data=(x, y), dataset_id=DATASET,
                       architecture_id=tinynet_arch).load()


# ----------------------------------------------------------------------------------------
# ONNX path (onnxruntime, black-box estimator, no torch conversion)
# ----------------------------------------------------------------------------------------

def test_onnx_round_trip(tmp_path: Path, eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    net = _TinyNet(7).eval()
    p = _onnx_file(tmp_path / "tiny.onnx", net)
    assert artifact.detect_format(p, "onnx") == "onnx"
    t = ArtifactTarget("onnx1", p, class_names=list(CLASS_NAMES), eval_data=eval_data, dataset_id=DATASET,
                       declared_format="onnx", license="test fixture")
    t.load()
    x, _ = eval_data
    proba = t.predict_proba(x)
    with torch.no_grad():
        ref = torch.softmax(net(torch.from_numpy(x)), dim=1).numpy()
    assert proba.shape == (30, 3) and np.allclose(proba, ref, atol=1e-4)
    assert np.array_equal(proba.argmax(1), ref.argmax(1))
    clf = t.art_classifier()
    assert type(clf).__name__ == "BlackBoxClassifier" and clf.nb_classes == 3 and clf.input_shape == (3, 8, 8)
    assert clf.predict(x[:5]).shape == (5, 3)
    assert t.torch_model() is None                     # no differentiable module is faked
    m = t.manifest()
    assert m["format"] == "onnx" and m["gradients"] is False
    assert m["onnx"]["opsets"].get("ai.onnx") == 17 and m["onnx"]["output_kind"] == "logits"
    assert m["onnx"]["estimator"] == "BlackBoxClassifier"
    mm = MLModelManifest.model_validate(m)
    assert mm.format == "onnx" and mm.gradients is False and mm.architecture_id is None and mm.bundled is False
    assert mm.sha256 == artifact.sha256_file(p) and mm.size_bytes == p.stat().st_size and mm.input_shape == [3, 8, 8]
    assert mm.dataset_id == DATASET and mm.dataset_split == "test" and mm.license == "test fixture"
    assert t.info().metadata["gradients"] is False


def test_onnx_corrupt_file_refused(tmp_path: Path, eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    p = tmp_path / "broken.onnx"
    p.write_bytes(b"\x08\x07\x12\x00garbage-not-a-model")
    assert artifact.sniff_format(p) == "onnx"
    with pytest.raises(UnsupportedArtifact, match="onnx_"):
        artifact.load_onnx_model(p)


def test_onnx_custom_op_domain_refused(tmp_path: Path) -> None:
    from onnx import TensorProto, helper

    node = helper.make_node("Frobnicate", ["input"], ["out"], domain="com.example.custom")
    graph = helper.make_graph([node], "g", [helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 4])],
                              [helper.make_tensor_value_info("out", TensorProto.FLOAT, [1, 4])])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17),
                                                    helper.make_opsetid("com.example.custom", 1)])
    p = tmp_path / "custom.onnx"
    onnx.save(model, str(p))
    with pytest.raises(UnsupportedArtifact, match="onnx_custom_op_domain"):
        artifact.load_onnx_model(p)


def test_onnx_external_data_refused(tmp_path: Path) -> None:
    from onnx.external_data_helper import convert_model_to_external_data

    net = _TinyNet(0).eval()
    model = onnx.load(str(_onnx_file(tmp_path / "inline.onnx", net)))
    convert_model_to_external_data(model, all_tensors_to_one_file=True, location="weights.bin", size_threshold=0)
    p = tmp_path / "external.onnx"
    onnx.save(model, str(p))
    with pytest.raises(UnsupportedArtifact, match="onnx_external_data"):
        artifact.load_onnx_model(p)


def test_onnx_shape_disagreements_refused(tmp_path: Path, eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    p = _onnx_file(tmp_path / "tiny.onnx", _TinyNet(0).eval())
    x, y = eval_data
    with pytest.raises(UnsupportedArtifact, match="shape_mismatch"):
        ArtifactTarget("o2", p, class_names=["a", "b", "c", "d"], eval_data=(x, y), dataset_id=DATASET).load()
    big = np.random.default_rng(0).random((30, 3, 16, 16), dtype=np.float32)
    with pytest.raises(UnsupportedArtifact, match="shape_mismatch"):
        ArtifactTarget("o3", p, class_names=list(CLASS_NAMES), eval_data=(big, y), dataset_id=DATASET).load()


def test_looks_like_probabilities() -> None:
    assert artifact.looks_like_probabilities(np.array([[0.2, 0.8], [1.0, 0.0]]))
    assert not artifact.looks_like_probabilities(np.array([[2.0, -1.0]]))
    assert not artifact.looks_like_probabilities(np.zeros((0, 3)))
