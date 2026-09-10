"""Artifact loader refusals and round trips (spec sections 9.2, 9.5, 22.3 ``test_loader_refusals``)."""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any

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
    with pytest.raises(UnsupportedArtifact, match="format_mismatch"):
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
    assert {"small_cnn", "smallcnn", "resnet18"} <= set(artifact.architecture_ids())
    assert artifact.canonical_architecture_id("smallcnn") == "small_cnn"
    assert artifact.canonical_architecture_id("resnet18") == "resnet18"
    with pytest.raises(UnsupportedArtifact, match="architecture_required"):
        artifact.load_state_dict_module(p, None)
    with pytest.raises(UnsupportedArtifact, match="architecture_not_allowlisted"):
        artifact.load_state_dict_module(p, "resnet_from_the_internet")


def test_allowlist_resolves_aliases_and_the_builders_architecture_block() -> None:
    from redsim.ml.targets.architectures import ResNet18, SmallCNN

    block = {"architecture_id": "small_cnn", "in_channels": 3, "n_classes": 3, "image_size": 8}
    for spelling in ("small_cnn", "smallcnn"):
        module = artifact.resolve_architecture(spelling, dict(block))
        assert isinstance(module, SmallCNN) and module.n_classes == 3 and module.image_size == 8
    assert isinstance(artifact.resolve_architecture("resnet18", {"n_classes": 3, "image_size": 8}), ResNet18)
    with pytest.raises(UnsupportedArtifact, match="architecture_mismatch"):
        artifact.resolve_architecture("resnet18", dict(block))          # block names another architecture
    with pytest.raises(UnsupportedArtifact, match="rejected its kwargs"):
        artifact.resolve_architecture("small_cnn", {"n_classes": 1})    # SmallCNN refuses n_classes < 2
    # A state_dict saved from small_cnn loads under the alias with the builder's architecture block as kwargs.
    net = SmallCNN(in_channels=3, n_classes=3, image_size=8).eval()
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "small.pt"
        torch.save(net.state_dict(), path)
        loaded = artifact.load_state_dict_module(path, "smallcnn", net.architecture_config())
    assert isinstance(loaded, SmallCNN)
    x = torch.rand(2, 3, 8, 8)
    with torch.no_grad():
        assert torch.allclose(loaded(x), net(x))


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


def test_safetensors_round_trip(
    tmp_path: Path,
    tinynet_arch: str,
    eval_data: tuple[np.ndarray, np.ndarray],
) -> None:
    save_file = pytest.importorskip("safetensors.torch").save_file
    net = _TinyNet(9).eval()
    path = tmp_path / "model.safetensors"
    save_file(net.state_dict(), str(path))
    assert artifact.detect_format(path, "safetensors_state_dict") == "safetensors_state_dict"
    target = ArtifactTarget(
        "safe-1",
        path,
        class_names=list(CLASS_NAMES),
        eval_data=eval_data,
        dataset_id=DATASET,
        architecture_id=tinynet_arch,
        declared_format="safetensors_state_dict",
    )
    target.load()
    assert target.manifest()["format"] == "safetensors_state_dict"
    assert target.info().metadata["gradients"] is True


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
# ONNX path (onnxruntime predictions; onnx2torch conversion for gradients, agreement recorded)
# ----------------------------------------------------------------------------------------

def test_onnx_round_trip_with_onnx2torch_gradients(tmp_path: Path, eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    pytest.importorskip("onnx2torch")
    net = _TinyNet(7).eval()
    p = _onnx_file(tmp_path / "tiny.onnx", net)
    assert artifact.detect_format(p, "onnx") == "onnx"
    t = ArtifactTarget("onnx1", p, class_names=list(CLASS_NAMES), eval_data=eval_data, dataset_id=DATASET,
                       declared_format="onnx", license="test fixture")
    assert t.info().metadata["gradients"] is None      # unknown until the conversion has been attempted
    t.load()
    x, _ = eval_data
    proba = t.predict_proba(x)
    with torch.no_grad():
        ref = torch.softmax(net(torch.from_numpy(x)), dim=1).numpy()
    assert proba.shape == (30, 3) and np.allclose(proba, ref, atol=1e-4)
    assert np.array_equal(proba.argmax(1), ref.argmax(1))
    clf = t.art_classifier()
    assert type(clf).__name__ == "PyTorchClassifier" and clf.nb_classes == 3 and clf.input_shape == (3, 8, 8)
    assert clf.predict(x[:5]).shape == (5, 3)
    grad = clf.loss_gradient(x[:4], np.eye(3, dtype=np.float32)[[0, 1, 2, 0]])
    assert grad.shape == (4, 3, 8, 8) and np.isfinite(grad).all()
    module = t.torch_model()
    assert isinstance(module, nn.Module) and not module.training
    with torch.no_grad():
        assert np.allclose(module(torch.from_numpy(x)).numpy(), net(torch.from_numpy(x)).numpy(), atol=1e-4)
    m = t.manifest()
    assert m["format"] == "onnx" and m["gradients"] is True
    assert m["onnx"]["opsets"].get("ai.onnx") == 17 and m["onnx"]["output_kind"] == "logits"
    assert m["onnx"]["estimator"] == "PyTorchClassifier" and m["onnx"]["predictions"] == "onnxruntime"
    assert m["onnx"]["conversion"]["status"] == "converted" and m["onnx"]["conversion"]["converter"] == "onnx2torch"
    agreement = m["onnx_torch_argmax_agreement"]
    assert agreement == {"n": 30, "n_agree": 30, "agreement": 1.0} == m["onnx"]["onnx_torch_argmax_agreement"]
    assert m["library_versions"]["onnx2torch"] != "not installed"
    mm = MLModelManifest.model_validate(m)
    assert mm.format == "onnx" and mm.gradients is True and mm.architecture_id is None and mm.bundled is False
    assert mm.sha256 == artifact.sha256_file(p) and mm.size_bytes == p.stat().st_size and mm.input_shape == [3, 8, 8]
    assert mm.dataset_id == DATASET and mm.dataset_split == "test" and mm.license == "test fixture"
    info = t.info()
    assert info.metadata["gradients"] is True and info.metadata["onnx_torch_argmax_agreement"] == agreement


def test_onnx_without_onnx2torch_stays_black_box(tmp_path: Path, eval_data: tuple[np.ndarray, np.ndarray],
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "onnx2torch", None)     # simulate the converter being absent
    p = _onnx_file(tmp_path / "tiny.onnx", _TinyNet(7).eval())
    t = ArtifactTarget("onnx2", p, class_names=list(CLASS_NAMES), eval_data=eval_data, dataset_id=DATASET,
                       declared_format="onnx")
    t.load()
    assert type(t.art_classifier()).__name__ == "BlackBoxClassifier"
    assert t.torch_model() is None                        # no differentiable module is faked
    m = t.manifest()
    assert m["gradients"] is False and m["onnx_torch_argmax_agreement"] is None
    assert m["onnx"]["estimator"] == "BlackBoxClassifier" and m["onnx"]["conversion"]["status"] == "unavailable"
    assert "onnx2torch" in m["onnx"]["conversion"]["reason"] and "not run" in m["onnx"]["note"]
    assert MLModelManifest.model_validate(m).gradients is False and t.info().metadata["gradients"] is False


def test_onnx_conversion_failure_and_disagreement_are_recorded_not_hidden(
        tmp_path: Path, eval_data: tuple[np.ndarray, np.ndarray], monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("onnx2torch")
    p = _onnx_file(tmp_path / "tiny.onnx", _TinyNet(7).eval())

    def failing(model):  # the converter rejects an operator
        return None, {"status": "failed", "reason": "unsupported_onnx_op: NotImplementedError: Frobnicate",
                      "converter": "onnx2torch", "version": "x"}

    monkeypatch.setattr(artifact, "convert_onnx_to_torch", failing)
    t = ArtifactTarget("onnx3", p, class_names=list(CLASS_NAMES), eval_data=eval_data, dataset_id=DATASET)
    t.load()
    m = t.manifest()
    assert m["gradients"] is False and m["onnx"]["conversion"]["status"] == "failed"
    assert "unsupported_onnx_op" in m["onnx"]["conversion"]["reason"] and t.torch_model() is None
    assert type(t.art_classifier()).__name__ == "BlackBoxClassifier"

    monkeypatch.undo()
    monkeypatch.setattr(artifact, "onnx_torch_argmax_agreement",
                        lambda model, module, x, max_n=artifact.AGREEMENT_MAX_N: {"n": 30, "n_agree": 21,
                                                                                  "agreement": 0.7})
    t2 = ArtifactTarget("onnx4", p, class_names=list(CLASS_NAMES), eval_data=eval_data, dataset_id=DATASET)
    t2.load()
    m2 = t2.manifest()
    assert m2["onnx"]["conversion"]["status"] == "disagreement" and "21/30" in m2["onnx"]["conversion"]["reason"]
    assert m2["onnx_torch_argmax_agreement"] == {"n": 30, "n_agree": 21, "agreement": 0.7}   # recorded as measured
    assert m2["gradients"] is False and t2.torch_model() is None
    assert type(t2.art_classifier()).__name__ == "BlackBoxClassifier"


def test_missing_eval_slice_path_is_dataset_unavailable(tmp_path: Path, tinynet_arch: str) -> None:
    from redsim.ml import errors

    p, _ = _state_dict_file(tmp_path / "m.pt")
    t = ArtifactTarget("nodata", p, class_names=list(CLASS_NAMES), eval_data=tmp_path / "absent.npz",
                       dataset_id=DATASET, architecture_id=tinynet_arch)
    with pytest.raises(errors.DatasetUnavailable, match="not found"):
        t.load()


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


# ----------------------------------------------------------------------------------------
# open-weights contracts: bare torchvision key layout, declared input preprocessing, NHWC graphs
# ----------------------------------------------------------------------------------------


def _catalog_resnet(n_classes: int = 3, image_size: int = 8) -> Any:
    from redsim.ml.targets.architectures import ResNet18

    torch.manual_seed(0)
    return ResNet18(in_channels=3, n_classes=n_classes, image_size=image_size).eval()


def test_bare_torchvision_state_dict_is_remapped_onto_the_catalog_resnet(
    tmp_path: Path, eval_data: tuple[np.ndarray, np.ndarray],
) -> None:
    """A Hugging Face / timm ``model.safetensors`` names ``conv1.weight`` .. ``fc.bias`` without the
    ``backbone.`` prefix and without the normalisation buffers; the loader prefixes the keys, keeps the
    identity buffers and records ``state_dict_layout: torchvision``. Predictions equal the backbone's."""
    from safetensors.torch import save_file

    net = _catalog_resnet()
    bare = {k: v.contiguous() for k, v in net.backbone.state_dict().items()}
    assert not any(k.startswith("backbone.") for k in bare) and "input_mean" not in bare
    path = tmp_path / "model.safetensors"
    save_file(bare, str(path))

    module, record = artifact.load_state_dict_module_with_record(path, "resnet18", net.architecture_config(),
                                                                artifact_format="safetensors_state_dict")
    assert record == {"state_dict_layout": "torchvision", "n_tensors": len(bare) + 2}
    x, y = eval_data
    with torch.no_grad():
        want = net.backbone(torch.from_numpy(x[:4])).numpy()
        got = module(torch.from_numpy(x[:4])).numpy()
    np.testing.assert_allclose(got, want, atol=1e-5)

    target = ArtifactTarget("hf", path, class_names=CLASS_NAMES, eval_data=eval_data, dataset_id=DATASET,
                            declared_format="safetensors_state_dict", architecture_id="resnet18")
    target.load()
    manifest = target.manifest()
    assert manifest["state_dict_layout"] == "torchvision" and manifest["gradients"] is True
    assert manifest["input_preprocessing"] is None
    MLModelManifest.model_validate({k: v for k, v in manifest.items() if k in MLModelManifest.model_fields})


def test_redsim_layout_state_dict_still_loads_and_records_its_layout(tmp_path: Path) -> None:
    net = _catalog_resnet()
    path = tmp_path / "model.pt"
    torch.save(net.state_dict(), path)
    module, record = artifact.load_state_dict_module_with_record(path, "resnet18", net.architecture_config())
    assert record["state_dict_layout"] == "redsim"
    assert set(module.state_dict()) == set(net.state_dict())


def test_partial_bare_state_dict_is_still_an_architecture_mismatch(tmp_path: Path) -> None:
    """Only a one-to-one key match earns the remap; a checkpoint missing tensors names the mismatch."""
    from safetensors.torch import save_file

    net = _catalog_resnet()
    bare = {k: v.contiguous() for k, v in net.backbone.state_dict().items()}
    bare.pop("fc.bias")
    path = tmp_path / "partial.safetensors"
    save_file(bare, str(path))
    with pytest.raises(UnsupportedArtifact, match="architecture_mismatch"):
        artifact.load_state_dict_module(path, "resnet18", net.architecture_config(),
                                        artifact_format="safetensors_state_dict")


def test_declared_preprocessing_wraps_the_state_dict_module(tmp_path: Path, tinynet_arch: str,
                                                            eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    """``resize``, ``scale`` and mean / std sit inside the model boundary: the estimator still takes
    the evaluation slice's [0, 1] NCHW shape and gradients flow back to those pixels."""
    path, net = _state_dict_file(tmp_path / "tiny.pt")
    prep = {"scale": 255, "mean": [127.5, 127.5, 127.5], "std": [63.75, 63.75, 63.75]}
    target = ArtifactTarget("t", path, class_names=CLASS_NAMES, eval_data=eval_data, dataset_id=DATASET,
                            architecture_id=tinynet_arch, input_preprocessing=prep)
    target.load()
    x, _ = eval_data
    want_in = (torch.from_numpy(x[:5]) * 255 - 127.5) / 63.75
    with torch.no_grad():
        want = torch.softmax(net(want_in), dim=1).numpy()
    np.testing.assert_allclose(target.predict_proba(x[:5]), want, atol=1e-5)
    clf = target.art_classifier()
    assert type(clf).__name__ == "PyTorchClassifier" and tuple(clf.input_shape) == (3, 8, 8)
    grads = clf.loss_gradient(x[:2], np.eye(3, dtype=np.float32)[[0, 1]])
    assert grads.shape == (2, 3, 8, 8) and np.isfinite(grads).all()
    manifest = target.manifest()
    assert manifest["input_preprocessing"] == {"scale": 255.0, "mean": [127.5] * 3, "std": [63.75] * 3,
                                               "resize": None, "layout": None}
    assert manifest["input_shape"] == [3, 8, 8]


def test_declared_resize_upsamples_before_the_module(tmp_path: Path, eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    """The evaluation slice stays 8x8 (eps keeps its meaning); the module sees 16x16 bilinear upsamples."""
    from safetensors.torch import save_file

    net = _catalog_resnet(image_size=16)
    path = tmp_path / "model.safetensors"
    save_file({k: v.contiguous() for k, v in net.state_dict().items()}, str(path))
    target = ArtifactTarget("r", path, class_names=CLASS_NAMES, eval_data=eval_data, dataset_id=DATASET,
                            declared_format="safetensors_state_dict", architecture_id="resnet18",
                            input_preprocessing={"resize": 16})
    target.load()
    x, _ = eval_data
    up = torch.nn.functional.interpolate(torch.from_numpy(x[:3]), size=(16, 16), mode="bilinear", align_corners=False)
    with torch.no_grad():
        want = torch.softmax(net(up), dim=1).numpy()
    np.testing.assert_allclose(target.predict_proba(x[:3]), want, atol=1e-5)
    assert target.manifest()["input_shape"] == [3, 8, 8]
    assert target.manifest()["architecture_kwargs"]["image_size"] == 16


@pytest.mark.parametrize(
    ("block", "match"),
    [
        ({"scale": 0}, "scale must be > 0"),
        ({"mean": [0.5, 0.5, 0.5]}, "come together"),
        ({"mean": [0.5, 0.5], "std": [0.2, 0.2]}, "1 or 3 matching"),
        ({"mean": [0.5], "std": [0.0]}, "std must be > 0"),
        ({"resize": 4}, "resize must be within"),
        ({"resize": 2048}, "resize must be within"),
        ({"layout": "CHWN"}, "layout must be one of"),
        ({"gamma": 2.2}, "unknown keys"),
        ({"scale": float("nan")}, "finite"),
    ],
)
def test_input_preprocessing_refusals_are_params_out_of_range(block: dict[str, Any], match: str) -> None:
    with pytest.raises(UnsupportedArtifact, match=f"params_out_of_range: .*{match}"):
        artifact.parse_input_preprocessing(block)


def test_nhwc_layout_is_refused_for_a_state_dict(tmp_path: Path, tinynet_arch: str,
                                                 eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    path, _ = _state_dict_file(tmp_path / "tiny.pt")
    target = ArtifactTarget("t", path, class_names=CLASS_NAMES, eval_data=eval_data, dataset_id=DATASET,
                            architecture_id=tinynet_arch, input_preprocessing={"layout": "nhwc"})
    with pytest.raises(UnsupportedArtifact, match="params_out_of_range: .*NHWC applies to ONNX"):
        target.load()


class _ChannelsLast(nn.Module):
    """A graph exported from a channels-last framework: consumes NHWC, scaled 0-255 pixels."""

    def __init__(self, net: nn.Module) -> None:
        super().__init__()
        self.net = net

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x.permute(0, 3, 1, 2) / 255.0)


def _nhwc_onnx_file(path: Path, net: nn.Module) -> Path:
    torch.onnx.export(_ChannelsLast(net).eval(), (torch.zeros(1, 8, 8, 3),), str(path), input_names=["input_1"],
                      output_names=["logits"], dynamic_axes={"input_1": {0: "n"}, "logits": {0: "n"}},
                      opset_version=17, dynamo=False)
    return path


def test_nhwc_onnx_graph_is_sniffed_permuted_and_converted(tmp_path: Path,
                                                            eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    """A ``[N, H, W, C]`` graph (the MLCommons tiny CIFAR-10 export shape) is served through a permute in
    front of the session and of the onnx2torch conversion; ``input_shape`` reads ``(C, H, W)``."""
    pytest.importorskip("onnx2torch")
    _, net = _state_dict_file(tmp_path / "tiny.pt")
    path = _nhwc_onnx_file(tmp_path / "nhwc.onnx", net)
    model = artifact.load_onnx_model(path)
    assert model.input_layout == "NHWC" and model.graph_input_shape == (8, 8, 3) and model.input_shape == (3, 8, 8)

    target = ArtifactTarget("nhwc", path, class_names=CLASS_NAMES, eval_data=eval_data, dataset_id=DATASET,
                            declared_format="onnx", input_preprocessing={"scale": 255})
    target.load()
    x, _ = eval_data
    with torch.no_grad():
        want = torch.softmax(net(torch.from_numpy(x[:6])), dim=1).numpy()
    np.testing.assert_allclose(target.predict_proba(x[:6]), want, atol=1e-4)
    manifest = target.manifest()
    assert manifest["onnx"]["input_layout"] == "NHWC" and manifest["onnx"]["graph_input_shape"] == [8, 8, 3]
    assert manifest["onnx_torch_argmax_agreement"]["agreement"] == 1.0 and manifest["gradients"] is True
    assert manifest["input_preprocessing"]["scale"] == 255.0
    clf = target.art_classifier()
    assert type(clf).__name__ == "PyTorchClassifier" and tuple(clf.input_shape) == (3, 8, 8)
    grads = clf.loss_gradient(x[:2], np.eye(3, dtype=np.float32)[[0, 1]])
    assert grads.shape == (2, 3, 8, 8) and np.isfinite(grads).all()


def test_nhwc_graph_without_the_declared_scale_still_loads_but_predicts_differently(
    tmp_path: Path, eval_data: tuple[np.ndarray, np.ndarray],
) -> None:
    """No contract is guessed: without ``scale`` the graph receives [0, 1] pixels and the accuracy the
    validate job records is the honest one for that contract."""
    _, net = _state_dict_file(tmp_path / "tiny.pt")
    path = _nhwc_onnx_file(tmp_path / "nhwc.onnx", net)
    target = ArtifactTarget("nhwc", path, class_names=CLASS_NAMES, eval_data=eval_data, dataset_id=DATASET,
                            declared_format="onnx")
    target.load()
    x, _ = eval_data
    with torch.no_grad():
        scaled = torch.softmax(net(torch.from_numpy(x[:6])), dim=1).numpy()
        unscaled = torch.softmax(net(torch.from_numpy(x[:6]) / 255.0), dim=1).numpy()
    np.testing.assert_allclose(target.predict_proba(x[:6]), unscaled, atol=1e-4)
    assert not np.allclose(unscaled, scaled, atol=1e-3)
    assert target.manifest()["input_preprocessing"] is None


def test_explicit_layout_overrides_the_sniffed_one(tmp_path: Path, eval_data: tuple[np.ndarray, np.ndarray]) -> None:
    """An NCHW graph whose spatial dims happen to be 1 or 3 would sniff as NHWC; the uploader's word wins."""
    _, net = _state_dict_file(tmp_path / "tiny.pt")
    path = _onnx_file(tmp_path / "nchw.onnx", net)
    forced = artifact.load_onnx_model(path, preprocessing=artifact.parse_input_preprocessing({"layout": "NCHW"}))
    assert forced.input_layout == "NCHW" and forced.preprocess is None
    wrong = artifact.load_onnx_model(path, preprocessing=artifact.parse_input_preprocessing({"layout": "NHWC"}))
    assert wrong.input_layout == "NHWC" and wrong.input_shape == (8, 3, 8)
    target = ArtifactTarget("x", path, class_names=CLASS_NAMES, eval_data=eval_data, dataset_id=DATASET,
                            declared_format="onnx", input_preprocessing={"layout": "NHWC"})
    with pytest.raises(UnsupportedArtifact, match="shape_mismatch: ONNX input .*NHWC graph"):
        target.load()


def test_sniff_input_layout() -> None:
    assert artifact.sniff_input_layout((3, 32, 32)) == "NCHW"
    assert artifact.sniff_input_layout((32, 32, 3)) == "NHWC"
    assert artifact.sniff_input_layout((None, None, 3)) == "NHWC"
    assert artifact.sniff_input_layout((3, 3, 3)) == "NCHW"
    assert artifact.sniff_input_layout((1, 28, 28)) == "NCHW"
    assert artifact.sniff_input_layout((30,)) == "NCHW"
