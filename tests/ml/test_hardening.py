"""Training defenses: catalog rows of kind ``training`` and the ``defense_apply`` stage on TinyTarget (spec 16.5, 16.6).

Everything runs offline on 8x8x3 inputs with a few dozen synthetic rows: a derived module is
produced within budget, its state_dict digest differs from the parent's while the parent is
untouched, the record is complete, the budget cap stops training early and is recorded, and
the tabular tree ensemble is a typed unavailable rather than a fake result.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("art")
pytest.importorskip("sklearn")

import numpy as np
import torch

from redsim.ml import defenses
from redsim.ml.artifacts import FilesystemSink
from redsim.ml.datasets.sampling import Sample
from redsim.ml.harden import apply as harden_apply
from redsim.ml.harden.apply import (
    REPORT_ARTIFACT,
    WEIGHTS_ARTIFACT,
    DerivedTorchTarget,
    TrainingDefenseUnavailable,
    TrainingRecord,
    TrainingUnavailable,
    apply_training_defense,
    assess_training_target,
    distillation_limitation,
    load_train_slice,
    resolve_training_params,
    state_dict_sha256,
    train_defense,
)
from redsim.ml.schema import CampaignConfig, DefenseConfig, ParamSpec
from redsim.ml.targets.base import Target
from tests.ml.fakes import CLASS_NAMES, TinyTabularTarget, TinyTarget

pytestmark = pytest.mark.ml

N_SLICE = 48
BUDGET_KEYS = ("epochs", "train_n", "batch_size", "lr", "backbone_frozen", "wall_budget_s")


def synthetic_slice(n: int = N_SLICE, seed: int = 7) -> Sample:
    rng = np.random.default_rng(seed)
    x = rng.random((n, 3, 8, 8), dtype=np.float32)
    y = (np.arange(n) % len(CLASS_NAMES)).astype(np.int64)
    return Sample(x=x, y=y, indices=np.arange(n), class_names=list(CLASS_NAMES))


class TinyTrainableTarget(TinyTarget):
    """TinyTarget with the ``train_sample`` accessor the bundled targets grow (ATTACKS_HARDEN-11)."""

    def train_sample(self, n: int, seed: int) -> Sample:
        s = synthetic_slice(64, seed=seed)
        return Sample(x=s.x[:n], y=s.y[:n], indices=s.indices[:n], class_names=s.class_names)


class NoModuleImageTarget(TinyTarget):
    def torch_model(self) -> Any:
        return None


def _conv_digest(module: torch.nn.Module) -> str:
    return state_dict_sha256(module.conv)


def _at_params(**over: Any) -> dict[str, Any]:
    return {"epochs": 2, "train_n": 32, "batch_size": 16, "pgd_iters": 2, "wall_budget_s": 600, **over}


# --- catalog ------------------------------------------------------------------------------------


def test_catalog_serves_training_rows_alongside_preprocessing_rows() -> None:
    rows = defenses.list_defenses()
    by_id = {r["id"]: r for r in rows}
    assert [r["id"] for r in rows] == ["feature_squeezing", "spatial_smoothing", "jpeg_compression",
                                       "adversarial_training", "defensive_distillation"]
    assert {r["kind"] for r in rows[:3]} == {"preprocessing"}
    assert {r["kind"] for r in rows[3:]} == {"training"}
    assert [d["id"] for d in defenses.DEFENSES] == ["feature_squeezing", "spatial_smoothing", "jpeg_compression"]
    assert defenses.training_defense_ids() == ["adversarial_training", "defensive_distillation"]
    for did in ("adversarial_training", "defensive_distillation"):
        row = by_id[did]
        assert row["domains"] == ["image"] and row["requires"] == {"torch_module": True, "train_slice": True}
        assert row["phase"] == "B" and row["implementation"].startswith("redsim.ml.harden.")
        assert all(isinstance(p, ParamSpec) for p in row["params_schema"]) and row["params_schema"]
        assert defenses.is_training_defense(did) and defenses.defense_kind(did) == "training"
        assert defenses.defense_reference(did) == f"defense:{did}"          # one prefix for both kinds
        cfg = DefenseConfig(id=did, art_class=row["art_class"])
        assert defenses.resolve_defense_spec(cfg) == (did, {})
        schema = {p.name: p for p in row["params_schema"]}
        assert set(BUDGET_KEYS) <= set(schema)
        assert schema["epochs"].max == 5 and schema["train_n"].max == 2000 and schema["wall_budget_s"].max == 600
        assert schema["backbone_frozen"].type == "bool" and schema["backbone_frozen"].default is True
    at = by_id["adversarial_training"]
    assert at["art_class"] == "art.defences.trainer.AdversarialTrainer" and at["art_class_role"] == "implementation"
    at_schema = {p.name: p for p in at["params_schema"]}
    assert at_schema["eps"].default == 0.0 and "reference eps" in at_schema["eps"].description
    assert at_schema["pgd_iters"].min == 0 and "FGSM" in at_schema["pgd_iters"].description
    assert any("training threat model" in ref for ref in at["references"])
    dd = by_id["defensive_distillation"]
    assert dd["art_class"] == "art.defences.transformer.evasion.DefensiveDistillation"
    assert dd["art_class_role"] == "reference"
    assert {p.name for p in dd["params_schema"]} == {"temperature", *BUDGET_KEYS}
    assert any("Carlini-Wagner" in ref for ref in dd["references"])
    assert any("no temperature" in ref for ref in dd["references"])
    assert not defenses.is_training_defense("feature_squeezing")
    # rows are copies: mutating one never edits the catalog
    rows[3]["requires"]["torch_module"] = False
    assert defenses.get_defense("adversarial_training")["requires"]["torch_module"] is True


def test_training_params_resolve_with_bounds_and_the_reference_eps_rule() -> None:
    resolved = defenses.resolve_defense_params("adversarial_training", {})
    assert resolved["eps"] == 0.0 and resolved["epochs"] == 2 and resolved["backbone_frozen"] is True
    assert resolved["train_n"] == 1024 and resolved["wall_budget_s"] == 300 and resolved["pgd_iters"] == 3
    with pytest.raises(ValueError, match="reference eps"):
        resolve_training_params("adversarial_training", {})
    assert resolve_training_params("adversarial_training", {}, reference_eps=0.03)["eps"] == 0.03
    assert resolve_training_params("adversarial_training", {"eps": 0.1}, reference_eps=0.03)["eps"] == 0.1
    dd = resolve_training_params("defensive_distillation", {"temperature": 5})
    assert dd["temperature"] == 5.0 and "eps" not in dd
    for did, bad in [("adversarial_training", {"epochs": 6}), ("adversarial_training", {"train_n": 2001}),
                     ("adversarial_training", {"wall_budget_s": 601}), ("adversarial_training", {"pgd_iters": 8}),
                     ("defensive_distillation", {"temperature": 41}), ("defensive_distillation", {"eps": 0.1}),
                     ("adversarial_training", {"backbone_frozen": "yes"})]:
        with pytest.raises(ValueError):
            defenses.resolve_defense_params(did, bad)


def test_apply_defense_refuses_training_defenses_with_a_pointer() -> None:
    base = TinyTarget()
    for did in defenses.training_defense_ids():
        with pytest.raises(ValueError, match="redsim.ml.harden.apply.apply_training_defense"):
            defenses.apply_defense(base, did, {})
        with pytest.raises(ValueError, match="training defense"):
            defenses.build_preprocessor(did, {})
    with pytest.raises(ValueError, match="training defense"):
        defenses.apply_defense(base, DefenseConfig(id="adversarial_training"))
    with pytest.raises(ValueError, match="apply it with redsim.ml.defenses.apply_defense"):
        apply_training_defense(base, "feature_squeezing", {}, synthetic_slice(), 0)
    with pytest.raises(ValueError, match="not a training defense"):
        assess_training_target(base, "jpeg_compression")


# --- adversarial training -----------------------------------------------------------------------


def test_adversarial_training_derives_a_new_model_within_budget_and_records_it() -> None:
    target = TinyTarget(seed=0)
    parent = target.torch_model()
    parent_sha = state_dict_sha256(parent)
    parent_conv = _conv_digest(parent)
    lines: list[str] = []

    derived, record = train_defense(target, "adversarial_training", _at_params(), synthetic_slice(),
                                             seed=11, log=lines.append, reference_eps=0.03)

    assert isinstance(derived, torch.nn.Module) and not derived.training and derived is not parent
    assert isinstance(record, TrainingRecord)
    assert record.weights_sha256 != parent_sha and record.weights_changed is True
    assert record.parent_weights_sha256 == parent_sha == state_dict_sha256(parent)   # parent untouched
    assert record.parent_manifest_sha256 == target.manifest()["weights_sha256"]
    assert _conv_digest(derived) == parent_conv                                       # backbone frozen
    assert _conv_digest(derived) != state_dict_sha256(derived.fc)
    assert record.trainable_modules == ["fc"] and 0 < record.n_params_trainable < record.n_params_total
    assert record.training_mode.startswith("eval")
    assert record.defense_id == record.method == "adversarial_training" and record.kind == "training"
    assert record.target_id == "tiny" and record.seed == 11 and record.norm == "linf"
    assert record.params["eps"] == 0.03 and record.params["epochs"] == 2 and record.params["backbone_frozen"] is True
    assert record.inner_attack is not None and record.inner_attack["id"] == "pgd"
    assert record.inner_attack["max_iter"] == 2 and record.inner_attack["eps_step"] == pytest.approx(0.25 * 0.03)
    assert record.n_train == 32 and record.n_train_available == N_SLICE
    assert sum(record.train_class_counts.values()) == 32 and set(record.train_class_counts) == set(CLASS_NAMES)
    assert len(record.train_indices_sha256) == 64
    assert record.epochs_requested == record.epochs_run == 2 and record.budget_exhausted is False
    assert 0.0 <= record.wall_time_s <= record.wall_budget_s == 600.0
    assert len(record.train_loss_per_epoch) == 2 and all(v >= 0 for v in record.train_loss_per_epoch)
    assert 0 <= record.train_clean_correct_before <= 32 and 0 <= record.train_clean_correct_after <= 32
    assert record.library_versions.get("art") and record.library_versions.get("torch")
    assert any("training threat model" in lim for lim in record.limitations)
    assert any("AdversarialTrainer" in note for note in record.notes)
    assert len(lines) == 3 and all(line.startswith("defense_apply adversarial_training") for line in lines)

    cfg = record.defense_config()
    assert cfg == DefenseConfig(id="adversarial_training", art_class="art.defences.trainer.AdversarialTrainer",
                                params=record.params)
    prov = record.provenance()
    assert prov["kind"] == "training" and prov["derived_sha256"] == record.weights_sha256
    assert prov["parent_sha256"] == target.manifest()["weights_sha256"]
    assert prov["training_report"]["epochs_run"] == 2 and prov["id"] == "adversarial_training"
    lineage = record.derived_from()
    assert lineage["parent_target_id"] == "tiny" and lineage["defense_id"] == "adversarial_training"
    assert lineage["training_budget"]["epochs_run"] == 2 and lineage["training_budget"]["n_train"] == 32
    # the derived module predicts on the slice with the parent's class count
    with torch.no_grad():
        out = derived(torch.from_numpy(synthetic_slice().x[:4]))
    assert out.shape == (4, len(CLASS_NAMES))
    for text in (*record.notes, *record.limitations):
        assert "hardened" not in text.lower()


def test_adversarial_training_is_deterministic_under_the_seed() -> None:
    def run(seed: int) -> str:
        _, record = train_defense(TinyTarget(seed=0), "adversarial_training", _at_params(),
                                           synthetic_slice(), seed=seed, reference_eps=0.03)
        return record.weights_sha256

    assert run(3) == run(3)
    assert run(3) != run(4)


def test_adversarial_training_fgsm_and_l2_variants_are_recorded() -> None:
    _, fgsm = train_defense(TinyTarget(), "adversarial_training", _at_params(pgd_iters=0, epochs=1),
                                     synthetic_slice(), seed=1, reference_eps=0.03)
    assert fgsm.inner_attack is not None and fgsm.inner_attack["id"] == "fgsm"
    assert fgsm.inner_attack["max_iter"] == 1 and fgsm.inner_attack["eps_step"] == 0.03
    _, l2 = train_defense(TinyTarget(), "adversarial_training", _at_params(eps=0.5, epochs=1),
                                   synthetic_slice(), seed=1, norm="l2")
    assert l2.norm == "l2" and l2.inner_attack is not None and l2.inner_attack["norm"] == "l2"
    assert l2.params["eps"] == 0.5 and l2.weights_changed
    with pytest.raises(ValueError, match="norm"):
        train_defense(TinyTarget(), "adversarial_training", _at_params(), synthetic_slice(), 1,
                               reference_eps=0.03, norm="l1")


def test_unfrozen_backbone_trains_every_parameter() -> None:
    target = TinyTarget()
    parent_conv = _conv_digest(target.torch_model())
    derived, record = train_defense(target, "adversarial_training",
                                             _at_params(backbone_frozen=False, epochs=1), synthetic_slice(),
                                             seed=2, reference_eps=0.03)
    assert record.backbone_frozen is False and record.n_params_trainable == record.n_params_total
    assert record.training_mode == "train" and set(record.trainable_modules) == {"conv", "fc"}
    assert _conv_digest(derived) != parent_conv


# --- distillation -------------------------------------------------------------------------------


def test_defensive_distillation_derives_a_student_and_names_the_bypass() -> None:
    target = TinyTarget(seed=0)
    parent_sha = state_dict_sha256(target.torch_model())
    derived, record = train_defense(target, "defensive_distillation",
                                             {"temperature": 10, "epochs": 2, "train_n": 32, "batch_size": 16},
                                             synthetic_slice(), seed=5)
    assert isinstance(derived, torch.nn.Module) and not derived.training
    assert record.weights_sha256 != parent_sha and state_dict_sha256(target.torch_model()) == parent_sha
    assert record.method == "defensive_distillation" and record.temperature == 10.0
    assert record.inner_attack is None and record.norm is None
    assert record.art_class_role == "reference" and "native torch" in record.implementation
    assert record.epochs_run == 2 and len(record.train_loss_per_epoch) == 2 and record.budget_exhausted is False
    # KL(soft || student) is >= 0 in exact arithmetic; float32 noise around zero at high T is tolerated
    assert all(v >= -1e-3 for v in record.train_loss_per_epoch) and "KL" in record.train_loss_kind
    assert record.trainable_modules == ["fc"] and _conv_digest(derived) == _conv_digest(target.torch_model())
    assert any("no temperature" in text for text in record.notes)
    assert any("Carlini-Wagner" in text for text in record.limitations)
    assert record.provenance()["art_class"] == "art.defences.transformer.evasion.DefensiveDistillation"
    assert record.defense_config().params["temperature"] == 10.0
    same = train_defense(TinyTarget(seed=0), "defensive_distillation",
                                  {"temperature": 10, "epochs": 2, "train_n": 32, "batch_size": 16},
                                  synthetic_slice(), seed=5)[1].weights_sha256
    assert same == record.weights_sha256                                             # deterministic
    assert "cw_l2" not in distillation_limitation(["fgsm", "pgd"])
    assert "already includes that attack" in distillation_limitation(["fgsm", "cw_l2"])


# --- budget -------------------------------------------------------------------------------------


@pytest.mark.parametrize("defense_id,params", [("adversarial_training", _at_params(epochs=3, wall_budget_s=300)),
                                               ("defensive_distillation", {"epochs": 3, "train_n": 32,
                                                                           "wall_budget_s": 300})])
def test_wall_budget_stops_training_early_and_is_recorded(monkeypatch: pytest.MonkeyPatch, defense_id: str,
                                                          params: dict[str, Any]) -> None:
    ticks = iter(range(200, 200_000, 200))          # every clock read advances 200 s

    monkeypatch.setattr(harden_apply, "_now", lambda: float(next(ticks)))
    lines: list[str] = []
    derived, record = train_defense(TinyTarget(), defense_id, params, synthetic_slice(), seed=1,
                                             log=lines.append, reference_eps=0.03)
    assert record.epochs_requested == 3 and record.epochs_run == 2      # 2 epochs = 400 s >= the 300 s budget
    assert record.budget_exhausted is True and record.wall_time_s == 400.0 and record.wall_budget_s == 300.0
    assert len(record.train_loss_per_epoch) == 2 and record.weights_changed
    assert any("wall budget reached after 2 of 3 epochs" in line for line in lines)
    assert record.derived_from()["training_budget"]["budget_exhausted"] is True


def test_training_runs_to_completion_inside_the_budget() -> None:
    _, record = train_defense(TinyTarget(), "defensive_distillation",
                                       {"epochs": 3, "train_n": 32, "wall_budget_s": 600}, synthetic_slice(), 1)
    assert record.epochs_run == 3 and record.budget_exhausted is False and record.wall_time_s < 600


# --- typed unavailable --------------------------------------------------------------------------


def test_tree_ensemble_is_a_typed_unavailable_not_a_result() -> None:
    tab = TinyTabularTarget()
    for did in defenses.training_defense_ids():
        unavailable = assess_training_target(tab, did)
        assert isinstance(unavailable, TrainingUnavailable)
        assert unavailable.code == "training_defense_unavailable" and unavailable.infeasible is True
        assert unavailable.register_item == "ATTACKS_HARDEN-20" and unavailable.domain == "tabular"
        assert "tree ensembles have no gradient-based adversarial training" in unavailable.reason
        assert unavailable.defense_id == did and unavailable.target_id == "tiny_tabular"
        with pytest.raises(TrainingDefenseUnavailable) as info:
            apply_training_defense(tab, did, {}, None, 0, reference_eps=0.05)
        assert info.value.unavailable == unavailable and info.value.code == "training_defense_unavailable"
        assert "tiny_tabular" in str(info.value)
    assert assess_training_target(TinyTarget(), "adversarial_training") is None


def test_image_target_without_a_torch_module_and_missing_slice_are_typed() -> None:
    no_module = assess_training_target(NoModuleImageTarget(), "adversarial_training")
    assert no_module is not None and no_module.infeasible is True and "no torch module" in no_module.reason
    with pytest.raises(TrainingDefenseUnavailable) as info:
        apply_training_defense(TinyTarget(), "adversarial_training", _at_params(), None, 0, reference_eps=0.03)
    assert info.value.unavailable.infeasible is False and "no training slice" in info.value.unavailable.reason
    assert info.value.unavailable.register_item is None


# --- slices -------------------------------------------------------------------------------------


def test_train_slice_sources_npz_pair_and_target_accessor(tmp_path: Path) -> None:
    target = TinyTarget()
    full = synthetic_slice(40)
    path = tmp_path / "train_slice.npz"
    np.savez(path, x=(full.x * 255).round().astype(np.uint8), y=full.y, indices=full.indices + 1000,
             class_names=np.asarray(full.class_names))
    sample, available = load_train_slice(path, target=target, defense_id="adversarial_training", n=12, seed=3)
    assert available == 40 and sample.x.shape == (12, 3, 8, 8) and sample.x.dtype == np.float32
    assert 0.0 <= sample.x.min() and sample.x.max() <= 1.0 and sample.class_names == list(CLASS_NAMES)
    assert set(sample.indices.tolist()) <= set(range(1000, 1040))                # source indices kept
    assert sorted(np.bincount(sample.y, minlength=3).tolist()) == [4, 4, 4]      # stratified
    again, _ = load_train_slice(path, target=target, defense_id="adversarial_training", n=12, seed=3)
    assert np.array_equal(again.indices, sample.indices)                          # seeded

    pair, available = load_train_slice((full.x, full.y), target=target, defense_id="adversarial_training",
                                       n=100, seed=0)
    assert available == 40 and len(pair.y) == 40 and pair.class_names == ["0", "1", "2"]

    trainable = TinyTrainableTarget()
    via_target, available = load_train_slice(None, target=trainable, defense_id="adversarial_training", n=20, seed=1)
    assert available == 20 and len(via_target.y) == 20
    _, record = train_defense(trainable, "adversarial_training", _at_params(train_n=32, epochs=1), None,
                                       seed=1, reference_eps=0.03)
    assert record.n_train == 32 and record.n_train_available == 32 and record.weights_changed

    with pytest.raises(FileNotFoundError):
        load_train_slice(tmp_path / "absent.npz", target=target, defense_id="adversarial_training", n=8, seed=0)
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        load_train_slice((full.x * 3.0, full.y), target=target, defense_id="adversarial_training", n=8, seed=0)
    with pytest.raises(TypeError):
        load_train_slice(42, target=target, defense_id="adversarial_training", n=8, seed=0)


# --- derived target and the runner hook ---------------------------------------------------------


def _verify_config(defense: DefenseConfig, *, attack_ids: list[str] | None = None, norm: str = "linf",
                   reference_eps: float = 0.03, seed: int = 4) -> CampaignConfig:
    grid = [0.01, reference_eps] if norm == "linf" else [0.25, reference_eps]
    return CampaignConfig(target_id="tiny", dataset_id="synthetic", modality="image",
                          attack_ids=attack_ids or ["fgsm", "pgd"], norm=norm, eps_grid=grid,
                          reference_eps=reference_eps, n_samples=12, seed=seed, defense=defense)


def test_derived_target_keeps_the_parent_identity_and_describes_the_training() -> None:
    base = TinyTarget(seed=0)
    derived = apply_training_defense(base, "adversarial_training", _at_params(epochs=1), synthetic_slice(), 4,
                                     reference_eps=0.03)
    assert isinstance(derived, DerivedTorchTarget) and isinstance(derived, Target)
    assert derived.id == base.id and derived.torch_model() is derived.module and not derived.module.training
    record = derived.record
    assert isinstance(record, TrainingRecord) and record.artifacts == {} and record.weights_file_sha256 is None
    info = derived.info()
    assert info.domain == "image" and info.name != base.info().name and record.weights_sha256[:8] in info.name
    assert info.metadata["defense"]["kind"] == "training" and info.metadata["defense"]["torch_model_defended"] is True
    s = derived.sample(12, seed=3)
    assert np.array_equal(s.indices, base.sample(12, seed=3).indices) and s.class_names == list(CLASS_NAMES)
    proba = derived.predict_proba(s.x)
    assert proba.shape == (12, 3) and proba.dtype == np.float32 and np.allclose(proba.sum(axis=1), 1.0, atol=1e-5)
    assert not np.allclose(proba, base.predict_proba(s.x))                        # different weights
    with torch.no_grad():
        expected = torch.softmax(derived.module(torch.from_numpy(s.x)), dim=1).numpy()
    assert np.allclose(proba, expected, atol=1e-6)
    clf = derived.art_classifier()
    assert clf.nb_classes == 3 and tuple(clf.input_shape) == (3, 8, 8) and clf.preprocessing_defences is None
    assert np.array_equal(clf.predict(s.x).argmax(1), proba.argmax(1))
    assert clf.loss_gradient(s.x, np.eye(3, dtype=np.float32)[s.y]).shape == s.x.shape   # white-box capable
    manifest = derived.manifest()
    assert manifest["weights_sha256"] == base.manifest()["weights_sha256"]          # parent identity kept (15.6)
    assert manifest["defense"]["derived_sha256"] == record.weights_sha256 != manifest["weights_sha256"]
    assert manifest["defense"]["parent_sha256"] == base.manifest()["weights_sha256"]
    assert manifest["defense"]["id"] == "adversarial_training" and manifest["defense"]["method"] == "adversarial_training"
    assert derived.describe() == {**record.provenance(), "name": "Adversarial fine-tuning (PGD/FGSM-based)",
                                  "torch_model_defended": True}
    assert derived.defense_config() == record.defense_config()
    assert base.art_classifier().preprocessing_defences is None and base.torch_model() is not derived.module


def test_runner_hook_call_shape_reads_the_campaign_config_and_writes_artifacts(tmp_path: Path) -> None:
    """``campaign._apply_defense`` calls ``hook(target, config.defense, config=config, sink=sink, seed=config.seed)``."""
    import inspect

    params = inspect.signature(apply_training_defense).parameters
    assert {"config", "sink", "seed"} <= set(params) and params["defense"].kind is not inspect.Parameter.KEYWORD_ONLY
    defense = DefenseConfig(id="adversarial_training", art_class="art.defences.trainer.AdversarialTrainer",
                            params={"epochs": 1, "train_n": 32, "batch_size": 16, "pgd_iters": 1})
    config = _verify_config(defense, norm="l2", reference_eps=0.5, seed=9)
    sink = FilesystemSink(tmp_path)
    target = TinyTrainableTarget()

    derived = apply_training_defense(target, config.defense, config=config, sink=sink, seed=config.seed)

    assert isinstance(derived, DerivedTorchTarget)
    record = derived.record
    assert record.params["eps"] == 0.5 and record.norm == "l2" and record.seed == 9       # from the config
    assert record.inner_attack is not None and record.inner_attack["norm"] == "l2"
    assert record.n_train == 32 and record.epochs_run == 1 and record.weights_changed
    assert set(record.artifacts) == {"weights", "training_report"}
    weights_path = tmp_path / "artifacts" / WEIGHTS_ARTIFACT
    report_path = tmp_path / "artifacts" / REPORT_ARTIFACT
    assert weights_path.is_file() and report_path.is_file()
    assert sink.sha256(record.artifacts["weights"]) == record.weights_file_sha256   # keyed by the put() path
    state = torch.load(weights_path, weights_only=True)
    reloaded = TinyTarget().torch_model()
    reloaded.load_state_dict(state)
    assert state_dict_sha256(reloaded) == record.weights_sha256                           # the artifact is the model
    report = json.loads(report_path.read_text())
    assert report["defense_id"] == "adversarial_training" and report["epochs_run"] == 1
    assert report["artifacts"]["weights"].endswith(WEIGHTS_ARTIFACT) and report["weights_file_sha256"]
    assert "training_report" not in report["artifacts"]                                   # written after the report
    assert derived.describe()["training_report"]["artifacts"]["training_report"].endswith(REPORT_ARTIFACT)

    # a DefenseConfig contradicting the catalog class is refused, and params alongside a config are refused
    with pytest.raises(ValueError, match="is art.defences.trainer.AdversarialTrainer, not"):
        apply_training_defense(target, DefenseConfig(id="adversarial_training", art_class="art.x.Y"), config=config)
    with pytest.raises(ValueError, match="inside the DefenseConfig"):
        apply_training_defense(target, defense, {"epochs": 2}, config=config)
    # no reference eps from anywhere is an explicit error, never a silent default
    with pytest.raises(ValueError, match="reference eps"):
        apply_training_defense(target, DefenseConfig(id="adversarial_training", params={"epochs": 1, "train_n": 32}))


def test_runner_hook_distillation_limitation_names_cw_l2_when_it_ran() -> None:
    defense = DefenseConfig(id="defensive_distillation", params={"epochs": 1, "train_n": 32})
    with_cw = apply_training_defense(TinyTrainableTarget(), defense,
                                     config=_verify_config(defense, attack_ids=["fgsm", "cw_l2"]))
    without = apply_training_defense(TinyTrainableTarget(), defense, config=_verify_config(defense))
    assert any("already includes that attack" in lim for lim in with_cw.record.limitations)
    assert not any("already includes that attack" in lim for lim in without.record.limitations)
    assert any("Carlini-Wagner" in lim for lim in without.record.limitations)
    assert with_cw.record.temperature == 20.0 and with_cw.record.weights_changed
