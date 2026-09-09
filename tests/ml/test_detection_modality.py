"""Detection modality (register MODALITIES-28..41; ``ml`` tier, offline, seeded, 16x16 inputs).

Covers the YOLO-subset loader with class exclusion, the packed ``.npz`` slice, the in-repo IoU / AP evaluation
against hand-computed toy cases, the ``TinyDetector`` double's contract, the DPatch adapter (patch area from
eps, seeded, values in [0, 1]) and its same-area control (no model access), the runner (box denominators,
suppression rate as ASR, ``conf_gap`` undefined, ``ExplainerUnavailable`` recorded with box evidence, a scorecard
and never an MRI, the frame hook contract) and the real torchvision architecture path (``train_detector`` for
one epoch on synthetic boxes, ``BundledDetectionTarget`` loading a digest-checked ``state_dict``, the COCO
checkpoint read from the local cache only).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("torchvision")
pytest.importorskip("art")

import numpy as np

from redsim.ml.artifacts import FilesystemSink
from redsim.ml.attacks import ATTACKS, KNOWN_ATTACK_CAPABILITIES, attack_capabilities
from redsim.ml.attacks import dpatch as dp
from redsim.ml.datasets import DatasetUnavailable
from redsim.ml.datasets import military_assets as ma
from redsim.ml.errors import ArtifactDigestMismatch, AttackNotApplicable
from redsim.ml.runners import detection as rd
from redsim.ml.runners.base import MODALITY_RUNNERS, CampaignFrame, ModalityResult, resolve_runner
from redsim.ml.schema import CampaignConfig, CampaignRecord, Measurement, MLModelManifest
from redsim.ml.targets import detection as td
from redsim.ml.targets.base import Target
from tests.ml.fakes_detection import CLASS_NAMES, IMAGE_SIZE, TinyDetector

pytestmark = pytest.mark.ml

GRID = [0.01, 0.03, 0.05]
REF = 0.03
N = 12
ROOT = Path(__file__).resolve().parents[2]


def detection_config(**overrides: Any) -> CampaignConfig:
    cfg: dict[str, Any] = {"target_id": "tiny_detector", "modality": td.DETECTION_MODALITY, "attack_ids": ["dpatch"],
                           "attack_params": {"dpatch": {"max_iter": 2}}, "norm": td.PATCH_AREA_NORM, "eps_grid": GRID,
                           "reference_eps": REF, "n_samples": N, "seed": 0, "explain_k": 3, "dataset_id": "synthetic"}
    cfg.update(overrides)
    return CampaignConfig(**cfg)


# --- dataset loader ----------------------------------------------------------------------------------------

def _write_yolo_tree(root: Path) -> None:
    """Four 20x10 images: two keep a box after exclusion, one holds only an excluded class, one has no label."""
    from PIL import Image

    (root / "train" / "images").mkdir(parents=True)
    (root / "train" / "labels").mkdir(parents=True)
    (root / "military_dataset.yaml").write_text("names: ['tank', 'soldier', 'truck']\nnc: 3\n", encoding="utf-8")
    for i in range(4):
        Image.new("RGB", (20, 10), (10 * i, 20, 30)).save(root / "train" / "images" / f"{i:03d}.png")
    labels = {
        0: "0 0.5 0.5 0.5 0.6\n1 0.2 0.2 0.1 0.2\n",      # tank (kept) + soldier (excluded)
        1: "1 0.5 0.5 0.4 0.4\n",                          # soldier only -> image dropped
        2: "2 0.75 0.5 0.3 0.8\n",                         # truck (kept, remapped to 1)
    }
    for i, text in labels.items():
        (root / "train" / "labels" / f"{i:03d}.txt").write_text(text, encoding="utf-8")


def test_yolo_split_scales_boxes_excludes_person_classes_and_drops_empty_images(tmp_path: Path) -> None:
    _write_yolo_tree(tmp_path)
    split = ma.load_yolo_split(tmp_path, "train", image_size=16, excluded_classes=("soldier", "weapon"))
    assert split.class_names == ["tank", "truck"] and split.excluded_classes == ["soldier"]
    assert split.n == 2 and split.n_images_dropped == 2 and split.n_boxes_excluded == 2
    assert split.x.shape == (2, 3, 16, 16) and split.x.dtype == np.uint8
    assert split.filenames == ["000.png", "002.png"] and split.indices.tolist() == [0, 2]
    # cx=0.5, cy=0.5, w=0.5, h=0.6 on 20x10 -> x 5..15, y 2..8 in source pixels; stretched by (16/20, 16/10).
    np.testing.assert_allclose(split.boxes[0], np.array([[4.0, 3.2, 12.0, 12.8]], dtype=np.float32), atol=1e-4)
    assert split.labels[0].tolist() == [0] and split.labels[1].tolist() == [1]
    assert split.per_class_boxes() == {"tank": 1, "truck": 1}
    assert ma.primary_labels(split.labels, 2).tolist() == [0, 1]


def test_parse_yolo_label_rejects_malformed_lines_and_clips_boxes() -> None:
    boxes, labels = ma.parse_yolo_label("0 0.5 0.5 2.0 2.0\n\n1 0.1 0.1 0.001 0.001\n", 16, 16)
    assert boxes.tolist() == [[0.0, 0.0, 16.0, 16.0]] and labels.tolist() == [0]   # clipped; degenerate dropped
    with pytest.raises(DatasetUnavailable):
        ma.parse_yolo_label("0 0.5 0.5\n", 16, 16)
    with pytest.raises(DatasetUnavailable):
        ma.parse_yolo_label("x 0.5 0.5 0.1 0.1\n", 16, 16)


def test_detection_npz_round_trip_and_seeded_stratified_sampling(tmp_path: Path) -> None:
    split = ma.synthetic_detection_split(10, 16, seed=3)
    sha = ma.save_detection_npz(tmp_path / "eval_det.npz", split, dataset_revision="rev-1")
    assert len(sha) == 64
    back = ma.load_detection_npz(tmp_path / "eval_det.npz")
    np.testing.assert_array_equal(back.x, split.x)
    assert [b.tolist() for b in back.boxes] == [b.tolist() for b in split.boxes]
    assert [lab.tolist() for lab in back.labels] == [lab.tolist() for lab in split.labels]
    assert back.class_names == list(ma.SYNTHETIC_CLASS_NAMES) and back.seed == 3
    assert ma.slice_provenance(tmp_path / "eval_det.npz") == {"dataset_id": ma.SUBSET_DATASET_ID,
                                                              "dataset_revision": "rev-1"}
    a = ma.stratified_detection_indices(split, 6, seed=0)
    b = ma.stratified_detection_indices(split, 6, seed=0)
    assert a.tolist() == b.tolist() and len(a) == 6 and len(set(a.tolist())) == 6
    with pytest.raises(DatasetUnavailable):
        ma.load_detection_npz(tmp_path / "missing.npz")


# --- evaluation --------------------------------------------------------------------------------------------

def _pred(boxes: list[list[float]], labels: list[int], scores: list[float]) -> dict[str, np.ndarray]:
    return {"boxes": np.asarray(boxes, dtype=np.float32).reshape(-1, 4), "labels": np.asarray(labels, dtype=np.int64),
            "scores": np.asarray(scores, dtype=np.float32)}


def test_evaluate_detections_matches_hand_computed_toy_cases() -> None:
    """Three images, classes a / b. Ground truth: img0 a@[0,0,8,8] and b@[8,8,16,16]; img1 a@[2,2,10,10]; img2 none.

    Perfect predictions: 3/3 matched, recall 1, AP(a) = AP(b) = 1 -> mAP 1. No predictions: 0/3 with the denominator
    kept, AP 0 for both classes -> mAP 0. Duplicates: two predictions on img0's a box count as one match (the
    second is a false positive), AP(a) over the ranking [tp 0.9, fp 0.8, tp 0.7] = precision 1 at recall 0.5 and
    2/3 at recall 1 -> AP(a) = 0.5 * 1 + 0.5 * 2/3 = 0.8333; a wrong-class prediction never matches; a prediction
    below the score threshold does not count for recall but still ranks for AP.
    """
    names = ["a", "b"]
    gts = [{"boxes": np.array([[0, 0, 8, 8], [8, 8, 16, 16]], dtype=np.float32), "labels": np.array([0, 1])},
           {"boxes": np.array([[2, 2, 10, 10]], dtype=np.float32), "labels": np.array([0])},
           {"boxes": np.zeros((0, 4), dtype=np.float32), "labels": np.zeros((0,), dtype=np.int64)}]
    perfect = [_pred([[0, 0, 8, 8], [8, 8, 16, 16]], [0, 1], [0.9, 0.9]), _pred([[2, 2, 10, 10]], [0], [0.9]),
               _pred([], [], [])]
    ev = td.evaluate_detections(perfect, gts, names, score_threshold=0.5)
    assert (ev.n_gt, ev.n_matched, ev.recall, ev.map50) == (3, 3, 1.0, 1.0)
    assert ev.per_class == {"a": {"n": 2, "n_correct": 2}, "b": {"n": 1, "n_correct": 1}}
    assert [m.tolist() for m in ev.matched] == [[True, True], [True], []]

    nothing = [_pred([], [], []) for _ in gts]
    ev0 = td.evaluate_detections(nothing, gts, names, score_threshold=0.5)
    assert (ev0.n_gt, ev0.n_matched, ev0.recall, ev0.map50, ev0.n_predictions) == (3, 0, 0.0, 0.0, 0)

    dup = [_pred([[0, 0, 8, 8], [0, 0, 8, 8], [8, 8, 16, 16]], [0, 0, 0], [0.9, 0.8, 0.9]),   # dup a; b box as class a
           _pred([[2, 2, 10, 10]], [0], [0.7]), _pred([], [], [])]
    ev2 = td.evaluate_detections(dup, gts, names, score_threshold=0.5)
    assert ev2.n_matched == 2 and ev2.per_class == {"a": {"n": 2, "n_correct": 2}, "b": {"n": 1, "n_correct": 0}}
    assert ev2.ap_per_class["b"] == 0.0
    # ranking for class a: 0.9 tp, 0.9 fp (b's box called a), 0.8 fp (duplicate), 0.7 tp -> stable order keeps the
    # first 0.9 (tp) ahead: precisions 1, 1/2, 1/3, 2/4; envelope at recall 0.5 -> 1.0, at recall 1.0 -> 0.5.
    assert ev2.ap_per_class["a"] == pytest.approx(0.75)

    low = [_pred([[0, 0, 8, 8], [8, 8, 16, 16]], [0, 1], [0.3, 0.9]), _pred([[2, 2, 10, 10]], [0], [0.9]),
           _pred([], [], [])]
    ev3 = td.evaluate_detections(low, gts, names, score_threshold=0.5)
    assert ev3.n_matched == 2 and ev3.n_predictions == 2 and ev3.ap_per_class["a"] == 1.0

    empty = td.evaluate_detections([_pred([], [], [])], [gts[2]], names, score_threshold=0.5)
    assert empty.n_gt == 0 and empty.recall is None and empty.map50 is None


def test_match_boxes_is_greedy_one_to_one_by_score() -> None:
    gt_b = np.array([[0, 0, 10, 10], [20, 20, 30, 30]], dtype=np.float32)
    gt_l = np.array([0, 0])
    pb = np.array([[0, 0, 10, 10], [1, 1, 10, 10], [20, 20, 30, 30]], dtype=np.float32)
    matched, tp = td.match_boxes(pb, np.array([0, 0, 1]), np.array([0.5, 0.9, 0.9]), gt_b, gt_l)
    # the 0.9-scored near-duplicate takes the first box, the 0.5 one is a false positive; class 1 never matches.
    assert matched.tolist() == [True, False] and tp.tolist() == [False, True, False]
    assert td.box_iou(gt_b, pb).shape == (2, 3) and td.box_iou(gt_b[:1], pb[:1])[0, 0] == pytest.approx(1.0)
    assert td.average_precision(np.array([]), np.array([], dtype=bool), 0) is None


# --- the test double -----------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def target() -> TinyDetector:
    return TinyDetector(seed=0)


@pytest.fixture(scope="module")
def slice_(target: TinyDetector) -> td.DetectionSample:
    return target.sample(N, seed=0)


def test_tiny_detector_satisfies_the_detection_target_contract(target: TinyDetector, slice_: td.DetectionSample) -> None:
    assert isinstance(target, Target) and isinstance(target, td.DetectionTarget)
    info = target.info()
    assert info.status == "available" and info.metadata["modality"] == "detection"
    assert info.domain == td.DETECTION_DOMAIN and td.is_detection_target(target)
    assert isinstance(slice_, td.DetectionSample) and slice_.x.shape == (N, 3, IMAGE_SIZE, IMAGE_SIZE)
    assert slice_.x.dtype == np.float32 and float(slice_.x.max()) <= 1.0
    assert len(slice_.targets) == N and slice_.n_boxes >= N
    assert slice_.class_names == CLASS_NAMES and set(slice_.y.tolist()) <= {0, 1}
    preds = target.predict(slice_.x)
    assert len(preds) == N and set(preds[0]) == {"boxes", "labels", "scores"}
    assert all(int(p["labels"].min()) >= 0 and int(p["labels"].max()) < len(CLASS_NAMES) for p in preds if len(p["labels"]))
    ev = td.evaluate_detections(preds, slice_.targets, slice_.class_names, score_threshold=target.score_threshold)
    assert ev.n_gt == slice_.n_boxes and ev.recall == 1.0     # the colour-evidence double finds every rectangle
    with pytest.raises(AttackNotApplicable):
        target.predict_proba(slice_.x)
    est = target.art_estimator()
    assert hasattr(est, "loss_gradient") and target.art_classifier() is est
    man = target.manifest()
    assert man["detection"]["score_threshold"] == 0.5 and man["detection"]["class_names"] == CLASS_NAMES
    assert man["label_offset"] == td.LABEL_OFFSET and "test double" in man["caveats"][0]


# --- DPatch and its control -------------------------------------------------------------------------------------

def _changed_pixels(x: np.ndarray, x_adv: np.ndarray) -> list[int]:
    return [int((np.abs(x_adv[i] - x[i]) > 0).any(axis=0).sum()) for i in range(x.shape[0])]


def test_dpatch_patch_area_matches_eps_is_seeded_and_stays_in_range(target: TinyDetector, slice_: td.DetectionSample) -> None:
    for eps in GRID:
        side = dp.patch_side(eps, IMAGE_SIZE, IMAGE_SIZE)
        assert side == max(1, round((eps * IMAGE_SIZE * IMAGE_SIZE) ** 0.5))
        out = dp.ADAPTER.run(target, slice_.x, slice_.y, {"eps": eps, "max_iter": 2}, 0, targets=slice_.targets)
        assert out.x_adv.shape == slice_.x.shape and out.x_adv.dtype == np.float32
        assert float(out.x_adv.min()) >= 0.0 and float(out.x_adv.max()) <= 1.0
        assert all(c <= side * side for c in _changed_pixels(slice_.x, out.x_adv))    # a pasted pixel may equal the original
        assert out.params["patch_side"] == side and out.params["eps"] == eps
        assert out.params["patch_area_share_realised"] == pytest.approx(side * side / (IMAGE_SIZE * IMAGE_SIZE))
        assert any(n.startswith("patch area share eps=") for n in out.notes) and dp.UNIVERSAL_PATCH_NOTE in out.notes
        assert dp.REPLACEMENT_NOTE in out.notes and dp.DIGITAL_PATCH_NOTE in out.notes
        assert "art" in out.library_versions and "torch" in out.library_versions
        assert out.linf_norm_mean >= 0.0 and out.l2_norm_mean >= 0.0
    again = dp.ADAPTER.run(target, slice_.x, slice_.y, {"eps": REF, "max_iter": 2}, 0, targets=slice_.targets)
    first = dp.ADAPTER.run(target, slice_.x, slice_.y, {"eps": REF, "max_iter": 2}, 0, targets=slice_.targets)
    np.testing.assert_array_equal(again.x_adv, first.x_adv)
    other = dp.ADAPTER.run(target, slice_.x, slice_.y, {"eps": REF, "max_iter": 2}, 7, targets=slice_.targets)
    assert not np.array_equal(other.x_adv, first.x_adv)
    # Without ground truth the adapter still runs and says which objective it used.
    no_gt = dp.ADAPTER.run(target, slice_.x, slice_.y, {"eps": REF, "max_iter": 1}, 0)
    assert any("detector's own clean predictions" in n for n in no_gt.notes)


def test_patch_control_same_area_same_locations_and_no_model_access(target: TinyDetector, slice_: td.DetectionSample) -> None:
    calls = (target.estimator_calls, target.predict_calls)
    for eps in GRID:
        ctrl = dp.CONTROL.run(target, slice_.x, slice_.y, {"eps": eps}, 0, targets=slice_.targets)
        side = dp.patch_side(eps, IMAGE_SIZE, IMAGE_SIZE)
        locs = dp.patch_locations(N, IMAGE_SIZE, IMAGE_SIZE, side, 0)
        expected = dp.paste_patch(slice_.x, np.full((3, side, side), -1.0, dtype=np.float32), locs)
        changed_ctrl = np.abs(ctrl.x_adv - slice_.x) > 0
        changed_ref = np.abs(expected - slice_.x) > 0
        assert np.all(changed_ctrl <= changed_ref)                 # the control only touches the attack's patch region
        assert ctrl.params["patch_side"] == side
        assert float(ctrl.x_adv.min()) >= 0.0 and float(ctrl.x_adv.max()) <= 1.0
    assert (target.estimator_calls, target.predict_calls) == calls   # gradient-free: no estimator, no predict
    assert dp.CONTROL.info().family == "control" and dp.CONTROL.info().requires_gradients is False
    assert "family:control" in dp.CONTROL.capabilities and "black_box" in dp.CONTROL.capabilities


def test_dpatch_params_domains_and_registration_guard() -> None:
    p = dp.ADAPTER.resolve_params({"eps": 0.03})
    assert p == {"eps": 0.03, "max_iter": 10, "learning_rate": 5.0, "batch_size": 4}
    with pytest.raises(ValueError):
        dp.ADAPTER.resolve_params({"eps": 0.03, "max_iter": 0})
    with pytest.raises(ValueError):
        dp.ADAPTER.resolve_params({"eps": 0.03, "bogus": 1})
    with pytest.raises(ValueError):
        dp.patch_side(0.0, 16, 16)
    info = dp.ADAPTER.info()
    assert info.id == "dpatch" and info.family == "evasion" and info.access == "white-box"
    assert info.requires_gradients is True and info.phase == "B" and dp.ADAPTER.domains == frozenset({"detection"})
    assert "white_box" in dp.ADAPTER.capabilities and dp.ADAPTER.takes_eps is True
    knows_detection = "modality:detection" in KNOWN_ATTACK_CAPABILITIES
    assert dp.REGISTERED is knows_detection
    assert (ATTACKS.maybe_get("dpatch") is not None) is knows_detection
    if knows_detection:
        assert {"modality:detection", "white_box", "family:evasion", "takes_eps"} <= attack_capabilities(dp.ADAPTER)
    else:
        with pytest.raises(ValueError):
            attack_capabilities(dp.ADAPTER)      # the vocabulary lacks the tag: refused, never registered wrongly


def test_dpatch_without_a_differentiable_estimator_is_not_applicable(slice_: td.DetectionSample) -> None:
    class NoGradients(TinyDetector):
        def art_estimator(self) -> Any:
            return object()

    with pytest.raises(AttackNotApplicable):
        dp.ADAPTER.run(NoGradients(seed=0), slice_.x, slice_.y, {"eps": REF, "max_iter": 1}, 0, targets=slice_.targets)


# --- the runner --------------------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> tuple[CampaignRecord, Path, TinyDetector]:
    root = tmp_path_factory.mktemp("detection_run")
    tgt = TinyDetector(seed=0)
    record = rd.run_detection_campaign(detection_config(), FilesystemSink(root), target=tgt)
    return record, root, tgt


def test_detection_rows_use_box_denominators_and_asr_is_suppression_rate(run: tuple[CampaignRecord, Path, TinyDetector]) -> None:
    record, root, tgt = run
    sample = tgt.sample(N, 0)
    clean = next(m for m in record.measurements if m.id == "m.clean")
    assert clean.n == sample.n_boxes and clean.n_correct == clean.n and clean.accuracy == 1.0
    assert clean.conf_gap_mean is None and rd.CONF_GAP_NOTE in clean.notes
    assert any(n.startswith("accuracy on this row is recall@IoU>=0.5") for n in clean.notes)
    assert clean.params["det_n_boxes"] == clean.n and clean.params["det_n_matched"] == clean.n_correct
    assert clean.params["det_n_images"] == N and isinstance(clean.params["det_map50"], float)
    assert sum(v["n"] for v in clean.per_class.values()) == clean.n and set(clean.per_class) == set(CLASS_NAMES)
    flips = json.loads((root / "artifacts" / rd.FLIP_MATRIX_NAME).read_text())
    assert flips["n_gt_boxes"] == clean.n and flips["budget"] == "patch_area" and flips["n"] == N
    for eps in GRID:
        tag = f"eps{eps:g}"
        m = next(m for m in record.measurements if m.id == f"m.evasion.dpatch.{tag}")
        assert m.family == "evasion" and m.attack_id == "dpatch" and m.n == clean.n
        assert m.n_clean_correct == clean.n_correct
        suppressed = sum(sum(flags) for flags in flips["suppressed_boxes"]["dpatch"][tag])
        assert m.n_flipped_from_clean == suppressed
        assert m.attack_success_rate == pytest.approx(suppressed / clean.n_correct)
        assert rd.SUPPRESSION_NOTE in m.notes and m.conf_gap_mean is None and m.conf_gap_n is None
        assert m.linf_norm_mean is not None and m.l2_norm_mean is not None
        assert m.params["eps"] == eps and m.params["budget"] == "patch_area" and m.params["patch_side"] >= 1
        assert m.params["det_suppression_rate"] == pytest.approx(m.attack_success_rate)
        assert flips["flipped"]["dpatch"][tag] == [any(f) for f in flips["suppressed_boxes"]["dpatch"][tag]]
        if td.MEASUREMENT_HAS_DETECTION:
            det = getattr(m, "detection")
            assert det is not None and det.n_boxes == m.n and det.n_matched == m.n_correct
        c = next(m for m in record.measurements if m.id == f"m.control.noise.{tag}")
        assert c.family == "control" and c.attack_id == "patch_noise_control" and c.n == clean.n
        assert c.n_clean_correct == clean.n_correct and c.params["patch_side"] == m.params["patch_side"]
        assert rd.CONTROL_NOTE in c.notes
    assert rd.is_detection_measurement(clean)
    # The scored slice really loses boxes under the optimised patch and none under the random patch (seed 0).
    ref_row = next(m for m in record.measurements if m.id == f"m.evasion.dpatch.eps{REF:g}")
    assert ref_row.n_correct < clean.n_correct
    assert all(m.n_correct == clean.n_correct for m in record.measurements if m.family == "control")


def test_explain_unavailable_is_recorded_honestly_with_box_evidence(run: tuple[CampaignRecord, Path, TinyDetector]) -> None:
    record, root, _ = run
    interp = next(i for i in record.interpretation if i.id == "i.explain.unavailable.dpatch")
    assert "ExplainerUnavailable: no SHAP explainer for object detectors" in interp.statement
    assert interp.basis == [f"m.evasion.dpatch.eps{REF:g}"]
    assert any("Explain stage unavailable for 'dpatch': ExplainerUnavailable: no SHAP explainer" in s
               for s in record.limitations)
    assert rd.EXPLAIN_LIMITATION in record.limitations
    assert record.observations and len(record.observations) <= 2 * 3
    for obs in record.observations:
        assert set(obs.artifacts) == {"clean_boxes", "adv_boxes", "boxes"}
        assert obs.metric_note == rd.OBS_METRIC_NOTE and obs.center_mass_ratio_clean is None
        for name, rel in obs.artifacts.items():
            path = root / rel
            assert path.is_file() and obs.artifact_sha256[name]
            assert "shap" not in rel
        doc = json.loads((root / obs.artifacts["boxes"]).read_text())
        assert set(doc) >= {"ground_truth", "clean", "adversarial", "patch", "legend", "class_names"}
        assert doc["patch"]["side"] == dp.patch_side(REF, IMAGE_SIZE, IMAGE_SIZE)
        assert len(doc["clean"]["matched_gt"]) == len(doc["ground_truth"]["labels"])
        assert (root / obs.artifacts["adv_boxes"]).read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    suppressed_first = [o.flipped for o in record.observations]
    assert suppressed_first[0] is True        # suppressed images are listed first
    every_row = {m.expl_shift_mean for m in record.measurements}
    assert every_row == {None}                # nothing pretends to be an attribution shift
    assert not any("shap" in str(p) for p in root.rglob("*"))


def test_no_mri_only_a_scorecard_and_the_guard_refuses(run: tuple[CampaignRecord, Path, TinyDetector]) -> None:
    record, root, _ = run
    assert record.score is None and record.completeness == "partial"
    assert record.score_status is not None and record.score_status.state == "unavailable"
    assert record.score_status.reason == rd.NO_MRI_REASON and rd.NO_MRI_REASON in record.limitations
    assert rd.NO_MRI_LIMITATION in record.limitations
    assert any("S_conf unavailable" in s for s in record.missing) and any("S_expl unavailable" in s for s in record.missing)
    card = json.loads((root / "artifacts" / rd.SCORECARD_NAME).read_text())

    def keys(o: Any) -> set[str]:
        if isinstance(o, dict):
            return set(o) | {k for v in o.values() for k in keys(v)}
        if isinstance(o, list):
            return {k for v in o for k in keys(v)}
        return set()

    assert not (keys(card) & rd.FORBIDDEN_SCORECARD_KEYS)
    per = card["per_attack"]["dpatch"]
    assert per["kind"] == "detection_scorecard" and per["clean_recall"]["n"] == per["worst_case_recall_ratio"]["n"]
    assert per["worst_case_recall_ratio"]["value"] == pytest.approx(min(v["accuracy"] for v in per["recall_by_eps"].values()))
    assert per["worst_case_recall_ratio"]["eps"] == max(GRID)
    assert per["suppression_rate_at_reference"]["eps"] == REF and per["suppression_rate_at_reference"]["n"] == per["clean_recall"]["n_correct"]
    assert set(per["suppression_by_eps"]) == {f"{e:g}" for e in GRID} and 0.0 <= per["recall_auc"]["value"] <= 1.0
    assert per["reason_no_mri"] == rd.NO_MRI_REASON
    with pytest.raises(rd.DetectionMRIRefused):
        rd.refuse_mri(record.measurements)
    with pytest.raises(rd.DetectionMRIRefused):
        rd.compute_mri(config=record.config, measurements=record.measurements)
    with pytest.raises(rd.DetectionMRIRefused):
        rd.validate_scorecard_payload({"kind": "detection_scorecard", "mri": 71})
    plain = Measurement(id="m.clean", family="clean", n=4, n_correct=3, accuracy=0.75)
    assert not rd.is_detection_measurement(plain)
    score, reason = rd.compute_mri(config=record.config, measurements=[plain])   # classification rows pass the guard
    assert score is None and reason is not None
    scorecard_interp = next(i for i in record.interpretation if i.id == "i.detection.scorecard.dpatch")
    assert "No MRI is computed for detection" in scorecard_interp.statement
    assert "m.clean" in scorecard_interp.basis and f"m.evasion.dpatch.eps{REF:g}" in scorecard_interp.basis


def test_stages_curves_limitations_and_record_round_trip(run: tuple[CampaignRecord, Path, TinyDetector]) -> None:
    record, root, _ = run
    assert record.stages_done == ["load_target", "sample", "clean_eval", "attack:dpatch", "control", "explain", "score",
                                  "interpret", "recommend", "report"]
    assert record.status == "succeeded" and record.kind == "attack" and record.settings_hash
    assert [a.id for a in record.attacks] == ["dpatch"] and record.attacks[0].phase == "B"
    assert len(record.curve) == 1 and record.curve[0].attack_id == "dpatch"
    curve = record.curve[0]
    assert [p.eps for p in curve.points] == GRID and all(p.n == curve.clean.n for p in curve.points)
    assert [p.eps for p in curve.control] == GRID and all(p.n_clean_correct == curve.clean.n_correct for p in curve.points)
    assert (root / "artifacts" / "curve" / "dpatch.json").is_file()
    assert rd.RECALL_LIMITATION in record.limitations and rd.PATCH_LIMITATION in record.limitations
    assert rd.DETECTION_STANDING in record.limitations and rd.D3_BOUNDS_LIMITATION in record.limitations
    assert record.limitations[0].startswith("local:synthetic-detection-rectangles is an open, unclassified")
    assert any(s.startswith("Dataset caveat (local:synthetic-detection-rectangles)") for s in record.limitations)
    assert record.recommendations == []    # suppression stayed below the default finding threshold of 0.2
    assert record.provenance is not None and record.provenance.model_manifest["n_gt_boxes"] == record.measurements[0].n
    assert record.provenance.model_manifest["modality"] == "detection"
    assert any("DPatch location sampling" in s for s in record.provenance.nondeterminism)
    reloaded = CampaignRecord.model_validate_json((root / "artifacts" / "run_record.json").read_text())
    assert reloaded.run_id == record.run_id and len(reloaded.measurements) == 1 + 2 * len(GRID)
    for eps in GRID:
        blob = np.load(root / "artifacts" / "adv_slice" / f"dpatch_eps{eps:g}.npz")
        assert blob["x_adv"].shape == (N, 3, IMAGE_SIZE, IMAGE_SIZE) and blob["offsets"][-1] == record.measurements[0].n


def test_control_toggle_and_recommendations_when_the_threshold_is_crossed(tmp_path: Path) -> None:
    tgt = TinyDetector(seed=0)
    no_ctrl = rd.run_detection_campaign(detection_config(include_control=False), FilesystemSink(tmp_path / "a"), target=tgt)
    assert not [m for m in no_ctrl.measurements if m.family == "control"]
    assert any("benign patch control was disabled" in s for s in no_ctrl.limitations)
    assert not [i for i in no_ctrl.interpretation if i.id.startswith("i.detection.I")]
    low = rd.run_detection_campaign(detection_config(finding_asr_threshold=0.05), FilesystemSink(tmp_path / "b"), target=tgt)
    ids = [r.id for r in low.recommendations]
    assert ids == ["r.R8.patch_adversarial_training.dpatch", "r.R8.occlusion_detection.dpatch",
                   "r.R8.multi_frame_consistency.dpatch", "r.R6.preprocessing.dpatch"]
    known = {m.id for m in low.measurements} | {i.id for i in low.interpretation}
    for rec in low.recommendations:
        assert rec.status == "candidate" and rec.validation == "not evaluated" and rec.measured is None
        assert set(rec.triggered_by) <= known and rec.narrative_source == "rules"
    assert any("Liu et al. 2019, DPatch" in ref for ref in low.recommendations[0].references)
    ref_row = next(m for m in low.measurements if m.id == f"m.evasion.dpatch.eps{REF:g}")
    assert any("crosses finding_asr_threshold 0.05" in n for n in ref_row.notes)
    assert rd.detection_recommendations(no_ctrl.config, no_ctrl.measurements, no_ctrl.interpretation) == []
    with pytest.raises(ValueError):
        rd.run_detection_campaign(detection_config(), FilesystemSink(tmp_path / "c"),
                                  target=__import__("tests.ml.fakes", fromlist=["TinyTarget"]).TinyTarget(seed=0))


def test_run_detection_is_the_registered_frame_hook(tmp_path: Path) -> None:
    assert MODALITY_RUNNERS["detection"] == "redsim.ml.runners.detection:run_detection"
    assert resolve_runner("detection") is rd.run_detection
    tgt = TinyDetector(seed=0)
    config = detection_config()
    adapters = rd.resolve_detection_adapters(config)
    frame = CampaignFrame(
        config=config, sink=FilesystemSink(tmp_path), target=tgt, info=tgt.info(), domain="detection",
        manifest=tgt.manifest(), adapters=adapters, params_by_attack={"dpatch": {"max_iter": 2}}, grid=GRID, ref=REF,
        l2=False, attack_registry=ATTACKS, explain=True, dataset_name="synthetic", dataset_revision=None,
        subject_centered=None,
    )
    result = rd.run_detection(config, tgt, frame=frame)
    assert isinstance(result, ModalityResult) and result.n == N and result.mri is False
    assert result.score_unavailable_reason == rd.NO_MRI_REASON and result.curves is True
    assert set(result.flip_matrix["dpatch"]) == {f"eps{e:g}" for e in GRID}
    assert all(len(v) == N for v in result.flip_matrix["dpatch"].values())
    assert result.flip_matrix_extra["n_gt_boxes"] == frame.measurements[0].n
    assert list(result.trailing_limitations) == list(rd.TRAILING_LIMITATIONS)
    assert frame.stages_done == ["sample", "clean_eval", "attack:dpatch", "control"]
    assert len(frame.measurements) == 1 + 2 * len(GRID) and (tmp_path / "artifacts" / rd.SCORECARD_NAME).is_file()
    assert result.explain is not None and not frame.observations
    result.explain()
    assert frame.observations and any(i.id == "i.explain.unavailable.dpatch" for i in frame.interpretation)
    with pytest.raises(AttackNotApplicable):
        rd.resolve_detection_adapters(detection_config(attack_ids=["fgsm"], attack_params={}))


# --- the real torchvision architecture: trainer and bundled target ---------------------------------------------

def test_train_detector_one_epoch_and_bundled_target_loads_digest_checked_state_dict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import torch

    from redsim.ml.assets import train_detector as tr

    monkeypatch.setattr(torch.hub, "get_dir", lambda: str(tmp_path / "hub"))    # an empty cache: no COCO checkpoint
    train = ma.synthetic_detection_split(8, IMAGE_SIZE, seed=1, name="train")
    eval_split = ma.synthetic_detection_split(8, IMAGE_SIZE, seed=2, name="eval")
    result = tr.train_detector(train, eval_split, epochs=1, seed=0, batch_size=4, anchor_sizes=(4, 6, 8),
                               pretrained=True, threads=2, log=lambda _s: None)
    assert result.training["coco_weights_loaded"] is False and "random init" in result.training["backbone_init"]
    assert result.metrics["n_gt_boxes"] == eval_split.n_boxes and result.metrics["n_images"] == 8
    assert "recall" in result.metrics and "map50" in result.metrics and len(result.history) == 1
    assert tr.MODEST_MAP_NOTE in result.metrics["notes"] and result.architecture["architecture_id"] == td.ARCHITECTURE_ID
    assert result.detection["class_names"] == list(ma.SYNTHETIC_CLASS_NAMES)
    # The default-anchor module reports the cache miss honestly instead of downloading.
    loaded, note = td.init_coco_weights(td.build_detector_module(n_classes=2, image_size=IMAGE_SIZE))
    assert loaded is False and "no cached COCO checkpoint" in note
    assert td.coco_detector_checkpoint() is None

    root = tmp_path / "assets"
    weights = tr.save_state_dict(result.model, root / "bundled" / td.BUNDLED_DETECTOR_ID / "weights.pt")
    slice_path = root / "datasets" / "synthetic" / ma.EVAL_SLICE_NAME
    slice_sha = tr.write_eval_slice(eval_split, slice_path, dataset_id=ma.SYNTHETIC_DATASET_ID)
    wsha = td.sha256_file(weights)
    n_gt = int(result.metrics["n_gt_boxes"])
    recall = result.metrics["recall"]
    entry = {
        "id": td.BUNDLED_DETECTOR_ID, "name": "tiny torchvision detector (test)", "modality": td.DETECTION_MODALITY,
        "format": "torch_state_dict", "sha256": wsha, "size_bytes": weights.stat().st_size,
        "file": {"path": "bundled/assets_frcnn_mnv3/weights.pt", "sha256": wsha, "size_bytes": weights.stat().st_size},
        "architecture_id": td.ARCHITECTURE_ID, "architecture": result.architecture, "input_shape": [3, IMAGE_SIZE, IMAGE_SIZE],
        "n_classes": 2, "class_names": list(ma.SYNTHETIC_CLASS_NAMES), "dataset_id": ma.SYNTHETIC_DATASET_ID,
        "dataset_split": "eval",
        "clean_accuracy": {"value": float(recall) if recall is not None else 0.0, "n": n_gt, "split": "eval"},
        "detection": result.detection, "metrics": result.metrics, "training": result.training, "license": "synthetic",
        "caveats": ["synthetic test asset"],
    }
    manifest = {"schema_version": 1, "builder": "test",
                "datasets": {ma.SYNTHETIC_DATASET_ID: {"id": ma.SYNTHETIC_DATASET_ID, "source": "local",
                                                       "class_names": list(ma.SYNTHETIC_CLASS_NAMES),
                                                       "splits": {"eval": {"name": "eval", "n": 8, "file": {
                                                           "path": "datasets/synthetic/eval_det.npz", "sha256": slice_sha,
                                                           "size_bytes": slice_path.stat().st_size}}}}},
                "models": {td.BUNDLED_DETECTOR_ID: entry}}
    (root / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))

    absent = td.BundledDetectionTarget(assets_dir=tmp_path / "nowhere")
    assert absent.info().status == "not_implemented" and "build-assets" in (absent.info().reason or "")
    tgt = td.BundledDetectionTarget(assets_dir=root)
    info = tgt.info()
    assert info.status == "available" and info.metadata["modality"] == "detection" and info.metadata["source"] == "bundled"
    tgt.load()
    sample = tgt.sample(8, 0)
    assert isinstance(sample, td.DetectionSample) and sample.x.shape == (8, 3, IMAGE_SIZE, IMAGE_SIZE)
    preds = tgt.predict(sample.x)
    assert len(preds) == 8 and all(set(p) == {"boxes", "labels", "scores"} for p in preds)
    with pytest.raises(AttackNotApplicable):
        tgt.predict_proba(sample.x)
    assert hasattr(tgt.art_estimator(), "loss_gradient") and tgt.torch_model() is not None
    man = tgt.manifest()
    MLModelManifest.model_validate(man)
    assert man["weights_sha256_verified"] == wsha and man["eval_n_boxes"] == eval_split.n_boxes
    assert man["detection"]["score_threshold"] == tgt.score_threshold == 0.5 and man["label_offset"] == 1
    # Measured, never asserted: a one-epoch random-init detector may match nothing, and the rows must say so.
    ev = td.evaluate_detections(preds, sample.targets, sample.class_names, score_threshold=tgt.score_threshold)
    row = rd.measure_detection("m.clean", "clean", ev)
    assert row.n == sample.n_boxes and row.n_correct == ev.n_matched
    if ev.n_matched == 0:
        assert row.accuracy == 0.0 and row.params["det_n_matched"] == 0
    # Tampered weights are refused before anything runs.
    weights.write_bytes(weights.read_bytes() + b"\0")
    with pytest.raises(ArtifactDigestMismatch):
        td.BundledDetectionTarget(assets_dir=root).load()


def test_detection_modules_import_without_ml_libraries() -> None:
    """The catalog side (targets, datasets, attacks) stays importable with torch / ART blocked (spec 9.1 rule 2)."""
    probe = (
        "import sys\n"
        "for name in ('torch', 'torchvision', 'art', 'shap', 'sklearn', 'onnx', 'onnxruntime', 'PIL'):\n"
        "    sys.modules[name] = None\n"
        "import redsim.ml.datasets.military_assets, redsim.ml.targets.detection, redsim.ml.attacks.dpatch\n"
        "from redsim.ml.targets.registry import TARGETS\n"
        "print('assets_frcnn_mnv3' in TARGETS)\n"
    )
    proc = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=120, check=False,
                          cwd=str(ROOT))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == "True"
