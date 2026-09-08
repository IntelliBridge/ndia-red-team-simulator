"""``redsim.ml.eval.measure`` and its helpers: counts, denominators, flips, norms, gaps.

Pure numpy; no torch or ART needed."""

from __future__ import annotations

import pytest

pytest.importorskip("numpy")

import numpy as np

from redsim.ml.eval import attack_success_rate, conf_gap, eps_tag, measure, perturbation_norms

pytestmark = pytest.mark.ml

CLASSES = ["circle", "square", "triangle"]


def test_clean_row_has_counts_and_per_class_denominators():
    y = np.array([0, 0, 1, 1, 2, 2, 2, 0])
    yp = np.array([0, 1, 1, 1, 2, 0, 2, 0])
    m = measure("m.clean", "clean", y, yp, CLASSES, wall_time_s=0.5)
    assert m.id == "m.clean" and m.family == "clean" and m.attack_id is None
    assert m.n == 8 and m.n_correct == 6
    assert m.accuracy == pytest.approx(6 / 8)
    assert m.n_flipped_from_clean is None and m.linf_norm_mean is None and m.l2_norm_mean is None
    assert m.severity is None
    assert set(m.per_class) == set(CLASSES)
    assert sum(v["n"] for v in m.per_class.values()) == m.n
    assert sum(v["n_correct"] for v in m.per_class.values()) == m.n_correct
    assert m.per_class["circle"] == {"n": 3, "n_correct": 2}
    assert m.per_class["triangle"] == {"n": 3, "n_correct": 2}
    assert m.wall_time_s == 0.5


def test_evasion_row_flips_asr_and_norms():
    y = np.array([0, 1, 2, 0, 1, 2])
    y_clean = np.array([0, 1, 2, 0, 2, 2])       # 5 clean-correct (index 4 wrong on clean)
    y_adv = np.array([1, 1, 0, 0, 1, 2])         # flips at 0 and 2; index 4 becomes right (not a flip)
    x = np.zeros((6, 3, 2, 2), dtype=np.float32)
    x_adv = x.copy()
    x_adv[0] += 0.03
    x_adv[2, 0, 0, 0] = 0.01
    m = measure("m.evasion.fgsm.eps0.03", "evasion", y, y_adv, CLASSES, attack_id="fgsm",
                params={"eps": 0.03, "norm_l2": False, "label": "dropped"}, x_ref=x, x_adv=x_adv,
                y_pred_clean=y_clean, wall_time_s=1.25, notes=["from test"])
    assert m.id == "m.evasion.fgsm.eps0.03" and m.family == "evasion" and m.attack_id == "fgsm"
    assert m.n == 6 and m.n_correct == 4 and m.accuracy == pytest.approx(4 / 6)
    assert m.n_flipped_from_clean == 2
    assert m.params == {"eps": 0.03, "norm_l2": False}          # non-scalar param dropped, noted
    assert any("attack_success_rate = 2/5 = 0.4000" in n for n in m.notes)
    assert any("'label'" in n for n in m.notes)
    assert "from test" in m.notes
    assert m.linf_norm_mean == pytest.approx((0.03 + 0.01) / 6, rel=1e-5)
    l2_0 = np.sqrt(12 * 0.03**2)
    assert m.l2_norm_mean == pytest.approx((l2_0 + 0.01) / 6, rel=1e-5)
    assert m.severity is None


def test_control_row_id_and_zero_denominator_note():
    y = np.array([0, 1, 2])
    y_clean = np.array([1, 2, 0])   # nothing correct on clean -> ASR undefined
    m = measure("m.control.noise.eps0.03", "control", y, y, CLASSES, attack_id="noise_control",
                y_pred_clean=y_clean)
    assert m.id == "m.control.noise.eps0.03" and m.family == "control"
    assert m.n_flipped_from_clean == 0
    assert any("not computed (denominator n_clean_correct = 0)" in n for n in m.notes)


def test_measure_rejects_misaligned_inputs():
    with pytest.raises(ValueError):
        measure("m.clean", "clean", np.array([0, 1]), np.array([0]), CLASSES)
    with pytest.raises(ValueError):
        measure("m.x", "evasion", np.array([0, 1]), np.array([0, 1]), CLASSES, y_pred_clean=np.array([0]))
    with pytest.raises(ValueError):
        perturbation_norms(np.zeros((2, 3)), np.zeros((3, 3)))


def test_empty_slice_is_not_a_percentage():
    m = measure("m.clean", "clean", np.array([], dtype=int), np.array([], dtype=int), CLASSES)
    assert m.n == 0 and m.n_correct == 0 and m.accuracy == 0.0
    assert any("denominator 0" in n for n in m.notes)


def test_attack_success_rate_helper():
    y = np.array([0, 0, 1, 1])
    n_flip, n_cc, asr = attack_success_rate(y, np.array([0, 0, 1, 0]), np.array([1, 0, 0, 0]))
    assert (n_flip, n_cc) == (2, 3) and asr == pytest.approx(2 / 3)
    assert attack_success_rate(y, np.array([1, 1, 0, 0]), y) == (0, 0, None)


def test_conf_gap_zero_on_robust_and_positive_when_confidently_wrong():
    y = np.array([0, 1, 2])
    robust = np.array([[0.9, 0.05, 0.05], [0.1, 0.8, 0.1], [0.2, 0.2, 0.6]])
    assert conf_gap(robust, y) == 0.0
    wrong = np.array([[0.1, 0.9, 0.0], [0.1, 0.8, 0.1], [0.7, 0.2, 0.1]])
    # sample 0: 0.9-0.1 = 0.8; sample 1: 0; sample 2: 0.7-0.1 = 0.6 -> mean over ALL n = 1.4/3
    assert conf_gap(wrong, y) == pytest.approx(1.4 / 3)
    assert conf_gap(np.zeros((0, 3)), np.array([], dtype=int)) == 0.0
    with pytest.raises(ValueError):
        conf_gap(np.zeros((2, 3)), np.array([0, 1, 2]))


def test_perturbation_norms_means():
    x = np.zeros((2, 4))
    xa = np.array([[0.1, 0.0, 0.0, 0.0], [0.2, 0.2, 0.0, 0.0]])
    linf, l2 = perturbation_norms(x, xa)
    assert linf == pytest.approx((0.1 + 0.2) / 2)
    assert l2 == pytest.approx((0.1 + np.sqrt(0.08)) / 2)
    assert perturbation_norms(np.zeros((0, 3)), np.zeros((0, 3))) == (0.0, 0.0)


def test_eps_tag_formats_grid_members():
    assert [eps_tag(e) for e in (0.01, 0.03, 0.1, 1.0, 0.25)] == ["eps0.01", "eps0.03", "eps0.1", "eps1", "eps0.25"]
