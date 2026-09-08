"""``redsim.ml.eval.measure`` and its helpers against the frozen M0 ``Measurement`` (spec 12.5, 14.2).

Pure numpy; no torch or ART needed. Every rate travels with its denominator: ``accuracy`` with
``n``, ``attack_success_rate`` with ``n_clean_correct``, ``conf_gap_mean`` with ``conf_gap_n``,
``pert_first_success_mean`` with ``pert_first_success_n``. Severity is not a Measurement field.
"""

from __future__ import annotations

import pytest

pytest.importorskip("numpy")

import numpy as np

from redsim.ml.eval import (
    attack_success_rate,
    conf_gap,
    eps_of,
    eps_tag,
    measure,
    per_sample_norm,
    pert_first_success,
    perturbation_norms,
)
from redsim.ml.schema import Measurement

pytestmark = pytest.mark.ml

CLASSES = ["circle", "square", "triangle"]


def test_measurement_carries_no_severity_field():
    # Severity is a Finding-level derivation (scoring.severity_for), never a Measurement field.
    assert "severity" not in Measurement.model_fields


def test_clean_row_has_counts_and_per_class_denominators():
    y = np.array([0, 0, 1, 1, 2, 2, 2, 0])
    yp = np.array([0, 1, 1, 1, 2, 0, 2, 0])
    m = measure("m.clean", "clean", y, yp, CLASSES, wall_time_s=0.5)
    assert m.id == "m.clean" and m.family == "clean" and m.attack_id is None
    assert m.n == 8 and m.n_correct == 6
    assert m.accuracy == pytest.approx(6 / 8)
    assert m.n_flipped_from_clean is None and m.n_clean_correct is None and m.attack_success_rate is None
    assert m.linf_norm_mean is None and m.l2_norm_mean is None
    assert m.conf_gap_mean is None and m.conf_gap_n is None and m.queries_mean is None
    assert m.pert_first_success_mean is None and m.expl_shift_mean is None
    assert set(m.per_class) == set(CLASSES)
    assert sum(v["n"] for v in m.per_class.values()) == m.n
    assert sum(v["n_correct"] for v in m.per_class.values()) == m.n_correct
    assert m.per_class["circle"] == {"n": 3, "n_correct": 2}
    assert m.per_class["triangle"] == {"n": 3, "n_correct": 2}
    assert m.wall_time_s == 0.5
    assert Measurement.model_validate(m.model_dump(mode="json")) == m


def test_evasion_row_flips_asr_conf_gap_and_norms():
    y = np.array([0, 1, 2, 0, 1, 2])
    y_clean = np.array([0, 1, 2, 0, 2, 2])       # 5 clean-correct (index 4 wrong on clean)
    y_adv = np.array([1, 1, 0, 0, 1, 2])         # flips at 0 and 2; index 4 becomes right (not a flip)
    proba_adv = np.array([[0.2, 0.7, 0.1],       # gap 0.5
                          [0.1, 0.8, 0.1],       # 0
                          [0.6, 0.1, 0.3],       # 0.3
                          [0.9, 0.05, 0.05],     # 0
                          [0.3, 0.4, 0.3],       # 0
                          [0.1, 0.2, 0.7]])      # 0
    x = np.zeros((6, 3, 2, 2), dtype=np.float32)
    x_adv = x.copy()
    x_adv[0] += 0.03
    x_adv[2, 0, 0, 0] = 0.01
    m = measure("m.evasion.fgsm.eps0.03", "evasion", y, y_adv, CLASSES, attack_id="fgsm",
                params={"eps": 0.03, "norm_l2": False, "norm": "linf", "label": ["dropped"]}, x_ref=x, x_adv=x_adv,
                y_pred_clean=y_clean, proba=proba_adv, wall_time_s=1.25, notes=["from test"])
    assert m.id == "m.evasion.fgsm.eps0.03" and m.family == "evasion" and m.attack_id == "fgsm"
    assert m.n == 6 and m.n_correct == 4 and m.accuracy == pytest.approx(4 / 6)
    # ASR = flipped among the clean-correct / clean-correct, both counts stored
    assert m.n_flipped_from_clean == 2 and m.n_clean_correct == 5
    assert m.attack_success_rate == pytest.approx(2 / 5)
    # string params are admitted (spec: ``params`` carries ``norm``); non-scalar ones are dropped and noted
    assert m.params == {"eps": 0.03, "norm_l2": False, "norm": "linf"}
    assert any("'label'" in n for n in m.notes)
    assert "from test" in m.notes
    assert m.conf_gap_mean == pytest.approx(0.8 / 6) and m.conf_gap_n == 6
    assert m.linf_norm_mean == pytest.approx((0.03 + 0.01) / 6, rel=1e-5)
    l2_0 = np.sqrt(12 * 0.03**2)
    assert m.l2_norm_mean == pytest.approx((l2_0 + 0.01) / 6, rel=1e-5)
    # reference-row fields belong to the campaign (pert) and the explain stage (expl_shift): untouched here
    assert m.pert_first_success_mean is None and m.pert_first_success_n is None
    assert m.expl_shift_mean is None and m.expl_shift_n is None and m.queries_mean is None
    assert Measurement.model_validate(m.model_dump(mode="json")) == m


def test_control_row_id_and_zero_denominator_is_not_a_rate():
    y = np.array([0, 1, 2])
    y_clean = np.array([1, 2, 0])   # nothing correct on clean -> ASR undefined
    m = measure("m.control.noise.eps0.03", "control", y, y, CLASSES, attack_id="noise_control",
                y_pred_clean=y_clean)
    assert m.id == "m.control.noise.eps0.03" and m.family == "control"
    assert m.n_flipped_from_clean == 0 and m.n_clean_correct == 0
    assert m.attack_success_rate is None
    assert any("not computed (denominator n_clean_correct = 0)" in n for n in m.notes)


def test_queries_mean_is_copied_through_for_black_box_rows():
    y = np.array([0, 1, 2, 0])
    m = measure("m.evasion.hopskipjump.eps0.1", "evasion", y, y, CLASSES, attack_id="hopskipjump",
                y_pred_clean=y, queries_mean=np.float64(12.5))
    assert m.queries_mean == 12.5 and isinstance(m.queries_mean, float)
    assert measure("m.clean", "clean", y, y, CLASSES).queries_mean is None


def test_measure_rejects_misaligned_inputs():
    with pytest.raises(ValueError):
        measure("m.clean", "clean", np.array([0, 1]), np.array([0]), CLASSES)
    with pytest.raises(ValueError):
        measure("m.x", "evasion", np.array([0, 1]), np.array([0, 1]), CLASSES, y_pred_clean=np.array([0]))
    with pytest.raises(ValueError):
        measure("m.x", "evasion", np.array([0, 1]), np.array([0, 1]), CLASSES, proba=np.zeros((3, 3)))
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
    # sample 0: 0.9-0.1 = 0.8; sample 1: 0; sample 2: 0.7-0.1 = 0.6 -> mean over ALL n (spec 12.5) = 1.4/3
    assert conf_gap(wrong, y) == pytest.approx(1.4 / 3)
    assert conf_gap(np.zeros((0, 3)), np.array([], dtype=int)) == 0.0
    with pytest.raises(ValueError):
        conf_gap(np.zeros((2, 3)), np.array([0, 1, 2]))


def test_perturbation_norms_and_per_sample_norm():
    x = np.zeros((2, 4))
    xa = np.array([[0.1, 0.0, 0.0, 0.0], [0.2, 0.2, 0.0, 0.0]])
    linf, l2 = perturbation_norms(x, xa)
    assert linf == pytest.approx((0.1 + 0.2) / 2)
    assert l2 == pytest.approx((0.1 + np.sqrt(0.08)) / 2)
    assert perturbation_norms(np.zeros((0, 3)), np.zeros((0, 3))) == (0.0, 0.0)
    np.testing.assert_allclose(per_sample_norm(x, xa), [0.1, 0.2])
    np.testing.assert_allclose(per_sample_norm(x, xa, l2=True), [0.1, np.sqrt(0.08)])
    with pytest.raises(ValueError):
        per_sample_norm(np.zeros((2, 3)), np.zeros((3, 3)))


def test_pert_first_success_takes_the_norm_at_the_smallest_flipping_eps():
    flips = {0.1: np.array([True, True, False]), 0.01: np.array([False, True, False]),
             0.03: np.array([True, True, False])}
    norms = {0.01: np.full(3, 0.01), 0.03: np.full(3, 0.03), 0.1: np.full(3, 0.1)}
    mean, n = pert_first_success(flips, norms)
    # sample 0 first flips at 0.03, sample 1 at 0.01, sample 2 never
    assert mean == pytest.approx((0.03 + 0.01) / 2) and n == 2
    assert pert_first_success({0.01: np.zeros(3, dtype=bool)}, {0.01: np.full(3, 0.01)}) == (None, 0)
    assert pert_first_success({}, {}) == (None, 0)


def test_eps_tag_and_eps_of():
    assert [eps_tag(e) for e in (0.01, 0.03, 0.1, 1.0, 0.25)] == ["eps0.01", "eps0.03", "eps0.1", "eps1", "eps0.25"]
    y = np.array([0, 1])
    assert eps_of(measure("m.evasion.fgsm.eps0.03", "evasion", y, y, CLASSES, params={"eps": 0.03})) == 0.03
    assert eps_of(measure("m.clean", "clean", y, y, CLASSES)) is None
    assert eps_of(measure("m.x", "evasion", y, y, CLASSES, params={"eps": True})) is None
