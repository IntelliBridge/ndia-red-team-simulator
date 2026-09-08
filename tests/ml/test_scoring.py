"""MRI scoring (spec section 15; master plan section 5). Pure Python, no ML extra.

Pins: fixed weights 0.35/0.25/0.20/0.10/0.10 summing to 1; MRI == round(sum w*S);
``(None, reason)`` when any subscore is missing and weights are never renormalised;
grade boundaries and attack-scoped readings with no banned wording; the severity
table of section 15.5; the delta rule of section 16 / 15.6.
"""

from __future__ import annotations

import math
import re

import pytest
from pydantic import ValidationError

from redsim.ml.schema import Scoring
from redsim.ml.scoring import (
    DEFAULT_WEIGHTS,
    GRADE_READINGS,
    GRADE_SENTENCE,
    SUBSCORE_KEYS,
    contains_banned_wording,
    delta,
    eps_bands,
    first_success,
    grade_for,
    normalize_weights,
    score_run,
    severity_for,
    trapezoid_auc_normalized,
)

GRID = [0.01, 0.03, 0.1]
REF = 0.03
BANNED = re.compile(r"hardened|fielding|deployment-ready|certif|\bsafe\b", re.IGNORECASE)


def rows(accs, *, asr=0.0, conf_gap=0.0, expl_shift=0.0):
    """Per-eps table for one attack; ``expl_shift`` is only defined at the reference eps (spec 15.1)."""
    out = {}
    for e, a in zip(GRID, accs, strict=True):
        at_ref = math.isclose(e, REF)
        out[e] = {"acc_adv": a, "asr": asr, "conf_gap": conf_gap,
                  "expl_shift": expl_shift if at_ref else None, "pert": e}
    return out


def score(per_attack, acc_clean=0.8, weights=None):
    return score_run(modality="image", acc_clean=acc_clean, per_attack=per_attack, eps_grid=GRID,
                     reference_eps=REF, weights=weights, basis_measurements=["m.clean"])


# --- weights ---------------------------------------------------------------------------------

def test_default_weights_are_the_spec_vector_and_sum_to_one():
    assert DEFAULT_WEIGHTS == {"S_acc": 0.35, "S_asr": 0.25, "S_eps": 0.20, "S_conf": 0.10, "S_expl": 0.10}
    assert math.isclose(sum(DEFAULT_WEIGHTS.values()), 1.0)
    assert normalize_weights({"acc": 0.35, "asr": 0.25, "eps": 0.2, "conf": 0.1, "expl": 0.1}) == DEFAULT_WEIGHTS


@pytest.mark.parametrize("bad", [
    {"S_acc": 0.5, "S_asr": 0.5},                                                     # missing dims
    {"S_acc": 0.5, "S_asr": 0.25, "S_eps": 0.2, "S_conf": 0.1, "S_expl": 0.1},        # sums to 1.15
    {"S_acc": 0.35, "S_asr": 0.25, "S_eps": 0.2, "S_conf": 0.1, "S_expl": 0.1, "S_x": 0.0},
])
def test_weights_must_be_complete_and_sum_to_one(bad):
    with pytest.raises(ValueError):
        normalize_weights(bad)


# --- subscores and MRI -----------------------------------------------------------------------

def test_perfectly_robust_campaign_scores_100_grade_a():
    s, reason = score({"fgsm": rows([0.8, 0.8, 0.8])})
    assert reason is None and isinstance(s, Scoring)
    assert s.mri == 100 and s.grade == "A"
    assert s.subscores == {k: 100.0 for k in SUBSCORE_KEYS}
    assert s.weights == DEFAULT_WEIGHTS
    assert s.not_a_readiness_statement is True
    assert s.attack_ids == ["fgsm"] and s.eps_grid == GRID and s.reference_eps == REF
    assert s.basis_measurements == ["m.clean"]


def test_subscore_definitions_and_round_half_even():
    # acc_clean 0.8; acc_adv 0.6/0.4/0.2 -> ratios 0.75/0.5/0.25
    # S_acc = 25; S_eps = trapz([0.75,0.5,0.25],[0.01,0.03,0.1]) / 0.09
    per = {"pgd": rows([0.6, 0.4, 0.2], asr=0.5, conf_gap=0.3, expl_shift=0.25)}
    s, reason = score(per)
    assert reason is None
    auc = ((0.02 * (0.75 + 0.5) / 2) + (0.07 * (0.5 + 0.25) / 2)) / 0.09
    assert s.subscores["S_acc"] == 25.0
    assert s.subscores["S_asr"] == 50.0
    assert s.subscores["S_eps"] == round(100 * auc, 1)
    assert s.subscores["S_conf"] == 70.0
    assert s.subscores["S_expl"] == 75.0
    weighted = sum(DEFAULT_WEIGHTS[k] * s.subscores[k] for k in SUBSCORE_KEYS)
    assert s.mri == round(weighted)
    assert all(0.0 <= v <= 100.0 for v in s.subscores.values())
    assert s.inputs["acc_clean"] == 0.8 and "pgd" in s.inputs["per_attack_subscores"]


def test_subscores_are_unweighted_means_over_attacks_and_ratios_are_clamped():
    per = {"fgsm": rows([0.8, 0.8, 0.8]), "pgd": rows([0.0, 0.0, 0.0], asr=1.0, conf_gap=1.5, expl_shift=2.0)}
    s, _ = score(per)
    assert s.subscores["S_acc"] == 50.0 and s.subscores["S_asr"] == 50.0
    assert s.subscores["S_eps"] == 50.0 and s.subscores["S_conf"] == 50.0 and s.subscores["S_expl"] == 50.0
    assert s.attack_ids == ["fgsm", "pgd"]
    # acc_adv above acc_clean clamps to 1
    s2, _ = score({"fgsm": rows([0.9, 0.9, 0.9])})
    assert s2.subscores["S_acc"] == 100.0


def test_trapezoid_is_over_declared_grid_only():
    assert trapezoid_auc_normalized([0.01, 0.03, 0.1], [1.0, 1.0, 1.0]) == pytest.approx(1.0)
    assert trapezoid_auc_normalized([0.01, 0.03, 0.1], [0.0, 0.0, 0.0]) == pytest.approx(0.0)
    assert trapezoid_auc_normalized([0.05], [0.4]) == 0.4                    # one-point grid degenerates
    s, _ = score_run(modality="image", acc_clean=1.0, per_attack={"fgsm": {0.05: {"acc_adv": 0.4, "asr": 0.6,
                     "conf_gap": 0.0, "expl_shift": 0.0}}}, eps_grid=[0.05], reference_eps=0.05,
                     basis_measurements=["m.clean"])
    assert s.subscores["S_eps"] == 40.0 and any("one-point" in n for n in s.inputs["notes"])


def test_scoring_is_deterministic():
    per = {"fgsm": rows([0.5, 0.4, 0.1], asr=0.4, conf_gap=0.2, expl_shift=0.3)}
    a, _ = score(per)
    b, _ = score(per)
    assert a.model_dump() == b.model_dump()


# --- the MRI-not-computed rule ----------------------------------------------------------------

def test_missing_expl_shift_yields_none_with_reason_and_no_renormalisation():
    s, reason = score({"fgsm": rows([0.6, 0.4, 0.2], asr=0.5, conf_gap=0.3, expl_shift=None)})
    assert s is None
    assert reason.startswith("MRI not computed")
    assert "S_expl" in reason and "explanation stability unavailable" in reason
    assert "weights not renormalised" in reason
    assert "S_acc=25.0" in reason and "S_asr=50.0" in reason   # the four available subscores are reported


def test_missing_asr_or_conf_gap_yields_none():
    s, reason = score({"fgsm": rows([0.6, 0.4, 0.2], asr=None)})
    assert s is None and "S_asr" in reason
    s, reason = score({"fgsm": rows([0.6, 0.4, 0.2], conf_gap=None)})
    assert s is None and "S_conf" in reason


def test_zero_clean_accuracy_yields_none():
    s, reason = score({"fgsm": rows([0.0, 0.0, 0.0])}, acc_clean=0.0)
    assert s is None and "acc_clean == 0" in reason


def test_partial_run_missing_eps_row_yields_none():
    per = {"fgsm": {0.01: {"acc_adv": 0.5, "asr": 0.1, "conf_gap": 0.0, "expl_shift": None},
                    0.03: {"acc_adv": 0.4, "asr": 0.2, "conf_gap": 0.0, "expl_shift": 0.1}}}
    s, reason = score(per)
    assert s is None and "partial run" in reason and "0.1" in reason


def test_configuration_errors_raise():
    with pytest.raises(ValueError):
        score_run(modality="image", acc_clean=0.8, per_attack={"fgsm": rows([0.8, 0.8, 0.8])}, eps_grid=GRID,
                  reference_eps=0.05, basis_measurements=[])
    with pytest.raises(ValueError):
        score({})
    with pytest.raises(ValueError):
        score({"fgsm": rows([0.8, 0.8, 0.8])}, weights={"S_acc": 1.0})


# --- grades ------------------------------------------------------------------------------------

@pytest.mark.parametrize("mri,grade", [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"), (60, "C"),
                                       (59, "D"), (40, "D"), (39, "F"), (0, "F")])
def test_grade_boundaries(mri, grade):
    assert grade_for(mri) == grade


def test_grade_bands_reached_through_score_run():
    def campaign_with_flat_subscore(v: float):
        # acc ratio v everywhere, asr 1-v, conf_gap 1-v, expl_shift 1-v -> every subscore == 100 v
        return score({"fgsm": rows([0.8 * v] * 3, asr=1 - v, conf_gap=1 - v, expl_shift=1 - v)})[0]
    assert campaign_with_flat_subscore(0.95).grade == "A"
    assert campaign_with_flat_subscore(0.80).grade == "B"
    assert campaign_with_flat_subscore(0.65).grade == "C"
    assert campaign_with_flat_subscore(0.50).grade == "D"
    assert campaign_with_flat_subscore(0.20).grade == "F"


def test_readings_are_attack_scoped_and_free_of_banned_words():
    assert set(GRADE_READINGS) == {"A", "B", "C", "D", "F"}
    for text in GRADE_READINGS.values():
        assert not BANNED.search(text), text
        assert not contains_banned_wording(text)
        assert "in-scope" in text or "declared grid" in text          # attack-scoped wording (D9 iii)
    for legacy in ("Hardened", "Harden before fielding", "Not deployment-ready"):
        assert legacy not in GRADE_READINGS.values()
    # The mandatory disclaimer (spec 15.5) is the one place the word "certification" must appear:
    # it states that no grade IS a certification statement.
    assert "not a readiness, safety, or certification statement" in GRADE_SENTENCE
    assert "does not describe robustness to attacks that were not run" in GRADE_SENTENCE
    for banned in ("Hardened", "Not deployment-ready", "certified robust", "Harden before fielding", "safe"):
        assert contains_banned_wording(banned)


# --- severity ---------------------------------------------------------------------------------

def test_eps_bands():
    assert eps_bands([0.01, 0.03, 0.1], 0.03) == (0.01, 0.03, 0.1)
    assert eps_bands([0.1, 0.01, 0.03], 0.1) == (0.01, 0.03, 0.1)      # ref not strictly inside -> median
    assert eps_bands([0.01, 0.02, 0.05, 0.1], 0.05) == (0.01, 0.05, 0.1)
    with pytest.raises(ValueError):
        eps_bands([], 0.03)


@pytest.mark.parametrize("first_eps,asr,expected", [
    (0.01, 0.5, "critical"), (0.01, 0.9, "critical"),
    (0.01, 0.3, "high"), (0.01, 0.2, "high"), (0.03, 0.5, "high"), (0.03, 0.8, "high"),
    (0.03, 0.2, "medium"), (0.03, 0.49, "medium"), (0.01, 0.1, "medium"),
    (0.1, 0.2, "low"), (0.1, 0.99, "low"),
    (None, None, None),
])
def test_severity_table(first_eps, asr, expected):
    assert severity_for("fgsm", first_eps, asr, 0.01, 0.03, 0.1) == expected


def test_first_success_uses_threshold_and_skips_undefined():
    table = {0.01: {"asr": 0.1}, 0.03: {"asr": 0.25}, 0.1: {"asr": 0.9}}
    assert first_success(table) == (0.03, 0.25)
    assert first_success(table, threshold=0.5) == (0.1, 0.9)
    assert first_success({0.01: {"asr": None}, 0.03: {"asr": 0.05}}) == (None, None)


# --- delta ------------------------------------------------------------------------------------

def test_delta_annotates_after_with_measured_differences():
    before, _ = score({"fgsm": rows([0.4, 0.3, 0.1], asr=0.6, conf_gap=0.5, expl_shift=0.5)})
    after, _ = score({"fgsm": rows([0.6, 0.5, 0.3], asr=0.3, conf_gap=0.2, expl_shift=0.2)})
    d = delta(before, after, before_run_id="run-before")
    assert d.delta_from == "run-before"
    assert d.delta_mri == after.mri - before.mri
    assert d.delta_subscores == {k: round(after.subscores[k] - before.subscores[k], 1) for k in SUBSCORE_KEYS}
    assert d.mri == after.mri and before.delta_mri is None


def test_delta_refuses_incompatible_campaigns():
    before, _ = score({"fgsm": rows([0.4, 0.3, 0.1])})
    other_attacks, _ = score({"pgd": rows([0.4, 0.3, 0.1])})
    with pytest.raises(ValueError, match="incompatible campaigns"):
        delta(before, other_attacks)
    other_modality = before.model_copy(update={"modality": "tabular"})
    with pytest.raises(ValueError, match="modality"):
        delta(before, other_modality)
    other_grid, _ = score_run(modality="image", acc_clean=0.8, per_attack={"fgsm": {0.03: {"acc_adv": 0.4,
                              "asr": 0.0, "conf_gap": 0.0, "expl_shift": 0.0}}}, eps_grid=[0.03],
                              reference_eps=0.03, basis_measurements=[])
    with pytest.raises(ValueError, match="eps grid"):
        delta(before, other_grid)


def test_scoring_record_cannot_omit_its_companions():
    with pytest.raises(ValidationError):
        Scoring(mri=50, grade="D", reading="x")  # subscores / weights / grid / attacks are required
