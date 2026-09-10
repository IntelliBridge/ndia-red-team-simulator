"""Rule layer: interpretation rules I1-I7 and recommendation rules R1-R7 (spec 14.6, 16.2, 22.3).

Built against the frozen M0 contract: ``(measurements, observations, score: MRIRecord | None)``,
``Measurement`` without a severity field, ``Observation`` with ``expl_shift`` / ``top_features_*``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest

from redsim.ml.recommend.rules import (
    THRESHOLDS,
    effective_thresholds,
    interpret,
    recommend,
)
from redsim.ml.schema import (
    CampaignConfig,
    CandidateRecommendation,
    Interpretation,
    InterpretationThresholds,
    Measurement,
    MRIInputRow,
    MRIRecord,
    MRIWeights,
    Observation,
    RunRecord,
    ScoringConfig,
    Subscores,
    TargetInfo,
    contains_banned_score_word,
)
from redsim.ml.scoring import DEFAULT_CONTROL_ALPHA, control_preserves_accuracy

pytestmark = pytest.mark.unit

GRID = [0.01, 0.03, 0.1]
T = datetime(2026, 9, 8, tzinfo=UTC)
N_CLEAN_CORRECT = 80


def _m(mid, family, n_correct, *, attack=None, eps=None, flipped=None, n=100, notes=None, **fields):
    extra = {}
    if flipped is not None:
        extra = {"n_flipped_from_clean": flipped, "n_clean_correct": N_CLEAN_CORRECT,
                 "attack_success_rate": round(flipped / N_CLEAN_CORRECT, 4)}
    params = {"eps": eps, "norm": "linf"} if eps is not None else {}
    return Measurement(id=mid, family=family, attack_id=attack, params=params, n=n, n_correct=n_correct,
                       accuracy=n_correct / n, notes=notes or [], **extra, **fields)


def _degraded() -> list[Measurement]:
    """Clean 80/100. FGSM 50/40/20 (ASR .375 at eps_small). PGD 30/20/5. Noise control flat at eps_ref."""
    return [
        _m("m.clean", "clean", 80),
        _m("m.evasion.fgsm.eps0.01", "evasion", 50, attack="fgsm", eps=0.01, flipped=30),
        _m("m.evasion.fgsm.eps0.03", "evasion", 40, attack="fgsm", eps=0.03, flipped=40),
        _m("m.evasion.fgsm.eps0.1", "evasion", 20, attack="fgsm", eps=0.1, flipped=60),
        _m("m.evasion.pgd.eps0.01", "evasion", 30, attack="pgd", eps=0.01, flipped=50),
        _m("m.evasion.pgd.eps0.03", "evasion", 20, attack="pgd", eps=0.03, flipped=60),
        _m("m.evasion.pgd.eps0.1", "evasion", 5, attack="pgd", eps=0.1, flipped=75),
        _m("m.control.noise.eps0.03", "control", 78, attack="noise_control", eps=0.03),
    ]


def _flat() -> list[Measurement]:
    return [
        _m("m.clean", "clean", 80),
        _m("m.evasion.fgsm.eps0.01", "evasion", 80, attack="fgsm", eps=0.01, flipped=0),
        _m("m.evasion.fgsm.eps0.03", "evasion", 79, attack="fgsm", eps=0.03, flipped=1),
        _m("m.evasion.fgsm.eps0.1", "evasion", 78, attack="fgsm", eps=0.1, flipped=2),
        _m("m.evasion.pgd.eps0.01", "evasion", 80, attack="pgd", eps=0.01, flipped=0),
        _m("m.evasion.pgd.eps0.03", "evasion", 79, attack="pgd", eps=0.03, flipped=1),
        _m("m.evasion.pgd.eps0.1", "evasion", 77, attack="pgd", eps=0.1, flipped=3),
        _m("m.control.noise.eps0.03", "control", 80, attack="noise_control", eps=0.03),
    ]


def _obs(n_flipped=4, clean=0.7, adv=0.4) -> list[Observation]:
    out = []
    for i in range(n_flipped):
        out.append(Observation(id=f"o.{i:03d}", sample_index=i, true_label="a", pred_clean="a", pred_adv="b",
                               flipped=True, confidence_clean=0.9, confidence_adv=0.8, artifacts={},
                               center_mass_ratio_clean=clean, center_mass_ratio_adv=adv, expl_shift=0.6))
    out.append(Observation(id="o.099", sample_index=99, true_label="a", pred_clean="a", pred_adv="a", flipped=False,
                           confidence_clean=0.9, confidence_adv=0.9, artifacts={}, center_mass_ratio_clean=0.6,
                           center_mass_ratio_adv=0.6, expl_shift=0.05))
    return out


def _score(conf_gap=0.6, expl_shift=0.55, attack_ids=("fgsm", "pgd")) -> MRIRecord:
    inputs = [MRIInputRow(attack_id=a, eps=e, acc_clean=0.8, acc_adv=0.3, asr=0.5, conf_gap=conf_gap,
                          expl_shift=expl_shift if e == 0.03 else None, n=100, n_correct_clean=N_CLEAN_CORRECT,
                          n_attacked=100, n_explained=4 if e == 0.03 else None) for a in attack_ids for e in GRID]
    return MRIRecord(scoring_version="mri-1", weights=MRIWeights(), eps_grid=GRID, reference_eps=0.03, norm="linf",
                     attack_ids=list(attack_ids), finding_asr_threshold=0.2, settings_hash="h" * 64, inputs=inputs,
                     subscores=Subscores(S_acc=12.5, S_asr=50.0, S_eps=20.0, S_conf=40.0, S_expl=45.0), mri=30,
                     grade="F", completeness="complete",
                     reading="Predictions flipped at the smallest eps in the declared grid.", computed_at=T)


def _partial_score(missing: str) -> MRIRecord:
    return MRIRecord(scoring_version="mri-1", weights=MRIWeights(), eps_grid=GRID, reference_eps=0.03, norm="linf",
                     attack_ids=["fgsm", "pgd"], finding_asr_threshold=0.2, settings_hash="h" * 64,
                     subscores=Subscores(S_acc=12.5, S_asr=50.0, S_eps=20.0, S_conf=40.0), mri=None, grade=None,
                     completeness="partial", missing=[missing], computed_at=T)


def _by_code(items: list[Interpretation], code: str) -> list[Interpretation]:
    return [i for i in items if i.statement.startswith(code + ":")]


def _rec(recs: list[CandidateRecommendation], rule: str) -> CandidateRecommendation | None:
    return next((r for r in recs if r.id == f"r.{rule}"), None)


def _all_ids(ms, obs, interp=()) -> set[str]:
    return {m.id for m in ms} | {o.id for o in obs} | {i.id for i in interp}


def _measurement_ids(rec: CandidateRecommendation) -> set[str]:
    return {i for i in rec.triggered_by if i.startswith(("m.", "o."))}


def _interp_ids(rec: CandidateRecommendation) -> set[str]:
    return {i for i in rec.triggered_by if i.startswith("i.")}


# --------------------------------------------------------------------------- thresholds

def test_default_thresholds_mirror_the_frozen_interpretation_thresholds():
    it = InterpretationThresholds()
    assert THRESHOLDS["attack_drop"] == it.evasion_drop and THRESHOLDS["control_flat"] == it.control_tolerance
    assert THRESHOLDS["control_drop"] == it.control_drop and THRESHOLDS["iterative_gap"] == it.iterative_margin
    assert THRESHOLDS["cmr_drop"] == it.center_mass_drop and THRESHOLDS["expl_shift"] == it.expl_shift_high
    assert THRESHOLDS["conf_gap"] == it.conf_gap_high and THRESHOLDS["asr"] == CampaignConfig.model_fields[
        "finding_asr_threshold"].default
    assert THRESHOLDS["control_alpha"] == DEFAULT_CONTROL_ALPHA == 0.05      # the binomial predicate's level
    assert effective_thresholds(None, None) == THRESHOLDS
    eff = effective_thresholds(InterpretationThresholds(expl_shift_high=0.9), 0.4)
    assert eff["expl_shift"] == 0.9 and eff["asr"] == 0.4 and eff["any_drop"] == THRESHOLDS["any_drop"]
    assert eff["control_alpha"] == DEFAULT_CONTROL_ALPHA


def test_thresholds_from_the_score_record_and_keyword_are_honoured():
    ms, obs, sc = _degraded(), _obs(), _score()
    assert _by_code(interpret(ms, obs, sc), "I5")
    assert not _by_code(interpret(ms, obs, sc, thresholds=InterpretationThresholds(expl_shift_high=0.9)), "I5")
    # R1 needs ASR >= threshold at eps_small (.375): a score record with a stricter threshold suppresses it
    strict = sc.model_copy(update={"finding_asr_threshold": 0.5})
    assert _rec(recommend(ms, obs, sc), "R1") is not None
    assert _rec(recommend(ms, obs, strict), "R1") is None
    assert _rec(recommend(ms, obs, sc, finding_asr_threshold=0.5), "R1") is None


def test_positional_contracts_and_scoring_config_settings():
    """The plan's order is (measurements, observations, score[, settings]). The campaign runner passes
    (measurements, observations, interpretation, score). Both orders must yield the same candidates."""
    ms, obs, sc = _degraded(), _obs(), _score()
    interp = interpret(ms, obs, sc)
    canonical = [r.model_dump() for r in recommend(ms, obs, sc, interpretation=interp, seed=1)]
    assert canonical and [r.model_dump() for r in recommend(ms, obs, interp, sc, seed=1)] == canonical
    assert any(i.startswith("i.") for r in canonical for i in r["triggered_by"])
    no_score = [r.model_dump() for r in recommend(ms, obs, None, interpretation=interp, seed=1)]
    assert [r.model_dump() for r in recommend(ms, obs, interp, None, seed=1)] == no_score
    # the fourth positional may be the frozen ScoringConfig, whose interpretation block sets the thresholds
    strict = ScoringConfig(interpretation=InterpretationThresholds(expl_shift_high=0.9))
    assert _by_code(interpret(ms, obs, sc), "I5") and not _by_code(interpret(ms, obs, sc, strict), "I5")
    r3 = _rec(recommend(ms, obs, sc, strict), "R3")
    assert r3 is not None and "shifted by" not in r3.rationale   # centre-mass branch only
    assert _rec(recommend(ms, obs, interp, strict), "R3") is not None
    # the explicit keyword still wins over settings
    assert _by_code(interpret(ms, obs, sc, strict, thresholds=InterpretationThresholds()), "I5")
    for bad in ({"mri": 1}, "score"):
        with pytest.raises(TypeError):
            recommend(ms, obs, bad)
        with pytest.raises(TypeError):
            interpret(ms, obs, bad)
    with pytest.raises(TypeError):
        recommend(ms, obs, sc, "settings")


# --------------------------------------------------------------------------- interpretation

def test_interpretation_rules_fire_and_cite_ids():
    ms, obs, sc = _degraded(), _obs(), _score()
    out = interpret(ms, obs, sc)
    ids = _all_ids(ms, obs)
    assert out and all(i.kind == "inferred" and i.basis and set(i.basis) <= ids for i in out)
    assert [i.id for i in out] == [f"i.{n}" for n in range(1, len(out) + 1)]

    i1 = _by_code(out, "I1")
    assert {tuple(sorted(i.basis)) for i in i1} == {
        ("m.clean", "m.control.noise.eps0.03", "m.evasion.fgsm.eps0.03"),
        ("m.clean", "m.control.noise.eps0.03", "m.evasion.pgd.eps0.03")}
    assert all("gradient" in i.statement for i in i1) and str(THRESHOLDS["attack_drop"]) in i1[0].statement
    assert not _by_code(out, "I2")  # control is flat
    i3 = _by_code(out, "I3")
    assert len(i3) == 3 and all(set(i.basis) == {f"m.evasion.pgd.eps{e:g}", f"m.evasion.fgsm.eps{e:g}"}
                                for i, e in zip(i3, GRID, strict=True))
    i4 = _by_code(out, "I4")
    assert len(i4) == 1 and set(i4[0].basis) == {f"o.{i:03d}" for i in range(4)} and "heuristic" in i4[0].statement
    i5 = _by_code(out, "I5")
    assert {i.basis[0] for i in i5} == {"m.evasion.fgsm.eps0.03", "m.evasion.pgd.eps0.03"} and "0.550" in i5[0].statement
    i6 = _by_code(out, "I6")
    assert {i.basis[0] for i in i6} == {"m.evasion.fgsm.eps0.03", "m.evasion.pgd.eps0.03"} and "0.600" in i6[0].statement
    assert not _by_code(out, "I7")
    assert not any(contains_banned_score_word(i.statement) for i in out)


def test_interpretation_i2_when_noise_also_degrades():
    ms = _degraded()
    ms[-1] = _m("m.control.noise.eps0.03", "control", 60, attack="noise_control", eps=0.03)
    out = interpret(ms, [], _score())
    assert not _by_code(out, "I1")
    i2 = _by_code(out, "I2")
    assert len(i2) == 1 and set(i2[0].basis) == {"m.control.noise.eps0.03", "m.clean"}


def test_interpretation_states_absent_score_when_expl_missing():
    ms = _degraded()
    out = interpret(ms, [], None, scoring_reason="S_expl unavailable: explain stage raised ExplainUnavailable")
    i7 = _by_code(out, "I7")
    assert len(i7) == 1 and "MRI not computed" in i7[0].statement and "S_expl unavailable" in i7[0].statement
    assert "never renormalised" in i7[0].statement
    assert set(i7[0].basis) == {"m.clean", "m.evasion.fgsm.eps0.03", "m.evasion.pgd.eps0.03"}
    # without an explicit reason the default names the missing explanation input
    out2 = interpret(ms, [], None)
    assert "S_expl" in _by_code(out2, "I7")[0].statement
    # and I5/I6 cannot fire without reference-row fields, score inputs or explain meta
    assert not _by_code(out2, "I5") and not _by_code(out2, "I6")


def test_interpretation_i7_names_what_a_partial_score_record_is_missing():
    out = interpret(_degraded(), [], _partial_score("S_expl unavailable (explain stage absent)"))
    i7 = _by_code(out, "I7")
    assert len(i7) == 1 and "S_expl unavailable (explain stage absent)" in i7[0].statement
    assert _by_code(interpret(_degraded(), [], _score()), "I7") == []


def test_interpretation_reads_reference_row_fields_first():
    """The frozen Measurement carries expl_shift_mean / conf_gap_mean on the reference row (spec 13.5)."""
    ms = [m for m in _degraded() if m.attack_id != "pgd"]
    ref = next(m for m in ms if m.id == "m.evasion.fgsm.eps0.03")
    ms[ms.index(ref)] = ref.model_copy(update={"expl_shift_mean": 0.55, "expl_shift_n": 4, "expl_shift_n_excluded": 0,
                                               "expl_shift_noise_floor": 0.1, "expl_shift_noise_floor_n": 4,
                                               "conf_gap_mean": 0.62, "conf_gap_n": 100})
    out = interpret(ms, [], None)
    assert _by_code(out, "I6") and "0.620" in _by_code(out, "I6")[0].statement and "n = 100" in _by_code(out, "I6")[0].statement
    assert _by_code(out, "I5") and "0.550" in _by_code(out, "I5")[0].statement and "n = 4" in _by_code(out, "I5")[0].statement
    recs = recommend(ms, [], None, interpretation=out)
    assert _rec(recs, "R4") is not None and _rec(recs, "R3") is not None
    assert _measurement_ids(_rec(recs, "R4")) == {"m.evasion.fgsm.eps0.03"}
    # the row's own field wins over a score input that disagrees
    sc = _score(conf_gap=0.1, expl_shift=0.1, attack_ids=("fgsm",))
    assert "0.620" in _by_code(interpret(ms, [], sc), "I6")[0].statement


def test_interpretation_reads_expl_shift_from_explain_meta_when_score_absent():
    ms = [m for m in _degraded() if m.attack_id != "pgd"]
    out = interpret(ms, [], None, explain_meta={"expl_shift_mean": 0.7, "modality": "image"})
    assert _by_code(out, "I5") and _by_code(out, "I5")[0].basis == ["m.evasion.fgsm.eps0.03"]


def test_flat_set_yields_no_interpretation():
    assert interpret(_flat(), _obs(n_flipped=0), _score(conf_gap=0.05, expl_shift=0.02)) == []
    assert interpret([], [], None) == []


def _scaled(n: int, clean_ok: int, ctrl_ok: int, *, fgsm=(0.6, 0.5, 0.3), flipped=(0.3, 0.4, 0.6)) -> list[Measurement]:
    """Clean, three FGSM rows with explicit ASR denominators and one control row at eps_ref, all at slice size ``n``."""
    ms = [_m("m.clean", "clean", clean_ok, n=n)]
    for e, acc, fl in zip(GRID, fgsm, flipped, strict=True):
        k = round(fl * clean_ok)
        ms.append(_m(f"m.evasion.fgsm.eps{e:g}", "evasion", round(acc * n), attack="fgsm", eps=e, n=n,
                     n_flipped_from_clean=k, n_clean_correct=clean_ok, attack_success_rate=k / clean_ok))
    ms.append(_m("m.control.noise.eps0.03", "control", ctrl_ok, attack="noise_control", eps=0.03, n=n))
    return ms


def test_i1_and_r1_read_the_binomial_control_predicate_not_a_fixed_tolerance():
    """Spec 12.4 / register G-SCORE1: the control comparison is ``scoring.control_preserves_accuracy``."""
    # small slice: clean 16/20, control 14/20 is a ten-point drop but inside binomial noise (p = 0.196 at alpha 0.05);
    # a fixed 0.05 tolerance would have withheld I1 and R1 here
    small = _scaled(20, 16, 14, fgsm=(0.5, 0.4, 0.2))
    assert control_preserves_accuracy(small[0], small[-1])
    out = interpret(small, [], None)
    i1 = _by_code(out, "I1")
    assert len(i1) == 1 and set(i1[0].basis) == {"m.clean", "m.evasion.fgsm.eps0.03", "m.control.noise.eps0.03"}
    s = i1[0].statement
    assert "control 14/20 vs clean 16/20" in s and "p = 0.196" in s and "alpha = 0.05" in s and "floor 0.02" in s
    assert "drop > 0.2" in s and "|delta|" not in s
    assert not _by_code(out, "I2")
    recs = recommend(small, [], None, interpretation=out)
    r1 = _rec(recs, "R1")
    assert r1 is not None and "p = 0.196" in r1.rationale and "alpha = 0.05" in r1.rationale
    assert _measurement_ids(r1) == {"m.evasion.fgsm.eps0.01", "m.control.noise.eps0.03", "m.clean"}
    assert _interp_ids(r1) == {i1[0].id} and _rec(recs, "R1b") is None

    # large slice: clean 800/1000, control 770/1000 is only a three-point drop but significant (p = 0.011);
    # a fixed 0.05 tolerance would have called the control flat. It is short of control_drop (0.10) too, so
    # neither the gradient-aligned nor the noise-sensitive statement is made and no R1 / R1b candidate exists.
    large = _scaled(1000, 800, 770)
    assert not control_preserves_accuracy(large[0], large[-1])
    out = interpret(large, [], None)
    assert not _by_code(out, "I1") and not _by_code(out, "I2")
    recs = recommend(large, [], None, interpretation=out)
    assert _rec(recs, "R1") is None and _rec(recs, "R1b") is None and _rec(recs, "R7") is not None

    # a control that is significantly below clean and past control_drop: I2 and R1b, never I1 / R1
    noisy = _scaled(1000, 800, 650)
    out = interpret(noisy, [], None)
    i2 = _by_code(out, "I2")
    assert not _by_code(out, "I1") and len(i2) == 1 and set(i2[0].basis) == {"m.control.noise.eps0.03", "m.clean"}
    assert "control 650/1000 vs clean 800/1000" in i2[0].statement and "p = 0.000" in i2[0].statement
    assert "drop > 0.1" in i2[0].statement
    recs = recommend(noisy, [], None, interpretation=out)
    assert _rec(recs, "R1") is None
    r1b = _rec(recs, "R1b")
    assert r1b is not None and "p = 0.000" in r1b.rationale and _interp_ids(r1b) == {i2[0].id}
    # the default level is the scoring module's, and it is printed rather than assumed
    assert THRESHOLDS["control_alpha"] == DEFAULT_CONTROL_ALPHA
    assert not any(contains_banned_score_word(i.statement) for i in out)


def test_i8_noise_sensitive_eps_cites_the_control_and_clean_rows():
    """Spec 12.4: the control alone crossing finding_asr_threshold at some grid eps is an Interpretation
    (kind inferred, basis = control + clean ids), not a caption on a measurement."""
    assert not _by_code(interpret(_degraded(), [], None), "I8")
    ms = _degraded() + [_m("m.control.noise.eps0.1", "control", 45, attack="noise_control", eps=0.1, flipped=35)]
    out = interpret(ms, [], None)
    i8 = _by_code(out, "I8")
    assert len(i8) == 1 and i8[0].basis == ["m.control.noise.eps0.1", "m.clean"] and i8[0].kind == "inferred"
    s = i8[0].statement
    assert "noise-sensitive at eps=0.1" in s and "80/100 to 45/100" in s and "not attributable" in s
    assert "control ASR 0.438 >= 0.2" in s                       # the control's own ASR against the campaign threshold
    # the threshold is the campaign's: a stricter one silences the rule, and the score record's value is read too
    assert not _by_code(interpret(ms, [], None, finding_asr_threshold=0.5), "I8")
    assert not _by_code(interpret(ms, [], _score().model_copy(update={"finding_asr_threshold": 0.5})), "I8")
    # without ASR fields on the control row, the accuracy drop is read against the same threshold
    plain = _m("m.control.noise.eps0.1", "control", 45, attack="noise_control", eps=0.1)
    s2 = _by_code(interpret(_degraded() + [plain], [], None), "I8")[0].statement
    assert "accuracy drop 0.350 > 0.2" in s2
    # I1 at eps_ref still fires: the control at 0.03 is flat while the one at 0.1 is not; I8 sits with I1/I2
    assert _by_code(out, "I1") and not _by_code(out, "I2")
    assert [i.id for i in out] == [f"i.{n}" for n in range(1, len(out) + 1)]
    assert not any(contains_banned_score_word(i.statement) for i in out)
    # a flat control at every eps yields no I8
    assert not _by_code(interpret(_flat() + [_m("m.control.noise.eps0.1", "control", 79, attack="noise_control",
                                                 eps=0.1, flipped=1)], [], None), "I8")


# --------------------------------------------------------------------------- recommendations

def test_recommendation_rules_fire_and_cite_ids():
    ms, obs, sc = _degraded(), _obs(), _score()
    interp = interpret(ms, obs, sc)
    recs = recommend(ms, obs, sc, interpretation=interp, seed=7)
    ids = _all_ids(ms, obs, interp)
    assert recs and all(r.status == "candidate" for r in recs)
    assert all(r.triggered_by and set(r.triggered_by) <= ids for r in recs)
    assert all(r.narrative is None and r.narrative_source == "rules" for r in recs)
    assert len({r.id for r in recs}) == len(recs)
    by_id = {i.id: i for i in interp}

    r1 = _rec(recs, "R1")
    assert r1 is not None and _measurement_ids(r1) == {"m.evasion.fgsm.eps0.01", "m.control.noise.eps0.03", "m.clean"}
    assert _interp_ids(r1) and all(by_id[i].statement.startswith("I1:") and "m.evasion.fgsm.eps0.03" in by_id[i].basis
                                   for i in _interp_ids(r1))
    assert "30/80" in r1.rationale and any("AdversarialTrainerMadryPGD" in ref for ref in r1.references)
    assert any(ref.startswith("Madry et al. 2018") for ref in r1.references)
    assert _rec(recs, "R1b") is None

    r2 = _rec(recs, "R2")
    assert r2 is not None and _measurement_ids(r2) == {f"m.evasion.{a}.eps{e:g}" for a in ("pgd", "fgsm") for e in GRID}
    assert _interp_ids(r2) == {i.id for i in _by_code(interp, "I3")}

    r3 = _rec(recs, "R3")
    assert r3 is not None and {f"o.{i:03d}" for i in range(4)} <= _measurement_ids(r3)
    assert {"m.evasion.fgsm.eps0.03", "m.evasion.pgd.eps0.03"} <= _measurement_ids(r3)
    assert _interp_ids(r3) == {i.id for i in _by_code(interp, "I4") + _by_code(interp, "I5")}
    assert "Heuristic" in r3.rationale
    assert any("FeatureSqueezing" in ref for ref in r3.references) and any("SpatialSmoothing" in ref for ref in r3.references)
    assert any(ref.startswith("Xu, Evans, Qi 2018") for ref in r3.references)

    r4 = _rec(recs, "R4")
    assert r4 is not None and _measurement_ids(r4) in ({"m.evasion.fgsm.eps0.03"}, {"m.evasion.pgd.eps0.03"})
    assert len(_interp_ids(r4)) == 1 and by_id[next(iter(_interp_ids(r4)))].statement.startswith("I6:")
    assert "0.600" in r4.rationale

    r6 = _rec(recs, "R6")
    assert r6 is not None and set(r6.triggered_by) == {m.id for m in ms if m.family == "evasion"} | {"m.clean"}
    assert any("JpegCompression" in ref for ref in r6.references) and "Athalye" in r6.rationale

    r7 = _rec(recs, "R7")
    assert r7 is not None and r7.triggered_by == ["m.clean"] and "100 samples" in r7.rationale and "seed 7" in r7.rationale
    assert _rec(recs, "R5") is None and _rec(recs, "R3t") is None


def test_recommendations_without_interpretation_cite_evidence_only():
    ms, obs, sc = _degraded(), _obs(), _score()
    recs = recommend(ms, obs, sc)
    assert recs and all(set(r.triggered_by) <= _all_ids(ms, obs) for r in recs)
    assert all(not _interp_ids(r) for r in recs)


def test_recommendation_r1b_when_noise_also_degrades():
    ms = _degraded()
    ms[-1] = _m("m.control.noise.eps0.03", "control", 60, attack="noise_control", eps=0.03)
    interp = interpret(ms, [], _score())
    recs = recommend(ms, [], _score(), interpretation=interp)
    assert _rec(recs, "R1") is None
    r1b = _rec(recs, "R1b")
    assert r1b is not None and _measurement_ids(r1b) == {"m.evasion.fgsm.eps0.01", "m.control.noise.eps0.03", "m.clean"}
    assert _interp_ids(r1b) == {i.id for i in _by_code(interp, "I2")}
    assert any("no ART implementation" in ref for ref in r1b.references)


def test_recommendation_r3t_and_r5_paths():
    ms = _degraded() + [_m("m.evasion.hopskipjump.eps0.03", "evasion", 50, attack="hopskipjump", eps=0.03, flipped=30,
                           queries_mean=850.0)]
    feats = ["url_length", "count_dot", "digit_ratio", "path_depth"]
    obs = []
    for i in range(4):   # 3 of 4 flipped rows change their top-3 feature set, one keeps it (reordered only)
        adv = feats[1:] + feats[:1] if i < 3 else [feats[2], feats[0], feats[1], feats[3]]
        obs.append(Observation(id=f"o.{i:03d}", sample_index=i, true_label="benign", pred_clean="benign",
                               pred_adv="malicious", flipped=True, confidence_clean=0.9, confidence_adv=0.8,
                               artifacts={}, top_features_clean=feats, top_features_adv=adv, expl_shift=0.3))
    obs.append(Observation(id="o.099", sample_index=99, true_label="benign", pred_clean="benign", pred_adv="benign",
                           flipped=False, confidence_clean=0.9, confidence_adv=0.9, artifacts={},
                           top_features_clean=feats, top_features_adv=feats[::-1]))
    recs = recommend(ms, obs, None)   # modality inferred from the feature rankings
    r3t = _rec(recs, "R3t")
    assert r3t is not None and r3t.triggered_by == ["o.000", "o.001", "o.002"] and "3 of 4" in r3t.rationale
    assert any("clip_values" in ref for ref in r3t.references)
    r5 = _rec(recs, "R5")
    assert r5 is not None and r5.triggered_by == ["m.evasion.hopskipjump.eps0.03"] and "850" in r5.rationale
    r6 = _rec(recs, "R6")
    assert r6 is not None and not any("JpegCompression" in ref for ref in r6.references)  # tabular: squeezing only
    # the explainer meta form is still honoured when observations carry no rankings
    meta = {"modality": "tabular", "top3_changed_fraction_flipped": 0.75, "top3_changed_n_flipped": 4}
    plain = [Observation(id="o.000", sample_index=0, true_label="benign", pred_clean="benign", pred_adv="malicious",
                         flipped=True, confidence_clean=0.9, confidence_adv=0.8, artifacts={})]
    r3t_meta = _rec(recommend(ms, plain, None, explain_meta=meta), "R3t")
    assert r3t_meta is not None and r3t_meta.triggered_by == ["o.000"] and "3 of 4" in r3t_meta.rationale


def test_flat_set_only_r7_fires():
    ms = _flat()
    recs = recommend(ms, _obs(n_flipped=0), _score(conf_gap=0.05, expl_shift=0.02), seed=0)
    assert [r.id for r in recs] == ["r.R7"]
    assert recs[0].triggered_by == ["m.clean"] and recs[0].status == "candidate"


def test_no_numeric_expected_gain_and_no_banned_words_anywhere():
    ms, obs, sc = _degraded(), _obs(), _score()
    interp = interpret(ms, obs, sc)
    recs = recommend(ms, obs, sc, interpretation=interp)
    gain_re = re.compile(r"(?i)(?:\+\s*\d+\s*(?:mri|points|%)|gain of \d|improv\w* (?:by|of) \d|expected gain:\s*\d)")
    for r in recs:
        dumped = r.model_dump()
        assert "expected_gain" not in dumped and "gain" not in {k.lower() for k in dumped}
        assert set(dumped) == {"id", "title", "rationale", "triggered_by", "status", "references", "narrative",
                               "narrative_source"}
        assert not gain_re.search(r.rationale) and not gain_re.search(r.title)
        assert "no measurement of its effect" in r.rationale
        assert "verify" not in r.rationale.lower() and "expected gain" not in r.rationale.lower()
        assert not any(ref.startswith("defense:") for ref in r.references)
        assert not contains_banned_score_word(r.title) and not contains_banned_score_word(r.rationale)
        assert not any(contains_banned_score_word(ref) for ref in r.references)
    assert not any(contains_banned_score_word(i.statement) for i in interp)


def test_ranking_is_by_exposure_then_degradation_then_id():
    ms, obs, sc = _degraded(), _obs(), _score()
    recs = recommend(ms, obs, sc, interpretation=interpret(ms, obs, sc))
    order = [r.id for r in recs]
    # R2 / R3 / R6 cite pgd (first success at eps 0.01 with ASR .625) and rank ahead of R1, which cites only
    # fgsm (ASR .375 at eps 0.01). R7 cites no evasion row and comes last.
    assert order[-1] == "r.R7"
    assert order.index("r.R2") < order.index("r.R1") and order.index("r.R6") < order.index("r.R1")
    assert order.index("r.R3") < order.index("r.R1")
    assert order == [r.id for r in recommend(ms, obs, sc, interpretation=interpret(ms, obs, sc))]  # deterministic


def test_recommend_handles_empty_and_reference_override():
    assert recommend([], [], None) == []
    ms = _degraded()
    recs = recommend(ms, [], None, reference_eps=0.1)
    r1 = _rec(recs, "R1")
    assert r1 is None  # no control row at eps 0.1, so the noise comparison cannot be made
    assert _rec(recs, "R7") is not None


def test_references_are_plain_text_art_classes_and_papers():
    ms, obs, sc = _degraded(), _obs(), _score()
    recs = recommend(ms, obs, sc)
    r6 = _rec(recs, "R6")
    assert r6 is not None
    assert r6.references[:6] == [
        "art.defences.preprocessor.JpegCompression",
        "Dziugaite, Ghahramani, Roy 2016, A study of the effect of JPG compression on adversarial images",
        "art.defences.preprocessor.SpatialSmoothing",
        "Xu, Evans, Qi 2018, Feature Squeezing",
        "art.defences.preprocessor.FeatureSqueezing",
    ][:6] or r6.references[:5] == [
        "art.defences.preprocessor.JpegCompression",
        "Dziugaite, Ghahramani, Roy 2016, A study of the effect of JPG compression on adversarial images",
        "art.defences.preprocessor.SpatialSmoothing",
        "Xu, Evans, Qi 2018, Feature Squeezing",
        "art.defences.preprocessor.FeatureSqueezing",
    ]
    assert r6.references[-1] == "Athalye, Carlini, Wagner 2018, Obfuscated Gradients Give a False Sense of Security"
    assert len(r6.references) == len(set(r6.references))
    for r in recs:
        assert all(isinstance(ref, str) and ":" not in ref.split(" ", 1)[0] for ref in r.references), r.references


def test_rule_output_assembles_into_a_valid_run_record():
    """The frozen RunRecord rejects dangling citations. Rule output must slot in as-is."""
    ms, obs, sc = _degraded(), _obs(), _score()
    interp = interpret(ms, obs, sc)
    recs = recommend(ms, obs, sc, interpretation=interp, seed=0)
    cfg = CampaignConfig(target_id="tiny", modality="image", attack_ids=["fgsm", "pgd"], eps_grid=GRID,
                         reference_eps=0.03, dataset_id="fixture/synthetic")
    target = TargetInfo(id="tiny", name="Tiny random CNN (test double)", domain="image", status="available")
    rec = RunRecord(run_id="r", status="running", created_at=T, config=cfg, target=target, measurements=ms,
                    observations=obs, interpretation=interp, recommendations=recs, score=sc)
    assert RunRecord.model_validate(rec.model_dump(mode="json")) == rec
    assert all(r.status == "candidate" for r in rec.recommendations)
