"""Rule layer: interpretation rules I1-I7 and recommendation rules R1-R7 (spec 14.6, 16.2, 22.3)."""

from __future__ import annotations

import re

import pytest

from redsim.ml.recommend.rules import THRESHOLDS, interpret, recommend
from redsim.ml.schema import CandidateRecommendation, Interpretation, Measurement, Observation, Scoring

pytestmark = pytest.mark.unit

GRID = [0.01, 0.03, 0.1]


def _m(mid, family, n_correct, *, attack=None, eps=None, flipped=None, severity=None, n=100, notes=None):
    return Measurement(id=mid, family=family, attack_id=attack, params={"eps": eps} if eps is not None else {}, n=n,
                       n_correct=n_correct, accuracy=n_correct / n, n_flipped_from_clean=flipped, severity=severity,
                       notes=notes or [])


def _degraded() -> list[Measurement]:
    """Clean 80/100; FGSM 50/40/20 (asr .375 at eps_small); PGD 30/20/10; noise control flat at eps_ref."""
    return [
        _m("m.clean", "clean", 80),
        _m("m.evasion.fgsm.eps0.01", "evasion", 50, attack="fgsm", eps=0.01, flipped=30, severity="high"),
        _m("m.evasion.fgsm.eps0.03", "evasion", 40, attack="fgsm", eps=0.03, flipped=40, severity="high"),
        _m("m.evasion.fgsm.eps0.1", "evasion", 20, attack="fgsm", eps=0.1, flipped=60, severity="high"),
        _m("m.evasion.pgd.eps0.01", "evasion", 30, attack="pgd", eps=0.01, flipped=50, severity="critical"),
        _m("m.evasion.pgd.eps0.03", "evasion", 20, attack="pgd", eps=0.03, flipped=60, severity="critical"),
        _m("m.evasion.pgd.eps0.1", "evasion", 5, attack="pgd", eps=0.1, flipped=75, severity="critical"),
        _m("m.control.noise.eps0.03", "control", 78, attack="noise", eps=0.03),
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
        _m("m.control.noise.eps0.03", "control", 80, attack="noise", eps=0.03),
    ]


def _obs(n_flipped=4, clean=0.7, adv=0.4) -> list[Observation]:
    out = []
    for i in range(n_flipped):
        out.append(Observation(id=f"o.{i:03d}", sample_index=i, true_label="a", pred_clean="a", pred_adv="b",
                               flipped=True, confidence_clean=0.9, confidence_adv=0.8, artifacts={},
                               center_mass_ratio_clean=clean, center_mass_ratio_adv=adv))
    out.append(Observation(id="o.099", sample_index=99, true_label="a", pred_clean="a", pred_adv="a", flipped=False,
                           confidence_clean=0.9, confidence_adv=0.9, artifacts={}, center_mass_ratio_clean=0.6,
                           center_mass_ratio_adv=0.6))
    return out


def _scoring(conf_gap=0.6, expl_shift=0.55, modality="image") -> Scoring:
    per_attack = {a: {e: {"acc_adv": 0.3, "asr": 0.5, "conf_gap": conf_gap, "expl_shift": expl_shift if e == 0.03 else None}
                      for e in GRID} for a in ("fgsm", "pgd")}
    return Scoring(mri=30, grade="F", reading="Predictions flipped at the smallest eps in the declared grid.",
                   subscores={"S_acc": 12.5, "S_asr": 50.0, "S_eps": 20.0, "S_conf": 40.0, "S_expl": 45.0},
                   weights={"S_acc": 0.35, "S_asr": 0.25, "S_eps": 0.2, "S_conf": 0.1, "S_expl": 0.1},
                   reference_eps=0.03, eps_grid=GRID, attack_ids=["fgsm", "pgd"], modality=modality,
                   inputs={"acc_clean": 0.8, "per_attack": per_attack})


def _by_code(items: list[Interpretation], code: str) -> list[Interpretation]:
    return [i for i in items if i.statement.startswith(code + ":")]


def _rec(recs: list[CandidateRecommendation], rule: str) -> CandidateRecommendation | None:
    return next((r for r in recs if r.id == f"r.{rule}"), None)


def _all_ids(ms, obs) -> set[str]:
    return {m.id for m in ms} | {o.id for o in obs}


# --------------------------------------------------------------------------- interpretation

def test_interpretation_rules_fire_and_cite_ids():
    ms, obs, sc = _degraded(), _obs(), _scoring()
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
    assert len(i3) == 3 and all(set(i.basis) == {f"m.evasion.pgd.eps{e:g}", f"m.evasion.fgsm.eps{e:g}"} for i, e in zip(i3, GRID))
    i4 = _by_code(out, "I4")
    assert len(i4) == 1 and set(i4[0].basis) == {f"o.{i:03d}" for i in range(4)} and "heuristic" in i4[0].statement
    i5 = _by_code(out, "I5")
    assert {i.basis[0] for i in i5} == {"m.evasion.fgsm.eps0.03", "m.evasion.pgd.eps0.03"} and "0.550" in i5[0].statement
    i6 = _by_code(out, "I6")
    assert {i.basis[0] for i in i6} == {"m.evasion.fgsm.eps0.03", "m.evasion.pgd.eps0.03"} and "0.600" in i6[0].statement
    assert not _by_code(out, "I7")


def test_interpretation_i2_when_noise_also_degrades():
    ms = _degraded()
    ms[-1] = _m("m.control.noise.eps0.03", "control", 60, attack="noise", eps=0.03)
    out = interpret(ms, [], _scoring())
    assert not _by_code(out, "I1")
    i2 = _by_code(out, "I2")
    assert len(i2) == 1 and set(i2[0].basis) == {"m.control.noise.eps0.03", "m.clean"}


def test_interpretation_states_absent_scoring_when_expl_missing():
    ms = _degraded()
    out = interpret(ms, [], None, scoring_reason="S_expl unavailable: explain stage raised ExplainUnavailable")
    i7 = _by_code(out, "I7")
    assert len(i7) == 1 and "MRI not computed" in i7[0].statement and "S_expl unavailable" in i7[0].statement
    assert "never renormalised" in i7[0].statement
    assert set(i7[0].basis) == {"m.clean", "m.evasion.fgsm.eps0.03", "m.evasion.pgd.eps0.03"}
    # without an explicit reason the default names the missing explanation input
    out2 = interpret(ms, [], None)
    assert "S_expl" in _by_code(out2, "I7")[0].statement
    # and I5/I6 cannot fire without scoring inputs or explain meta
    assert not _by_code(out2, "I5") and not _by_code(out2, "I6")


def test_interpretation_reads_expl_shift_from_explain_meta_when_scoring_absent():
    ms = [m for m in _degraded() if m.attack_id != "pgd"]
    out = interpret(ms, [], None, explain_meta={"expl_shift_mean": 0.7, "modality": "image"})
    assert _by_code(out, "I5") and _by_code(out, "I5")[0].basis == ["m.evasion.fgsm.eps0.03"]


def test_flat_set_yields_no_interpretation():
    assert interpret(_flat(), _obs(n_flipped=0), _scoring(conf_gap=0.05, expl_shift=0.02)) == []
    assert interpret([], [], None) == []


# --------------------------------------------------------------------------- recommendations

def test_recommendation_rules_fire_and_cite_ids():
    ms, obs, sc = _degraded(), _obs(), _scoring()
    interp = interpret(ms, obs, sc)
    recs = recommend(ms, obs, interp, sc, seed=7)
    ids = _all_ids(ms, obs)
    assert recs and all(r.status == "candidate" and r.validation == "not evaluated" for r in recs)
    assert all(r.triggered_by and set(r.triggered_by) <= ids for r in recs)
    assert all(r.narrative is None and r.narrative_source == "rules" for r in recs)
    assert len({r.id for r in recs}) == len(recs)

    r1 = _rec(recs, "R1")
    assert r1 is not None and set(r1.triggered_by) == {"m.evasion.fgsm.eps0.01", "m.control.noise.eps0.03", "m.clean"}
    assert "30/80" in r1.rationale and any("AdversarialTrainerMadryPGD" in ref for ref in r1.references)
    assert any(ref.startswith("defense:adversarial_training") for ref in r1.references)
    assert _rec(recs, "R1b") is None

    r2 = _rec(recs, "R2")
    assert r2 is not None and set(r2.triggered_by) == {f"m.evasion.{a}.eps{e:g}" for a in ("pgd", "fgsm") for e in GRID}

    r3 = _rec(recs, "R3")
    assert r3 is not None and {f"o.{i:03d}" for i in range(4)} <= set(r3.triggered_by)
    assert {"m.evasion.fgsm.eps0.03", "m.evasion.pgd.eps0.03"} <= set(r3.triggered_by)
    assert "Heuristic" in r3.rationale
    assert any("FeatureSqueezing" in ref for ref in r3.references) and any("SpatialSmoothing" in ref for ref in r3.references)
    assert any(ref.startswith("defense:feature_squeezing") for ref in r3.references)

    r4 = _rec(recs, "R4")
    assert r4 is not None and r4.triggered_by in (["m.evasion.fgsm.eps0.03"], ["m.evasion.pgd.eps0.03"])
    assert "0.600" in r4.rationale

    r6 = _rec(recs, "R6")
    assert r6 is not None and set(r6.triggered_by) == {m.id for m in ms if m.family == "evasion"} | {"m.clean"}
    assert any("JpegCompression" in ref for ref in r6.references) and "Athalye" in r6.rationale

    r7 = _rec(recs, "R7")
    assert r7 is not None and r7.triggered_by == ["m.clean"] and "100 samples" in r7.rationale and "seed 7" in r7.rationale
    assert _rec(recs, "R5") is None and _rec(recs, "R3t") is None


def test_recommendation_r1b_when_noise_also_degrades():
    ms = _degraded()
    ms[-1] = _m("m.control.noise.eps0.03", "control", 60, attack="noise", eps=0.03)
    recs = recommend(ms, [], [], _scoring())
    assert _rec(recs, "R1") is None
    r1b = _rec(recs, "R1b")
    assert r1b is not None and set(r1b.triggered_by) == {"m.evasion.fgsm.eps0.01", "m.control.noise.eps0.03", "m.clean"}
    assert any("no ART implementation" in ref for ref in r1b.references)


def test_recommendation_r3t_and_r5_paths():
    ms = _degraded() + [_m("m.evasion.hopskipjump.eps0.03", "evasion", 50, attack="hopskipjump", eps=0.03, flipped=30,
                           notes=["queries_mean=850"])]
    obs = [Observation(id="o.000", sample_index=0, true_label="benign", pred_clean="benign", pred_adv="malicious",
                       flipped=True, confidence_clean=0.9, confidence_adv=0.8, artifacts={})]
    meta = {"modality": "tabular", "top3_changed_fraction_flipped": 0.75, "top3_changed_n_flipped": 4}
    recs = recommend(ms, obs, [], None, explain_meta=meta)
    r3t = _rec(recs, "R3t")
    assert r3t is not None and r3t.triggered_by == ["o.000"] and "3 of 4" in r3t.rationale
    assert any("clip_values" in ref for ref in r3t.references)
    r5 = _rec(recs, "R5")
    assert r5 is not None and r5.triggered_by == ["m.evasion.hopskipjump.eps0.03"] and "850" in r5.rationale
    r6 = _rec(recs, "R6")
    assert r6 is not None and not any("JpegCompression" in ref for ref in r6.references)  # tabular: squeezing only


def test_flat_set_only_r7_fires():
    ms = _flat()
    recs = recommend(ms, _obs(n_flipped=0), [], _scoring(conf_gap=0.05, expl_shift=0.02), seed=0)
    assert [r.id for r in recs] == ["r.R7"]
    assert recs[0].triggered_by == ["m.clean"] and recs[0].status == "candidate"


def test_no_numeric_expected_gain_anywhere():
    ms, obs, sc = _degraded(), _obs(), _scoring()
    recs = recommend(ms, obs, interpret(ms, obs, sc), sc)
    gain_re = re.compile(r"(?i)(?:\+\s*\d+\s*(?:mri|points|%)|gain of \d|improv\w* (?:by|of) \d|expected gain:\s*\d)")
    for r in recs:
        dumped = r.model_dump()
        assert "expected_gain" not in dumped and "gain" not in {k.lower() for k in dumped}
        assert not gain_re.search(r.rationale) and not gain_re.search(r.title)
        assert "not measured" in r.rationale
        for banned in ("hardened", "deployment-ready", "certified", "safe "):
            assert banned not in r.rationale.lower() and banned not in r.title.lower()


def test_ranking_is_by_severity_then_degradation_then_id():
    ms, obs, sc = _degraded(), _obs(), _scoring()
    recs = recommend(ms, obs, interpret(ms, obs, sc), sc)
    order = [r.id for r in recs]
    # R2/R3/R6 cite critical pgd rows and rank ahead of R1 (high-severity fgsm) and R7 (no evasion citation, last)
    assert order[-1] == "r.R7"
    assert order.index("r.R2") < order.index("r.R1") and order.index("r.R6") < order.index("r.R1")
    assert order == [r.id for r in recommend(ms, obs, interpret(ms, obs, sc), sc)]  # deterministic


def test_recommend_handles_empty_and_reference_override():
    assert recommend([], [], [], None) == []
    ms = _degraded()
    recs = recommend(ms, [], [], None, reference_eps=0.1)
    r1 = _rec(recs, "R1")
    assert r1 is None  # no control row at eps 0.1, so the noise comparison cannot be made
    assert _rec(recs, "R7") is not None


def test_rules_read_campaign_note_format_when_scoring_absent():
    """campaign.py appends ``conf_gap_mean = 0.6200 over n=100 (...)`` / ``expl_shift_mean = 0.5500 over ...``."""
    ms = [m for m in _degraded() if m.attack_id != "pgd"]
    ref = next(m for m in ms if m.id == "m.evasion.fgsm.eps0.03")
    ref.notes.extend(["conf_gap_mean = 0.6200 over n=100 (mean of max(0, max_j!=y p_j - p_y) on x_adv)",
                      "expl_shift_mean = 0.5500 over 4 explained samples (explain stage)"])
    out = interpret(ms, [], None)
    assert _by_code(out, "I6") and "0.620" in _by_code(out, "I6")[0].statement
    assert _by_code(out, "I5") and "0.550" in _by_code(out, "I5")[0].statement
    recs = recommend(ms, [], out, None)
    assert _rec(recs, "R4") is not None and _rec(recs, "R3") is not None
    assert _rec(recs, "R4").triggered_by == ["m.evasion.fgsm.eps0.03"]


def test_defense_references_use_registered_ids_when_module_present():
    pytest.importorskip("redsim.ml.defenses")
    from redsim.ml.defenses import list_defenses
    registered = {d["id"] for d in list_defenses()}
    ms, obs, sc = _degraded(), _obs(), _scoring()
    recs = recommend(ms, obs, [], sc)
    r6 = _rec(recs, "R6")
    cited = {ref.split(":", 1)[1].split(" ")[0] for ref in r6.references if ref.startswith("defense:")}
    assert cited and cited <= registered  # every preprocessing candidate maps to an id apply_defense accepts
    assert not any("not registered" in ref for ref in r6.references)
