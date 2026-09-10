"""MRI scoring against the frozen M0 contract (spec section 15; master plan section 5). Pure Python, no ML extra.

Pins: the ``ScoringConfig`` weight vector (0.35/0.25/0.20/0.10/0.10 by default) is used as given and
never renormalised; ``MRI == round(sum w*S)`` only when all five subscores exist, else a PARTIAL
``MRIRecord`` that names what is missing and carries no ``mri`` or ``grade``; grade bands come from
``schema.grade_for_mri``; readings are attack-scoped and free of banned wording; the severity table of
section 15.5 reads ``SeverityThresholds``; ``IncompatibleCampaigns`` is the typed refusal of the
comparison layer; one ``RobustnessCurve`` per attack is read back from the measurement table.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from redsim.ml.errors import MLError
from redsim.ml.eval import eps_tag
from redsim.ml.schema import (
    GRADE_STATEMENT,
    CampaignConfig,
    ConfidenceThresholds,
    Measurement,
    MLFindingDetail,
    MRIRecord,
    MRIWeights,
    RobustnessCurve,
    ScoringConfig,
    SeverityThresholds,
    contains_banned_score_word,
    grade_for_mri,
)
from redsim.ml.scoring import (
    CONTROL_ACCURACY_FLOOR,
    DEFAULT_CONTROL_ALPHA,
    DEFAULT_EPS_GRID_L2,
    DEFAULT_EPS_GRID_LINF,
    DEFAULT_MAX_EPS_GRID_MEMBERS,
    DEFAULT_REFERENCE_EPS,
    GRADE_READINGS,
    GRADE_SENTENCE,
    SCORING_VERSION,
    SUBSCORE_KEYS,
    IncompatibleCampaigns,
    binomial_cdf,
    canonical_settings_json,
    confidence_for,
    contains_banned_wording,
    control_degradation_pvalue,
    control_preserves_accuracy,
    default_eps_grid,
    default_reference_eps,
    eps_bands,
    finding_inputs,
    first_success,
    input_rows,
    reading_for,
    robustness_curves,
    score_run,
    settings_hash,
    severity_for,
    trapezoid_auc_normalized,
    weights_by_subscore,
)

GRID = [0.01, 0.03, 0.1]
REF = 0.03
N = 100
N_CLEAN_CORRECT = 80
T = datetime(2026, 9, 8, tzinfo=UTC)
SPEC_WEIGHTS = {"S_acc": 0.35, "S_asr": 0.25, "S_eps": 0.20, "S_conf": 0.10, "S_expl": 0.10}


def config(**over) -> CampaignConfig:
    base = {"target_id": "tiny", "modality": "image", "attack_ids": ["fgsm"], "eps_grid": GRID,
            "reference_eps": REF, "dataset_id": "synthetic"}
    base.update(over)
    return CampaignConfig(**base)


def clean(acc: float = 0.8, n: int = N) -> Measurement:
    n_correct = round(acc * n)
    return Measurement(id="m.clean", family="clean", n=n, n_correct=n_correct, accuracy=n_correct / n)


def row(attack: str, eps: float, acc_adv: float, *, asr: float | None = 0.0, conf_gap: float | None = 0.0,
        expl_shift: float | None = None, n: int = N, n_clean_correct: int = N_CLEAN_CORRECT,
        pert: float | None = None, queries: float | None = None) -> Measurement:
    n_correct = round(acc_adv * n)
    n_cc = 0 if asr is None else n_clean_correct
    return Measurement(
        id=f"m.evasion.{attack}.{eps_tag(eps)}", family="evasion", attack_id=attack,
        params={"eps": eps, "norm": "linf"}, n=n, n_correct=n_correct, accuracy=n_correct / n,
        n_flipped_from_clean=0 if asr is None else round(asr * n_cc), n_clean_correct=n_cc,
        attack_success_rate=asr, conf_gap_mean=conf_gap, conf_gap_n=None if conf_gap is None else n,
        expl_shift_mean=expl_shift, expl_shift_n=None if expl_shift is None else 8,
        pert_first_success_mean=pert, pert_first_success_n=None if pert is None else 5, queries_mean=queries)


def control(eps: float, acc: float, *, asr: float = 0.0, n: int = N) -> Measurement:
    n_correct = round(acc * n)
    return Measurement(id=f"m.control.noise.{eps_tag(eps)}", family="control", attack_id="noise_control",
                       params={"eps": eps, "norm": "linf"}, n=n, n_correct=n_correct, accuracy=n_correct / n,
                       n_flipped_from_clean=round(asr * N_CLEAN_CORRECT), n_clean_correct=N_CLEAN_CORRECT,
                       attack_success_rate=asr)


def rows(attack: str, accs, *, asr=0.0, conf_gap=0.0, expl_shift=0.0, **kw) -> list[Measurement]:
    """Per-eps rows for one attack; ``expl_shift`` is defined at the reference eps only (spec 15.1)."""
    return [row(attack, e, a, asr=asr, conf_gap=conf_gap,
                expl_shift=expl_shift if math.isclose(e, REF) else None, **kw)
            for e, a in zip(GRID, accs, strict=True)]


def score(per_attack: dict[str, list[Measurement]], acc_clean: float = 0.8, **cfg):
    ms = [clean(acc_clean)] + [m for ms_ in per_attack.values() for m in ms_]
    return score_run(config=config(attack_ids=list(per_attack), **cfg), measurements=ms, computed_at=T)


# --- weights ---------------------------------------------------------------------------------

def test_weights_come_from_scoring_config_and_are_never_renormalised():
    assert weights_by_subscore(MRIWeights()) == SPEC_WEIGHTS
    assert math.isclose(sum(SPEC_WEIGHTS.values()), 1.0)
    with pytest.raises(ValidationError, match="sum to 1.0"):
        MRIWeights(acc=0.5)
    custom = MRIWeights(acc=0.5, asr=0.2, eps=0.1, conf=0.1, expl=0.1)
    s, reason = score({"fgsm": rows("fgsm", [0.8, 0.8, 0.8])}, scoring=ScoringConfig(weights=custom))
    assert reason is None and s.weights == custom
    # a partial record keeps the configured vector: nothing is renormalised over the available dimensions
    p, why = score({"fgsm": rows("fgsm", [0.8, 0.8, 0.8], expl_shift=None)}, scoring=ScoringConfig(weights=custom))
    assert p.weights == custom and p.mri is None and "weights not renormalised" in why


# --- subscores and MRI -----------------------------------------------------------------------

def test_perfectly_robust_campaign_scores_100_grade_a():
    s, reason = score({"fgsm": rows("fgsm", [0.8, 0.8, 0.8])})
    assert reason is None and isinstance(s, MRIRecord)
    assert s.mri == 100 and s.grade == "A" == grade_for_mri(100)
    assert s.completeness == "complete" and s.missing == [] and s.subscores.missing() == []
    assert s.subscores.model_dump() == {k: 100.0 for k in SUBSCORE_KEYS}
    assert s.weights == MRIWeights() and s.scoring_version == SCORING_VERSION == "mri-1"
    assert s.attack_ids == ["fgsm"] and s.eps_grid == GRID and s.reference_eps == REF and s.norm == "linf"
    assert s.finding_asr_threshold == 0.2 and s.settings_hash == settings_hash(config())
    pa = s.per_attack["fgsm"]
    assert pa.S_acc.value == 100.0 and pa.S_acc.n == N and pa.S_acc.reason is None
    assert pa.S_asr.n == N_CLEAN_CORRECT and pa.S_expl.n == 8 and pa.S_conf.n == N
    assert [(r.attack_id, r.eps) for r in s.inputs] == [("fgsm", e) for e in GRID]
    assert s.reading and not contains_banned_score_word(s.reading)
    assert s.computed_at == T
    assert MRIRecord.model_validate(s.model_dump(mode="json")) == s


def test_subscore_definitions_and_round_half_even():
    # acc_clean 0.8; acc_adv 0.6/0.4/0.2 -> ratios 0.75/0.5/0.25
    s, reason = score({"pgd": rows("pgd", [0.6, 0.4, 0.2], asr=0.5, conf_gap=0.3, expl_shift=0.25)})
    assert reason is None
    auc = ((0.02 * (0.75 + 0.5) / 2) + (0.07 * (0.5 + 0.25) / 2)) / 0.09
    sub = s.subscores
    assert sub.S_acc == 25.0 and sub.S_asr == 50.0 and sub.S_eps == round(100 * auc, 1)
    assert sub.S_conf == 70.0 and sub.S_expl == 75.0
    weighted = sum(SPEC_WEIGHTS[k] * getattr(sub, k) for k in SUBSCORE_KEYS)
    assert s.mri == round(weighted) == 44 and s.grade == grade_for_mri(44) == "D"
    assert all(0.0 <= getattr(sub, k) <= 100.0 for k in SUBSCORE_KEYS)
    ref = next(r for r in s.inputs if math.isclose(r.eps, REF))
    assert (ref.acc_clean, ref.acc_adv, ref.asr, ref.conf_gap, ref.expl_shift) == (0.8, 0.4, 0.5, 0.3, 0.25)
    assert (ref.n, ref.n_correct_clean, ref.n_attacked, ref.n_explained) == (N, N_CLEAN_CORRECT, N, 8)
    assert s.per_attack["pgd"].S_asr.value == 50.0 and s.per_attack["pgd"].S_asr.n == N_CLEAN_CORRECT


def test_subscores_are_unweighted_means_over_attacks_and_ratios_are_clamped():
    per = {"fgsm": rows("fgsm", [0.8, 0.8, 0.8]),
           "pgd": rows("pgd", [0.0, 0.0, 0.0], asr=1.0, conf_gap=1.5, expl_shift=2.0)}
    s, _ = score(per)
    assert s.subscores.model_dump() == {k: 50.0 for k in SUBSCORE_KEYS}
    assert s.attack_ids == ["fgsm", "pgd"] and set(s.per_attack) == {"fgsm", "pgd"}
    assert s.per_attack["pgd"].S_conf.value == 0.0 and s.per_attack["fgsm"].S_conf.value == 100.0
    s2, _ = score({"fgsm": rows("fgsm", [0.9, 0.9, 0.9])})     # acc_adv above acc_clean clamps to 1
    assert s2.subscores.S_acc == 100.0 and s2.subscores.S_eps == 100.0


def test_trapezoid_is_over_declared_grid_only():
    assert trapezoid_auc_normalized([0.01, 0.03, 0.1], [1.0, 1.0, 1.0]) == pytest.approx(1.0)
    assert trapezoid_auc_normalized([0.01, 0.03, 0.1], [0.0, 0.0, 0.0]) == pytest.approx(0.0)
    assert trapezoid_auc_normalized([0.05], [0.4]) == 0.4                    # one-point grid degenerates
    with pytest.raises(ValueError):
        trapezoid_auc_normalized([], [])
    one = row("fgsm", 0.05, 0.4, asr=0.6, expl_shift=0.0)
    s, reason = score_run(config=config(eps_grid=[0.05], reference_eps=0.05), measurements=[clean(1.0), one])
    assert reason is None and s.subscores.S_eps == 40.0 and s.subscores.S_acc == 40.0 and len(s.inputs) == 1


def test_scoring_is_deterministic():
    per = {"fgsm": rows("fgsm", [0.5, 0.4, 0.1], asr=0.4, conf_gap=0.2, expl_shift=0.3)}
    a, _ = score(per)
    b, _ = score(per)
    assert a.model_dump() == b.model_dump()


# --- the MRI-not-computed rule ----------------------------------------------------------------

def test_missing_expl_shift_yields_a_partial_record_without_mri_and_no_renormalisation():
    s, reason = score({"fgsm": rows("fgsm", [0.6, 0.4, 0.2], asr=0.5, conf_gap=0.3, expl_shift=None)})
    assert isinstance(s, MRIRecord)
    assert s.mri is None and s.grade is None and s.reading is None and s.completeness == "partial"
    assert len(s.missing) == 1 and s.missing[0].startswith("S_expl unavailable")
    assert "explanation stability unavailable" in s.missing[0]
    assert s.subscores.missing() == ["S_expl"]
    assert (s.subscores.S_acc, s.subscores.S_asr, s.subscores.S_conf) == (25.0, 50.0, 70.0)
    assert s.per_attack["fgsm"].S_expl.value is None and s.per_attack["fgsm"].S_expl.reason
    assert s.weights == MRIWeights()
    assert reason.startswith("MRI not computed") and "S_expl" in reason
    assert "weights not renormalised" in reason and "S_acc=25.0" in reason and "S_asr=50.0" in reason
    assert MRIRecord.model_validate(s.model_dump(mode="json")) == s
    # the frozen record refuses an MRI stamped onto a partial score
    with pytest.raises(ValidationError, match="missing"):
        MRIRecord.model_validate({**s.model_dump(), "mri": 50, "grade": "D", "completeness": "complete"})


def test_missing_asr_or_conf_gap_yields_partial_records():
    s, reason = score({"fgsm": rows("fgsm", [0.6, 0.4, 0.2], asr=None)})
    assert s.mri is None and s.subscores.missing() == ["S_asr"] and "S_asr" in reason
    assert s.per_attack["fgsm"].S_asr.n == 0 and "n_clean_correct == 0" in s.missing[0]
    s, reason = score({"fgsm": rows("fgsm", [0.6, 0.4, 0.2], conf_gap=None)})
    assert s.mri is None and s.subscores.missing() == ["S_conf"] and "S_conf" in reason


def test_zero_clean_accuracy_yields_partial_with_three_dimensions_missing():
    s, reason = score({"fgsm": rows("fgsm", [0.0, 0.0, 0.0])}, acc_clean=0.0)
    assert s.mri is None and s.subscores.missing() == ["S_acc", "S_asr", "S_eps"]
    assert "acc_clean == 0" in reason and s.subscores.S_conf == 100.0


def test_partial_run_or_no_clean_row_yields_none():
    two = [row("fgsm", 0.01, 0.5, asr=0.1), row("fgsm", 0.03, 0.4, asr=0.2, expl_shift=0.1)]
    s, reason = score_run(config=config(), measurements=[clean(), *two])
    assert s is None and "partial run" in reason and "0.1" in reason
    s, reason = score_run(config=config(), measurements=two)
    assert s is None and "no clean row" in reason
    s, reason = score_run(config=config(attack_ids=["fgsm", "pgd"]),
                          measurements=[clean(), *rows("fgsm", [0.5] * 3)])
    assert s is None and "'pgd'" in reason


def test_unknown_scoring_version_raises():
    with pytest.raises(ValueError, match="not implemented"):
        score({"fgsm": rows("fgsm", [0.8] * 3)}, scoring=ScoringConfig(version="mri-2"))


# --- grades ------------------------------------------------------------------------------------

@pytest.mark.parametrize("mri,grade", [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"), (60, "C"),
                                       (59, "D"), (40, "D"), (39, "F"), (0, "F")])
def test_grade_boundaries_come_from_the_schema(mri, grade):
    assert grade_for_mri(mri) == grade


def test_grade_bands_reached_through_score_run():
    def flat(v: float):
        # acc ratio v everywhere, asr 1-v, conf_gap 1-v, expl_shift 1-v -> every subscore == 100 v
        s, _ = score({"fgsm": rows("fgsm", [0.8 * v] * 3, asr=1 - v, conf_gap=1 - v, expl_shift=1 - v)})
        assert s.grade == grade_for_mri(s.mri)
        return s.grade
    assert [flat(v) for v in (0.95, 0.80, 0.65, 0.50, 0.20)] == ["A", "B", "C", "D", "F"]


def test_readings_are_attack_scoped_and_free_of_banned_words():
    assert set(GRADE_READINGS) == {"A", "B", "C", "D", "F"}
    for text in GRADE_READINGS.values():
        assert not contains_banned_score_word(text) and not contains_banned_wording(text)
        assert "in-scope" in text or "declared grid" in text          # attack-scoped wording (D9 iii)
    cfg = config(attack_ids=["fgsm", "pgd"])
    reading = reading_for("C", cfg)
    assert reading.startswith(GRADE_READINGS["C"])
    assert "attacks fgsm, pgd" in reading and "norm linf" in reading
    assert "eps grid [0.01, 0.03, 0.1]" in reading and "reference eps 0.03" in reading
    assert GRADE_SENTENCE == GRADE_STATEMENT
    assert "not a readiness, safety, or certification statement" in GRADE_SENTENCE
    for banned in ("Hardened", "Not deployment-ready", "certified robust", "Harden before fielding", "safe"):
        assert contains_banned_wording(banned)


# --- severity, confidence and the finding inputs -------------------------------------------------

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
    assert severity_for(first_eps, asr, GRID, REF) == expected
    assert severity_for(first_eps, asr, GRID, REF, SeverityThresholds()) == expected


def test_severity_and_confidence_read_the_configured_thresholds():
    strict = SeverityThresholds(asr_high=0.8, asr_mid=0.4)
    assert severity_for(0.01, 0.5, GRID, REF, strict) == "high"
    assert severity_for(0.01, 0.3, GRID, REF, strict) == "medium"
    assert severity_for(0.03, 0.79, GRID, REF, strict) == "medium"
    assert [confidence_for(n) for n in (100, 99, 30, 29)] == ["high", "medium", "medium", "low"]
    assert confidence_for(50, ConfidenceThresholds(n_high=50, n_medium=10)) == "high"


def test_first_success_uses_threshold_and_skips_undefined():
    table = {0.01: 0.1, 0.03: 0.25, 0.1: 0.9}
    assert first_success(table, 0.2) == (0.03, 0.25)
    assert first_success(table, 0.5) == (0.1, 0.9)
    assert first_success({0.01: None, 0.03: 0.05}, 0.2) == (None, None)
    as_rows = dict(zip(GRID, rows("fgsm", [0.5] * 3, asr=0.3), strict=True))
    assert first_success(as_rows, 0.2) == (0.01, 0.3)


def test_finding_inputs_derive_severity_confidence_and_the_finding_detail_shape():
    ms = [clean(), row("fgsm", 0.01, 0.7, asr=0.1), row("fgsm", 0.03, 0.5, asr=0.3), row("fgsm", 0.1, 0.2, asr=0.6)]
    fi = finding_inputs(config(), ms, "fgsm")
    assert fi.attack_id == "fgsm" and fi.threshold == 0.2 and fi.n_clean_correct == N_CLEAN_CORRECT
    assert fi.asr_by_eps == {"0.01": 0.1, "0.03": 0.3, "0.1": 0.6}
    assert (fi.first_success_eps, fi.asr_at_first_success, fi.asr_at_reference) == (0.03, 0.3, 0.3)
    assert fi.severity == "medium" == severity_for(0.03, 0.3, GRID, REF)
    assert fi.confidence == "medium" and fi.crosses_threshold and fi.denominator_ok
    detail = MLFindingDetail(attack_id=fi.attack_id, attack_name="FGSM", norm="linf", eps_grid=GRID,
                             reference_eps=REF, first_success_eps=fi.first_success_eps,
                             asr_at_reference=fi.asr_at_reference, asr_by_eps=fi.asr_by_eps,
                             threshold=fi.threshold, measurements=ms[1:])
    assert detail.atlas_technique is None            # Phase B2 stamps it; nothing here guesses
    small = finding_inputs(config(), [clean(0.05), *ms[1:]], "fgsm")
    assert small.confidence == "low" and not small.denominator_ok
    quiet = finding_inputs(config(), [clean(), *rows("fgsm", [0.8] * 3, asr=0.05)], "fgsm")
    assert quiet.severity is None and not quiet.crosses_threshold


# --- settings hash and inputs -----------------------------------------------------------------------

def test_settings_hash_excludes_presentation_fields_and_covers_the_model():
    base = settings_hash(config())
    assert len(base) == 64 and int(base, 16) >= 0
    assert settings_hash(config(llm_narrative=True)) == base
    assert settings_hash(config(target_snapshot={"frozen": True})) == base
    assert settings_hash(config(eps_grid=[0.01, 0.03, 0.2])) != base
    assert settings_hash(config(n_samples=50)) != base
    assert settings_hash(config(), model_sha256="a" * 64) != base
    assert settings_hash(config(), model_sha256="a" * 64) != settings_hash(config(), model_sha256="b" * 64)
    payload = canonical_settings_json(config())
    assert '"defense"' not in payload and '"target_snapshot"' not in payload and '"llm_narrative"' not in payload


@pytest.mark.parametrize("name", ["run_record.json", "run_record_phase_b.json"])
def test_frozen_fixture_settings_hash_is_unchanged_by_the_smaller_exclude_set(name):
    """2026-09-09: ``defense`` left ``CampaignConfig`` and the exclude set at the same time, so the canonical
    payload (and the hash) of every stored record is byte-identical under the old and the new exclude set.
    The frozen fixtures carry a placeholder hash (``f1x7ure…``), so the invariant is asserted on the payload."""
    import hashlib
    import json
    from pathlib import Path

    from redsim.ml.scoring import _SETTINGS_HASH_EXCLUDE

    fixture = json.loads((Path(__file__).parent / "fixtures" / name).read_text(encoding="utf-8"))
    assert "defense" not in fixture["config"]
    cfg = CampaignConfig.model_validate(fixture["config"])
    assert _SETTINGS_HASH_EXCLUDE == frozenset({"llm_narrative", "target_snapshot"})
    old_exclude = set(_SETTINGS_HASH_EXCLUDE) | {"defense"}
    old_payload = json.dumps(cfg.model_dump(mode="json", exclude=old_exclude), sort_keys=True, separators=(",", ":"))
    new_payload = json.dumps(cfg.model_dump(mode="json", exclude=set(_SETTINGS_HASH_EXCLUDE)), sort_keys=True,
                             separators=(",", ":"))
    assert old_payload == new_payload == canonical_settings_json(cfg)
    model_sha256 = (fixture.get("provenance") or {}).get("model_sha256")
    old_hash = hashlib.sha256(old_payload.encode("utf-8") + str(model_sha256).encode("utf-8")).hexdigest()
    assert settings_hash(cfg, model_sha256) == old_hash


def test_input_rows_carry_denominators():
    ms = [clean(), *rows("fgsm", [0.6, 0.4, 0.2], asr=0.5, conf_gap=0.3, expl_shift=0.25, pert=0.02)]
    inputs = input_rows(config(), ms)
    assert [r.eps for r in inputs] == GRID
    for r in inputs:
        assert r.n == N and r.n_correct_clean == N_CLEAN_CORRECT and r.n_attacked == N and r.acc_clean == 0.8
        assert r.pert == 0.02 and r.queries is None
    assert inputs[1].expl_shift == 0.25 and inputs[1].n_explained == 8 and inputs[0].expl_shift is None
    with pytest.raises(ValueError, match="no clean row"):
        input_rows(config(), ms[1:])
    with pytest.raises(ValueError, match="partial run"):
        input_rows(config(), ms[:3])


# --- robustness curve ---------------------------------------------------------------------------------

def test_robustness_curves_one_per_attack_with_the_control_at_the_same_eps():
    ms = [clean(), *rows("fgsm", [0.6, 0.4, 0.2], asr=0.3), *rows("pgd", [0.5, 0.3, 0.1], asr=0.5),
          control(0.01, 0.79), control(0.03, 0.78, asr=0.02), control(0.1, 0.7, asr=0.1)]
    curves = robustness_curves(config(attack_ids=["fgsm", "pgd"]), ms)
    assert [c.attack_id for c in curves] == ["fgsm", "pgd"]
    fg = curves[0]
    assert isinstance(fg, RobustnessCurve) and fg.norm == "linf" and fg.eps_grid == GRID and fg.reference_eps == REF
    assert (fg.clean.n, fg.clean.n_correct, fg.clean.accuracy) == (N, N_CLEAN_CORRECT, 0.8)
    assert [p.eps for p in fg.points] == GRID and [p.n_correct for p in fg.points] == [60, 40, 20]
    assert all(p.n == N and p.n_clean_correct == N_CLEAN_CORRECT and p.asr == 0.3 for p in fg.points)
    assert [p.eps for p in fg.control] == GRID and [p.n_correct for p in fg.control] == [79, 78, 70]
    assert fg.control == curves[1].control
    assert RobustnessCurve.model_validate(fg.model_dump(mode="json")) == fg
    assert robustness_curves(config(), ms[:4])[0].control == []
    with pytest.raises(ValueError, match="no clean row"):
        robustness_curves(config(), ms[1:])


# --- spec 12.3 default budgets (register G-ATK6) --------------------------------------------------------

def test_default_grid_constants_match_spec_12_3_and_admit_as_campaigns():
    assert DEFAULT_EPS_GRID_LINF == (0.01, 0.03, 0.1)
    assert DEFAULT_EPS_GRID_L2 == (0.25, 0.5, 1.0)
    assert DEFAULT_REFERENCE_EPS == 0.03 and DEFAULT_REFERENCE_EPS in DEFAULT_EPS_GRID_LINF
    assert DEFAULT_MAX_EPS_GRID_MEMBERS == 3
    for grid in (DEFAULT_EPS_GRID_LINF, DEFAULT_EPS_GRID_L2):
        assert len(grid) <= DEFAULT_MAX_EPS_GRID_MEMBERS and list(grid) == sorted(grid)
        assert all(0.0 < e <= 1.0 for e in grid)
    assert default_eps_grid() == list(DEFAULT_EPS_GRID_LINF) == default_eps_grid("linf")
    assert default_eps_grid("l2") == list(DEFAULT_EPS_GRID_L2)
    assert default_eps_grid() is not default_eps_grid()                 # a fresh list, never the shared tuple
    assert default_reference_eps() == default_reference_eps("linf") == DEFAULT_REFERENCE_EPS
    assert default_reference_eps("l2") == 0.5 and default_reference_eps("l2") in DEFAULT_EPS_GRID_L2
    with pytest.raises(ValueError, match="no default eps grid"):
        default_eps_grid("l1")
    # the defaults admit through the frozen CampaignConfig, and L2 never shares the L-inf grid or hash
    linf = config(norm="linf", eps_grid=default_eps_grid("linf"), reference_eps=default_reference_eps("linf"))
    l2 = config(norm="l2", eps_grid=default_eps_grid("l2"), reference_eps=default_reference_eps("l2"))
    assert linf.eps_grid == [0.01, 0.03, 0.1] and linf.reference_eps == 0.03
    assert l2.eps_grid == [0.25, 0.5, 1.0] and l2.reference_eps == 0.5
    assert settings_hash(linf) != settings_hash(l2)
    assert eps_bands(linf.eps_grid, linf.reference_eps) == (0.01, 0.03, 0.1)


# --- spec 12.4 control predicate (register G-SCORE1) -----------------------------------------------------

def _cdf_brute(k: int, n: int, p: float) -> float:
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))


def ctrl_row(n_correct: int, n: int) -> Measurement:
    return Measurement(id=f"m.control.noise.{eps_tag(REF)}", family="control", attack_id="noise_control",
                       params={"eps": REF, "norm": "linf"}, n=n, n_correct=n_correct,
                       accuracy=(n_correct / n) if n else 0.0)


def clean_counts(n_correct: int, n: int) -> Measurement:
    return Measurement(id="m.clean", family="clean", n=n, n_correct=n_correct, accuracy=(n_correct / n) if n else 0.0)


def test_binomial_cdf_is_exact_and_handles_the_edges():
    for n, k, p in [(10, 3, 0.5), (20, 14, 0.8), (100, 72, 0.8), (7, 0, 0.3), (50, 49, 0.99)]:
        assert binomial_cdf(k, n, p) == pytest.approx(_cdf_brute(k, n, p), rel=1e-9)
    assert binomial_cdf(-1, 10, 0.5) == 0.0 and binomial_cdf(10, 10, 0.5) == 1.0 and binomial_cdf(12, 10, 0.5) == 1.0
    assert binomial_cdf(3, 10, 0.0) == 1.0 and binomial_cdf(3, 10, 1.0) == 0.0 and binomial_cdf(10, 10, 1.0) == 1.0
    assert 0.0 < binomial_cdf(500, 1000, 0.8) < 1e-90     # the log-space sum survives where p**k underflows to 0
    with pytest.raises(ValueError):
        binomial_cdf(1, -1, 0.5)
    with pytest.raises(ValueError):
        binomial_cdf(1, 5, 1.5)


def test_control_preserves_accuracy_is_a_binomial_predicate_with_a_two_point_floor():
    assert CONTROL_ACCURACY_FLOOR == 0.02 and DEFAULT_CONTROL_ALPHA == 0.05
    c100 = clean_counts(80, 100)
    # within two points of clean: preserved whatever the test says (spec 12.4 floor)
    assert control_preserves_accuracy(c100, ctrl_row(78, 100))
    # below the floor but not significantly below at alpha 0.05 (one-sided exact binomial, H0: p = acc_clean)
    assert control_degradation_pvalue(c100, ctrl_row(76, 100)) == pytest.approx(0.189, abs=1e-3)
    assert control_degradation_pvalue(c100, ctrl_row(73, 100)) == pytest.approx(0.056, abs=1e-3)
    assert control_preserves_accuracy(c100, ctrl_row(76, 100)) and control_preserves_accuracy(c100, ctrl_row(73, 100))
    # significantly below: degraded
    assert control_degradation_pvalue(c100, ctrl_row(72, 100)) == pytest.approx(0.034, abs=1e-3)
    assert not control_preserves_accuracy(c100, ctrl_row(72, 100))
    # small n: a ten-point drop is within binomial noise (a fixed 0.05 tolerance would have called it degraded)
    c20 = clean_counts(16, 20)
    assert control_degradation_pvalue(c20, ctrl_row(14, 20)) == pytest.approx(0.196, abs=1e-3)
    assert control_preserves_accuracy(c20, ctrl_row(14, 20)) and not control_preserves_accuracy(c20, ctrl_row(12, 20))
    # large n: a three-point drop is significant (a fixed 0.05 tolerance would have called it flat)
    c1000 = clean_counts(800, 1000)
    assert control_degradation_pvalue(c1000, ctrl_row(770, 1000)) == pytest.approx(0.011, abs=1e-3)
    assert not control_preserves_accuracy(c1000, ctrl_row(770, 1000))
    assert control_preserves_accuracy(c1000, ctrl_row(780, 1000))          # exactly two points: the floor
    # a perfectly classified slice: any miss is significant, the floor still absorbs a small one
    assert control_preserves_accuracy(clean_counts(1000, 1000), ctrl_row(985, 1000))
    assert control_degradation_pvalue(clean_counts(10, 10), ctrl_row(8, 10)) == 0.0
    assert not control_preserves_accuracy(clean_counts(10, 10), ctrl_row(8, 10))
    # a control above the clean accuracy always preserves it; alpha is honoured
    assert control_preserves_accuracy(c100, ctrl_row(90, 100))
    assert not control_preserves_accuracy(c100, ctrl_row(76, 100), alpha=0.2)
    assert control_preserves_accuracy(c100, ctrl_row(72, 100), alpha=0.01)
    # no evidence is never "preserved": a zero denominator on either side is False and has no p-value
    assert control_degradation_pvalue(clean_counts(0, 0), ctrl_row(0, 0)) is None
    assert not control_preserves_accuracy(clean_counts(0, 0), ctrl_row(78, 100))
    assert not control_preserves_accuracy(c100, ctrl_row(0, 0))
    # counts, not accuracies: floats are refused loudly, and alpha must be a probability
    with pytest.raises(TypeError, match="Measurement rows"):
        control_preserves_accuracy(0.8, 0.78, 100)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        control_degradation_pvalue(c100, 0.78)  # type: ignore[arg-type]
    for bad in (0.0, 1.0, 1.5, -0.1):
        with pytest.raises(ValueError, match="alpha"):
            control_preserves_accuracy(c100, ctrl_row(78, 100), alpha=bad)


def test_incompatible_campaigns_is_the_typed_409_refusal():
    exc = IncompatibleCampaigns(["eps grid [0.01] != [0.03]", "attack set differs"])
    assert isinstance(exc, ValueError) and isinstance(exc, MLError)
    assert exc.code == "incompatible_campaigns" == IncompatibleCampaigns.code
    assert exc.reasons == ["eps grid [0.01] != [0.03]", "attack set differs"]
    assert str(exc).startswith("incompatible campaigns: eps grid")
