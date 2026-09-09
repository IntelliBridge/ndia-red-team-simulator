"""``redsim.ml.campaign.run_campaign`` on the TinyTarget double against the frozen M0 contract (``ml`` tier).

The explain, recommend, summary, narrative, defenses and hardening modules are injected or removed through
``sys.modules`` so these tests hold whether or not the concurrent builders' modules are present. The
Phase B frame (``redsim.ml.runners``): runners are dispatched by modality from ``MODALITY_RUNNERS`` and a
missing runner refuses before any stage; a ``kind: training`` defense goes through
``redsim.ml.harden.apply.apply_training_defense`` and a missing module records the defense unavailable
with the score withheld; ``defense_apply`` is emitted only when ``schema.STAGES`` carries it; the run
pins ``NLTK_DATA`` and ``TORCH_HOME`` offline for its duration.

Pins: ``CampaignConfig`` in, ``CampaignRecord`` (a ``RunRecord``) out with the ``score`` stage;
``RunRecord.score`` is an ``MRIRecord`` that is PARTIAL (no ``mri``, no ``grade``) whenever the explain
stage gave ``S_expl`` no input; ``RunRecord.attacks`` carries the registry snapshots; the limitations
start with ``schema.standing_limitations``; the P0 provenance fields are filled; every citation
resolves; candidates carry no measured delta; the benign control runs at the same eps as the attacks.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path

import pytest
from pydantic import ValidationError

pytest.importorskip("torch")
pytest.importorskip("art")

import numpy as np

from redsim.ml.artifacts import FilesystemSink
from redsim.ml.attacks import ATTACKS, apply_mask, perturbable_mask, resolve_from_schema
from redsim.ml.attacks.base import AttackOutput
from redsim.ml.campaign import (
    CURVE_PNG_NAME,
    D3_BOUNDS_LIMITATION,
    DEFENSE_LIMITATION,
    REALIZABILITY_CAVEAT,
    SHAP_SUMMARY_TEXT_NAME,
    SUBJECT_CENTERED_CAVEAT,
    TABULAR_LIMITATION,
    TRAINING_DEFENSE_LIMITATION,
    TRAINING_DEFENSE_MODULE,
    run_campaign,
)
from redsim.ml.errors import AttackNotApplicable, ExplainUnavailable, MLError, TargetUnavailable
from redsim.ml.eval import eps_tag, per_sample_norm, perturbation_norms
from redsim.ml.explain.base import ExplainOutput
from redsim.ml.runners import base as runners_base
from redsim.ml.runners.base import (
    MODALITY_RUNNERS,
    CampaignFrame,
    ModalityResult,
    ModalityRunnerUnavailable,
    resolve_runner,
)
from redsim.ml.schema import (
    STAGES,
    AttackInfo,
    CampaignConfig,
    CampaignRecord,
    CandidateRecommendation,
    DefenseConfig,
    Interpretation,
    Measurement,
    MLFindingDetail,
    MRIRecord,
    MRIWeights,
    Observation,
    ParamSpec,
    RunRecord,
    ScoringConfig,
    contains_banned_score_word,
    grade_for_mri,
    standing_limitations,
)
from redsim.ml.scoring import (
    SUBSCORE_KEYS,
    confidence_for,
    delta,
    finding_inputs,
    severity_for,
    weights_by_subscore,
)
from redsim.ml.targets.registry import TARGETS
from tests.ml.fakes import TABULAR_DATASET, TABULAR_FROZEN, TinyTabularTarget, TinyTarget

pytestmark = pytest.mark.ml

EXPLAIN_MOD = "redsim.ml.explain.shap_image"
RULES_MOD = "redsim.ml.recommend.rules"
SUMMARY_MOD = "redsim.ml.explain.summary"
NARRATIVE_MOD = "redsim.ml.recommend.narrative"
DEFENSES_MOD = "redsim.ml.defenses"
GRID = [0.01, 0.03, 0.1]
REF = 0.03
EPS_TAGS = ("0.01", "0.03", "0.1")

if TARGETS.maybe_get("tiny") is None:
    TARGETS.register(TinyTarget(seed=0))


def base_config(**overrides) -> CampaignConfig:
    cfg = {"target_id": "tiny", "modality": "image", "attack_ids": ["fgsm", "pgd"],
           "attack_params": {"pgd": {"max_iter": 3}}, "eps_grid": GRID, "reference_eps": REF,
           "n_samples": 16, "seed": 0, "explain_k": 4, "dataset_id": "synthetic"}
    cfg.update(overrides)
    return CampaignConfig(**cfg)


# --- test doubles for the optional stages ------------------------------------------------------------

def make_fake_explain(shift: float | None = 0.4, raise_exc: Exception | None = None):
    """An explainer that honours the ``ExplainOutput`` contract (spec 13.3 / 13.5)."""
    mod = types.ModuleType(EXPLAIN_MOD)
    calls: list[dict] = []

    def explain(target, sample, x_adv, proba_clean, proba_adv, sink, *, k, seed, x_ctrl=None, eps=None):
        calls.append({"k": k, "seed": seed, "n": len(sample.y), "x_adv_shape": x_adv.shape,
                      "has_control": x_ctrl is not None, "eps": eps})
        if raise_exc is not None:
            raise raise_exc
        obs = []
        for i in range(min(k, len(sample.y))):
            path = sink.put(f"obs_{i:03d}/shap_adv.npz", b"fake")
            obs.append(Observation(
                id=f"o.{i:03d}", sample_index=int(sample.indices[i]),
                true_label=sample.class_names[int(sample.y[i])],
                pred_clean=sample.class_names[int(proba_clean[i].argmax())],
                pred_adv=sample.class_names[int(proba_adv[i].argmax())],
                flipped=bool(proba_clean[i].argmax() != proba_adv[i].argmax()),
                confidence_clean=float(proba_clean[i].max()), confidence_adv=float(proba_adv[i].max()),
                artifacts={"shap_adv": path}, artifact_sha256={"shap_adv": sink.sha256(path)},
                center_mass_ratio_clean=0.5, center_mass_ratio_adv=0.4, expl_shift=shift))
        return ExplainOutput(
            observations=obs, expl_shift_mean=shift,
            expl_shift_n=len(obs) if shift is not None else 0,
            expl_shift_n_excluded=0 if shift is not None else len(obs),
            expl_shift_noise_floor=0.05 if x_ctrl is not None else None,
            expl_shift_noise_floor_n=len(obs) if x_ctrl is not None else None,
            meta={"nondeterminism": "SHAP GradientExplainer background sampling (background_size=8, nsamples=8)"})

    mod.explain = explain
    mod.calls = calls
    return mod


def make_fake_rules(*, dangling: bool = False):
    """A rules module with the real ``interpret`` / ``recommend`` signatures."""
    mod = types.ModuleType(RULES_MOD)
    seen: dict = {}

    def interpret(measurements, observations, score, *, explain_meta=None, reference_eps=None,
                  scoring_reason=None, thresholds=None, finding_asr_threshold=None):
        seen["interpret"] = {"n_measurements": len(measurements), "n_observations": len(observations),
                             "score": score, "reference_eps": reference_eps, "thresholds": thresholds,
                             "finding_asr_threshold": finding_asr_threshold, "scoring_reason": scoring_reason,
                             "explain_meta": explain_meta}
        out = [Interpretation(id="i.1", statement="Random noise did not reduce accuracy while fgsm did.",
                              basis=["m.clean", "m.evasion.fgsm.eps0.03", "m.control.noise.eps0.03"])]
        if dangling:
            out.append(Interpretation(id="i.9", statement="cites a row that was never measured", basis=["m.nope"]))
        return out

    def recommend(measurements, observations, score, *, interpretation=None, explain_meta=None,
                  reference_eps=None, modality=None, seed=None, thresholds=None, finding_asr_threshold=None):
        seen["recommend"] = {"n_measurements": len(measurements), "n_observations": len(observations),
                             "interpretation": [i.id for i in (interpretation or [])], "score": score,
                             "modality": modality, "seed": seed, "thresholds": thresholds}
        out = [CandidateRecommendation(id="r.R1", title="Adversarial training (candidate)",
                                       rationale="Gradient-aligned degradation at eps=0.03.",
                                       triggered_by=["m.evasion.fgsm.eps0.03", "i.1"],
                                       references=["art.defences.trainer.AdversarialTrainer"])]
        if dangling:
            out.append(CandidateRecommendation(id="r.R9", title="t", rationale="r", triggered_by=["o.999"]))
        return out

    mod.interpret = interpret
    mod.recommend = recommend
    mod.seen = seen
    return mod


def make_fake_narrative_stack():
    summary = types.ModuleType(SUMMARY_MOD)
    summary_calls: list[dict] = []

    def text_summary(measurements, observations, score, *, explain_meta=None, scoring_reason=None,
                     limitations=None, norm=None):
        summary_calls.append({"n": len(measurements), "norm": norm, "limitations": limitations})
        return "summary text"

    summary.text_summary = text_summary
    summary.calls = summary_calls
    narrative = types.ModuleType(NARRATIVE_MOD)
    calls: list = []

    def add_narrative(recs, summary_text, settings):
        calls.append((summary_text, settings))
        return [r.model_copy(update={"narrative": "Rule text rewritten.", "narrative_source": "llm"}) for r in recs]

    narrative.add_narrative = add_narrative
    narrative.calls = calls
    return summary, narrative


def make_fake_defenses():
    defenses = types.ModuleType(DEFENSES_MOD)
    seen: dict = {}

    def apply_defense(target, defense_id, params):
        seen["args"] = (target.id, defense_id, params)
        return target

    defenses.apply_defense = apply_defense
    defenses.seen = seen
    return defenses


@pytest.fixture
def no_optional_modules(monkeypatch):
    for name in (EXPLAIN_MOD, RULES_MOD, SUMMARY_MOD, NARRATIVE_MOD):
        monkeypatch.setitem(sys.modules, name, None)


@pytest.fixture
def sink(tmp_path) -> FilesystemSink:
    return FilesystemSink(tmp_path / "run")


# --- explain disabled: valid record, partial score ---------------------------------------------------

@pytest.fixture(scope="module")
def record_no_explain(tmp_path_factory):
    saved = {name: sys.modules.get(name, "__absent__") for name in (EXPLAIN_MOD, RULES_MOD)}
    for name in saved:
        sys.modules[name] = None
    try:
        root = tmp_path_factory.mktemp("campaign")
        rec = run_campaign(base_config(), FilesystemSink(root), explain=False)
    finally:
        for name, before in saved.items():
            if before == "__absent__":
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = before
    return rec, root


def test_run_without_explain_is_a_valid_record_with_a_partial_score(record_no_explain):
    rec, _ = record_no_explain
    assert isinstance(rec, CampaignRecord) and isinstance(rec, RunRecord)
    assert rec.status == "succeeded" and rec.stage == "report" and rec.error is None
    assert rec.kind == "attack" and rec.completed_at is not None and rec.settings_hash
    assert rec.config == base_config() and rec.target.id == "tiny"
    assert [a.id for a in rec.attacks] == ["fgsm", "pgd"] and all(a.phase == "A" for a in rec.attacks)
    score = rec.score
    assert isinstance(score, MRIRecord) and rec.score_status is None
    assert score.mri is None and score.grade is None and score.completeness == "partial"
    assert score.subscores.missing() == ["S_expl"] and score.missing and "S_expl" in score.missing[0]
    assert rec.completeness == "partial" and rec.missing == score.missing
    assert score.settings_hash == rec.settings_hash and score.weights == MRIWeights()
    assert set(score.per_attack) == {"fgsm", "pgd"} and len(score.inputs) == 6
    assert any("MRI not computed" in lim and "S_expl" in lim for lim in rec.limitations)
    assert any("Explanations were not computed (explain disabled)" in lim for lim in rec.limitations)
    assert rec.observations == [] and rec.recommendations == []


def test_measurement_rows_ids_denominators_and_control(record_no_explain):
    rec, _ = record_no_explain
    assert "severity" not in Measurement.model_fields
    ids = [m.id for m in rec.measurements]
    assert ids[0] == "m.clean"
    assert {i for i in ids if i.startswith("m.evasion")} == {
        f"m.evasion.{a}.eps{e}" for a in ("fgsm", "pgd") for e in EPS_TAGS}
    assert {i for i in ids if i.startswith("m.control")} == {f"m.control.noise.eps{e}" for e in EPS_TAGS}
    assert len(rec.measurements) == 1 + 6 + 3
    clean = rec.measurements[0]
    for m in rec.measurements:
        assert m.n == clean.n == 16
        assert 0 <= m.n_correct <= m.n and m.accuracy == pytest.approx(m.n_correct / m.n)
        assert sum(v["n"] for v in m.per_class.values()) == m.n
        if m.family == "clean":
            assert m.attack_id is None and m.n_flipped_from_clean is None and m.n_clean_correct is None
            continue
        # the ASR denominator is the clean row's n_correct (spec 12.5), on evasion and control rows alike
        assert m.n_clean_correct == clean.n_correct
        assert m.n_flipped_from_clean is not None and 0 <= m.n_flipped_from_clean <= m.n_clean_correct
        if m.n_clean_correct:
            assert m.attack_success_rate == pytest.approx(m.n_flipped_from_clean / m.n_clean_correct)
        else:
            assert m.attack_success_rate is None
        assert m.params["eps"] == float(m.id.rsplit("eps", 1)[1]) and m.params["norm"] == "linf"
        assert m.linf_norm_mean is not None and m.linf_norm_mean <= m.params["eps"] + 1e-6
        assert m.l2_norm_mean is not None
        assert m.conf_gap_mean is not None and m.conf_gap_n == m.n
        assert m.expl_shift_mean is None and m.queries_mean is None          # white-box rows, no explain
        if m.family == "control":
            assert m.attack_id == "noise_control"
            assert any("never create a Finding" in n_ for n_ in m.notes)
    for a in ("fgsm", "pgd"):
        by_eps = {m.params["eps"]: m for m in rec.measurements if m.family == "evasion" and m.attack_id == a}
        ref = by_eps[REF]
        assert ref.pert_first_success_n is not None                    # reference row only (spec 15.1)
        if ref.pert_first_success_n:
            assert 0.0 < ref.pert_first_success_mean <= 0.1 + 1e-6
        else:
            assert ref.pert_first_success_mean is None
        assert all(by_eps[e].pert_first_success_mean is None for e in (0.01, 0.1))
        assert all(by_eps[e].pert_first_success_n is None for e in (0.01, 0.1))


def test_finding_facts_are_derived_never_stamped_on_rows(record_no_explain):
    rec, _ = record_no_explain
    clean = rec.measurements[0]
    for a in ("fgsm", "pgd"):
        fi = finding_inputs(rec.config, rec.measurements, a)
        assert fi.n_clean_correct == clean.n_correct
        assert fi.severity == severity_for(fi.first_success_eps, fi.asr_at_first_success, GRID, REF,
                                           rec.config.scoring.severity)
        rows = [m for m in rec.measurements if m.family == "evasion" and m.attack_id == a]
        if not fi.denominator_ok:
            assert all(any("denominator too small for a finding" in n_ for n_ in m.notes) for m in rows)
        else:
            for m in rows:
                crosses = (m.attack_success_rate is not None
                           and m.attack_success_rate >= rec.config.finding_asr_threshold)
                assert crosses == any("crosses finding_asr_threshold" in n_ for n_ in m.notes)


def test_stages_provenance_and_limitations(record_no_explain):
    rec, _ = record_no_explain
    assert rec.stages_done == ["load_target", "sample", "clean_eval", "attack:fgsm", "attack:pgd", "control",
                               "score", "interpret", "recommend", "report"]
    assert all(s.split(":")[0] in STAGES for s in rec.stages_done)
    assert "explain" not in rec.stages_done and STAGES.index("score") == STAGES.index("explain") + 1
    p = rec.provenance
    assert p is not None and p.art and p.torch and p.numpy and p.python and p.redsim_version and p.hostname
    assert p.model_sha256 == TinyTarget().manifest()["weights_sha256"]
    assert p.dataset == "synthetic" and p.dataset_split == "test" and p.dataset_revision is None
    assert p.sample_indices_sha256 == hashlib.sha256(np.arange(16, dtype=np.int64).tobytes()).hexdigest()
    assert p.settings_hash == rec.settings_hash == rec.score.settings_hash
    assert p.baseline_run_id is None and p.parent_run_id is None and p.defense is None and p.llm is None
    assert p.thread_env.get("torch_threads") and p.shap
    assert p.finished_at is not None and p.finished_at >= p.started_at and p.device == "cpu"
    assert "CPU float32 reductions; results may differ across BLAS builds and thread counts" in p.nondeterminism
    assert "Uniform noise control drawn with numpy default_rng(seed)" in p.nondeterminism
    assert p.model_manifest["seed"] == 0 and p.model_manifest["n_samples"] == 16
    lims = rec.limitations
    standing = standing_limitations("synthetic", GRID)
    assert lims[:len(standing)] == standing
    assert any("not causal proof" in lim for lim in lims)
    assert any(lim == "Results come from a single seed; the ε grid was [0.01, 0.03, 0.1]." for lim in lims)
    assert not any(contains_banned_score_word(lim) for lim in lims if lim not in standing)
    assert any(i.id == "i.rules.unavailable" and i.basis == ["m.clean"] for i in rec.interpretation)


def test_record_round_trips_and_artifacts_written(record_no_explain):
    rec, root = record_no_explain
    plain = RunRecord.model_validate(rec.model_dump())
    assert plain.run_id == rec.run_id and plain.score == rec.score and plain.measurements == rec.measurements
    assert CampaignRecord.model_validate_json(rec.model_dump_json()).model_dump() == rec.model_dump()
    art = Path(root) / "artifacts"
    for name in ("run_record.json", "flip_matrix.json", "score.json"):
        assert (art / name).exists()
    for a in ("fgsm", "pgd"):
        curve = json.loads((art / "curve" / f"{a}.json").read_text())
        assert curve["attack_id"] == a and curve["eps_grid"] == GRID and curve["reference_eps"] == REF
        assert [pt["eps"] for pt in curve["points"]] == GRID
        assert all(pt["n"] == 16 and "n_correct" in pt and "n_clean_correct" in pt for pt in curve["points"])
        assert len(curve["control"]) == 3 and all(pt["n"] == 16 for pt in curve["control"])
        assert curve["clean"]["n_correct"] == rec.measurements[0].n_correct
        for e in EPS_TAGS:
            assert (art / "adv_slice" / f"{a}_eps{e}.npz").exists()
    assert [c.attack_id for c in rec.curve] == ["fgsm", "pgd"] and all(len(c.points) == 3 for c in rec.curve)
    flips = json.loads((art / "flip_matrix.json").read_text())
    assert set(flips["flipped"]) == {"fgsm", "pgd"} and len(flips["flipped"]["fgsm"]["eps0.03"]) == 16
    saved = json.loads((art / "run_record.json").read_text())
    assert saved["run_id"] == rec.run_id and saved["score"]["mri"] is None
    assert saved["score"]["completeness"] == "partial"


# --- explain paths ---------------------------------------------------------------------------------

def test_missing_explain_module_records_interpretation_and_partial_score(no_optional_modules, sink):
    rec = run_campaign(base_config(), sink, explain=True)
    assert rec.score is not None and rec.score.mri is None and rec.observations == []
    ids = {i.id: i for i in rec.interpretation}
    for a in ("fgsm", "pgd"):
        i = ids[f"i.explain.unavailable.{a}"]
        assert i.kind == "inferred" and i.basis == [f"m.evasion.{a}.eps0.03"]
        assert "unavailable" in i.statement and "not importable" in i.statement
    assert "explain" in rec.stages_done and "score" in rec.stages_done
    assert any("Explain stage unavailable for 'fgsm'" in lim for lim in rec.limitations)


def test_explainer_raising_explain_unavailable_is_recorded_not_faked(monkeypatch, sink):
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD,
                        make_fake_explain(raise_exc=ExplainUnavailable("no GradientExplainer")))
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    rec = run_campaign(base_config(), sink)
    assert rec.score.mri is None and rec.observations == []
    assert any("ExplainUnavailable: no GradientExplainer" in i.statement for i in rec.interpretation)


def test_injected_explain_yields_a_complete_score_with_five_subscores(monkeypatch, sink):
    fake = make_fake_explain(shift=0.4)
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, fake)
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    cfg = base_config()
    rec = run_campaign(cfg, sink)
    assert len(fake.calls) == 2
    assert all(c["k"] == 4 and c["seed"] == 0 and c["has_control"] and c["eps"] == REF for c in fake.calls)
    s = rec.score
    assert s is not None and rec.score_status is None and s.completeness == "complete" and s.missing == []
    assert s.subscores.missing() == [] and all(0 <= getattr(s.subscores, k) <= 100 for k in SUBSCORE_KEYS)
    assert s.weights == cfg.scoring.weights == MRIWeights() and s.subscores.S_expl == 60.0
    assert s.mri is not None and 0 <= s.mri <= 100 and s.grade == grade_for_mri(s.mri)
    assert s.reading and not contains_banned_score_word(s.reading) and "fgsm, pgd" in s.reading
    w = weights_by_subscore(cfg.scoring.weights)
    assert s.mri == round(sum(w[k] * getattr(s.subscores, k) for k in SUBSCORE_KEYS))
    assert s.attack_ids == ["fgsm", "pgd"] and s.reference_eps == REF and s.eps_grid == GRID and s.norm == "linf"
    assert set(s.per_attack) == {"fgsm", "pgd"} and len(s.inputs) == 6
    ref_inputs = [r for r in s.inputs if r.eps == REF]
    assert len(ref_inputs) == 2
    assert all(r.expl_shift == 0.4 and r.n_explained == 4 for r in ref_inputs)
    assert all(r.n_correct_clean == rec.measurements[0].n_correct for r in ref_inputs)
    assert s.delta is None and rec.completeness == "complete" and rec.missing == []
    # observations from both attacks kept, colliding ids namespaced by attack
    assert len(rec.observations) == 8
    assert {o.id for o in rec.observations} == {f"o.{i:03d}" for i in range(4)} | {f"o.{i:03d}.pgd" for i in range(4)}
    assert all(o.metric_kind == "heuristic" and o.expl_shift == 0.4 for o in rec.observations)
    for a in ("fgsm", "pgd"):
        ref_row = next(m for m in rec.measurements if m.id == f"m.evasion.{a}.eps0.03")
        assert ref_row.expl_shift_mean == 0.4 and ref_row.expl_shift_n == 4 and ref_row.expl_shift_n_excluded == 0
        assert ref_row.expl_shift_noise_floor == 0.05 and ref_row.expl_shift_noise_floor_n == 4
        assert any(n_.startswith("expl_shift_mean = 0.4000") for n_ in ref_row.notes)
        others = [m for m in rec.measurements if m.family == "evasion" and m.attack_id == a and m.id != ref_row.id]
        assert all(m.expl_shift_mean is None for m in others)
    nd = rec.provenance.nondeterminism
    assert "SHAP GradientExplainer background sampling (background_size=8, nsamples=8)" in nd
    assert any("explained out of n=16, at the reference budget eps=0.03 only" in lim for lim in rec.limitations)
    assert any("summarises this campaign only" in lim for lim in rec.limitations)
    assert not any("MRI not computed" in lim for lim in rec.limitations)
    assert rec.stages_done == ["load_target", "sample", "clean_eval", "attack:fgsm", "attack:pgd", "control",
                               "explain", "score", "interpret", "recommend", "report"]
    assert (Path(sink.root) / "artifacts" / "score.json").exists()
    assert RunRecord.model_validate(rec.model_dump()).score == s


def test_explainer_without_shift_leaves_the_score_partial(monkeypatch, sink):
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, make_fake_explain(shift=None))
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    rec = run_campaign(base_config(), sink)
    assert rec.score.mri is None and rec.score.subscores.missing() == ["S_expl"] and len(rec.observations) == 8
    ref_row = next(m for m in rec.measurements if m.id == "m.evasion.fgsm.eps0.03")
    assert ref_row.expl_shift_mean is None and ref_row.expl_shift_n == 0 and ref_row.expl_shift_n_excluded == 4
    assert any("returned no explanation-shift aggregate" in lim for lim in rec.limitations)


def test_custom_weights_flow_into_the_score_unrenormalised(monkeypatch, sink):
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, make_fake_explain(shift=0.0))
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    weights = MRIWeights(acc=0.5, asr=0.2, eps=0.1, conf=0.1, expl=0.1)
    rec = run_campaign(base_config(scoring=ScoringConfig(weights=weights)), sink)
    assert rec.score.weights == weights and rec.score.mri is not None
    w = weights_by_subscore(weights)
    assert rec.score.mri == round(sum(w[k] * getattr(rec.score.subscores, k) for k in SUBSCORE_KEYS))
    with pytest.raises(ValidationError, match="sum to 1.0"):
        base_config(scoring=ScoringConfig(weights=MRIWeights(acc=1.0)))


# --- interpret / recommend / narrative wiring ------------------------------------------------------

def test_rules_and_narrative_wiring(monkeypatch, sink):
    rules = make_fake_rules()
    summary, narrative = make_fake_narrative_stack()
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, make_fake_explain())
    monkeypatch.setitem(sys.modules, RULES_MOD, rules)
    monkeypatch.setitem(sys.modules, SUMMARY_MOD, summary)
    monkeypatch.setitem(sys.modules, NARRATIVE_MOD, narrative)
    cfg = base_config()

    rec = run_campaign(cfg, sink, narrative_settings=None)
    assert [i.id for i in rec.interpretation] == ["i.1"]
    seen = rules.seen
    assert seen["interpret"]["n_measurements"] == 10 and seen["interpret"]["n_observations"] == 8
    assert seen["interpret"]["thresholds"] == cfg.scoring.interpretation
    assert seen["interpret"]["finding_asr_threshold"] == cfg.finding_asr_threshold
    assert seen["interpret"]["reference_eps"] == REF and seen["interpret"]["score"] == rec.score
    assert seen["interpret"]["scoring_reason"] is None and seen["interpret"]["explain_meta"]["modality"] == "image"
    assert seen["recommend"]["interpretation"] == ["i.1"] and seen["recommend"]["modality"] == "image"
    assert seen["recommend"]["seed"] == 0 and seen["recommend"]["thresholds"] == cfg.scoring.interpretation
    assert [r.id for r in rec.recommendations] == ["r.R1"]
    r = rec.recommendations[0]
    assert r.status == "candidate" and r.validation == "not evaluated" and r.measured is None
    assert r.triggered_by == ["m.evasion.fgsm.eps0.03", "i.1"]
    assert r.narrative is None and r.narrative_source == "rules"
    assert narrative.calls == []                       # settings None -> no LLM call
    assert any("No LLM narrative was requested" in lim for lim in rec.limitations)
    assert rec.provenance.llm is None
    assert rec.stages_done[-4:] == ["score", "interpret", "recommend", "report"]

    rec2 = run_campaign(cfg, sink, narrative_settings=object())
    assert len(narrative.calls) == 1 and narrative.calls[0][0] == "summary text"
    assert summary.calls[-1]["norm"] == "linf" and summary.calls[-1]["limitations"]
    r2 = rec2.recommendations[0]
    assert r2.narrative_source == "llm" and r2.narrative
    assert r2.validation == "not evaluated" and r2.measured is None      # still no measured gain
    assert any(n_.startswith("LLM narrative is nondeterministic") for n_ in rec2.provenance.nondeterminism)
    assert rec2.provenance.llm is not None


def test_rule_output_with_dangling_citations_is_dropped_never_recorded(monkeypatch, sink):
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, None)
    monkeypatch.setitem(sys.modules, RULES_MOD, make_fake_rules(dangling=True))
    rec = run_campaign(base_config(), sink, explain=False)
    assert [i.id for i in rec.interpretation] == ["i.1"]
    assert [r.id for r in rec.recommendations] == ["r.R1"]
    assert any("Dropped interpretation 'i.9'" in lim and "m.nope" in lim for lim in rec.limitations)
    assert any("Dropped recommendation 'r.R9'" in lim and "o.999" in lim for lim in rec.limitations)
    RunRecord.model_validate(rec.model_dump())          # the frozen validator agrees: nothing dangles


def test_narrative_failure_leaves_rule_output_standing(monkeypatch, sink):
    rules = make_fake_rules()
    summary, narrative = make_fake_narrative_stack()

    def boom(recs, summary_text, settings):
        raise RuntimeError("gateway 503")

    narrative.add_narrative = boom
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, None)
    monkeypatch.setitem(sys.modules, RULES_MOD, rules)
    monkeypatch.setitem(sys.modules, SUMMARY_MOD, summary)
    monkeypatch.setitem(sys.modules, NARRATIVE_MOD, narrative)
    rec = run_campaign(base_config(), sink, explain=False, narrative_settings=object())
    assert rec.status == "succeeded" and rec.recommendations[0].narrative_source == "rules"
    assert any("LLM narrative not generated (RuntimeError: gateway 503)" in lim for lim in rec.limitations)


def test_llm_narrative_requested_without_pythia_env_is_a_limitation(monkeypatch, sink):
    for var in ("PYTHIA_BASE_URL", "PYTHIA_API_KEY", "REDSIM_ML_LLM_MODEL", "REDSIM_LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, None)
    monkeypatch.setitem(sys.modules, RULES_MOD, make_fake_rules())
    rec = run_campaign(base_config(llm_narrative=True), sink, explain=False)
    assert any("Pythia is not configured" in lim for lim in rec.limitations)
    assert rec.recommendations[0].narrative_source == "rules" and rec.recommendations[0].narrative is None


# --- finding derivation on a larger slice ------------------------------------------------------------

def test_finding_derivation_on_a_larger_slice(no_optional_modules, sink):
    cfg = base_config(attack_ids=["fgsm"], attack_params={}, n_samples=48)
    rec = run_campaign(cfg, sink, explain=False)
    clean = rec.measurements[0]
    assert clean.n_correct >= 10, "slice must clear the denominator guard for this test"
    fi = finding_inputs(cfg, rec.measurements, "fgsm")
    assert fi.denominator_ok and fi.crosses_threshold, "FGSM must cross the 0.2 ASR threshold on the brittle model"
    assert fi.severity == severity_for(fi.first_success_eps, fi.asr_at_first_success, GRID, REF,
                                       cfg.scoring.severity)
    assert fi.severity in ("critical", "high", "medium", "low")
    assert fi.confidence == confidence_for(clean.n_correct, cfg.scoring.confidence)
    rows = {m.params["eps"]: m for m in rec.measurements if m.family == "evasion"}
    for m in rows.values():
        crosses = m.attack_success_rate is not None and m.attack_success_rate >= cfg.finding_asr_threshold
        assert crosses == any("crosses finding_asr_threshold" in n_ for n_ in m.notes)
        assert m.n_clean_correct == clean.n_correct
    assert fi.asr_by_eps == {f"{e:g}": m.attack_success_rate for e, m in rows.items()}
    detail = MLFindingDetail(attack_id="fgsm", attack_name=rec.attacks[0].name, norm=cfg.norm, eps_grid=GRID,
                             reference_eps=REF, first_success_eps=fi.first_success_eps,
                             asr_at_reference=fi.asr_at_reference, asr_by_eps=fi.asr_by_eps,
                             threshold=fi.threshold, measurements=list(rows.values()), limitations=rec.limitations)
    assert detail.atlas_technique is None and detail.review.state == "unreviewed" and detail.verify is None
    assert len(rec.attacks) == 1 and rec.attacks[0].id == "fgsm"


# --- hopskipjump in the campaign: eps thresholding ---------------------------------------------------

def test_hopskipjump_rows_are_thresholded_against_the_grid(no_optional_modules, sink):
    cfg = base_config(attack_ids=["hopskipjump"], n_samples=10,
                      attack_params={"hopskipjump": {"max_iter": 1, "max_eval": 100, "init_eval": 10, "init_size": 3}})
    rec = run_campaign(cfg, sink, explain=False)
    rows = [m for m in rec.measurements if m.family == "evasion"]
    assert [m.id for m in rows] == [f"m.evasion.hopskipjump.eps{e}" for e in EPS_TAGS]
    for m in rows:
        assert m.linf_norm_mean <= m.params["eps"] + 1e-6
        assert m.queries_mean is not None and m.queries_mean > 0
        assert any(n_.startswith("thresholded at eps=") for n_ in m.notes)
    assert rec.attacks[0].access == "black-box" and rec.attacks[0].requires_gradients is False
    assert all(r.queries is not None for r in rec.score.inputs)
    assert any("black-box attack hopskipjump" in lim for lim in rec.limitations)
    assert any(n_.startswith("HopSkipJump random initial adversarial point") for n_ in rec.provenance.nondeterminism)
    assert_pert_first_success_is_mean_first_flip_norm(rec, Path(sink.root) / "artifacts", "hopskipjump",
                                                      TinyTarget().sample(10, 0).x)


def assert_pert_first_success_is_mean_first_flip_norm(rec: CampaignRecord, art: Path, attack_id: str,
                                                      x_clean: np.ndarray) -> None:
    """ATTACKS_HARDEN-06 (spec 15.1): on a minimal-norm or black-box attack the grid is an evaluation grid, so
    ``pert_first_success_mean`` on the reference row is the mean achieved norm at the smallest grid eps at which
    each sample flips, over exactly the flipped samples (``pert_first_success_n``); recomputed here from the
    written slices and ``flip_matrix.json``. Importable by the adapter tests of the CW-L2, DeepFool and ZOO
    tracks, which inherit the mechanism through ``takes_eps=False``."""
    flips = json.loads((art / "flip_matrix.json").read_text())["flipped"][attack_id]
    grid = sorted(float(e) for e in rec.config.eps_grid)
    l2 = rec.config.norm == "l2"
    norms = {e: per_sample_norm(x_clean, np.load(art / "adv_slice" / f"{attack_id}_{eps_tag(e)}.npz")["x_adv"], l2=l2)
             for e in grid}
    first: list[float] = []
    for i in range(len(x_clean)):
        for e in grid:
            if flips[eps_tag(e)][i]:
                first.append(float(norms[e][i]))
                break
    ref_row = next(m for m in rec.measurements if m.id == f"m.evasion.{attack_id}.{eps_tag(rec.config.reference_eps)}")
    assert ref_row.pert_first_success_n == len(first)
    if first:
        assert ref_row.pert_first_success_mean == pytest.approx(sum(first) / len(first), rel=1e-5)
        assert all(v <= max(grid) + 1e-6 for v in first)          # the evaluation grid bounds every first success
    else:
        assert ref_row.pert_first_success_mean is None
    others = [m for m in rec.measurements if m.family == "evasion" and m.attack_id == attack_id and m is not ref_row]
    assert all(m.pert_first_success_mean is None and m.pert_first_success_n is None for m in others)


# --- configuration errors and options ------------------------------------------------------------------

def test_control_toggle(no_optional_modules, sink):
    rec = run_campaign(base_config(attack_ids=["fgsm"], attack_params={}, include_control=False), sink,
                       explain=False)
    assert [a.id for a in rec.attacks] == ["fgsm"] and rec.config.attack_ids == ["fgsm"]
    assert not any(m.family == "control" for m in rec.measurements)
    assert "control" not in rec.stages_done
    assert all(c.control == [] for c in rec.curve)
    assert any("noise control was disabled" in lim for lim in rec.limitations)


@pytest.mark.parametrize("overrides,exc", [
    ({"target_id": "nope"}, TargetUnavailable),
    ({"attack_ids": ["zoo"], "attack_params": {}}, AttackNotApplicable),
    ({"attack_ids": ["noise_control"], "attack_params": {}}, AttackNotApplicable),
    ({"modality": "tabular"}, ValueError),
    ({"norm": "l2"}, AttackNotApplicable),                     # fgsm is L-inf only
    ({"attack_params": {"pgd": {"max_iter": 3, "bogus": 1}}}, ValueError),
    ({"attack_params": {"pgd": {"max_iter": 99}}}, ValueError),
    ({"attack_params": {"pgd": {"eps": 0.5}}}, ValueError),    # eps comes from the grid
])
def test_configuration_errors_raise_before_running(no_optional_modules, sink, overrides, exc):
    with pytest.raises(exc):
        run_campaign(base_config(**overrides), sink, explain=False)


@pytest.mark.parametrize("snapshot", [
    {"id": "tiny-1a2b3c4d", "kind": "ml_model", "value": "bundled:tiny", "detail": {}},
    {"id": "tiny-1a2b3c4d", "kind": "ml_model", "value": "blob", "detail": {"bundled_id": "tiny"}},
])
def test_per_project_target_id_resolves_the_bundled_registry_id(no_optional_modules, sink, snapshot):
    # POST /v1/models registers bundled models with a per-project Target.id; the registry id
    # travels in target_snapshot.value ("bundled:<id>") or detail.bundled_id.
    rec = run_campaign(base_config(target_id="tiny-1a2b3c4d", attack_ids=["fgsm"], attack_params={},
                                   target_snapshot=snapshot), sink, explain=False)
    assert rec.config.target_id == "tiny-1a2b3c4d"
    assert rec.target.id == "tiny"


@pytest.mark.parametrize("overrides", [
    {"reference_eps": 0.05},
    {"eps_grid": [0.03, -0.1], "reference_eps": 0.03},
    {"attack_ids": [], "attack_params": {}},
    {"attack_params": {"cw": {"c": 1.0}}},
    {"n_samples": 5},
])
def test_frozen_config_rejects_invalid_campaigns_at_construction(overrides):
    with pytest.raises(ValidationError):
        base_config(**overrides)


def test_defense_without_defenses_module_refuses_to_run_undefended(no_optional_modules, monkeypatch, sink):
    monkeypatch.setitem(sys.modules, DEFENSES_MOD, None)
    with pytest.raises(MLError):
        run_campaign(base_config(defense=DefenseConfig(id="feature_squeezing")), sink, explain=False)


def test_verify_run_applies_the_defense_and_measures_a_delta_against_its_baseline(monkeypatch, sink, tmp_path):
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, make_fake_explain(shift=0.3))
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    defenses = make_fake_defenses()
    monkeypatch.setitem(sys.modules, DEFENSES_MOD, defenses)
    baseline = run_campaign(base_config(), sink)
    defense = DefenseConfig(id="spatial_smoothing", params={"window_size": 3})
    verify = run_campaign(base_config(defense=defense), FilesystemSink(tmp_path / "verify"),
                          baseline_run_id=baseline.run_id)
    assert defenses.seen["args"] == ("tiny", "spatial_smoothing", {"window_size": 3})
    assert verify.kind == "verify" and verify.baseline_run_id == baseline.run_id
    assert verify.provenance.baseline_run_id == baseline.run_id
    assert verify.provenance.defense == defense.model_dump(mode="json")
    assert any("straight-through gradient estimate" in lim for lim in verify.limitations)
    # the settings hash ignores the defense, so the two campaigns are comparable
    assert verify.settings_hash == baseline.settings_hash and verify.score.mri is not None
    d = delta(baseline.score, verify.score, baseline_run_id=baseline.run_id,
              measurements_before=baseline.measurements, measurements_after=verify.measurements)
    assert d.baseline_run_id == baseline.run_id and d.mri_before == baseline.score.mri
    assert d.delta == 0 and d.delta_acc_clean.delta == 0.0            # identity defense: nothing changed
    assert [f.measurement_id for f in d.delta_families] == [
        f"m.evasion.{a}.eps{e}" for a in ("fgsm", "pgd") for e in EPS_TAGS]
    # the campaign itself never writes a delta or a measured gain: that is the verify task's job
    assert baseline.score.delta is None and verify.score.delta is None
    assert all(r.measured is None and r.validation == "not evaluated" for r in verify.recommendations)


def test_verify_run_records_the_applied_defense_as_the_wrapper_describes_it(no_optional_modules, sink):
    """With the real ``redsim.ml.defenses``, ``Provenance.defense`` carries the ART class and the resolved
    params (spec 14.4), not just the requested ``DefenseConfig``."""
    pytest.importorskip("art.defences.preprocessor")
    record = run_campaign(base_config(defense=DefenseConfig(id="feature_squeezing")), sink, explain=False)
    prov = record.provenance.defense
    assert record.kind == "verify" and prov is not None
    assert prov["id"] == "feature_squeezing"
    assert prov["art_class"] == "art.defences.preprocessor.FeatureSqueezing"
    assert prov["params"] == {"bit_depth": 4}                # the catalog default, resolved and recorded
    assert prov["torch_model_defended"] is False              # what the wrapper does not defend, stated
    assert record.target.name.endswith("+ Feature squeezing (bit-depth reduction)")
    assert record.target.metadata["defense"] == prov


# --- tabular campaign end to end (spec 12.9, register G-ATK-TAB, G-CAVEAT) ---------------------------

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def tabular_config(**overrides) -> CampaignConfig:
    cfg = {"target_id": "tiny_tabular", "modality": "tabular", "attack_ids": ["pgd", "hopskipjump"],
           "attack_params": {"pgd": {"max_iter": 3},
                             "hopskipjump": {"max_iter": 1, "max_eval": 100, "init_eval": 10, "init_size": 3}},
           "eps_grid": GRID, "reference_eps": REF, "n_samples": 24, "seed": 0, "explain_k": 4,
           "dataset_id": TABULAR_DATASET}
    cfg.update(overrides)
    return CampaignConfig(**cfg)


def test_tabular_campaign_end_to_end(monkeypatch, sink):
    """PGD by surrogate transfer + HopSkipJump + control on the shared tabular double, TreeExplainer on the real
    model, the realizability caveat on every evasion row, and the campaign's own complete MRI."""
    pytest.importorskip("shap")
    pytest.importorskip("sklearn")
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    target = TinyTabularTarget(seed=0)
    assert not hasattr(target.art_classifier(), "loss_gradient")           # the real tree has no gradients
    assert hasattr(target.surrogate_art_classifier(), "loss_gradient")     # the declared surrogate has
    with pytest.raises(NotImplementedError):
        target.torch_model()
    cfg = tabular_config()

    rec = run_campaign(cfg, sink, target_override=target)

    assert rec.status == "succeeded" and rec.target.domain == "tabular" and rec.config == cfg
    assert [a.id for a in rec.attacks] == ["pgd", "hopskipjump"]
    clean = rec.measurements[0]
    assert clean.id == "m.clean" and clean.n == 24 and clean.n_correct >= 10
    evasion = [m for m in rec.measurements if m.family == "evasion"]
    assert {m.id for m in evasion} == {f"m.evasion.{a}.eps{e}" for a in ("pgd", "hopskipjump") for e in EPS_TAGS}
    manifest = target.manifest()
    agree = manifest["surrogate"]["agreement_clean"]
    for m in evasion:
        assert REALIZABILITY_CAVEAT in m.notes                              # realizability caveat on every row
        assert m.n == 24 and m.n_clean_correct == clean.n_correct and m.conf_gap_n == 24
        if m.attack_id == "pgd":
            notes = [n_ for n_ in m.notes if n_.startswith("white-box via surrogate transfer")]
            assert len(notes) == 1, "exactly one surrogate-transfer label per row (adapter or campaign, never both)"
            assert "kind=logistic_regression" in notes[0]
            assert f"{agree['n_correct']}/{agree['n']}" in notes[0]                 # measured agreement, k/n
            assert m.queries_mean is None
        else:
            assert not any(n_.startswith("white-box via surrogate transfer") for n_ in m.notes)
            assert m.queries_mean is not None and any(n_.startswith("thresholded at eps=") for n_ in m.notes)
    control = [m for m in rec.measurements if m.family == "control"]
    assert [m.params["eps"] for m in control] == GRID and all(m.n == 24 for m in control)
    # the frozen features (declared perturbable=false) are untouched by the surrogate-transfer attack
    art = Path(sink.root) / "artifacts"
    x_clean = target.sample(24, 0).x
    frozen_cols = [i for i, name in enumerate(target.feature_names) if name in TABULAR_FROZEN]
    for e in EPS_TAGS:
        x_adv = np.load(art / "adv_slice" / f"pgd_eps{e}.npz")["x_adv"]
        assert np.array_equal(x_adv[:, frozen_cols], x_clean[:, frozen_cols])
        assert np.abs(x_adv - x_clean).max() <= float(e) + 1e-5
    # the campaign's own MRI: five subscores over both tabular families, never mixed with an image campaign
    s = rec.score
    assert s is not None and rec.score_status is None and s.attack_ids == ["pgd", "hopskipjump"]
    assert s.completeness == "complete" and s.mri is not None and s.grade == grade_for_mri(s.mri)
    assert s.subscores.missing() == [] and set(s.per_attack) == {"pgd", "hopskipjump"} and len(s.inputs) == 6
    assert rec.completeness == "complete" and not contains_banned_score_word(s.reading or "")
    # TreeExplainer on the real model: feature identifiers, no centre-mass analogue
    assert rec.observations and all(o.center_mass_ratio_clean is None and o.top_features_clean for o in rec.observations)
    assert all(f in target.feature_names for o in rec.observations for f in o.top_features_clean)
    assert "TreeExplainer is deterministic" in rec.provenance.nondeterminism
    assert rec.provenance.sklearn and rec.provenance.model_sha256 == manifest["weights_sha256"]
    lims = rec.limitations
    assert TABULAR_LIMITATION in lims and D3_BOUNDS_LIMITATION in lims
    surrogate_lim = next(lim for lim in lims if lim.startswith("White-box rows for pgd were computed by surrogate transfer"))
    assert "kind=logistic_regression" in surrogate_lim and "realizability is not established" in surrogate_lim
    assert any(lim.startswith(f"Dataset caveat ({TABULAR_DATASET}):") for lim in lims)
    assert not any("MRI not computed" in lim for lim in lims)
    assert any("black-box attack hopskipjump" in lim for lim in lims)
    assert (art / SHAP_SUMMARY_TEXT_NAME).exists() and (art / CURVE_PNG_NAME).exists()
    txt = (art / SHAP_SUMMARY_TEXT_NAME).read_text()
    assert "SHAP attributions describe the model's sensitivity, not the cause of a failure." in txt
    assert f"MRI = {s.mri}" in txt and "top features by mean |SHAP|" in txt
    assert not any(i.id.startswith("i.explain.unavailable") or i.id.startswith("i.attack.not_run") for i in rec.interpretation)
    RunRecord.model_validate(rec.model_dump())


def test_white_box_not_run_removed_before_scoring(monkeypatch, sink):
    """A white-box attack on a target without loss gradients and without a surrogate is recorded not_run: no row,
    no curve, no slice, an Interpretation and a limitation; scoring runs over the attacks that ran (spec 9.5, 15.4)."""
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    target = TinyTabularTarget(seed=0, surrogate=False)
    assert target.surrogate_art_classifier() is None and "surrogate" not in target.manifest()
    cfg = tabular_config()

    rec = run_campaign(cfg, sink, target_override=target, explain=False)

    assert rec.status == "succeeded"
    assert rec.config.attack_ids == ["pgd", "hopskipjump"]               # the declared set stays on the record
    assert [a.id for a in rec.attacks] == ["hopskipjump"]                # the in-scope set is what ran
    assert not any(m.attack_id == "pgd" for m in rec.measurements)       # no row, no number, nothing faked
    assert {m.id for m in rec.measurements if m.family == "evasion"} == {
        f"m.evasion.hopskipjump.eps{e}" for e in EPS_TAGS}
    assert "attack:pgd" not in rec.stages_done and "attack:hopskipjump" in rec.stages_done
    s = rec.score
    assert s is not None and rec.score_status is None                    # scored, over the reduced set
    assert s.attack_ids == ["hopskipjump"] and set(s.per_attack) == {"hopskipjump"} and len(s.inputs) == 3
    assert s.subscores.S_acc is not None and s.subscores.missing() == ["S_expl"]     # explain off, so partial
    assert not any("partial run" in lim for lim in rec.limitations)      # the reduced set is not a partial run
    i = next(i for i in rec.interpretation if i.id == "i.attack.not_run.pgd")
    assert i.kind == "inferred" and i.basis == ["m.clean"]
    assert "not_run" in i.statement and "removed from the in-scope attack set before scoring" in i.statement
    assert any(lim.startswith("Attack 'pgd' was not run") and "removed from the in-scope attack set" in lim
               for lim in rec.limitations)
    assert not any(lim.startswith("White-box rows for") for lim in rec.limitations)   # none declared, none claimed
    assert not any(n_.startswith("white-box via surrogate transfer") for m in rec.measurements for n_ in m.notes)
    assert [c.attack_id for c in rec.curve] == ["hopskipjump"]
    art = Path(sink.root) / "artifacts"
    assert (art / "curve" / "hopskipjump.json").exists() and not (art / "curve" / "pgd.json").exists()
    assert not list((art / "adv_slice").glob("pgd_*")) and list((art / "adv_slice").glob("hopskipjump_*"))
    flips = json.loads((art / "flip_matrix.json").read_text())
    assert flips["attack_ids"] == ["hopskipjump"] and set(flips["flipped"]) == {"hopskipjump"}
    assert set(flips["not_run"]) == {"pgd"} and flips["not_run"]["pgd"]
    assert json.loads((art / "run_record.json").read_text())["score"]["attack_ids"] == ["hopskipjump"]
    RunRecord.model_validate(rec.model_dump())


def test_all_attacks_not_run_leaves_the_score_unavailable(monkeypatch, sink):
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    target = TinyTabularTarget(seed=0, surrogate=False)
    rec = run_campaign(tabular_config(attack_ids=["pgd"], attack_params={"pgd": {"max_iter": 3}}), sink,
                       target_override=target, explain=False)
    assert rec.status == "succeeded" and rec.attacks == [] and rec.curve == []
    assert rec.score is None and rec.score_status is not None and rec.score_status.state == "unavailable"
    assert "not_run" in (rec.score_status.reason or "") and rec.missing == [rec.score_status.reason]
    assert [m.family for m in rec.measurements] == ["clean", "control", "control", "control"]
    assert not any(s.startswith("attack:") for s in rec.stages_done) and "score" in rec.stages_done
    assert any("No declared attack could run" in lim for lim in rec.limitations)
    assert any(i.id == "i.attack.not_run.pgd" for i in rec.interpretation)
    assert not (Path(sink.root) / "artifacts" / CURVE_PNG_NAME).exists()
    RunRecord.model_validate(rec.model_dump())


# --- robustness_curve.png (spec 12.3, register G-ATK7) ----------------------------------------------

def test_curve_png_written(record_no_explain):
    rec, root = record_no_explain
    png = Path(root) / "artifacts" / CURVE_PNG_NAME
    assert png.exists() and png.read_bytes()[:8] == PNG_MAGIC and png.stat().st_size > 2000
    assert (Path(root) / "artifacts" / "curve" / "fgsm.json").exists()        # rendered beside the JSON
    assert not any("not rendered" in lim for lim in rec.limitations)


def test_curve_png_skipped_with_a_limitation_when_matplotlib_is_absent(no_optional_modules, monkeypatch, sink):
    for name in ("matplotlib", "matplotlib.figure", "matplotlib.backends", "matplotlib.backends.backend_agg"):
        monkeypatch.setitem(sys.modules, name, None)
    rec = run_campaign(base_config(attack_ids=["fgsm"], attack_params={}), sink, explain=False)
    assert rec.status == "succeeded" and rec.score is not None
    art = Path(sink.root) / "artifacts"
    assert not (art / CURVE_PNG_NAME).exists() and (art / "curve" / "fgsm.json").exists()
    assert any(lim.startswith(f"{CURVE_PNG_NAME} not rendered: matplotlib is not installed") for lim in rec.limitations)


# --- noise-sensitivity Interpretation through the control predicate (spec 12.4, register G-SCORE1) ----

def test_noise_sensitive_control_records_an_interpretation_with_its_basis(no_optional_modules, monkeypatch, sink,
                                                                          record_no_explain):
    control = ATTACKS.get("noise_control")
    real_run = control.run

    def misclassified_inputs(target, x, y, params, seed):
        """Hand back, for every sample, a clean input the model gets wrong for that sample's label."""
        out = real_run(target, x, y, params, seed)
        pred = np.asarray(target.predict_proba(x)).argmax(axis=1)
        x_adv = np.array(x, copy=True)
        for i in range(len(y)):
            x_adv[i] = x[next(k for k in range(len(y)) if pred[k] != y[i])]
        out.x_adv = x_adv
        return out

    monkeypatch.setattr(control, "run", misclassified_inputs)
    rec = run_campaign(base_config(attack_ids=["fgsm"], attack_params={}, n_samples=48), sink, explain=False)
    clean = rec.measurements[0]
    assert clean.n_correct >= 5, "the slice must carry some clean-correct samples for the drop to be measurable"
    rows = [m for m in rec.measurements if m.family == "control"]
    assert len(rows) == 3 and all(m.n_correct == 0 for m in rows)
    ids = {i.id: i for i in rec.interpretation}
    for e in EPS_TAGS:
        i = ids[f"i.control.noise_sensitive.eps{e}"]
        assert i.kind == "inferred" and i.basis == ["m.clean", f"m.control.noise.eps{e}"]
        assert f"noise-sensitive at eps={float(e):g}" in i.statement and f"{clean.n_correct}/48 to 0/48" in i.statement
        assert "not attributable to adversarial alignment alone" in i.statement
        assert "control_preserves_accuracy" in i.statement or "campaign fallback" in i.statement
    assert all(any("the control did not preserve accuracy" in n_ for n_ in m.notes) for m in rows)
    assert sum("noise-sensitive at eps=" in lim for lim in rec.limitations) == 3
    RunRecord.model_validate(rec.model_dump())
    # an ordinary run states the verdict on every control row too, whichever way it went
    plain, _ = record_no_explain
    for m in (m for m in plain.measurements if m.family == "control"):
        assert any(n_.startswith("control preserves accuracy") or "did not preserve accuracy" in n_ for n_ in m.notes)


# --- subject_centered caveat, shap_summary.txt and the standing text (spec 13.4, 13.6, 14.5) ----------

class _OffCentreTarget(TinyTarget):
    """The manifest of a dataset whose subjects are not reliably centred, with a build-time caveat."""

    def manifest(self) -> dict:
        return {**super().manifest(), "subject_centered": False,
                "caveats": ["Subjects are web-thumbnail framed and not tightly cropped."]}


def test_subject_centered_false_adds_the_weak_subject_caveat(monkeypatch, sink, tmp_path):
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, make_fake_explain(shift=0.4))
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    rec = run_campaign(base_config(), sink, target_override=_OffCentreTarget())
    assert len(rec.observations) == 8
    for o in rec.observations:
        assert o.metric_kind == "heuristic" and o.metric_note.startswith("center_mass_ratio")
        assert o.metric_note.endswith(SUBJECT_CENTERED_CAVEAT)
    assert SUBJECT_CENTERED_CAVEAT in rec.limitations
    assert "Dataset caveat (synthetic): Subjects are web-thumbnail framed and not tightly cropped." in rec.limitations
    assert rec.provenance.model_manifest["subject_centered"] is False
    assert not contains_banned_score_word(SUBJECT_CENTERED_CAVEAT)
    # a manifest that declares nothing gets no caveat: the flag is read, never assumed
    plain = run_campaign(base_config(), FilesystemSink(tmp_path / "plain"))
    assert plain.observations and not any(SUBJECT_CENTERED_CAVEAT in o.metric_note for o in plain.observations)
    assert SUBJECT_CENTERED_CAVEAT not in plain.limitations
    assert not any(lim.startswith("Dataset caveat") for lim in plain.limitations)


def test_shap_summary_text_written_whenever_explain_ran(monkeypatch, sink, tmp_path, record_no_explain):
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, make_fake_explain(shift=0.4))
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    monkeypatch.delitem(sys.modules, SUMMARY_MOD, raising=False)          # the real summary module
    rec = run_campaign(base_config(), sink)
    path = Path(sink.root) / "artifacts" / SHAP_SUMMARY_TEXT_NAME
    assert path.exists()
    txt = path.read_text(encoding="utf-8")
    assert txt.rstrip().endswith("SHAP attributions describe the model's sensitivity, not the cause of a failure.")
    assert f"MRI = {rec.score.mri} (grade {rec.score.grade})" in txt and "Limitations:" in txt
    assert D3_BOUNDS_LIMITATION in txt and "Observations: 8 explained samples" in txt
    assert not any(SHAP_SUMMARY_TEXT_NAME in lim for lim in rec.limitations)
    # explain did not run: no summary and no claim of one
    _, root = record_no_explain
    assert not (Path(root) / "artifacts" / SHAP_SUMMARY_TEXT_NAME).exists()
    # the summary module is absent: recorded as unavailable, never a placeholder file
    monkeypatch.setitem(sys.modules, SUMMARY_MOD, None)
    rec2 = run_campaign(base_config(), FilesystemSink(tmp_path / "nosummary"))
    assert not (tmp_path / "nosummary" / "artifacts" / SHAP_SUMMARY_TEXT_NAME).exists()
    assert any(lim.startswith(f"{SHAP_SUMMARY_TEXT_NAME} not written (module '{SUMMARY_MOD}' not importable")
               for lim in rec2.limitations)


def test_limitations_carry_the_d3_bounds_statement_after_the_standing_text(record_no_explain):
    rec, _ = record_no_explain
    standing = standing_limitations("synthetic", GRID)
    assert rec.limitations[:len(standing)] == standing and rec.limitations[len(standing)] == D3_BOUNDS_LIMITATION
    assert not contains_banned_score_word(D3_BOUNDS_LIMITATION)
    assert "never trains, optimises or deploys targeting or weapons models" in D3_BOUNDS_LIMITATION
    assert "not a readiness or certification determination" in D3_BOUNDS_LIMITATION
    assert TABULAR_LIMITATION not in rec.limitations                        # image campaign: no tabular caveat
    assert not any("surrogate transfer" in lim for lim in rec.limitations)  # no surrogate was used


# --- the campaign-side surrogate fallback (spec 12.9) for adapters that do not resolve the surrogate -------

class _GradientOnlyAdapter:
    """A white-box adapter that only knows ``target.art_classifier()``: one signed-gradient step on the surrogate."""

    id = "gradient_only"
    domains = frozenset({"tabular"})
    takes_eps = True
    _schema = [ParamSpec(name="eps", type="float", default=0.03, min=1e-6, max=1.0)]

    def info(self) -> AttackInfo:
        return AttackInfo(id=self.id, name="one signed gradient step (test adapter)", domain="tabular",
                          family="evasion", params_schema=list(self._schema), access="white-box",
                          requires_gradients=True)

    def resolve_params(self, params):
        return resolve_from_schema(self._schema, params)

    def run(self, target, x, y, params, seed):
        clf = target.art_classifier()
        if not hasattr(clf, "loss_gradient"):
            raise AttackNotApplicable("gradient_only needs a differentiable estimator (no loss_gradient)")
        p = self.resolve_params(params)
        one_hot = np.eye(int(clf.nb_classes), dtype=np.float32)[np.asarray(y).astype(int)]
        grad = np.asarray(clf.loss_gradient(np.asarray(x, dtype=np.float32), one_hot))
        lo, hi = clf.clip_values
        x_adv = np.clip(x + float(p["eps"]) * np.sign(grad), lo, hi).astype(np.float32)
        x_adv = apply_mask(x, x_adv, perturbable_mask(target, x))
        linf, l2 = perturbation_norms(x, x_adv)
        return AttackOutput(x_adv=x_adv, linf_norm_mean=linf, l2_norm_mean=l2, wall_time_s=0.0, params=dict(p),
                            notes=["one signed gradient step"])


class _RegistryWithTestAdapter:
    def __init__(self, extra):
        self._extra = extra

    def maybe_get(self, aid):
        return self._extra if aid == self._extra.id else ATTACKS.maybe_get(aid)

    def get(self, aid):
        found = self.maybe_get(aid)
        if found is None:
            raise KeyError(aid)
        return found

    def ids(self):
        return [*ATTACKS.ids(), self._extra.id]


def test_campaign_hands_the_declared_surrogate_to_an_adapter_that_cannot_find_it(monkeypatch, sink):
    """An adapter that raises AttackNotApplicable on the real estimator is retried on a view of the target whose
    estimator is the declared surrogate; the row and the limitations say so, predictions stay on the real model."""
    import redsim.ml.campaign as campaign_module

    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    monkeypatch.setattr(campaign_module, "ATTACKS", _RegistryWithTestAdapter(_GradientOnlyAdapter()))
    target = TinyTabularTarget(seed=0)
    cfg = tabular_config(attack_ids=["gradient_only"], attack_params={})
    rec = run_campaign(cfg, sink, target_override=target, explain=False)
    rows = [m for m in rec.measurements if m.family == "evasion"]
    assert [m.id for m in rows] == [f"m.evasion.gradient_only.eps{e}" for e in EPS_TAGS]
    for m in rows:
        note = next(n_ for n_ in m.notes if n_.startswith("white-box via surrogate transfer"))
        assert "the campaign handed the adapter the declared surrogate estimator" in note
        assert "kind=logistic_regression" in note and "agreement_clean=" in note and "scored on the real model" in note
        assert REALIZABILITY_CAVEAT in m.notes and m.n_clean_correct == rec.measurements[0].n_correct
    assert rec.score is not None and rec.score.attack_ids == ["gradient_only"]
    assert not any(i.id.startswith("i.attack.not_run") for i in rec.interpretation)
    assert any(lim.startswith("White-box rows for gradient_only were computed by surrogate transfer") for lim in rec.limitations)
    # the same adapter without a declared surrogate is not_run, never quietly handed the real estimator
    rec2 = run_campaign(cfg, FilesystemSink(Path(sink.root).parent / "no_surrogate"),
                        target_override=TinyTabularTarget(seed=0, surrogate=False), explain=False)
    assert rec2.attacks == [] and rec2.score is None and "gradient_only" in json.loads(
        (Path(sink.root).parent / "no_surrogate" / "artifacts" / "flip_matrix.json").read_text())["not_run"]


# --- Phase B frame: modality runner dispatch (MODALITIES-09) ------------------------------------------------

def test_modality_runner_registry_names_the_sibling_hooks():
    """The frame dispatches by modality; text and detection are registered by name for the sibling tracks and
    resolved lazily, so this tree needs neither module to import the frame."""
    assert MODALITY_RUNNERS["image"] == MODALITY_RUNNERS["tabular"] == "redsim.ml.runners.classification:run_classification"
    assert MODALITY_RUNNERS["text"] == "redsim.ml.runners.text:run_text"
    assert MODALITY_RUNNERS["detection"] == "redsim.ml.runners.detection:run_detection"
    from redsim.ml.runners.classification import run_classification
    assert resolve_runner("image") is run_classification and resolve_runner("tabular") is run_classification
    with pytest.raises(ModalityRunnerUnavailable, match="no modality runner is registered"):
        resolve_runner("audio")


def test_missing_runner_module_refuses_before_any_stage(monkeypatch, sink):
    monkeypatch.setitem(sys.modules, "redsim.ml.runners.text", None)
    with pytest.raises(ModalityRunnerUnavailable, match="not importable"):
        resolve_runner("text")
    hookless = types.ModuleType("redsim.ml.runners.detection")
    monkeypatch.setitem(sys.modules, "redsim.ml.runners.detection", hookless)
    with pytest.raises(ModalityRunnerUnavailable, match="no callable 'run_detection'"):
        resolve_runner("detection")
    # the frame refuses before load_target: no stage callback, no artifact, the same MLError family as a
    # missing target or attack, so the sandbox child turns it into a failed partial record
    monkeypatch.setitem(runners_base.MODALITY_RUNNERS, "image", "redsim.ml.runners.text:run_text")
    stages: list[str] = []
    with pytest.raises(ModalityRunnerUnavailable) as excinfo:
        run_campaign(base_config(), sink, explain=False, on_stage=stages.append)
    assert isinstance(excinfo.value, MLError) and excinfo.value.code == "modality_runner_unavailable"
    assert stages == [] and not list(Path(sink.root).rglob("*.json"))


def _fake_runner_module(name: str, hook: str, *, mri: bool, curves: bool, explain: bool):
    """A runner that honours the frame contract on TinyTarget with argmax rows, so the frame's generic paths
    (a modality without an explainer, without an MRI) are exercised without a text or detection target."""
    from redsim.ml.eval import measure

    mod = types.ModuleType(name)
    seen: dict = {}

    def run(config, target, *, frame: CampaignFrame) -> ModalityResult:
        seen["frame"] = frame
        sample = target.sample(config.n_samples, config.seed)
        x = np.asarray(sample.x, dtype=np.float32)
        y = np.asarray(sample.y).astype(int)
        names = list(sample.class_names)
        frame.stage_done("sample")
        proba = np.asarray(target.predict_proba(x), dtype=np.float64)
        y_clean = proba.argmax(axis=1)
        frame.measurements.append(measure("m.clean", "clean", y, y_clean, names))
        frame.stage_done("clean_eval")
        flip_matrix: dict[str, dict[str, list[bool]]] = {}
        for adapter in frame.adapters:
            flip_matrix[adapter.id] = {}
            for e in frame.grid:
                x_adv = np.clip(x + e, 0.0, 1.0).astype(np.float32)          # a fixed shift, deterministic
                pa = np.asarray(target.predict_proba(x_adv), dtype=np.float64)
                y_adv = pa.argmax(axis=1)
                frame.measurements.append(measure(f"m.evasion.{adapter.id}.{eps_tag(e)}", "evasion", y, y_adv, names,
                                                  attack_id=adapter.id, params={"eps": e, "norm": config.norm},
                                                  x_ref=x, x_adv=x_adv, y_pred_clean=y_clean, proba=pa))
                flip_matrix[adapter.id][eps_tag(e)] = [bool(v) for v in (y_clean == y) & (y_adv != y)]
            frame.stage_done(f"attack:{adapter.id}")
        frame.close_attack_set()
        for e in frame.grid:
            frame.measurements.append(measure(f"m.control.noise.{eps_tag(e)}", "control", y, y_clean, names,
                                              attack_id="noise_control", params={"eps": e, "norm": config.norm},
                                              x_ref=x, x_adv=x, y_pred_clean=y_clean, proba=proba))
        frame.stage_done("control")

        def explain_stage() -> None:
            seen["explained"] = True
            frame.explain_meta["fgsm"] = {"expl_shift_mean": 0.1}

        return ModalityResult(n=len(y), indices=sample.indices, flip_matrix=flip_matrix,
                              explain=explain_stage if explain else None, curves=curves, mri=mri,
                              score_unavailable_reason=None if mri else "MRI not computed: this modality declares no MRI "
                              "by construction (detection scorecard instead)",
                              trailing_limitations=["fake modality caveat"], flip_matrix_extra={"boxes": 0})

    setattr(mod, hook, run)
    mod.seen = seen
    return mod


def test_frame_dispatches_an_injected_runner_and_records_no_explainer_and_no_mri(monkeypatch, sink):
    """A runner without an explainer and without an MRI (the detection shape): the frame still writes the
    curve and flip-matrix artifacts, records the missing explainer per attack, withholds the score with the
    runner's reason and keeps the stage vocabulary."""
    fake = _fake_runner_module("redsim.ml.runners.fake_detection", "run_fake", mri=False, curves=False, explain=False)
    monkeypatch.setitem(sys.modules, "redsim.ml.runners.fake_detection", fake)
    monkeypatch.setitem(runners_base.MODALITY_RUNNERS, "image", "redsim.ml.runners.fake_detection:run_fake")
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    stages: list[str] = []
    rec = run_campaign(base_config(), sink, explain=True, on_stage=stages.append)
    assert rec.status == "succeeded" and rec.stages_done == stages
    assert rec.stages_done == ["load_target", "sample", "clean_eval", "attack:fgsm", "attack:pgd", "control", "explain",
                               "score", "interpret", "recommend", "report"]
    assert all(s.split(":")[0] in STAGES for s in rec.stages_done)
    assert isinstance(fake.seen["frame"], CampaignFrame) and fake.seen["frame"].in_scope_ids == ["fgsm", "pgd"]
    assert "explained" not in fake.seen
    for a in ("fgsm", "pgd"):
        i = next(i for i in rec.interpretation if i.id == f"i.explain.unavailable.{a}")
        assert "no explainer is implemented for the 'image' domain" in i.statement
        assert i.basis == [f"m.evasion.{a}.eps0.03"]
    assert rec.score is None and rec.score_status is not None and rec.score_status.state == "unavailable"
    assert "declares no MRI" in rec.score_status.reason and rec.missing == [rec.score_status.reason]
    assert rec.curve == [] and "fake modality caveat" in rec.limitations
    assert [a.id for a in rec.attacks] == ["fgsm", "pgd"]
    art = Path(sink.root) / "artifacts"
    assert not (art / CURVE_PNG_NAME).exists() and not (art / "curve").exists()
    flips = json.loads((art / "flip_matrix.json").read_text())
    assert flips["boxes"] == 0 and set(flips["flipped"]) == {"fgsm", "pgd"} and flips["n"] == 16
    assert rec.provenance.sample_indices_sha256 == hashlib.sha256(np.arange(16, dtype=np.int64).tobytes()).hexdigest()
    RunRecord.model_validate(rec.model_dump())


def test_frame_runs_the_runner_explain_closure_after_the_curve_artifacts(monkeypatch, sink):
    fake = _fake_runner_module("redsim.ml.runners.fake_cls", "run_fake", mri=True, curves=True, explain=True)
    monkeypatch.setitem(sys.modules, "redsim.ml.runners.fake_cls", fake)
    monkeypatch.setitem(runners_base.MODALITY_RUNNERS, "image", "redsim.ml.runners.fake_cls:run_fake")
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    rec = run_campaign(base_config(attack_ids=["fgsm"], attack_params={}), sink)
    assert fake.seen["explained"] is True and "explain" in rec.stages_done
    assert rec.score is not None and rec.score.attack_ids == ["fgsm"]           # scored over the in-scope set
    assert [c.attack_id for c in rec.curve] == ["fgsm"] and (Path(sink.root) / "artifacts" / CURVE_PNG_NAME).exists()
    assert not any(i.id.startswith("i.explain.unavailable") for i in rec.interpretation)


# --- Phase B frame: the training-defense hook (ATTACKS_HARDEN-06) ---------------------------------------------

HARDEN_MOD = TRAINING_DEFENSE_MODULE


def make_fake_defenses_catalog(kind: str = "training"):
    """A defenses catalog whose ``adv_train`` entry carries ``kind`` and whose preprocessing hook must not run."""
    defenses = types.ModuleType(DEFENSES_MOD)
    seen: dict = {}

    def get_defense(defense_id):
        if defense_id == "adv_train":
            return {"id": "adv_train", "kind": kind, "art_class": "art.defences.trainer.AdversarialTrainer"}
        raise ValueError(f"unknown defense: {defense_id!r}")

    def apply_defense(target, defense_id, params):
        seen["preprocessing_args"] = (target.id, defense_id, params)
        return target

    defenses.get_defense = get_defense
    defenses.apply_defense = apply_defense
    defenses.seen = seen
    return defenses


class _HardenedView:
    """What apply_training_defense hands back: the derived model, describing itself for the provenance."""

    def __init__(self, target, defense):
        self._target = target
        self._defense = defense
        self.id = target.id

    def describe(self):
        return {"id": self._defense.id, "kind": "training", "params": dict(self._defense.params),
                "epochs_run": 1, "derived_sha256": "0" * 64}

    def __getattr__(self, name):
        return getattr(self._target, name)


def make_fake_harden():
    harden = types.ModuleType(HARDEN_MOD)
    seen: dict = {}

    def apply_training_defense(target, defense, *, config, sink, seed):
        seen["args"] = {"target": target.id, "defense": defense, "config": config, "sink": sink, "seed": seed}
        return _HardenedView(target, defense)

    harden.apply_training_defense = apply_training_defense
    harden.seen = seen
    return harden


def test_training_defense_is_applied_through_the_harden_hook(no_optional_modules, monkeypatch, sink):
    defenses = make_fake_defenses_catalog()
    harden = make_fake_harden()
    monkeypatch.setitem(sys.modules, DEFENSES_MOD, defenses)
    monkeypatch.setitem(sys.modules, HARDEN_MOD, harden)
    defense = DefenseConfig(id="adv_train", params={"epochs": 1})
    cfg = base_config(attack_ids=["fgsm"], attack_params={}, defense=defense)
    rec = run_campaign(cfg, sink, explain=False, baseline_run_id="baseline-1")
    args = harden.seen["args"]
    assert args["target"] == "tiny" and args["defense"] == defense and args["config"] == cfg
    assert args["sink"] is sink and args["seed"] == 0
    assert "preprocessing_args" not in defenses.seen                    # kind: training never goes through apply_defense
    assert rec.kind == "verify" and rec.baseline_run_id == "baseline-1"
    assert rec.provenance.defense == {"id": "adv_train", "kind": "training", "params": {"epochs": 1}, "epochs_run": 1,
                                      "derived_sha256": "0" * 64}
    assert rec.score is not None                                         # measured on the derived model, scored
    assert TRAINING_DEFENSE_LIMITATION in rec.limitations and DEFENSE_LIMITATION not in rec.limitations
    assert "defense_apply" not in rec.stages_done                        # this tree's STAGES has no such stage
    assert rec.stages_done[:2] == ["load_target", "sample"]


def test_training_defense_without_harden_module_is_recorded_unavailable_and_unscored(no_optional_modules, monkeypatch,
                                                                                    sink):
    """The hook module is absent: the run completes with real rows on the undefended model, the defense is recorded
    unavailable in the provenance and the limitations, and the score is withheld so no delta can be read."""
    monkeypatch.setitem(sys.modules, DEFENSES_MOD, make_fake_defenses_catalog())
    monkeypatch.setitem(sys.modules, HARDEN_MOD, None)
    rec = run_campaign(base_config(attack_ids=["fgsm"], attack_params={}, defense=DefenseConfig(id="adv_train")), sink,
                       explain=False)
    assert rec.status == "succeeded" and rec.kind == "verify"
    prov = rec.provenance.defense
    assert prov["status"] == "unavailable" and prov["kind"] == "training" and prov["id"] == "adv_train"
    assert HARDEN_MOD in prov["reason"] and prov["requested"] == {"id": "adv_train", "art_class": None, "params": {}}
    assert rec.score is None and rec.score_status is not None and rec.score_status.state == "unavailable"
    assert "was not applied" in rec.score_status.reason and "fake a delta" in rec.score_status.reason
    assert any(lim.startswith("Defense 'adv_train' (kind training) was not applied") for lim in rec.limitations)
    assert DEFENSE_LIMITATION not in rec.limitations and TRAINING_DEFENSE_LIMITATION not in rec.limitations
    assert [m.family for m in rec.measurements] == ["clean", "evasion", "evasion", "evasion", "control", "control", "control"]
    assert not (Path(sink.root) / "artifacts" / "score.json").exists()
    RunRecord.model_validate(rec.model_dump())


def test_defense_apply_stage_is_emitted_only_when_schema_stages_carry_it(no_optional_modules, monkeypatch, sink,
                                                                        tmp_path):
    """The stage vocabulary is read from ``schema.STAGES`` at run time (B0 adds ``defense_apply``); with it present a
    verify run records the stage right after load_target, an attack run never does."""
    import redsim.ml.schema as schema_module

    monkeypatch.setitem(sys.modules, DEFENSES_MOD, make_fake_defenses())
    widened = ("load_target", "defense_apply", *tuple(s for s in STAGES if s != "load_target"))
    monkeypatch.setattr(schema_module, "STAGES", widened)
    verify = run_campaign(base_config(attack_ids=["fgsm"], attack_params={}, defense=DefenseConfig(id="feature_squeezing")),
                          sink, explain=False)
    assert verify.stages_done[:3] == ["load_target", "defense_apply", "sample"]
    attack = run_campaign(base_config(attack_ids=["fgsm"], attack_params={}), FilesystemSink(tmp_path / "attack"),
                          explain=False)
    assert "defense_apply" not in attack.stages_done
    assert verify.stages_done[2:] == attack.stages_done[1:]


# --- Phase B frame: offline pins for the child (MODALITIES-10) ----------------------------------------------

class _EnvCapturingTarget(TinyTarget):
    """Records the offline pins as the runner sees them during prediction."""

    captured: dict[str, str | None] = {}

    def predict_proba(self, x):
        type(self).captured = {k: os.environ.get(k) for k in ("NLTK_DATA", "TORCH_HOME")}
        return super().predict_proba(x)


def test_run_pins_nltk_data_and_torch_home_offline_for_its_duration(no_optional_modules, monkeypatch, sink, tmp_path):
    for key in ("NLTK_DATA", "TORCH_HOME"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(tmp_path / "assets"))
    cfg = base_config(attack_ids=["fgsm"], attack_params={})
    run_campaign(cfg, sink, explain=False, target_override=_EnvCapturingTarget())
    captured = _EnvCapturingTarget.captured
    assert captured["TORCH_HOME"] == str(Path(sink.root) / "torch")                  # an empty cache under the work dir
    assert captured["NLTK_DATA"] == str(tmp_path / "assets" / "lexicons" / "nltk_data")
    assert os.environ.get("NLTK_DATA") is None and os.environ.get("TORCH_HOME") is None  # restored afterwards
    # an explicit setting is never overridden, and without an assets dir the lexicon path stays under the work dir
    monkeypatch.setenv("TORCH_HOME", str(tmp_path / "hub"))
    monkeypatch.delenv("REDSIM_ML_ASSETS_DIR", raising=False)
    run_campaign(cfg, FilesystemSink(tmp_path / "second"), explain=False, target_override=_EnvCapturingTarget())
    captured = _EnvCapturingTarget.captured
    assert captured["TORCH_HOME"] == str(tmp_path / "hub")
    assert captured["NLTK_DATA"] == str(tmp_path / "second" / "nltk_data")
    assert os.environ["TORCH_HOME"] == str(tmp_path / "hub")
    pins = runners_base.offline_env_pins(None)
    assert set(pins) == {"NLTK_DATA", "TORCH_HOME"} and all(pins.values())
