"""``redsim.ml.campaign.run_campaign`` on the TinyTarget double against the frozen M0 contract (``ml`` tier).

The explain, recommend, summary, narrative and defenses modules are injected or removed through
``sys.modules`` so these tests hold whether or not the concurrent builders' modules are present.

Pins: ``CampaignConfig`` in, ``CampaignRecord`` (a ``RunRecord``) out with the ``score`` stage;
``RunRecord.score`` is an ``MRIRecord`` that is PARTIAL (no ``mri``, no ``grade``) whenever the explain
stage gave ``S_expl`` no input; ``RunRecord.attacks`` carries the registry snapshots; the limitations
start with ``schema.standing_limitations``; the P0 provenance fields are filled; every citation
resolves; candidates carry no measured delta; the benign control runs at the same eps as the attacks.
"""

from __future__ import annotations

import hashlib
import json
import sys
import types
from pathlib import Path

import pytest
from pydantic import ValidationError

pytest.importorskip("torch")
pytest.importorskip("art")

import numpy as np

from redsim.ml.artifacts import FilesystemSink
from redsim.ml.campaign import run_campaign
from redsim.ml.errors import AttackNotApplicable, ExplainUnavailable, MLError, TargetUnavailable
from redsim.ml.explain.base import ExplainOutput
from redsim.ml.schema import (
    STAGES,
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
from tests.ml.fakes import TinyTarget

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
