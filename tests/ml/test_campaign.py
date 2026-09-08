"""``redsim.ml.campaign.run_campaign`` on the TinyTarget double (``ml`` tier).

The explain and recommend modules are injected or removed through ``sys.modules`` so
these tests hold whether or not the concurrent builders' modules are present.
"""

from __future__ import annotations

import json
import re
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path

import pytest

pytest.importorskip("torch")
pytest.importorskip("art")

from redsim.ml.artifacts import FilesystemSink
from redsim.ml.campaign import run_campaign
from redsim.ml.errors import AttackNotApplicable, ExplainUnavailable, MLError, TargetUnavailable
from redsim.ml.schema import (
    STAGES,
    STANDING_LIMITATIONS,
    CandidateRecommendation,
    Interpretation,
    Observation,
    RunConfig,
    RunRecord,
)
from redsim.ml.scoring import (
    DEFAULT_WEIGHTS,
    SUBSCORE_KEYS,
    eps_bands,
    first_success,
    severity_for,
)
from redsim.ml.targets.registry import TARGETS
from tests.ml.fakes import TinyTarget

pytestmark = pytest.mark.ml

EXPLAIN_MOD = "redsim.ml.explain.shap_image"
RULES_MOD = "redsim.ml.recommend.rules"
SUMMARY_MOD = "redsim.ml.explain.summary"
NARRATIVE_MOD = "redsim.ml.recommend.narrative"
BANNED = re.compile(r"hardened|fielding|deployment-ready|certif|\bsafe\b", re.IGNORECASE)

if TARGETS.maybe_get("tiny") is None:
    TARGETS.register(TinyTarget(seed=0))


def base_config(**overrides) -> RunConfig:
    cfg = {"target_id": "tiny", "attack_ids": ["fgsm", "pgd"], "n_samples": 16, "seed": 0,
           "params": {"max_iter": 3}, "explain_k": 4}
    cfg.update(overrides)
    return RunConfig(**cfg)


@dataclass
class FakeExplainOutput:
    observations: list
    expl_shift_mean: float | None
    meta: dict = field(default_factory=dict)


def make_fake_explain(shift: float | None = 0.4, raise_exc: Exception | None = None):
    mod = types.ModuleType(EXPLAIN_MOD)
    calls: list[dict] = []

    def explain(target, sample, x_adv, proba_clean, proba_adv, sink, *, k, seed):
        calls.append({"k": k, "seed": seed, "n": len(sample.y), "x_adv_shape": x_adv.shape})
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
                center_mass_ratio_clean=0.5, center_mass_ratio_adv=0.4))
        return FakeExplainOutput(obs, shift, {"nondeterminism": "SHAP GradientExplainer background sampling "
                                              "(background_size=8, nsamples=8)", "expl_shift_n": len(obs)})

    mod.explain = explain
    mod.calls = calls
    return mod


def make_fake_rules():
    mod = types.ModuleType(RULES_MOD)
    seen: dict = {}

    def interpret(measurements, observations, scoring):
        seen["interpret"] = (len(measurements), len(observations), scoring)
        return [Interpretation(id="i.1", statement="Random noise did not reduce accuracy while fgsm did.",
                               basis=["m.clean", "m.evasion.fgsm.eps0.03", "m.control.noise.eps0.03"])]

    def recommend(measurements, observations, interpretation, scoring):
        seen["recommend"] = (len(measurements), len(observations), [i.id for i in interpretation], scoring)
        return [CandidateRecommendation(id="r.R1", title="Adversarial training (candidate)",
                                        rationale="Gradient-aligned degradation at eps=0.03.",
                                        triggered_by=["m.evasion.fgsm.eps0.03"],
                                        references=["art.defences.trainer.AdversarialTrainer"])]

    mod.interpret = interpret
    mod.recommend = recommend
    mod.seen = seen
    return mod


def make_fake_narrative_stack():
    summary = types.ModuleType(SUMMARY_MOD)
    summary.text_summary = lambda measurements, observations, scoring: "clean 9/16"
    narrative = types.ModuleType(NARRATIVE_MOD)
    calls: list = []

    def add_narrative(recs, summary_text, settings):
        calls.append((summary_text, settings))
        return [r.model_copy(update={"narrative": "Rule text rewritten.", "narrative_source": "llm"}) for r in recs]

    narrative.add_narrative = add_narrative
    narrative.calls = calls
    return summary, narrative


@pytest.fixture
def no_optional_modules(monkeypatch):
    for name in (EXPLAIN_MOD, RULES_MOD, SUMMARY_MOD, NARRATIVE_MOD):
        monkeypatch.setitem(sys.modules, name, None)


@pytest.fixture
def sink(tmp_path) -> FilesystemSink:
    return FilesystemSink(tmp_path / "run")


# --- explain disabled: valid record, scoring None -----------------------------------------------

@pytest.fixture(scope="module")
def record_no_explain(tmp_path_factory):
    for name in (EXPLAIN_MOD, RULES_MOD):
        saved = sys.modules.get(name, "__absent__")
        sys.modules[name] = None
    try:
        root = tmp_path_factory.mktemp("campaign")
        rec = run_campaign(base_config(), FilesystemSink(root), explain=False)
    finally:
        for name in (EXPLAIN_MOD, RULES_MOD):
            if saved == "__absent__":
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = saved
    return rec, root


def test_run_without_explain_is_a_valid_record_with_scoring_none(record_no_explain):
    rec, _ = record_no_explain
    assert isinstance(rec, RunRecord) and rec.status == "succeeded" and rec.stage == "report"
    assert rec.scoring is None
    assert any("MRI not computed" in lim and "S_expl" in lim for lim in rec.limitations)
    assert any("Explanations were not computed (explain disabled)" in lim for lim in rec.limitations)
    assert rec.observations == []
    assert rec.error is None
    assert rec.attack is None                         # two attacks: no single-attack form
    assert rec.target.id == "tiny" and rec.config.attack_ids == ["fgsm", "pgd"]


def test_measurement_rows_ids_denominators_and_control(record_no_explain):
    rec, _ = record_no_explain
    ids = [m.id for m in rec.measurements]
    assert ids[0] == "m.clean"
    assert {i for i in ids if i.startswith("m.evasion")} == {
        f"m.evasion.{a}.eps{e}" for a in ("fgsm", "pgd") for e in ("0.01", "0.03", "0.1")}
    assert {i for i in ids if i.startswith("m.control")} == {f"m.control.noise.eps{e}" for e in ("0.01", "0.03", "0.1")}
    assert len(rec.measurements) == 1 + 6 + 3
    n = rec.measurements[0].n
    for m in rec.measurements:
        assert m.n == n == 16
        assert 0 <= m.n_correct <= m.n
        assert m.accuracy == pytest.approx(m.n_correct / m.n)
        assert sum(v["n"] for v in m.per_class.values()) == m.n
        if m.family == "clean":
            assert m.attack_id is None and m.n_flipped_from_clean is None
        else:
            assert m.n_flipped_from_clean is not None
            assert any(n_.startswith("attack_success_rate") for n_ in m.notes)
            assert m.params["eps"] == float(m.id.rsplit("eps", 1)[1])
            assert m.linf_norm_mean is not None and m.linf_norm_mean <= m.params["eps"] + 1e-6
            assert m.l2_norm_mean is not None
        if m.family == "control":
            assert m.attack_id == "noise_control" and m.severity is None
            assert any("never create a Finding" in n_ for n_ in m.notes)
        if m.family == "evasion":
            assert any(n_.startswith("conf_gap_mean") for n_ in m.notes)


def test_severity_not_derived_when_denominator_too_small(record_no_explain):
    rec, _ = record_no_explain
    clean = rec.measurements[0]
    assert clean.n_correct < 10
    for m in rec.measurements:
        if m.family == "evasion":
            assert m.severity is None
            assert any("denominator too small for a finding" in n_ for n_ in m.notes)


def test_stages_provenance_atlas_and_limitations(record_no_explain):
    rec, _ = record_no_explain
    assert rec.stages_done == ["load_target", "sample", "clean_eval", "attack", "control", "interpret",
                               "recommend", "report"]
    assert all(s in STAGES for s in rec.stages_done)
    p = rec.provenance
    assert p is not None and p.art and p.torch and p.numpy and p.python and p.redsim_version and p.hostname
    assert p.model_sha256 == TinyTarget().manifest()["weights_sha256"]
    assert p.dataset == "synthetic" and p.finished_at is not None and p.finished_at >= p.started_at
    assert "CPU float32 reductions; results may differ across BLAS builds and thread counts" in p.nondeterminism
    assert "Uniform noise control drawn with numpy default_rng(seed)" in p.nondeterminism
    assert p.model_manifest["seed"] == 0 and p.model_manifest["sample_indices_sha256"]
    assert rec.atlas_coverage == ["AML.T0043"]
    lims = rec.limitations
    assert any("not causal proof" in lim for lim in lims)
    assert any("Recommendations are candidates" in lim for lim in lims)
    assert any("does not establish safety" in lim for lim in lims)
    assert any(lim == "Results come from a single seed; the eps grid was [0.01, 0.03, 0.1]." for lim in lims)
    assert any(lim.startswith("synthetic is an open, unclassified public benchmark") for lim in lims)
    assert not any(lim in lims for lim in STANDING_LIMITATIONS if lim.startswith("CIFAR-10"))
    assert any(i.id == "i.rules.unavailable" and i.basis == ["m.clean"] for i in rec.interpretation)
    assert rec.recommendations == []


def test_record_round_trips_and_artifacts_written(record_no_explain):
    rec, root = record_no_explain
    dumped = rec.model_dump_json()
    again = RunRecord.model_validate_json(dumped)
    assert again.model_dump() == rec.model_dump()
    art = Path(root) / "artifacts"
    assert (art / "run_record.json").exists() and (art / "flip_matrix.json").exists()
    for a in ("fgsm", "pgd"):
        curve = json.loads((art / "curve" / f"{a}.json").read_text())
        assert curve["attack_id"] == a and curve["eps_grid"] == [0.01, 0.03, 0.1]
        assert [pt["eps"] for pt in curve["points"]] == [0.01, 0.03, 0.1]
        assert all("n" in pt and pt["n"] == 16 and "n_correct" in pt for pt in curve["points"])
        assert len(curve["control"]) == 3 and all(pt["n"] == 16 for pt in curve["control"])
        for e in ("0.01", "0.03", "0.1"):
            assert (art / "adv_slice" / f"{a}_eps{e}.npz").exists()
    flips = json.loads((art / "flip_matrix.json").read_text())
    assert set(flips["flipped"]) == {"fgsm", "pgd"} and len(flips["flipped"]["fgsm"]["eps0.03"]) == 16
    saved = json.loads((art / "run_record.json").read_text())
    assert saved["run_id"] == rec.run_id and saved["scoring"] is None


# --- explain paths ---------------------------------------------------------------------------------

def test_missing_explain_module_records_interpretation_and_no_score(no_optional_modules, sink):
    rec = run_campaign(base_config(), sink, explain=True)
    assert rec.scoring is None and rec.observations == []
    ids = {i.id: i for i in rec.interpretation}
    for a in ("fgsm", "pgd"):
        i = ids[f"i.explain.unavailable.{a}"]
        assert i.kind == "inferred" and i.basis == [f"m.evasion.{a}.eps0.03"]
        assert "unavailable" in i.statement and "not importable" in i.statement
    assert "explain" in rec.stages_done
    assert any("Explain stage unavailable for 'fgsm'" in lim for lim in rec.limitations)


def test_explainer_raising_explain_unavailable_is_recorded_not_faked(monkeypatch, sink):
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, make_fake_explain(raise_exc=ExplainUnavailable("no GradientExplainer")))
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    rec = run_campaign(base_config(), sink)
    assert rec.scoring is None and rec.observations == []
    assert any("ExplainUnavailable: no GradientExplainer" in i.statement for i in rec.interpretation)


def test_injected_explain_yields_scoring_with_five_subscores(monkeypatch, sink):
    fake = make_fake_explain(shift=0.4)
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, fake)
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    cfg = base_config()
    rec = run_campaign(cfg, sink)
    assert len(fake.calls) == 2 and all(c["k"] == 4 and c["seed"] == 0 for c in fake.calls)
    s = rec.scoring
    assert s is not None
    assert set(s.subscores) == set(SUBSCORE_KEYS) and all(0 <= v <= 100 for v in s.subscores.values())
    assert s.weights == DEFAULT_WEIGHTS and s.subscores["S_expl"] == 60.0
    assert 0 <= s.mri <= 100 and s.grade in "ABCDF" and not BANNED.search(s.reading)
    assert s.mri == round(sum(DEFAULT_WEIGHTS[k] * s.subscores[k] for k in SUBSCORE_KEYS))
    assert s.modality == "image" and s.attack_ids == ["fgsm", "pgd"] and s.reference_eps == 0.03
    assert s.basis_measurements[0] == "m.clean" and len(s.basis_measurements) == 7
    assert s.delta_mri is None and s.not_a_readiness_statement is True
    # observations from both attacks kept, colliding ids namespaced by attack
    assert len(rec.observations) == 8
    assert {o.id for o in rec.observations} == {f"o.{i:03d}" for i in range(4)} | {f"o.{i:03d}.pgd" for i in range(4)}
    assert all(o.metric_kind == "heuristic" for o in rec.observations)
    for a in ("fgsm", "pgd"):
        ref_row = next(m for m in rec.measurements if m.id == f"m.evasion.{a}.eps0.03")
        assert any(n_.startswith("expl_shift_mean = 0.4000") for n_ in ref_row.notes)
    assert "SHAP GradientExplainer background sampling (background_size=8, nsamples=8)" in rec.provenance.nondeterminism
    assert any("explained out of n=16, at the reference budget eps=0.03 only" in lim for lim in rec.limitations)
    assert any("summarises this campaign only" in lim for lim in rec.limitations)
    assert not any("MRI not computed" in lim for lim in rec.limitations)
    assert rec.stages_done == [s_ for s_ in STAGES]


def test_explainer_without_shift_leaves_scoring_none(monkeypatch, sink):
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, make_fake_explain(shift=None))
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    rec = run_campaign(base_config(), sink)
    assert rec.scoring is None and len(rec.observations) == 8
    assert any("returned no explanation-shift aggregate" in lim for lim in rec.limitations)


def test_custom_weights_flow_into_scoring(monkeypatch, sink):
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, make_fake_explain(shift=0.0))
    monkeypatch.setitem(sys.modules, RULES_MOD, None)
    weights = {"S_acc": 0.5, "S_asr": 0.2, "S_eps": 0.1, "S_conf": 0.1, "S_expl": 0.1}
    rec = run_campaign(base_config(scoring_weights=weights), sink)
    assert rec.scoring.weights == weights
    with pytest.raises(ValueError):
        run_campaign(base_config(scoring_weights={"S_acc": 1.0}), sink)


# --- interpret / recommend / narrative wiring ------------------------------------------------------

def test_rules_and_narrative_wiring(monkeypatch, sink):
    rules = make_fake_rules()
    summary, narrative = make_fake_narrative_stack()
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, make_fake_explain())
    monkeypatch.setitem(sys.modules, RULES_MOD, rules)
    monkeypatch.setitem(sys.modules, SUMMARY_MOD, summary)
    monkeypatch.setitem(sys.modules, NARRATIVE_MOD, narrative)

    rec = run_campaign(base_config(), sink, narrative_settings=None)
    assert [i.id for i in rec.interpretation] == ["i.1"]
    assert rules.seen["interpret"][0] == 10 and rules.seen["interpret"][1] == 8
    assert rules.seen["recommend"][2] == ["i.1"]
    assert [r.id for r in rec.recommendations] == ["r.R1"]
    assert rec.recommendations[0].status == "candidate" and rec.recommendations[0].validation == "not evaluated"
    assert rec.recommendations[0].narrative is None and rec.recommendations[0].narrative_source == "rules"
    assert narrative.calls == []                       # settings None -> no LLM call
    assert any("No LLM narrative was requested" in lim for lim in rec.limitations)

    rec2 = run_campaign(base_config(), sink, narrative_settings=object())
    assert len(narrative.calls) == 1 and narrative.calls[0][0] == "clean 9/16"
    assert rec2.recommendations[0].narrative_source == "llm" and rec2.recommendations[0].narrative
    assert any(n_.startswith("LLM narrative is nondeterministic") for n_ in rec2.provenance.nondeterminism)


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
    for var in ("PYTHIA_BASE_URL", "PYTHIA_API_KEY", "REDSIM_LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setitem(sys.modules, EXPLAIN_MOD, None)
    monkeypatch.setitem(sys.modules, RULES_MOD, make_fake_rules())
    rec = run_campaign(base_config(llm_narrative=True), sink, explain=False)
    assert any("Pythia is not configured" in lim for lim in rec.limitations)
    assert rec.recommendations[0].narrative_source == "rules"


# --- severity derivation on a larger slice ----------------------------------------------------------

def test_severity_is_derived_from_first_success_and_asr(no_optional_modules, sink):
    rec = run_campaign(base_config(attack_ids=["fgsm"], n_samples=48, params={}), sink, explain=False)
    clean = rec.measurements[0]
    assert clean.n_correct >= 10, "slice must clear the denominator guard for this test"
    rows = {m.params["eps"]: m for m in rec.measurements if m.family == "evasion"}
    table = {e: {"asr": m.n_flipped_from_clean / clean.n_correct} for e, m in rows.items()}
    fs_eps, fs_asr = first_success(table)
    assert fs_eps is not None, "FGSM must cross the 0.2 ASR threshold somewhere on the brittle model"
    expected = severity_for("fgsm", fs_eps, fs_asr, *eps_bands([0.01, 0.03, 0.1], 0.03))
    for e, m in rows.items():
        if table[e]["asr"] >= 0.2:
            assert m.severity == expected
            assert any("derived per spec 15.5" in n_ for n_ in m.notes)
        else:
            assert m.severity is None
    assert rec.attack is not None and rec.attack.id == "fgsm"


# --- hopskipjump in the campaign: eps thresholding ---------------------------------------------------

def test_hopskipjump_rows_are_thresholded_against_the_grid(no_optional_modules, sink):
    cfg = base_config(attack_ids=["hopskipjump"], n_samples=10,
                      params={"max_iter": 1, "max_eval": 100, "init_eval": 10, "init_size": 3})
    rec = run_campaign(cfg, sink, explain=False)
    rows = [m for m in rec.measurements if m.family == "evasion"]
    assert [m.id for m in rows] == [f"m.evasion.hopskipjump.eps{e}" for e in ("0.01", "0.03", "0.1")]
    for m in rows:
        assert m.linf_norm_mean <= m.params["eps"] + 1e-6
        assert any(n_.startswith("thresholded at eps=") for n_ in m.notes)
        assert any(n_.startswith("queries_mean = ") for n_ in m.notes)
    assert rec.atlas_coverage == ["AML.T0040"]
    assert any("black-box attack hopskipjump" in lim for lim in rec.limitations)
    assert any(n_.startswith("HopSkipJump random initial adversarial point") for n_ in rec.provenance.nondeterminism)


# --- configuration errors and options ------------------------------------------------------------------

def test_single_attack_id_form_and_control_toggle(no_optional_modules, sink):
    rec = run_campaign(base_config(attack_ids=[], attack_id="fgsm", include_control=False, params={}), sink,
                       explain=False)
    assert rec.attack.id == "fgsm" and rec.config.attack_id == "fgsm"
    assert not any(m.family == "control" for m in rec.measurements)
    assert "control" not in rec.stages_done
    assert any("noise control was disabled" in lim for lim in rec.limitations)


@pytest.mark.parametrize("overrides,exc", [
    ({"target_id": "nope"}, TargetUnavailable),
    ({"attack_ids": ["zoo"]}, AttackNotApplicable),
    ({"attack_ids": ["noise_control"]}, AttackNotApplicable),
    ({"attack_ids": [], "attack_id": None}, ValueError),
    ({"reference_eps": 0.05}, ValueError),
    ({"params": {"max_iter": 3, "bogus": 1}}, ValueError),
    ({"params": {"max_iter": 99}}, ValueError),
    ({"eps_grid": [0.03, -0.1], "reference_eps": 0.03}, ValueError),
])
def test_configuration_errors_raise_before_running(no_optional_modules, sink, overrides, exc):
    with pytest.raises(exc):
        run_campaign(base_config(**overrides), sink, explain=False)


def test_defense_without_defenses_module_refuses_to_run_undefended(no_optional_modules, monkeypatch, sink):
    monkeypatch.setitem(sys.modules, "redsim.ml.defenses", None)
    with pytest.raises(MLError):
        run_campaign(base_config(defense={"id": "feature_squeezing", "params": {}}), sink, explain=False)


def test_defense_is_applied_through_apply_defense(no_optional_modules, monkeypatch, sink):
    defenses = types.ModuleType("redsim.ml.defenses")
    seen = {}

    def apply_defense(target, defense_id, params):
        seen["args"] = (target.id, defense_id, params)
        return target

    defenses.apply_defense = apply_defense
    monkeypatch.setitem(sys.modules, "redsim.ml.defenses", defenses)
    rec = run_campaign(base_config(defense={"id": "spatial_smoothing", "params": {"window_size": 3}}), sink,
                       explain=False)
    assert seen["args"] == ("tiny", "spatial_smoothing", {"window_size": 3})
    assert any("straight-through gradient estimate" in lim for lim in rec.limitations)
