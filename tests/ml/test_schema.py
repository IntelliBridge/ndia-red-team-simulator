"""Contract tests for the frozen M0 evidence model (``redsim/ml/schema.py``).

Offline, no ``ml`` extra: these tests never import torch, ART or SHAP.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from redsim.ml import schema as S

T = datetime(2026, 9, 8, tzinfo=UTC)


def _config(**over):
    base = {"target_id": "t", "modality": "image", "attack_ids": ["fgsm", "pgd"],
            "eps_grid": [0.01, 0.03, 0.1], "reference_eps": 0.03, "dataset_id": "fixture/x"}
    base.update(over)
    return S.CampaignConfig(**base)


def _target():
    return S.TargetInfo(id="tiny", name="Tiny random CNN (test double)", domain="image", status="available")


def _measurement(mid="m.clean", family="clean", **over):
    base = {"id": mid, "family": family, "n": 10, "n_correct": 8, "accuracy": 0.8}
    base.update(over)
    return S.Measurement(**base)


def _score(**over):
    base = {"scoring_version": "mri-1", "weights": S.MRIWeights(), "eps_grid": [0.01, 0.03, 0.1],
            "reference_eps": 0.03, "norm": "linf", "attack_ids": ["fgsm"], "finding_asr_threshold": 0.2,
            "settings_hash": "h" * 64, "completeness": "complete", "computed_at": T,
            "subscores": S.Subscores(S_acc=50.0, S_asr=50.0, S_eps=50.0, S_conf=50.0, S_expl=50.0),
            "mri": 50, "grade": "D"}
    base.update(over)
    return S.MRIRecord(**base)


# --- STAGES and constants ----------------------------------------------------

def test_stages_has_score_after_explain():
    assert "score" in S.STAGES
    assert S.STAGES.index("score") == S.STAGES.index("explain") + 1
    assert S.STAGES[-1] == "report"


def test_run_status_carries_cancelled_and_not_implemented():
    assert S.RunRecord(run_id="r", status="cancelled", created_at=T, config=_config(), target=_target())
    assert S.RunRecord(run_id="r", status="not_implemented", created_at=T, config=_config(), target=_target())


# --- CampaignConfig -----------------------------------------------------------

def test_campaign_config_round_trip_and_defaults():
    cfg = _config()
    assert cfg.norm == "linf" and cfg.n_samples == 200 and cfg.explain_k == 8
    assert cfg.finding_asr_threshold == 0.2 and cfg.auto_recommend is True and cfg.llm_narrative is False
    again = S.CampaignConfig.model_validate(cfg.model_dump(mode="json"))
    assert again == cfg


@pytest.mark.parametrize("grid", [[], [0.03, 0.01], [0.01, 0.01], [0.0, 0.03], [0.03, 1.5]])
def test_campaign_config_rejects_bad_grids(grid):
    with pytest.raises(ValidationError):
        _config(eps_grid=grid, reference_eps=grid[0] if grid else 0.03)


def test_campaign_config_reference_must_be_in_grid():
    with pytest.raises(ValidationError, match="reference_eps"):
        _config(reference_eps=0.05)


def test_campaign_config_needs_an_attack_and_known_params():
    with pytest.raises(ValidationError):
        _config(attack_ids=[])
    with pytest.raises(ValidationError, match="attack_params"):
        _config(attack_params={"cw": {"c": 1.0}})


def test_campaign_config_sample_bounds():
    with pytest.raises(ValidationError):
        _config(n_samples=5)
    with pytest.raises(ValidationError):
        _config(explain_k=33)


# --- ScoringConfig and weights -----------------------------------------------

def test_scoring_weights_default_vector_sums_to_one():
    w = S.MRIWeights()
    assert (w.acc, w.asr, w.eps, w.conf, w.expl) == (0.35, 0.25, 0.20, 0.10, 0.10)
    assert abs(sum(w.as_dict().values()) - 1.0) < 1e-9
    with pytest.raises(ValidationError, match="sum to 1.0"):
        S.MRIWeights(acc=0.5)


def test_scoring_config_defaults_match_spec():
    sc = S.ScoringConfig()
    assert sc.version == "mri-1"
    assert (sc.severity.asr_high, sc.severity.asr_mid) == (0.5, 0.2)
    assert (sc.confidence.n_high, sc.confidence.n_medium) == (100, 30)
    it = sc.interpretation
    assert (it.evasion_drop, it.control_tolerance, it.control_drop) == (0.20, 0.05, 0.10)
    assert (it.iterative_margin, it.center_mass_drop, it.expl_shift_high, it.conf_gap_high) == (0.10, 0.15, 0.5, 0.5)


# --- Literals are the contract ----------------------------------------------

def test_literal_labels_cannot_be_forged():
    with pytest.raises(ValidationError):
        S.Observation(id="o.000", sample_index=0, true_label="a", pred_clean="a", pred_adv="b", flipped=True,
                      confidence_clean=0.9, confidence_adv=0.6, artifacts={}, metric_kind="measured")
    with pytest.raises(ValidationError):
        S.Interpretation(id="i.1", statement="x", basis=["m.clean"], kind="observed")
    with pytest.raises(ValidationError):
        S.CandidateRecommendation(id="r.1", title="t", rationale="r", triggered_by=["m.clean"], status="validated")


def test_basis_and_triggered_by_need_at_least_one_id():
    with pytest.raises(ValidationError):
        S.Interpretation(id="i.1", statement="x", basis=[])
    with pytest.raises(ValidationError):
        S.CandidateRecommendation(id="r.1", title="t", rationale="r", triggered_by=[])


def test_recommendation_measured_pairs_with_validation():
    delta = S.MeasuredDelta(
        verify_run_id="v", baseline_run_id="b", defense=S.DefenseConfig(id="feature_squeezing"),
        delta_mri=7, delta_acc_clean=S.CleanAccuracyDelta(
            before=S.AccuracyPoint(n=10, n_correct=8, accuracy=0.8),
            after=S.AccuracyPoint(n=10, n_correct=7, accuracy=0.7), delta=-0.1),
        settings_hash="h" * 64, measured_at=T)
    ok = S.CandidateRecommendation(id="r.1", title="t", rationale="r", triggered_by=["m.clean"],
                                   validation="measured", measured=delta)
    assert ok.status == "candidate"
    with pytest.raises(ValidationError, match="requires a measured block"):
        S.CandidateRecommendation(id="r.1", title="t", rationale="r", triggered_by=["m.clean"],
                                  validation="measured")
    with pytest.raises(ValidationError, match="requires validation 'measured'"):
        S.CandidateRecommendation(id="r.1", title="t", rationale="r", triggered_by=["m.clean"], measured=delta)


def test_recommendation_has_no_expected_gain_field():
    fields = set(S.CandidateRecommendation.model_fields)
    assert not {f for f in fields if "gain" in f or "expected" in f}


# --- Measurement additions ---------------------------------------------------

def test_measurement_carries_scoring_inputs_and_string_params():
    m = _measurement("m.evasion.pgd.eps0.03", "evasion", attack_id="pgd",
                     params={"eps": 0.03, "norm": "linf", "max_iter": 10},
                     n_flipped_from_clean=3, n_clean_correct=8, attack_success_rate=0.375,
                     pert_first_success_mean=0.02, pert_first_success_n=3, conf_gap_mean=0.4, conf_gap_n=10,
                     expl_shift_mean=0.5, expl_shift_n=6, queries_mean=None)
    assert m.params["norm"] == "linf"
    assert S.Measurement.model_validate(m.model_dump(mode="json")) == m


def test_observation_additions_default_empty():
    o = S.Observation(id="o.000", sample_index=0, true_label="a", pred_clean="a", pred_adv="b", flipped=True,
                      confidence_clean=0.9, confidence_adv=0.6, artifacts={"input_clean": "art-1"})
    assert o.expl_shift is None and o.top_features_clean == [] and o.metric_kind == "heuristic"


# --- MRIRecord ----------------------------------------------------------------

def test_mri_record_round_trip():
    rec = _score()
    assert S.MRIRecord.model_validate(rec.model_dump(mode="json")) == rec


def test_mri_requires_all_five_subscores_and_matching_grade():
    with pytest.raises(ValidationError, match="missing"):
        _score(subscores=S.Subscores(S_acc=50.0, S_asr=50.0, S_eps=50.0, S_conf=50.0), mri=50, grade="D")
    with pytest.raises(ValidationError, match="does not match"):
        _score(grade="A")
    with pytest.raises(ValidationError, match="partial"):
        _score(completeness="partial")


def test_partial_score_record_has_no_mri_and_names_missing():
    rec = _score(mri=None, grade=None, completeness="partial",
                 subscores=S.Subscores(S_acc=50.0, S_asr=50.0, S_eps=50.0, S_conf=50.0),
                 missing=["S_expl unavailable (explain stage absent)"])
    assert rec.mri is None and rec.grade is None
    with pytest.raises(ValidationError, match="name what is missing"):
        _score(mri=None, grade=None, completeness="partial", missing=[])
    with pytest.raises(ValidationError, match="grade without mri"):
        _score(mri=None, grade="F", completeness="partial", missing=["x"])


@pytest.mark.parametrize("word", ["hardened", "Deployment-ready", "certified", "safe", "harden before fielding"])
def test_reading_rejects_banned_readiness_words(word):
    with pytest.raises(ValidationError, match="banned"):
        _score(reading=f"The model is {word} under these attacks.")


def test_reading_allows_unsafe_as_a_different_word():
    # "unsafe" is not the banned whole word "safe".
    assert _score(reading="Inputs outside the declared range are unsafe to assume.").reading


def test_grade_bands():
    assert [S.grade_for_mri(v) for v in (100, 90, 89, 75, 74, 60, 59, 40, 39, 0)] == list("AABBCCDDFF")


# --- MLModelManifest ------------------------------------------------------------

def test_model_manifest_accepts_spec_field_set():
    m = S.MLModelManifest(
        name="URL maliciousness classifier", modality="tabular", format="sklearn_joblib", sha256="a" * 64,
        size_bytes=1234, input_shape=[16], n_classes=2, class_names=["benign", "malicious"],
        features=[S.FeatureSpec(name="url_length", dtype="int", min=4, max=2048, perturbable=True)],
        surrogate=S.SurrogateInfo(kind="mlp", sha256="b" * 64,
                                  agreement_clean=S.AccuracyPoint(n=1000, n_correct=970, accuracy=0.97)),
        dataset_id="kaggle:sid321axn/malicious-urls-dataset", dataset_revision="r1", dataset_split="test",
        clean_accuracy=S.CleanAccuracy(value=0.93, n=1000, split="test"), status="available", gradients=True,
        bundled=True, license="CC0: Public Domain", source_url="https://example.invalid", manifest_sha256="c" * 64)
    assert S.MLModelManifest.model_validate(m.model_dump(mode="json")) == m


def test_model_manifest_consistency_rules():
    base = {"name": "n", "modality": "image", "format": "onnx", "sha256": "a" * 64, "size_bytes": 1,
            "n_classes": 3, "dataset_id": "d"}
    with pytest.raises(ValidationError, match="class_names"):
        S.MLModelManifest(**base, class_names=["a", "b"])
    with pytest.raises(ValidationError, match="architecture_id"):
        S.MLModelManifest(**{**base, "format": "torch_state_dict"})
    with pytest.raises(ValidationError, match="refusal_reason"):
        S.MLModelManifest(**base, status="refused")
    with pytest.raises(ValidationError, match="refusal_reason"):
        S.MLModelManifest(**base, refusal_reason="pickle_refused")
    refused = S.MLModelManifest(**base, status="refused", refusal_reason="pickle_refused")
    assert refused.status == "refused"


# --- MLFindingDetail ---------------------------------------------------------------

def test_finding_detail_defaults():
    d = S.MLFindingDetail(attack_id="pgd", attack_name="PGD", norm="linf", eps_grid=[0.01, 0.03, 0.1],
                          reference_eps=0.03, threshold=0.2)
    assert d.family == "evasion" and d.review.state == "unreviewed" and d.verify is None
    assert d.atlas_technique is None


# --- RunRecord -----------------------------------------------------------------

def test_run_record_rejects_dangling_citations():
    common = {"run_id": "r", "status": "running", "created_at": T, "config": _config(), "target": _target(),
              "measurements": [_measurement()]}
    S.RunRecord(**common, interpretation=[S.Interpretation(id="i.1", statement="s", basis=["m.clean"])])
    with pytest.raises(ValidationError, match="cites unknown ids"):
        S.RunRecord(**common, interpretation=[S.Interpretation(id="i.1", statement="s", basis=["m.nope"])])
    with pytest.raises(ValidationError, match="cites unknown ids"):
        S.RunRecord(**common, recommendations=[
            S.CandidateRecommendation(id="r.1", title="t", rationale="r", triggered_by=["o.999"])])


def test_run_record_may_cite_interpretations():
    rec = S.RunRecord(run_id="r", status="running", created_at=T, config=_config(), target=_target(),
                      measurements=[_measurement()],
                      interpretation=[S.Interpretation(id="i.1", statement="s", basis=["m.clean"])],
                      recommendations=[S.CandidateRecommendation(id="r.1", title="t", rationale="r",
                                                                 triggered_by=["i.1"])])
    assert rec.recommendations[0].triggered_by == ["i.1"]


def test_succeeded_run_needs_limitations():
    with pytest.raises(ValidationError, match="limitations"):
        S.RunRecord(run_id="r", status="succeeded", created_at=T, config=_config(), target=_target())


def test_campaign_record_needs_score_or_score_status():
    base = {"run_id": "r", "status": "running", "created_at": T, "config": _config(), "target": _target()}
    with pytest.raises(ValidationError, match="score_status"):
        S.CampaignRecord(**base)
    rec = S.CampaignRecord(**base, score_status=S.ScoreStatus(state="pending"))
    assert rec.score is None and rec.kind == "attack" and rec.completeness == "partial"
    with pytest.raises(ValidationError, match="mutually exclusive"):
        S.CampaignRecord(**base, score=_score(), score_status=S.ScoreStatus(state="pending"))


# --- Limitations ---------------------------------------------------------------------

def test_standing_limitations_are_parameterised_by_dataset_and_grid():
    lims = S.standing_limitations("CIFAR-10", [0.01, 0.03, 0.1])
    assert lims[0].startswith("CIFAR-10 is an open, unclassified public benchmark")
    assert "ε grid was [0.01, 0.03, 0.1]" in lims[1]
    assert S.standing_limitations("CIFAR-10")[1] == S.SINGLE_BUDGET_LIMITATION
    assert lims[2:] == list(S.STANDING_LIMITATIONS)
    assert not any("CIFAR" in s for s in S.STANDING_LIMITATIONS)
    assert any("deployment readiness" in s for s in S.STANDING_LIMITATIONS)
