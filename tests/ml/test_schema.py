"""Contract tests for the frozen M0 evidence model (``redsim/ml/schema.py``).

Offline, no ``ml`` extra: these tests never import torch, ART or SHAP.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from redsim.ml import schema as S

T = datetime(2026, 9, 8, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures" / "run_record.json"

#: The ``STAGES`` tuple at the P0 freeze: the Phase A pipeline in order.
P0_STAGES = ("load_target", "sample", "clean_eval", "attack", "control", "explain", "score",
             "interpret", "recommend", "report")


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


def test_stages_are_the_p0_order_without_a_defense_stage():
    # 2026-09-09: the verify paradigm left; ``defense_apply`` is gone and the P0 order stands.
    assert S.STAGES == P0_STAGES and "defense_apply" not in S.STAGES
    assert len(S.STAGES) == len(set(S.STAGES))


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


def test_recommendation_is_a_candidate_and_nothing_more():
    rec = S.CandidateRecommendation(id="r.1", title="t", rationale="r", triggered_by=["m.clean"])
    assert rec.status == "candidate" and rec.narrative is None and rec.narrative_source == "rules"
    fields = set(S.CandidateRecommendation.model_fields)
    assert fields == {"id", "title", "rationale", "triggered_by", "status", "references", "narrative",
                      "narrative_source"}
    assert not {f for f in fields if "gain" in f or "expected" in f or "valid" in f or "measured" in f}
    for removed in ("validation", "measured", "expected_gain"):
        assert removed not in S.CandidateRecommendation.model_json_schema()["properties"]
    for name in ("DefenseConfig", "MeasuredDelta", "MRIDelta", "FamilyDelta", "CleanAccuracyDelta", "FindingVerify",
                 "DerivedFrom"):
        assert not hasattr(S, name), name


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
    assert d.family == "evasion" and d.review.state == "unreviewed"
    assert d.atlas_technique is None
    assert d.review.history == [] and d.review.revisions == []
    assert "verify" not in S.MLFindingDetail.model_fields and "retests" not in S.MLFindingDetail.model_fields


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


# --- Phase B additions (plan 12 section 3): additive, default-valued -----------------------
#
# Every field below landed after the P0 freeze under plan 01 section 8. The frozen fixture
# ``tests/ml/fixtures/run_record.json`` is never edited: it must validate as a CampaignRecord
# and, viewed with ``exclude_unset``, dump back byte-for-byte.

#: ``(model, field)`` for every Phase B field on a frozen model. Each must have a default.
PHASE_B_FIELDS = (
    (S.Measurement, "edit_fraction_mean"), (S.Measurement, "detection"),
    (S.Observation, "text"), (S.Observation, "detection"),
    (S.MLModelManifest, "text"), (S.MLModelManifest, "detection"),
    (S.MLModelManifest, "endpoint"),
    (S.FindingReview, "history"), (S.FindingReview, "revisions"),
    (S.CampaignRecord, "schema_version"),
    (S.RunSummary, "kind"), (S.RunSummary, "probe_ids"),
)

#: The ``MLModelManifest`` field set at the P0 freeze, the keys a Phase A manifest dump carries.
P0_MANIFEST_KEYS = frozenset({
    "name", "modality", "format", "sha256", "size_bytes", "architecture_id", "input_shape", "n_classes",
    "class_names", "features", "surrogate", "dataset_id", "dataset_revision", "dataset_split",
    "clean_accuracy", "status", "refusal_reason", "gradients", "bundled", "license", "source_url",
    "manifest_sha256",
})


def _manifest(**over):
    base = {"name": "n", "modality": "image", "format": "onnx", "sha256": "a" * 64, "size_bytes": 1,
            "n_classes": 3, "dataset_id": "d"}
    base.update(over)
    return S.MLModelManifest(**base)


def _observation(**over):
    base = {"id": "o.000", "sample_index": 0, "true_label": "a", "pred_clean": "a", "pred_adv": "b",
            "flipped": True, "confidence_clean": 0.9, "confidence_adv": 0.6, "artifacts": {}}
    base.update(over)
    return S.Observation(**base)


def _endpoint(**over):
    base = {"url_host": "models.example.invalid:8443", "auth_profile_id": "ap-1", "contract_version": "endpoint-v1",
            "input_shape": [3, 32, 32]}
    base.update(over)
    return S.EndpointSpec(**base)


def test_every_phase_b_field_has_a_default():
    for model, name in PHASE_B_FIELDS:
        assert not model.model_fields[name].is_required(), f"{model.__name__}.{name} was added without a default"


def test_frozen_fixture_validates_unchanged_with_phase_b_defaults():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    record = S.CampaignRecord.model_validate(payload)
    assert record.schema_version == "campaign-record-1"
    assert all(m.edit_fraction_mean is None and m.detection is None for m in record.measurements)
    assert all(o.text is None and o.detection is None for o in record.observations)
    assert record.model_dump(mode="json", exclude_unset=True) == payload
    # The full dump adds only the Phase B keys, each at its default.
    full = record.model_dump(mode="json")
    assert set(full) - set(payload) == {"schema_version"}
    assert all(set(m) - set(p) == {"edit_fraction_mean", "detection"}
               for m, p in zip(full["measurements"], payload["measurements"], strict=True))
    assert all(set(o) - set(p) == {"text", "detection"}
               for o, p in zip(full["observations"], payload["observations"], strict=True))


def test_modality_literals_accept_text_and_detection():
    assert _config(modality="text", norm="edit").modality == "text"
    assert _config(modality="detection", norm="patch_area").modality == "detection"
    assert _manifest(modality="text", format="sklearn_joblib").modality == "text"
    assert _manifest(modality="detection", format="torch_state_dict", architecture_id="fasterrcnn").modality
    assert S.TargetInfo(id="t", name="n", domain="text", status="available").domain == "text"
    assert S.AttackInfo(id="dpatch", name="DPatch", domain="detection", family="evasion").domain == "detection"
    with pytest.raises(ValidationError):
        _config(modality="audio")
    with pytest.raises(ValidationError):
        S.TargetInfo(id="t", name="n", domain="audio", status="available")


def test_norm_literals_edit_and_patch_area():
    for norm in ("linf", "l2", "edit", "patch_area"):
        cfg = _config(norm=norm)
        assert cfg.norm == norm
        assert _score(norm=norm).norm == norm
        curve = S.RobustnessCurve(attack_id="a", norm=norm, eps_grid=[0.1], reference_eps=0.1,
                                  clean=S.AccuracyPoint(n=10, n_correct=8, accuracy=0.8))
        assert curve.norm == norm
        detail = S.MLFindingDetail(attack_id="a", attack_name="A", norm=norm, eps_grid=[0.1],
                                   reference_eps=0.1, threshold=0.2)
        assert detail.norm == norm
    with pytest.raises(ValidationError):
        _config(norm="l1")


def test_measurement_detection_block_optional():
    row = _measurement()
    assert row.edit_fraction_mean is None and row.detection is None
    assert "detection" not in row.model_dump(exclude_unset=True)
    text = _measurement("m.evasion.word_substitution.eps0.2", "evasion", attack_id="word_substitution",
                        params={"eps": 0.2, "norm": "edit"}, edit_fraction_mean=0.17)
    assert text.edit_fraction_mean == 0.17
    det = _measurement("m.evasion.dpatch.eps0.05", "evasion", attack_id="dpatch", n=120, n_correct=84, accuracy=0.7,
                       n_clean_correct=110, n_flipped_from_clean=26, attack_success_rate=round(26 / 110, 4),
                       detection=S.DetectionMetrics(n_boxes=120, n_matched=84, map50=0.61, recall=0.7,
                                                    suppression_rate=round(26 / 110, 4)))
    assert det.detection is not None and det.detection.n_boxes == det.n
    assert S.Measurement.model_validate(det.model_dump(mode="json")) == det
    assert S.DetectionMetrics().model_dump() == {"n_boxes": None, "n_matched": None, "map50": None,
                                                 "recall": None, "suppression_rate": None}
    with pytest.raises(ValidationError):
        S.DetectionMetrics(recall=1.5)


def test_observation_text_and_detection_blocks_optional():
    o = _observation()
    assert o.text is None and o.detection is None and "text" not in o.model_dump(exclude_unset=True)
    text = S.TextObservation(n_tokens=12, n_changed=2, changed_positions=[3, 9], edit_fraction=round(2 / 12, 4),
                             top_tokens_clean=[3, 0, 9], top_tokens_adv=[9, 3, 1],
                             attribution_artifacts={"shap_text": "art-7"})
    with_text = _observation(text=text, artifacts={"text_diff": "art-8"},
                             metric_note="expl_shift over positional token attributions")
    assert S.Observation.model_validate(with_text.model_dump(mode="json")) == with_text
    assert with_text.text is not None and with_text.text.n_changed == 2
    with pytest.raises(ValidationError, match="n_changed"):
        S.TextObservation(n_tokens=3, n_changed=4)
    det = S.DetectionObservation(n_gt=5, n_matched_clean=5, n_matched_adv=2, patch_bbox=[10, 10, 42, 42])
    with_det = _observation(detection=det, metric_note="no attribution metric; the observation is the box table")
    assert S.Observation.model_validate(with_det.model_dump(mode="json")) == with_det
    with pytest.raises(ValidationError):
        S.DetectionObservation(n_gt=5, n_matched_clean=5, n_matched_adv=2, patch_bbox=[10, 10, 42])


def test_model_manifest_text_and_detection_blocks():
    plain = _manifest()
    assert plain.text is None and plain.detection is None and plain.endpoint is None
    assert "derived_from" not in S.MLModelManifest.model_fields
    text = _manifest(modality="text", format="sklearn_joblib", text=S.TextModelSpec(
        token_pattern=r"(?u)\b\w\w+\b", lowercase=True, ngram_range=[1, 2], vocabulary_size=8000, max_words=64))
    assert S.MLModelManifest.model_validate(text.model_dump(mode="json")) == text
    assert text.model_dump(mode="json")["text"]["ngram_range"] == [1, 2]
    det = _manifest(modality="detection", format="torch_state_dict", architecture_id="fasterrcnn_mobilenet",
                    detection=S.DetectionModelSpec(input_size=[320, 320], iou_threshold=0.5, score_threshold=0.3,
                                                   classes=["tank", "truck", "apc"], excluded_classes=["person"]))
    assert S.MLModelManifest.model_validate(det.model_dump(mode="json")) == det
    with pytest.raises(ValidationError):
        S.TextModelSpec(ngram_range=[1])
    with pytest.raises(ValidationError):
        S.DetectionModelSpec(iou_threshold=0.0)


def test_endpoint_manifest_round_trip_and_rules():
    m = _manifest(format="endpoint", sha256="e" * 64, size_bytes=0, gradients=False, endpoint=_endpoint())
    assert S.MLModelManifest.model_validate(m.model_dump(mode="json")) == m
    assert m.model_dump(mode="json")["endpoint"]["url_host"] == "models.example.invalid:8443"
    with pytest.raises(ValidationError, match="requires an endpoint block"):
        _manifest(format="endpoint", size_bytes=0)
    with pytest.raises(ValidationError, match="requires format 'endpoint'"):
        _manifest(format="onnx", endpoint=_endpoint())
    with pytest.raises(ValidationError, match="no gradients"):
        _manifest(format="endpoint", size_bytes=0, gradients=True, endpoint=_endpoint())
    for bad in ("https://models.example.invalid", "models.example.invalid/predict", "user@host", "host?x=1", ""):
        with pytest.raises(ValidationError, match="url_host"):
            _endpoint(url_host=bad)
    with pytest.raises(ValidationError):
        _endpoint(batch_rows=0)
    with pytest.raises(ValidationError):
        _endpoint(timeout_s=0)


def test_endpoint_contract_version_is_the_contract_modules_constant():
    contract = pytest.importorskip("redsim.ml.targets.endpoint_contract")
    spec = _endpoint(contract_version=contract.CONTRACT_VERSION)
    assert spec.contract_version == contract.CONTRACT_VERSION


def test_phase_a_manifest_dump_and_digest_are_unchanged():
    """The four Phase B blocks are omitted while None, so ``manifest_sha256`` of every manifest written
    before Phase B is unchanged (redsim.ml.assets.manifest.manifest_digest is the sha256 of this dump)."""
    from redsim.ml.assets.manifest import manifest_digest

    plain = _manifest(manifest_sha256=None)
    dump = plain.model_dump(mode="json")
    assert set(dump) == P0_MANIFEST_KEYS
    assert set(plain.model_dump()) == P0_MANIFEST_KEYS and "endpoint" not in plain.model_dump_json()
    canonical = json.dumps({k: v for k, v in dump.items() if k != "manifest_sha256"},
                           sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert manifest_digest(plain) == hashlib.sha256(canonical).hexdigest()
    # A block that is set travels, and the model's JSON schema still lists every property.
    with_block = _manifest(format="endpoint", size_bytes=0, gradients=False, endpoint=_endpoint())
    assert set(with_block.model_dump(mode="json")) == P0_MANIFEST_KEYS | {"endpoint"}
    assert manifest_digest(with_block) != manifest_digest(plain)
    props = set(S.MLModelManifest.model_json_schema()["properties"])
    assert props == P0_MANIFEST_KEYS | {"text", "detection", "endpoint"}
    assert set(S.MLModelManifest.model_json_schema(mode="serialization")["properties"]) == props


def test_review_vocabulary_is_additive():
    old_blob = {"attack_id": "pgd", "attack_name": "PGD", "norm": "linf", "eps_grid": [0.01, 0.03, 0.1],
                "reference_eps": 0.03, "threshold": 0.2,
                "review": {"state": "dismissed", "reviewer": "user:reviewer", "reason": "duplicate", "at": None,
                           "notes": None}}
    detail = S.MLFindingDetail.model_validate(old_blob)
    assert detail.review.state == "dismissed" and detail.review.history == [] and detail.review.revisions == []
    assert detail.model_dump(mode="json", exclude_unset=True) == old_blob
    for state in ("unreviewed", "dismissed", "draft", "in_review", "confirmed", "resolved"):
        assert S.FindingReview(state=state).state == state
    with pytest.raises(ValidationError):
        S.FindingReview(state="approved")
    event = S.ReviewEvent(action="confirm", from_state="in_review", to_state="confirmed", actor="user:reviewer",
                          at=T, reason="reproduced on the retest", revision=2)
    revision = S.FindingRevision(revision=2, author="user:analyst", created_at=T, submitted_at=T,
                                 evidence_ids=["m.evasion.pgd.eps0.03", "o.003"], observation="obs",
                                 interpretation="interp", candidate="cand", sha256="c" * 64)
    review = S.FindingReview(state="confirmed", reviewer="user:reviewer", at=T, history=[event], revisions=[revision])
    assert S.FindingReview.model_validate(review.model_dump(mode="json")) == review
    with pytest.raises(ValidationError):
        S.ReviewEvent(action="x", to_state="approved", actor="a", at=T)
    with pytest.raises(ValidationError):
        S.FindingRevision(revision=0, author="a", created_at=T)


def test_campaign_record_schema_version_defaults_and_is_disclosed():
    base = {"run_id": "r", "status": "running", "created_at": T, "config": _config(), "target": _target(),
            "score_status": S.ScoreStatus(state="pending")}
    rec = S.CampaignRecord(**base)
    assert rec.schema_version == S.CAMPAIGN_RECORD_SCHEMA_VERSION == "campaign-record-1"
    assert rec.model_dump(mode="json")["schema_version"] == "campaign-record-1"
    assert S.CampaignRecord(**base, schema_version="campaign-record-1").schema_version == "campaign-record-1"
    assert "schema_version" not in S.RunRecord.model_fields


def test_run_summary_kind_and_probe_ids_optional():
    plain = S.RunSummary(run_id="r", status="queued", stage=None, target_id="t", attack_ids=["fgsm"], created_at=T)
    assert plain.kind is None and plain.probe_ids == []
    assert plain.model_dump(mode="json", exclude_unset=True) == {
        "run_id": "r", "status": "queued", "stage": None, "target_id": "t", "attack_ids": ["fgsm"],
        "created_at": "2026-09-08T00:00:00Z"}
    probe = S.RunSummary(run_id="r", status="queued", stage=None, target_id="t", attack_ids=[], created_at=T,
                         kind="llm_probe", probe_ids=["dan.Dan_11_0", "encoding.InjectBase64"])
    assert probe.kind == "llm_probe" and len(probe.probe_ids) == 2
    for kind in ("attack", "ingest"):
        assert S.RunSummary(run_id="r", status="queued", stage=None, target_id="t", attack_ids=["fgsm"],
                            created_at=T, kind=kind).kind == kind
    with pytest.raises(ValidationError):
        S.RunSummary(run_id="r", status="queued", stage=None, target_id="t", attack_ids=["fgsm"], created_at=T,
                     kind="verify")
    with pytest.raises(ValidationError):
        S.RunSummary(run_id="r", status="queued", stage=None, target_id="t", attack_ids=[], created_at=T,
                     kind="campaign")
