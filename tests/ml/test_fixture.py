"""``tests/ml/fixtures/run_record.json`` is the ``GET /v1/runs/{id}/campaign`` shape the web tests render.

It is a test double built through the schema models. Its target is named so
a screenshot can never pass as a real model, and every number is illustrative.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redsim.ml import schema as S

FIXTURE = Path(__file__).parent / "fixtures" / "run_record.json"


@pytest.fixture(scope="module")
def payload() -> dict:
    return json.loads(FIXTURE.read_text())


@pytest.fixture(scope="module")
def record(payload) -> S.CampaignRecord:
    return S.CampaignRecord.model_validate(payload)


def test_fixture_validates_and_round_trips(payload, record):
    # exclude_unset: Phase B default-valued fields (schema_version, edit_fraction_mean, ...)
    # never appear in the old-record view; the frozen fixture stays byte-identical.
    assert record.model_dump(mode="json", exclude_unset=True) == payload


def test_fixture_is_labelled_as_a_test_double(record):
    assert record.target.name == "Tiny random CNN (test double)"
    assert any("FIXTURE" in s and "illustrative" in s for s in record.limitations)
    assert "Illustrative" in (record.score.reading or "")


def test_fixture_config(record):
    cfg = record.config
    assert cfg.attack_ids == ["fgsm", "pgd"]
    assert cfg.eps_grid == [0.01, 0.03, 0.1]
    assert cfg.reference_eps in cfg.eps_grid
    assert cfg.finding_asr_threshold == 0.2
    assert cfg.scoring.weights == S.MRIWeights()


def test_fixture_has_every_panel(record):
    assert len(record.attacks) == 2 and record.provenance is not None
    fam = {m.family for m in record.measurements}
    assert fam == {"clean", "evasion", "control"}
    assert all(m.n > 0 and m.n_correct <= m.n for m in record.measurements)
    # 1 clean + 2 attacks x 3 eps + 3 control rows (spec 14.2)
    assert len(record.measurements) == 1 + 6 + 3
    assert {c.attack_id for c in record.curve} == {"fgsm", "pgd"}
    assert all(len(c.points) == 3 and len(c.control) == 3 for c in record.curve)
    assert record.observations and all(o.metric_kind == "heuristic" for o in record.observations)
    assert all(o.center_mass_ratio_clean is not None for o in record.observations)
    assert record.interpretation and all(i.kind == "inferred" for i in record.interpretation)
    assert record.recommendations
    assert all(r.status == "candidate" and r.validation == "not evaluated" and r.measured is None
               for r in record.recommendations)
    assert record.limitations
    assert record.completeness == "complete" and record.missing == []


def test_fixture_score_is_complete(record):
    score = record.score
    assert score is not None and record.score_status is None
    assert score.mri is not None and score.grade == S.grade_for_mri(score.mri)
    assert score.subscores.missing() == []
    assert set(score.per_attack) == set(score.attack_ids) == {"fgsm", "pgd"}
    assert len(score.inputs) == 6 and all(r.n > 0 and r.n_correct_clean for r in score.inputs)
    assert score.eps_grid == record.config.eps_grid and score.reference_eps == record.config.reference_eps
    assert score.reading and not S.contains_banned_score_word(score.reading)
    assert score.delta is None


def test_fixture_asr_denominators_are_the_clean_row(record):
    clean = next(m for m in record.measurements if m.family == "clean")
    for m in record.measurements:
        if m.family == "evasion":
            assert m.n_clean_correct == clean.n_correct
            assert m.attack_success_rate == round(m.n_flipped_from_clean / clean.n_correct, 4)
