"""Contract tests for the redsim evidence model."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from redsim.schema import (
    CandidateRecommendation,
    Interpretation,
    Observation,
    RunConfig,
    RunRecord,
    TargetInfo,
)


def _run(**overrides: object) -> RunRecord:
    values = {
        "run_id": "run_test",
        "status": "succeeded",
        "stage": "report",
        "created_at": datetime(2026, 9, 8, tzinfo=UTC),
        "config": RunConfig(target_id="cifar10", attack_id="fgsm"),
        "target": TargetInfo(
            id="cifar10",
            name="Bundled CIFAR-10 classifier",
            domain="image",
            status="available",
        ),
        "limitations": ["Synthetic fixture; not an operational evaluation."],
    }
    values.update(overrides)
    return RunRecord.model_validate(values)


def test_run_record_round_trips_without_losing_fixed_labels() -> None:
    run = _run(
        observations=[
            Observation(
                id="o.001",
                sample_index=1,
                true_label="cat",
                pred_clean="cat",
                pred_adv="dog",
                flipped=True,
                confidence_clean=0.8,
                confidence_adv=0.7,
                artifacts={},
            )
        ],
        interpretation=[
            Interpretation(id="i.001", statement="An inference", basis=["o.001"])
        ],
        recommendations=[
            CandidateRecommendation(
                id="r.001",
                title="Evaluate a mitigation",
                rationale="Requires a separate experiment.",
                triggered_by=["o.001"],
            )
        ],
    )

    restored = RunRecord.model_validate_json(run.model_dump_json())

    assert restored == run
    assert restored.observations[0].metric_kind == "heuristic"
    assert restored.interpretation[0].kind == "inferred"
    assert restored.recommendations[0].status == "candidate"
    assert restored.recommendations[0].validation == "not evaluated"


@pytest.mark.parametrize("limitations", [[], None])
def test_succeeded_run_requires_a_limitation(limitations: object) -> None:
    with pytest.raises(ValidationError):
        _run(limitations=limitations)


def test_succeeded_run_cannot_omit_limitations() -> None:
    data = _run().model_dump()
    data.pop("limitations")

    with pytest.raises(ValidationError, match="must state its limitations"):
        RunRecord.model_validate(data)


def test_in_progress_run_may_have_no_limitations_yet() -> None:
    assert _run(status="running", limitations=[]).limitations == []


@pytest.mark.parametrize(
    ("model", "field", "invalid", "fixture"),
    [
        (
            Observation,
            "metric_kind",
            "causal",
            {
                "id": "o.001",
                "sample_index": 1,
                "true_label": "cat",
                "pred_clean": "cat",
                "pred_adv": "dog",
                "flipped": True,
                "confidence_clean": 0.8,
                "confidence_adv": 0.7,
                "artifacts": {},
            },
        ),
        (
            Interpretation,
            "kind",
            "measured",
            {"id": "i.001", "statement": "An inference", "basis": ["m.clean"]},
        ),
        (
            CandidateRecommendation,
            "status",
            "approved",
            {
                "id": "r.001",
                "title": "Candidate",
                "rationale": "Requires evaluation.",
                "triggered_by": ["m.clean"],
            },
        ),
        (
            CandidateRecommendation,
            "validation",
            "validated",
            {
                "id": "r.001",
                "title": "Candidate",
                "rationale": "Requires evaluation.",
                "triggered_by": ["m.clean"],
            },
        ),
    ],
)
def test_evidence_labels_cannot_be_overstated(
    model: type, field: str, invalid: str, fixture: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate({**fixture, field: invalid})


@pytest.mark.parametrize("n_samples", [9, 1001])
def test_run_config_rejects_out_of_range_sample_counts(n_samples: int) -> None:
    with pytest.raises(ValidationError):
        RunConfig(target_id="cifar10", attack_id="fgsm", n_samples=n_samples)


@pytest.mark.parametrize("explain_k", [-1, 33])
def test_run_config_rejects_out_of_range_explanation_counts(explain_k: int) -> None:
    with pytest.raises(ValidationError):
        RunConfig(target_id="cifar10", attack_id="fgsm", explain_k=explain_k)