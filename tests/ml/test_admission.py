"""Admission services: audit-before-rows, verify with real rule recommendations, rerun lineage.

Register rows G-API-ATTACKS (audit order, refused rows), G-VER1 (verify admission
matches the defense through ``rules.defense_configs``; ``recommendation_id`` and
``defense`` optional with the spec 16.5 default) and G-API-RERUN (``parent_run_id``
copies the parent configuration and stores the lineage, original untouched).

Offline, on the harness of ``tests/ml/test_campaign_routes.py``. The verify
finding's recommendations are the real output of
``redsim.ml.recommend.rules.recommend`` over synthetic measurements, so the
``defense:<id>`` reference shape the worker writes is what admission reads.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from redsim.api.errors import HTTP_STATUS, ApiError
from redsim.config import RedsimConfig
from redsim.db.models import Artifact, Finding, Job, Run, Target
from redsim.ml.recommend.rules import recommend
from redsim.ml.schema import CampaignRecord, CandidateRecommendation, Measurement, MLFindingDetail
from redsim.services.ml_campaigns import (
    DEFAULT_VERIFY_DEFENSE_ID,
    create_attack_campaign,
    create_verify_campaign,
)
from tests.ml.test_campaign_routes import (
    ACTOR,
    CELERY_TASK_ID,
    DATASET,
    MODEL,
    PROJECT,
    SHA256,
    Harness,
    build_harness,
    launch,
    parent_config,
    seed_campaign_run,
    seed_model,
)

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).parent / "fixtures" / "run_record.json"
GRID = [0.01, 0.03, 0.1]
N_CLEAN_CORRECT = 80


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Harness]:
    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    yield build_harness(tmp_path, monkeypatch, with_api=True)
    rl._BUCKETS.clear()


# --------------------------------------------------------------------------- attack.run order

def test_create_attack_campaign_audits_before_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    harness = build_harness(tmp_path, monkeypatch, with_api=False)
    seed_model(harness)
    seen_at_enqueue: dict[str, Any] = {}

    def observing_delay(job_id: str) -> Any:
        # By the time Celery is touched the audit row and the durable rows both exist.
        seen_at_enqueue["events"] = [(event.action, event.success) for event in harness.writer.events]
        seen_at_enqueue["counts"] = harness.counts()
        harness.delay_calls.append(job_id)
        return type("_Task", (), {"id": CELERY_TASK_ID})()

    monkeypatch.setattr("redsim.workers.tasks.ml_campaign.ml_campaign_run.delay", observing_delay)

    handle = create_attack_campaign(
        campaign={"target_id": MODEL, "attack_ids": ["fgsm", "pgd"], "seed": 3},
        project_id=PROJECT, actor=ACTOR, config=RedsimConfig(), audit_writer=harness.writer,
    )

    assert harness.writer.run_existed_at_append == [False], "the attack.run row precedes the Run row"
    assert seen_at_enqueue["events"] == [("attack.run", True)]
    assert seen_at_enqueue["counts"] == {"runs": 1, "jobs": 1, "campaigns": 1}
    assert harness.delay_calls == handle.job_ids
    with harness.Session() as session:
        run = session.get(Run, handle.run_id)
        job = session.get(Job, handle.job_ids[0])
    assert run is not None and run.status == "queued" and run.scanner == "ml.campaign"
    assert job is not None and job.celery_task_id == CELERY_TASK_ID
    assert job.detail["campaign_config"]["attack_ids"] == ["fgsm", "pgd"]
    assert job.detail["campaign_config"]["seed"] == 3
    assert job.detail["campaign_config"]["eps_grid"] == GRID
    row = harness.campaign_row(handle.run_id)
    assert row is not None and row["kind"] == "attack" and row["target_id"] == MODEL
    event = harness.writer.events[0]
    assert event.action == "attack.run" and event.success and event.run_id == handle.run_id
    assert event.detail["model_sha256"] == SHA256 and event.detail["attack_ids"] == ["fgsm", "pgd"]


def test_create_attack_campaign_refusal_writes_a_failed_row_and_nothing_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = build_harness(tmp_path, monkeypatch, with_api=False)
    seed_model(harness)

    with pytest.raises(ApiError) as excinfo:
        create_attack_campaign(
            campaign={"target_id": MODEL, "attack_ids": ["fgsm", "nope"]},
            project_id=PROJECT, actor=ACTOR, config=RedsimConfig(), audit_writer=harness.writer,
        )

    assert excinfo.value.code == "unknown_attack" and excinfo.value.status == 422
    assert excinfo.value.detail["field"] == "attack_ids"
    assert harness.counts() == {"runs": 0, "jobs": 0, "campaigns": 0} and harness.delay_calls == []
    assert [(e.action, e.success) for e in harness.writer.events] == [("attack.run", False)]
    refused = harness.writer.events[0]
    assert refused.run_id is None and refused.project_id == PROJECT
    assert refused.detail["code"] == "unknown_attack" and refused.detail["target_id"] == MODEL
    assert refused.detail["attack_ids"] == ["fgsm", "nope"]


# --------------------------------------------------------------------------- verify with rule output

def _m(mid: str, family: str, n_correct: int, *, attack: str | None = None, eps: float | None = None,
       flipped: int | None = None, n: int = 100) -> Measurement:
    extra: dict[str, Any] = {}
    if flipped is not None:
        extra = {"n_flipped_from_clean": flipped, "n_clean_correct": N_CLEAN_CORRECT,
                 "attack_success_rate": round(flipped / N_CLEAN_CORRECT, 4)}
    params = {"eps": eps, "norm": "linf"} if eps is not None else {}
    return Measurement(id=mid, family=family, attack_id=attack, params=params, n=n, n_correct=n_correct,
                       accuracy=n_correct / n, notes=[], **extra)


def _degraded() -> list[Measurement]:
    """Clean 80/100, FGSM and PGD degrade across the grid, noise control flat: fires R1, R2, R6, R7."""
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


def _rule_candidates() -> list[CandidateRecommendation]:
    recs = recommend(_degraded(), [], None, modality="image")
    assert {r.id for r in recs} >= {"r.R1", "r.R6", "r.R7"}
    return recs


def seed_verify_baseline(harness: Harness, monkeypatch: pytest.MonkeyPatch, *,
                         baseline_status: str = "succeeded") -> dict[str, str]:
    """The frozen fixture campaign as a succeeded baseline plus two ML findings carrying rule output."""
    record = CampaignRecord.model_validate(json.loads(FIXTURE.read_text()))
    record_bytes = record.model_dump_json().encode()
    measurements = _degraded()
    recs = _rule_candidates()
    findings: dict[str, str] = {}
    with harness.Session.begin() as session:
        session.add(Target(id=record.config.target_id, project_id=PROJECT, kind="ml_model_artifact",
                           value="bundled:tiny", verified=True,
                           detail={"modality": "image", "status": "available", "sha256": SHA256}))
        session.add(Run(id=record.run_id, project_id=PROJECT, scanner="ml.campaign",
                        target_id=record.config.target_id, status=baseline_status, stage_table={}))
        session.flush()
        session.add(Artifact(
            id="artifact-baseline-record", run_id=record.run_id, project_id=PROJECT, kind="ml.run_record",
            sha256=hashlib.sha256(record_bytes).hexdigest(), location="memory://baseline/run_record.json",
            content_type="application/json", size_bytes=len(record_bytes),
        ))
        for attack_id in ("fgsm", "pgd"):
            detail = MLFindingDetail(
                attack_id=attack_id, attack_name=attack_id.upper(), norm="linf", eps_grid=GRID,
                reference_eps=0.03, first_success_eps=0.01, asr_at_reference=0.5, threshold=0.2,
                measurements=[m for m in measurements if m.attack_id == attack_id], recommendations=recs,
            )
            finding_id = f"finding-verify-{attack_id}"
            session.add(Finding(
                id=finding_id, scanner_finding_id=f"ml.{attack_id}", run_id=record.run_id, project_id=PROJECT,
                schema_blob={"ml": detail.model_dump(mode="json")}, status="open", severity="high",
                source_tool=f"redsim.ml/{attack_id}", validation_state="unvalidated",
            ))
            findings[attack_id] = finding_id
        session.execute(harness.campaigns.insert().values(
            run_id=record.run_id, project_id=PROJECT, target_id=record.config.target_id, kind="attack",
            modality="image", config=record.config.model_dump(mode="json"), settings_hash=record.settings_hash,
            provenance=record.provenance.model_dump(mode="json") if record.provenance else None,
            score=record.score.model_dump(mode="json") if record.score else None, limitations=record.limitations,
        ))
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store",
                        lambda: type("_BlobStore", (), {"get": lambda _self, _key: record_bytes})())
    return {"run_id": record.run_id, **findings}


def test_verify_admits_with_real_rule_recommendations(api: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    ids = seed_verify_baseline(api, monkeypatch)
    assert api.client is not None

    # 1. Route, body empty: recommendation_id optional, defense defaults per spec 16.5, 202 JobHandle.
    response = api.client.post(f"/v1/findings/{ids['fgsm']}/verify", json={})
    assert response.status_code == 202, response.text
    body = response.json()
    assert set(body) == {"run_id", "job_ids", "status_url"} and body["status_url"] == f"/v1/runs/{body['run_id']}"
    with api.Session() as session:
        run = session.get(Run, body["run_id"])
        job = session.get(Job, body["job_ids"][0])
        finding = session.get(Finding, ids["fgsm"])
    assert run is not None and run.scanner == "ml.verify" and run.status == "queued"
    assert job is not None and job.type == "verify.replay" and job.celery_task_id == CELERY_TASK_ID
    assert job.detail["recommendation_id"] is None and job.detail["baseline_run_id"] == ids["run_id"]
    defense = job.detail["campaign_config"]["defense"]
    assert defense["id"] == DEFAULT_VERIFY_DEFENSE_ID == "feature_squeezing"
    assert defense["art_class"] == "art.defences.preprocessor.FeatureSqueezing"
    assert defense["params"] == {"bit_depth": 4}, "spec 16.5 default parameters"
    row = api.campaign_row(body["run_id"])
    assert row is not None and row["kind"] == "verify" and row["baseline_run_id"] == ids["run_id"]
    assert row["parent_run_id"] is None
    assert finding is not None and finding.status == "fixing"
    events = api.events("verify.replay")
    assert len(events) == 1 and events[0].success and api.writer.run_existed_at_append == [False]
    assert events[0].detail["defense"]["id"] == "feature_squeezing"
    assert events[0].detail["finding_id"] == ids["fgsm"] and events[0].detail["recommendation_id"] is None

    # 2. Service, on the other finding: the rule-generated R6 cites defense:<id> references and the
    #    requested defense is one of them; the params come from the request.
    handle = create_verify_campaign(
        finding_id=ids["pgd"], defense_id="jpeg_compression", params={"quality": 60},
        recommendation_id="r.R6", actor=ACTOR, config=RedsimConfig(), audit_writer=api.writer,
    )
    with api.Session() as session:
        job = session.get(Job, handle.job_ids[0])
    assert job is not None and job.detail["recommendation_id"] == "r.R6"
    assert job.detail["campaign_config"]["defense"] == {
        "id": "jpeg_compression", "art_class": "art.defences.preprocessor.JpegCompression",
        "params": {"quality": 60},
    }
    assert [event.success for event in api.events("verify.replay")] == [True, True]
    assert api.delay_calls == [body["job_ids"][0], handle.job_ids[0]]


@pytest.mark.parametrize(
    ("finding", "body", "code", "field"),
    [
        pytest.param("fgsm", {"defense": "nope"}, "unknown_defense", "defense", id="unknown_defense"),
        pytest.param("fgsm", {"recommendation_id": "r.R6"}, "params_out_of_range", "defense",
                     id="several_cited_defenses_need_an_explicit_choice"),
        pytest.param("fgsm", {"recommendation_id": "r.R6", "defense": "spatial_smoothing",
                              "params": {"window_size": 99}}, "params_out_of_range", "params",
                     id="defense_param_above_max"),
        pytest.param("fgsm", {"recommendation_id": "r.R7"}, "params_out_of_range", "defense",
                     id="recommendation_names_no_defense"),
        pytest.param("fgsm", {"recommendation_id": "r.R1", "defense": "jpeg_compression"},
                     "params_out_of_range", "defense", id="defense_not_named_by_recommendation"),
        pytest.param("fgsm", {"recommendation_id": "r.R1"}, "not_implemented", "defense",
                     id="adversarial_training_is_phase_b"),
        pytest.param("fgsm", {"recommendation_id": "r.nope"}, "params_out_of_range", "recommendation_id",
                     id="recommendation_not_on_finding"),
    ],
)
def test_verify_refusal_codes(api: Harness, monkeypatch: pytest.MonkeyPatch, finding: str,
                              body: dict[str, Any], code: str, field: str) -> None:
    ids = seed_verify_baseline(api, monkeypatch)
    assert api.client is not None

    response = api.client.post(f"/v1/findings/{ids[finding]}/verify", json=body)

    assert response.status_code == HTTP_STATUS[code], response.text
    detail = response.json()["detail"]
    assert detail["code"] == code and detail["field"] == field
    if code == "not_implemented":
        assert detail["phase"] == "B"
    assert api.counts() == {"runs": 1, "jobs": 0, "campaigns": 1}, "only the baseline remains"
    assert api.delay_calls == []
    with api.Session() as session:
        row = session.get(Finding, ids[finding])
    assert row is not None and row.status == "open"
    events = api.events("verify.replay")
    assert [event.success for event in events] == [False]
    assert events[0].run_id is None and events[0].detail["code"] == code
    assert events[0].detail["finding_id"] == ids[finding]
    assert "campaign_config" not in events[0].detail and "params" not in events[0].detail


def test_verify_job_in_flight_and_campaign_not_terminal(api: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    ids = seed_verify_baseline(api, monkeypatch)
    assert api.client is not None
    first = api.client.post(f"/v1/findings/{ids['fgsm']}/verify", json={"defense": "spatial_smoothing"})
    assert first.status_code == 202, first.text

    second = api.client.post(f"/v1/findings/{ids['fgsm']}/verify", json={"defense": "spatial_smoothing"})
    assert second.status_code == 409, second.text
    assert second.json()["detail"]["code"] == "job_in_flight"

    with api.Session.begin() as session:
        baseline = session.get(Run, ids["run_id"])
        assert baseline is not None
        baseline.status = "running"
    third = api.client.post(f"/v1/findings/{ids['pgd']}/verify", json={})
    assert third.status_code == 409, third.text
    assert third.json()["detail"]["code"] == "campaign_not_terminal"
    assert third.json()["detail"]["status"] == "running"

    with api.Session.begin() as session:
        baseline = session.get(Run, ids["run_id"])
        assert baseline is not None
        baseline.status = "failed"
    fourth = api.client.post(f"/v1/findings/{ids['pgd']}/verify", json={})
    assert fourth.status_code == 409, fourth.text
    assert fourth.json()["detail"]["code"] == "score_unavailable"
    assert [event.success for event in api.events("verify.replay")] == [True, False, False, False]


def test_verify_queue_unavailable_rolls_back(api: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    ids = seed_verify_baseline(api, monkeypatch)
    assert api.client is not None

    def broken_delay(_job_id: str) -> Any:
        raise ConnectionError("broker unreachable")

    monkeypatch.setattr("redsim.workers.tasks.ml_campaign.ml_campaign_run.delay", broken_delay)
    response = api.client.post(f"/v1/findings/{ids['fgsm']}/verify", json={})
    assert response.status_code == 503, response.text
    assert response.json()["detail"]["code"] == "queue_unavailable"
    assert api.counts() == {"runs": 1, "jobs": 0, "campaigns": 1}
    with api.Session() as session:
        finding = session.get(Finding, ids["fgsm"])
    assert finding is not None and finding.status == "open", "the fixing transition was rolled back"
    assert [event.success for event in api.events("verify.replay")] == [True, False]


# --------------------------------------------------------------------------- rerun lineage

def test_rerun_links_parent(api: Harness) -> None:
    seed_model(api)
    config = parent_config()
    seed_campaign_run(api, "run-parent-failed", status="failed", config=config)
    with api.Session() as session:
        before = session.get(Run, "run-parent-failed")
        assert before is not None
        parent_before = {"status": before.status, "stage_table": dict(before.stage_table),
                         "completed_at": before.completed_at, "created_by": before.created_by}
    parent_row_before = dict(api.campaign_row("run-parent-failed") or {})

    response = launch(api, {"parent_run_id": "run-parent-failed"})

    assert response.status_code == 202, response.text
    body = response.json()
    run_id, (job_id,) = body["run_id"], body["job_ids"]
    assert run_id != "run-parent-failed"
    with api.Session() as session:
        run = session.get(Run, run_id)
        job = session.get(Job, job_id)
        parent = session.get(Run, "run-parent-failed")
    assert run is not None and run.status == "queued" and run.target_id == MODEL
    assert run.stage_table["parent_run_id"] == "run-parent-failed"
    assert job is not None and job.detail["parent_run_id"] == "run-parent-failed"
    copied = job.detail["campaign_config"]
    for key in ("attack_ids", "attack_params", "norm", "eps_grid", "reference_eps", "n_samples", "seed",
                "explain_k", "dataset_id", "dataset_revision", "finding_asr_threshold", "scoring"):
        assert copied[key] == config[key], key
    assert copied["target_snapshot"]["id"] == MODEL and [a["id"] for a in copied["attacks"]] == ["fgsm", "pgd"]
    row = api.campaign_row(run_id)
    assert row is not None and row["parent_run_id"] == "run-parent-failed" and row["kind"] == "attack"
    assert row["config"]["seed"] == config["seed"] == 7
    # Lineage on the chain; the original run and campaign row are untouched.
    events = api.events("attack.run")
    assert len(events) == 1 and events[0].success and events[0].run_id == run_id
    assert events[0].detail["rerun"] is True and events[0].detail["parent_run_id"] == "run-parent-failed"
    assert api.writer.run_existed_at_append == [False]
    assert parent is not None
    assert {"status": parent.status, "stage_table": dict(parent.stage_table), "completed_at": parent.completed_at,
            "created_by": parent.created_by} == parent_before
    assert dict(api.campaign_row("run-parent-failed") or {}) == parent_row_before
    assert api.delay_calls == [job_id]


def test_rerun_of_a_cancelled_parent_is_admitted_too(api: Harness) -> None:
    seed_model(api)
    seed_campaign_run(api, "run-parent-cancelled", status="cancelled")
    response = launch(api, {"parent_run_id": "run-parent-cancelled"})
    assert response.status_code == 202, response.text
    row = api.campaign_row(response.json()["run_id"])
    assert row is not None and row["parent_run_id"] == "run-parent-cancelled"
    assert row["config"]["dataset_id"] == DATASET
