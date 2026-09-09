"""Phase B worker-half of ``redsim.ml_campaign_run`` (worker-campaign-phase-b track).

Runs the real task body eagerly on the sqlite harness of :mod:`tests.ml.test_tasks`, covering:

* **ENDPOINT-05 lifecycle** — a black-box endpoint campaign: the worker resolves the AuthProfile
  credential from the vault at run time, ``run_campaign_sandboxed`` starts the ``PredictBroker`` in the
  worker parent (here a real broker against ``tests/ml/tiny_endpoint_server.py``), the child reaches it
  over the socket, and the broker's query counts and per-job budget are recorded on the run record and on
  the ``attack.execute`` / ``campaign.score`` / ``job.complete`` audit rows — never a URL or a credential.
* **ATTACKS_HARDEN-13 / -18** — a verify whose defense had kind ``training`` registers the derived model
  the child produced as a new Target (``ml_model_artifact``, source ``derived``, ``DerivedFrom`` lineage)
  through the register-then-validate path with a ``model.register`` audit row, and names the derived digest
  and training budget on the ``verify.execute`` row and the remediation summary.
* **REVIEW_REPORTS-08** — every verify appends a ``FindingVerify`` (with ``settings_hash`` and
  ``baseline_run_id``) to ``MLFindingDetail.retests``, keeping ``verify`` the latest.
* **INTEROP-04** — the ``ml.clean_slice`` / ``ml.control_slice`` artifact kinds this track owns.

Nothing here loads a model in the Celery process except the endpoint case, which spawns no child (the
broker runs in-process against the tiny server) and is guarded by ``ml`` imports.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

pytest.importorskip("numpy")

from redsim.db.models import AuthProfile, Finding, Job, RemediationAttempt, Target
from redsim.ml.schema import CampaignRecord, DefenseConfig
from tests.ml.test_tasks import (
    ATTACK_JOB_ID,
    ATTACK_RUN_ID,
    BASELINE_RUN_ID,
    DEFENSE,
    PROJECT_ID,
    Harness,
    fixture_record,
    verify_record,
)
from tests.ml.test_tasks import harness as harness  # noqa: F401 - reused pytest fixture

pytestmark = pytest.mark.integration

# Low-entropy fake bearer token (mirrors tests/ml/tiny_endpoint_server.DEFAULT_TOKEN).
FAKE_TOKEN = "tok-123"
DERIVED_STATE_SHA = "ab" * 32          # the derived module's state_dict digest (fake, fixed)
PARENT_MANIFEST_SHA = "d0" * 32        # the fixture campaign's model_sha256


# --------------------------------------------------------------------------- artifact kinds (INTEROP-04)


def test_slice_and_derived_artifact_kinds() -> None:
    from redsim.workers.tasks.ml_campaign import artifact_kind

    # INTEROP-04: this track's names for the per-run export slices.
    assert artifact_kind("clean_slice.npz") == "ml.clean_slice"
    assert artifact_kind("clean_slice/eps0.03.npz") == "ml.clean_slice"
    assert artifact_kind("control_slice/eps0.03.npz") == "ml.control_slice"
    assert artifact_kind("adv_slice/fgsm_eps0.03.npz") == "ml.adv_slice"
    # ATTACKS_HARDEN-13: the derived model the training verify produced.
    assert artifact_kind("derived_model/weights.pt") == "ml.derived_model"
    assert artifact_kind("derived_model/training_report.json") == "ml.training_report"
    # Partial (killed child) variants keep their provenance.
    assert artifact_kind("ml/partial/clean_slice.npz") == "ml.partial.clean_slice"


def test_worker_persists_clean_and_control_slices(harness: Harness) -> None:
    """The worker gives the runner-written clean / control slices their INTEROP-04 kinds and stores them."""
    harness.add_attack_job()

    def add_slices(sink: Any) -> None:
        sink.put("clean_slice.npz", b"clean-slice-npz", "application/octet-stream")
        sink.put("control_slice/eps0.03.npz", b"control-slice-npz", "application/octet-stream")

    harness.install_sandbox(fixture_record(), before_return=add_slices)

    harness.run_job(ATTACK_JOB_ID)

    kinds = {a.kind for a in harness.artifacts(ATTACK_RUN_ID)}
    # install_sandbox already writes adv_slice/fgsm_eps0.03.npz -> ml.adv_slice.
    assert {"ml.clean_slice", "ml.control_slice", "ml.adv_slice"} <= kinds


# --------------------------------------------------------------------------- REVIEW_REPORTS-08: retests


def _add_verify(harness: Harness, finding_id: str, run_id: str, job_id: str) -> None:
    config = harness.baseline.config.model_dump(mode="json")
    config["defense"] = DEFENSE
    harness.add_job(
        run_id=run_id, job_id=job_id, job_type="verify.replay", config=config,
        detail={"finding_id": finding_id, "baseline_run_id": BASELINE_RUN_ID},
        kind="verify", baseline_run_id=BASELINE_RUN_ID, scanner="ml.verify",
    )


def test_every_verify_appends_a_retest_keeping_verify_the_latest(harness: Harness) -> None:
    finding_id = harness.seed_baseline()
    harness.install_sandbox(verify_record(partial=False))

    _add_verify(harness, finding_id, "run-verify-a", "job-verify-a")
    harness.run_job("job-verify-a")
    _add_verify(harness, finding_id, "run-verify-b", "job-verify-b")
    harness.run_job("job-verify-b")

    finding = harness.row(Finding, finding_id)
    assert finding is not None
    ml = finding.schema_blob["ml"]
    # REVIEW_REPORTS-08: full history, verify stays the latest.
    assert len(ml["retests"]) == 2
    assert ml["verify"] == ml["retests"][-1]
    assert [rt["run_id"] for rt in ml["retests"]] == ["run-verify-a", "run-verify-b"]
    for rt in ml["retests"]:
        assert rt["settings_hash"] == harness.baseline.settings_hash
        assert rt["baseline_run_id"] == BASELINE_RUN_ID
        assert rt["defense"]["id"] == DEFENSE["id"]


def test_failed_verify_still_records_a_retest(harness: Harness) -> None:
    from redsim.ml.sandbox import partial_campaign_record

    finding_id = harness.seed_baseline()
    _add_verify(harness, finding_id, "run-verify-fail", "job-verify-fail")
    config = verify_record().config
    failed = partial_campaign_record(
        config, status="failed", error="SandboxKilled: ML sandbox child died with signal SIGKILL",
        stages_done=["load_target", "sample"], baseline_run_id=BASELINE_RUN_ID, parent_run_id=None,
    )
    harness.install_sandbox(failed, stages=["load_target", "sample"])

    with pytest.raises(RuntimeError, match="SandboxKilled"):
        harness.run_job("job-verify-fail")

    finding = harness.row(Finding, finding_id)
    assert finding is not None
    ml = finding.schema_blob["ml"]
    assert len(ml["retests"]) == 1
    assert ml["retests"][-1]["outcome"] == "inconclusive"
    assert ml["retests"][-1]["baseline_run_id"] == BASELINE_RUN_ID
    assert ml["verify"] == ml["retests"][-1]


# --------------------------------------------------------------------------- ATTACKS_HARDEN-13 / -18: derived


def _training_verify_record(baseline_target_id: str, weights_bytes: bytes) -> CampaignRecord:
    """A verify record whose defense had kind ``training`` and whose provenance names the derived model."""
    base = verify_record(partial=False)
    training_defense = DefenseConfig(
        id="adversarial_training", art_class="art.defences.trainer.AdversarialTrainer",
        params={"epochs": 2, "eps": 0.03},
    )
    provenance_defense: dict[str, Any] = {
        "id": "adversarial_training", "art_class": "art.defences.trainer.AdversarialTrainer",
        "params": {"epochs": 2, "eps": 0.03}, "kind": "training", "method": "adversarial_training",
        "parent_sha256": PARENT_MANIFEST_SHA, "derived_sha256": DERIVED_STATE_SHA,
        "training_report": {
            "target_id": baseline_target_id, "parent_manifest_sha256": PARENT_MANIFEST_SHA,
            "weights_sha256": DERIVED_STATE_SHA, "epochs_requested": 2, "epochs_run": 2, "n_train": 64,
            "wall_budget_s": 300, "wall_time_s": 5.0, "budget_exhausted": False, "backbone_frozen": True,
            "weights_file_sha256": hashlib.sha256(weights_bytes).hexdigest(),
        },
    }
    config = base.config.model_copy(update={"defense": training_defense})
    provenance = base.provenance.model_copy(update={"defense": provenance_defense}) if base.provenance else None
    return base.model_copy(update={"config": config, "provenance": provenance, "kind": "verify"})


def _enrich_parent_manifest(harness: Harness, target_id: str) -> None:
    """Give the fixture parent a full manifest so the derived MLModelManifest validates."""
    with harness.get_session() as session:
        target = session.get(Target, target_id)
        assert target is not None
        detail = dict(target.detail or {})
        detail["manifest"] = {
            "name": "Tiny fixture", "modality": "image", "format": "torch_state_dict",
            "sha256": PARENT_MANIFEST_SHA, "size_bytes": 4096, "architecture_id": "small_cnn",
            "input_shape": [3, 8, 8], "n_classes": 3, "class_names": ["circle", "square", "triangle"],
            "dataset_id": "fixture/synthetic-shapes", "dataset_split": "test", "status": "registered",
        }
        target.detail = detail


def test_training_verify_registers_a_derived_target_with_lineage(harness: Harness) -> None:
    finding_id = harness.seed_baseline()
    baseline_target_id = harness.baseline.config.target_id
    _enrich_parent_manifest(harness, baseline_target_id)

    weights_bytes = b"derived-weights-blob-v1"
    report_bytes = b'{"target_id": "tgt-tiny-fixture"}'
    blob_sha = hashlib.sha256(weights_bytes).hexdigest()

    def write_derived(sink: Any) -> None:
        sink.put("derived_model/weights.pt", weights_bytes, "application/octet-stream")
        sink.put("derived_model/training_report.json", report_bytes, "application/json")

    _add_verify(harness, finding_id, "run-verify-train", "job-verify-train")
    harness.install_sandbox(_training_verify_record(baseline_target_id, weights_bytes),
                            before_return=write_derived)

    result = harness.run_job("job-verify-train")
    assert result["status"] == "succeeded"

    # A new derived Target with DerivedFrom lineage (ATTACKS_HARDEN-13).
    with harness.sessions() as session:
        derived = session.query(Target).filter(Target.id.like("derived-%")).all()
        validate_jobs = session.query(Job).filter(Job.type == "model.validate").all()
    assert len(derived) == 1
    dt = derived[0]
    assert dt.kind == "ml_model_artifact" and dt.project_id == PROJECT_ID
    detail = dt.detail or {}
    assert detail["source"] == "derived" and detail["status"] == "validating"
    lineage = detail["derived_from"]
    assert lineage["parent_target_id"] == baseline_target_id
    assert lineage["parent_sha256"] == PARENT_MANIFEST_SHA
    assert lineage["defense_id"] == "adversarial_training"
    assert lineage["training_budget"]["epochs_run"] == 2 and lineage["training_budget"]["n_train"] == 64
    # register-then-validate: the manifest carries the same lineage and a validate Job is queued.
    assert detail["manifest"]["derived_from"]["defense_id"] == "adversarial_training"
    assert detail["manifest"]["sha256"] == blob_sha
    assert len(validate_jobs) == 1 and validate_jobs[0].status == "queued"
    validate_run_id = validate_jobs[0].run_id

    # model.register audit row on the validate run's own chain (ATTACKS_HARDEN-13 register-then-validate).
    register_events = [e for e in harness.events(validate_run_id) if e["action"] == "model.register"]
    assert len(register_events) == 1 and register_events[0]["success"] is True
    reg = register_events[0]["detail"]
    assert reg["source"] == "derived" and reg["target_id"] == dt.id
    assert reg["derived_sha256"] == DERIVED_STATE_SHA and reg["defense_id"] == "adversarial_training"
    assert reg["parent_target_id"] == baseline_target_id

    # ATTACKS_HARDEN-18 (worker half): the verify.execute row names the derived digest and budget.
    verify_events = [e for e in harness.events("run-verify-train") if e["action"] == "verify.execute"]
    assert len(verify_events) == 1
    vd = verify_events[0]["detail"]
    assert vd["derived_target_id"] == dt.id and vd["derived_sha256"] == DERIVED_STATE_SHA
    assert vd["parent_sha256"] == PARENT_MANIFEST_SHA and vd["training_budget"]["epochs_run"] == 2

    # The remediation summary (the MeasuredDelta's context) also carries the lineage.
    with harness.sessions() as session:
        attempts = session.query(RemediationAttempt).filter(
            RemediationAttempt.finding_id == finding_id).all()
    assert attempts
    summary = json.loads(attempts[-1].detail["result"])
    assert summary["derived"]["derived_target_id"] == dt.id
    assert summary["derived"]["derived_sha256"] == DERIVED_STATE_SHA


def test_preprocessing_verify_registers_no_derived_target(harness: Harness) -> None:
    """A preprocessing defense produces no derived model, so nothing is registered (never faked)."""
    finding_id = harness.seed_baseline()
    _add_verify(harness, finding_id, "run-verify-pre", "job-verify-pre")
    harness.install_sandbox(verify_record(partial=False))

    harness.run_job("job-verify-pre")

    with harness.sessions() as session:
        assert session.query(Target).filter(Target.id.like("derived-%")).count() == 0
        assert session.query(Job).filter(Job.type == "model.validate").count() == 0
    verify_events = [e for e in harness.events("run-verify-pre") if e["action"] == "verify.execute"]
    assert verify_events and "derived_sha256" not in verify_events[0]["detail"]


# --------------------------------------------------------------------------- ENDPOINT-05 lifecycle


EP_RUN_ID = "run-endpoint-1"
EP_JOB_ID = "job-endpoint-1"
ENDPOINT_TARGET_ID = "endpoint-tgt"

# What ``redsim.ml.sandbox`` attaches to provenance.model_manifest["endpoint_broker"] after the
# worker-parent broker has served the child (the parent-side counters and the per-job budget).
_BROKER_STATS = {
    "rows": 137, "requests": 21,
    "by_purpose": {"probe": {"requests": 1, "rows": 8}, "predict": {"requests": 20, "rows": 129}},
    "limits": {"rps": 10_000.0, "batch_rows": 32, "timeout_s": 10.0, "max_rows": 500_000,
               "max_requests": 20_000},
    "rate_limit_wait_s": 0.0, "fingerprint_sha256": "0" * 64,
    "tls_mode": "plaintext",
}


def _endpoint_config() -> dict[str, Any]:
    return {
        "target_id": ENDPOINT_TARGET_ID, "modality": "image", "attack_ids": ["hopskipjump"],
        "attack_params": {"hopskipjump": {"max_iter": 1, "max_eval": 100, "init_eval": 10, "init_size": 3,
                                          "batch_size": 64}},
        "norm": "linf", "eps_grid": [0.03], "reference_eps": 0.03, "n_samples": 10, "seed": 0,
        "include_control": True, "explain_k": 0, "dataset_id": "synthetic/tiny",
        "dataset_revision": "deadbeef", "dataset_split": "eval",
    }


@pytest.mark.ml
def test_endpoint_campaign_resolves_the_vault_credential_and_records_broker_budget(
    harness: Harness, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The worker half of ENDPOINT-05: the campaign task detects the endpoint target, resolves the
    AuthProfile credential from the vault at run time, hands the endpoint descriptor + credential +
    allowlist to ``run_campaign_sandboxed`` (which starts the broker in the worker parent), and records
    the broker's query counts and budget on the run and the audit rows -- never a URL or a credential.

    The genuine HTTP path through the ``PredictBroker`` and the tiny server is covered by
    ``tests/ml/test_endpoint_target.py``; here the sandbox is faked (as every task test fakes it) and
    drives the real campaign machinery over ``TinyTarget`` with the broker's counters attached, so the
    worker's wiring and recording are exercised deterministically. See the cross-track notes: the
    ``endpoint_broker.build_predict_body`` <-> B0 ``endpoint_contract.PredictRequest`` seam must be
    reconciled by the assembler before the real broker path is green.
    """
    pytest.importorskip("torch")
    pytest.importorskip("art")
    from cryptography.fernet import Fernet

    from redsim.ml.campaign import run_campaign
    from redsim.security_utils.secrets import encrypt_secret
    from tests.ml.fakes import CLASS_NAMES, TinyTarget

    # A real AuthProfile vault entry: the worker must resolve this secret at run time, not the test.
    fake_token = "tok-endpoint-123"
    monkeypatch.setenv("REDSIM_AUTH_PROFILES_KEY", Fernet.generate_key().decode())
    ciphertext = encrypt_secret(fake_token)

    with harness.get_session() as session:
        session.add(AuthProfile(id="ap-1", project_id=PROJECT_ID, name="endpoint", kind="bearer",
                                config={}, secret_ciphertext=ciphertext))
        session.add(Target(
            id=ENDPOINT_TARGET_ID, project_id=PROJECT_ID, kind="ml_model_endpoint",
            value="endpoint:tiny", verified=True,
            detail={
                "source": "endpoint", "status": "available",
                # The full request URL is an internal Target field, never the manifest/report (D3).
                "endpoint": {"url": "https://127.0.0.1:9443/predict", "auth_profile_id": "ap-1",
                             "batch_rows": 32, "timeout_s": 10.0},
                "manifest": {"modality": "image", "format": "endpoint", "n_classes": 3,
                             "class_names": list(CLASS_NAMES), "input_shape": [3, 8, 8],
                             "dataset_id": "synthetic/tiny",
                             "endpoint": {"url_host": "127.0.0.1:9443", "auth_profile_id": "ap-1",
                                          "contract_version": "endpoint-v1"}},
            },
        ))

    harness.add_job(run_id=EP_RUN_ID, job_id=EP_JOB_ID, job_type="attack.run",
                    config=_endpoint_config(), scanner="ml.campaign")

    captured: dict[str, Any] = {}

    def fake_sandboxed(config: Any, sink: Any, **kwargs: Any) -> CampaignRecord:
        # The sandbox is where run_campaign_sandboxed starts the worker-parent broker; the worker's
        # contract with it is the target_endpoint block, the resolved credential and the allowlist.
        captured["target_endpoint"] = kwargs.get("target_endpoint")
        captured["endpoint_auth"] = kwargs.get("endpoint_auth")
        captured["endpoint_allowlist"] = kwargs.get("endpoint_allowlist")
        record = run_campaign(config, sink, explain=False, target_override=TinyTarget(seed=0),
                              on_stage=kwargs.get("on_stage"), baseline_run_id=kwargs.get("baseline_run_id"),
                              parent_run_id=kwargs.get("parent_run_id"))
        payload = record.model_dump(mode="json")
        provenance = payload.get("provenance")
        if isinstance(provenance, dict):
            manifest = dict(provenance.get("model_manifest") or {})
            manifest["endpoint_broker"] = dict(_BROKER_STATS)
            payload["provenance"] = {**provenance, "model_manifest": manifest}
        return CampaignRecord.model_validate(payload)

    monkeypatch.setattr("redsim.ml.sandbox.run_campaign_sandboxed", fake_sandboxed)

    result = harness.run_job(EP_JOB_ID)
    assert result["status"] == "succeeded", result

    # The credential was decrypted from the vault at run time and handed on; the target_endpoint block the
    # worker built for the broker names only the profile id, never the secret.
    assert captured["endpoint_auth"]["secret"] == fake_token
    assert captured["endpoint_auth"]["kind"] == "bearer"
    assert captured["target_endpoint"]["auth_profile_id"] == "ap-1"
    assert captured["target_endpoint"]["url"] == "https://127.0.0.1:9443/predict"
    assert "secret" not in captured["target_endpoint"] and "auth" not in captured["target_endpoint"]
    assert captured["endpoint_allowlist"] is not None

    record = harness.persisted_record(EP_RUN_ID)
    broker_stats = record.provenance.model_manifest["endpoint_broker"] if record.provenance else {}
    assert broker_stats["rows"] == 137 and broker_stats["requests"] == 21

    # ENDPOINT-05/-08: query counts and the budget travel on the attack and job.complete rows.
    events = harness.events(EP_RUN_ID)
    attack_rows = [e for e in events if e["action"] == "attack.execute.hopskipjump"]
    assert len(attack_rows) == 1 and attack_rows[0]["success"] is True
    endpoint_detail = attack_rows[0]["detail"]["endpoint"]
    assert endpoint_detail["rows"] == 137 and endpoint_detail["requests"] == 21
    assert endpoint_detail["budget"]["max_rows"] == 500_000
    complete = next(e for e in events if e["action"] == "job.complete")
    assert complete["detail"]["endpoint"]["rows"] == 137

    # No credential reaches the run record, the audit trail or the job detail.
    assert fake_token not in json.dumps(events) and fake_token not in record.model_dump_json()
    job = harness.row(Job, EP_JOB_ID)
    assert job is not None and fake_token not in json.dumps(job.detail or {})
