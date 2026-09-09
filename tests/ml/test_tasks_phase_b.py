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
    TRAINING_DEFENSE,
    VERIFY_JOB_ID,
    VERIFY_RUN_ID,
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


TINY_CLASS_NAMES = ["circle", "square", "triangle"]      # tests.ml.fakes.CLASS_NAMES without importing torch


def test_endpoint_request_block_reads_the_url_the_way_endpoint_admission_stores_it() -> None:
    """ENDPOINT-05 seam with endpoint-admission: ``services.ml_models.admit_endpoint_registration`` writes the
    normalised request URL as ``Target.value`` and keeps ``detail`` host-only (D3). The worker reads the URL
    from there, builds the binding with the same helper the validate task uses, and lets the frozen config fix
    the modality and the dataset the child binds; a row that stores no URL anywhere is a typed failure."""
    from types import SimpleNamespace

    from redsim.ml.schema import CampaignConfig
    from redsim.services.ml_models import endpoint_request_block
    from redsim.workers.tasks.ml_campaign import _endpoint_request_block, _is_endpoint_target

    config = CampaignConfig.model_validate(_endpoint_config())
    detail = {
        "source": "endpoint", "status": "available", "endpoint_kind": "predict", "auth_profile_id": "ap-1",
        "manifest": {"modality": "image", "format": "endpoint", "n_classes": 3, "class_names": TINY_CLASS_NAMES,
                     "input_shape": [3, 8, 8], "dataset_id": "synthetic/tiny", "dataset_split": "test",
                     "endpoint": {"url_host": "127.0.0.1:9443", "auth_profile_id": "ap-1",
                                  "contract_version": "endpoint-v1", "batch_rows": 16, "timeout_s": 5.0}},
    }
    target = SimpleNamespace(kind="ml_model_endpoint", value="https://127.0.0.1:9443/predict", detail=detail)
    assert _is_endpoint_target(target)

    block = _endpoint_request_block(target, config)
    assert block["url"] == "https://127.0.0.1:9443/predict" and block["auth_profile_id"] == "ap-1"
    assert block["batch_rows"] == 16 and block["timeout_s"] == 5.0
    manifest = block["manifest"]
    # The frozen config owns the binding the child evaluates under (admission checked it at launch).
    assert manifest["modality"] == config.modality == "image"
    assert manifest["dataset_id"] == config.dataset_id and manifest["dataset_split"] == config.dataset_split == "eval"
    assert manifest["dataset_revision"] == config.dataset_revision == "deadbeef"
    # The registration's contract fields the broker encodes and validates against (endpoint-v1).
    assert manifest["input_shape"] == [3, 8, 8] and manifest["n_classes"] == 3
    assert manifest["class_names"] == TINY_CLASS_NAMES
    assert not ({"secret", "auth", "token", "url_host", "socket"} & set(block))
    # One helper for both workers: the validate task's block differs only in the config-owned binding keys.
    shared = endpoint_request_block(target.value, detail)
    assert block["manifest"] == {**shared["manifest"], "modality": "image", "dataset_id": config.dataset_id,
                                 "dataset_split": "eval", "dataset_revision": "deadbeef"}
    assert (block["batch_rows"], block["timeout_s"]) == (shared["batch_rows"], shared["timeout_s"])

    # A row that stores the URL neither as its value nor in detail: refused, never an invented endpoint.
    with pytest.raises(RuntimeError, match="no stored request URL"):
        _endpoint_request_block(SimpleNamespace(kind="ml_model_endpoint", value="endpoint:tiny", detail=detail),
                                config)
    # A row written before the convention (URL under detail.endpoint.url) still reads.
    older = {**detail, "endpoint": {"url": "https://127.0.0.1:9443/predict", "auth_profile_id": "ap-1"}}
    legacy = _endpoint_request_block(SimpleNamespace(kind="ml_model_endpoint", value="endpoint:tiny", detail=older),
                                     config)
    assert legacy["url"] == "https://127.0.0.1:9443/predict" and legacy["auth_profile_id"] == "ap-1"


def test_expected_stages_and_kind_tables_are_merged_without_duplicates() -> None:
    """The B1 assemble's ``expected_stages`` (``defense_apply`` for a training defense) and the B2 kind rows
    (derived model, training report, export slices) coexist in one table each, every row exactly once."""
    from redsim.ml.schema import CampaignConfig
    from redsim.workers.tasks.ml_campaign import _BASENAME_KINDS, _EXACT_KINDS, _PREFIX_KINDS, expected_stages

    base = _endpoint_config()
    plain = expected_stages(CampaignConfig.model_validate(base))
    assert plain == ["load_target", "sample", "clean_eval", "attack:hopskipjump", "control", "score",
                     "interpret", "recommend", "report"]
    preprocessing = expected_stages(CampaignConfig.model_validate({**base, "defense": DEFENSE}))
    assert preprocessing == plain, "a preprocessing defense wraps the target and has no stage of its own"
    training = expected_stages(CampaignConfig.model_validate({**base, "defense": {
        "id": "adversarial_training", "art_class": "art.defences.trainer.AdversarialTrainer",
        "params": {"epochs": 1}}}))
    assert training == ["load_target", "defense_apply", *plain[1:]]
    for stages in (plain, preprocessing, training):
        assert len(stages) == len(set(stages))

    prefixes = [prefix for prefix, _kind in _PREFIX_KINDS]
    assert len(prefixes) == len(set(prefixes))
    exact_values = list(_EXACT_KINDS.values())
    for kind in ("ml.derived_model", "ml.training_report", "ml.clean_slice", "ml.detection.scorecard"):
        assert exact_values.count(kind) == 1, kind
    assert [kind for _prefix, kind in _PREFIX_KINDS].count("ml.control_slice") == 1
    assert [kind for _prefix, kind in _PREFIX_KINDS].count("ml.clean_slice") == 1
    for kind in ("ml.text.diff", "ml.shap.text", "ml.detection.boxes"):
        assert list(_BASENAME_KINDS.values()).count(kind) == 1, kind
    # The three tables never claim the same name.
    assert not (set(_EXACT_KINDS) & set(_BASENAME_KINDS))
    assert not any(name.startswith(prefix) for name in _EXACT_KINDS for prefix in prefixes)


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


# --------------------------------------------------------------------------- BULK-16: shared defended run


def _both_finding_ids(harness: Harness, fgsm_id: str) -> tuple[str, str]:
    """``(fgsm, pgd)`` finding ids of the seeded baseline (``seed_baseline`` returns the fgsm one)."""
    with harness.sessions() as session:
        rows = session.query(Finding).filter(Finding.run_id == BASELINE_RUN_ID).all()
        pgd = next(f for f in rows if f.schema_blob["ml"]["attack_id"] == "pgd")
        return fgsm_id, str(pgd.id)


def _add_bulk_verify(harness: Harness, finding_ids: list[str], run_id: str, job_id: str) -> None:
    config = harness.baseline.config.model_dump(mode="json")
    config["defense"] = DEFENSE
    harness.add_job(
        run_id=run_id, job_id=job_id, job_type="verify.replay", config=config,
        detail={"finding_id": finding_ids[0], "finding_ids": list(finding_ids), "baseline_run_id": BASELINE_RUN_ID,
                "batch_id": "batch-verify-1"},
        kind="verify", baseline_run_id=BASELINE_RUN_ID, scanner="ml.verify",
    )


def test_verify_finding_ids_puts_the_primary_first_and_deduplicates() -> None:
    from redsim.workers.tasks.ml_campaign import verify_finding_ids

    assert verify_finding_ids({"finding_id": "a"}) == ["a"]
    assert verify_finding_ids({"finding_id": "b", "finding_ids": ["a", "b", "c", "a"]}) == ["b", "a", "c"]
    assert verify_finding_ids({"finding_ids": ["a", "", None, "b"]}) == ["a", "b"]
    assert verify_finding_ids({}) == []


def test_bulk_verify_projects_the_shared_record_onto_every_listed_finding(harness: Harness) -> None:
    """Owner decision BULK-16 (worker half): one defended run, ``Job.detail.finding_ids`` two findings, each
    projected from its own attack rows with its own ``verify.execute`` row, the primary first."""
    from redsim.workers.tasks.ml_campaign import VERIFY_STATUS_MAP
    from redsim.workers.tasks.verify import _STATE_MAP

    fgsm, pgd = _both_finding_ids(harness, harness.seed_baseline())
    _add_bulk_verify(harness, [fgsm, pgd], "run-verify-bulk", "job-verify-bulk")
    record = verify_record(partial=False)
    harness.install_sandbox(record)

    result = harness.run_job("job-verify-bulk")

    assert result["status"] == "succeeded" and result["verify"]["finding_ids"] == [fgsm, pgd]
    projected: dict[str, Any] = {}
    for fid in (fgsm, pgd):
        finding = harness.row(Finding, fid)
        assert finding is not None
        ml = finding.schema_blob["ml"]
        assert ml["verify"]["run_id"] == "run-verify-bulk" and ml["verify"]["defense"]["id"] == DEFENSE["id"]
        assert ml["verify"]["baseline_run_id"] == BASELINE_RUN_ID
        assert ml["verify"]["settings_hash"] == harness.baseline.settings_hash
        assert ml["retests"][-1] == ml["verify"]
        outcome = ml["verify"]["outcome"]
        assert finding.status == VERIFY_STATUS_MAP[outcome] and finding.validation_state == _STATE_MAP[outcome]
        projected[fid] = outcome
    # Each finding is read from its own attack rows of the one record: the outcome is per attack.
    from redsim.workers.tasks.ml_campaign import _verify_outcome

    assert projected == {fgsm: _verify_outcome(record, "fgsm")[0], pgd: _verify_outcome(record, "pgd")[0]}
    events = harness.events("run-verify-bulk")
    verify_rows = [e for e in events if e["action"] == "verify.execute"]
    assert [e["detail"]["finding_id"] for e in verify_rows] == [fgsm, pgd], "one row per finding, primary first"
    for row in verify_rows:
        assert row["detail"]["shared_run_projection"] is True
        assert row["detail"]["primary_finding_id"] == fgsm and row["detail"]["finding_ids"] == [fgsm, pgd]
        assert row["detail"]["outcome"] == projected[row["detail"]["finding_id"]]
    assert [e["action"] for e in events].index("verify.execute") < [e["action"] for e in events].index("job.complete")
    with harness.sessions() as session:
        attempts = session.query(RemediationAttempt).filter(
            RemediationAttempt.finding_id.in_([fgsm, pgd])).all()
    assert {a.finding_id for a in attempts} == {fgsm, pgd}
    for attempt in attempts:
        summary = json.loads(attempt.detail["result"])
        assert summary["verify_run_id"] == "run-verify-bulk"
        assert summary["shared_run_projection"]["finding_ids"] == [fgsm, pgd]


def test_failed_bulk_verify_leaves_every_listed_finding_inconclusive(harness: Harness) -> None:
    from redsim.ml.errors import SandboxTimeout

    fgsm, pgd = _both_finding_ids(harness, harness.seed_baseline())
    _add_bulk_verify(harness, [fgsm, pgd], "run-verify-bulk-fail", "job-verify-bulk-fail")
    harness.install_sandbox(verify_record(), stages=["load_target"],
                            raise_after=SandboxTimeout("ML sandbox timed out after 1200s"))

    with pytest.raises(SandboxTimeout):
        harness.run_job("job-verify-bulk-fail")

    for fid in (fgsm, pgd):
        finding = harness.row(Finding, fid)
        assert finding is not None
        assert finding.validation_state == "inconclusive" and finding.status == "open"
        retest = finding.schema_blob["ml"]["retests"][-1]
        assert retest["run_id"] == "run-verify-bulk-fail" and retest["outcome"] == "inconclusive"
        assert finding.schema_blob["ml"]["verify"] == retest


def test_single_verify_is_unchanged_by_the_finding_ids_loop(harness: Harness) -> None:
    """A single verify names one finding: one ``verify.execute`` row, no shared-run keys, the same result shape."""
    finding_id = harness.seed_baseline()
    _add_verify(harness, finding_id, "run-verify-single", "job-verify-single")
    harness.install_sandbox(verify_record(partial=False))

    result = harness.run_job("job-verify-single")

    assert set(result["verify"]) == {"outcome", "validation_state", "status"}
    rows = [e for e in harness.events("run-verify-single") if e["action"] == "verify.execute"]
    assert len(rows) == 1 and "shared_run_projection" not in rows[0]["detail"]


# --------------------------------------------------------------------------- REVIEW_REPORTS-16 / -20 (worker half)


def test_completion_renders_every_report_format_and_records_the_first_snapshot(harness: Harness) -> None:
    from redsim.db.models import ReportSnapshot
    from redsim.ml.pdf import PDF_MAGIC
    from redsim.ml.reporting import REPORT_FORMATS_ALL
    from redsim.services.reports import REPORT_FORMATS as SERVICE_FORMATS
    from redsim.workers.tasks.ml_campaign import REPORT_FORMATS

    assert tuple(REPORT_FORMATS) == tuple(REPORT_FORMATS_ALL) == tuple(SERVICE_FORMATS) == ("md", "json", "html", "pdf")
    harness.add_attack_job()
    harness.install_sandbox(fixture_record())

    result = harness.run_job(ATTACK_JOB_ID)

    artifacts = {a.kind: a for a in harness.artifacts(ATTACK_RUN_ID)}
    assert {"report.md", "report.json", "report.html", "report.pdf"} <= set(artifacts)
    pdf = harness.store.get(str(artifacts["report.pdf"].location))
    pdf_bytes = pdf.encode() if isinstance(pdf, str) else bytes(pdf)
    assert pdf_bytes.startswith(PDF_MAGIC) and artifacts["report.pdf"].content_type == "application/pdf"
    events = {e["action"]: e for e in harness.events(ATTACK_RUN_ID)}
    render = events["report.render"]["detail"]
    assert render["formats"] == ["md", "json", "html", "pdf"] and render["source"] == "completion"
    assert "pdf_unavailable" not in render
    for ext in REPORT_FORMATS:
        assert render["artifact_ids"][f"report.{ext}"] == artifacts[f"report.{ext}"].id
        assert render["sha256"][f"report.{ext}"] == artifacts[f"report.{ext}"].sha256
    # REVIEW_REPORTS-20: exactly one snapshot, over the four report rows, projected from the run record bytes.
    with harness.sessions() as session:
        snapshots = session.query(ReportSnapshot).filter(ReportSnapshot.run_id == ATTACK_RUN_ID).all()
    assert len(snapshots) == 1
    snap = snapshots[0]
    assert result["snapshot_id"] == snap.id and snap.project_id == PROJECT_ID and snap.archived is False
    assert set(snap.artifact_ids) == {artifacts[f"report.{ext}"].id for ext in REPORT_FORMATS}
    assert snap.record_sha256 == artifacts["ml.run_record"].sha256 and snap.created_by == "user:alice"
    actions = [e["action"] for e in harness.events(ATTACK_RUN_ID)]
    assert actions.index("report.render") < actions.index("job.complete")


def test_missing_pdf_renderer_falls_back_to_the_text_formats_and_says_so(harness: Harness) -> None:
    from redsim.db.models import ReportSnapshot

    def no_reportlab(*_a: Any, **_k: Any) -> bytes:
        raise ImportError("No module named 'reportlab'")

    harness.monkeypatch.setattr("redsim.ml.pdf.render_pdf", no_reportlab)
    harness.add_attack_job()
    harness.install_sandbox(fixture_record())

    result = harness.run_job(ATTACK_JOB_ID)

    kinds = {a.kind for a in harness.artifacts(ATTACK_RUN_ID)}
    assert {"report.md", "report.json", "report.html"} <= kinds and "report.pdf" not in kinds, "nothing faked"
    render = next(e for e in harness.events(ATTACK_RUN_ID) if e["action"] == "report.render")["detail"]
    assert render["formats"] == ["md", "json", "html"] and render["pdf_unavailable"].startswith("ImportError")
    with harness.sessions() as session:
        snap = session.query(ReportSnapshot).filter(ReportSnapshot.run_id == ATTACK_RUN_ID).one()
    assert len(snap.artifact_ids) == 3 and result["snapshot_id"] == snap.id


# --------------------------------------------------------------------------- spec 6.5: the record closes the table


def test_stage_listed_done_by_the_record_is_succeeded_even_when_its_live_frame_was_missed(harness: Harness) -> None:
    """A stage the returned record lists in ``stages_done`` completed; a live frame that never reached the parent
    (here ``defense_apply``, which the tracker had marked skipped when ``sample`` closed) must not leave it skipped."""
    from redsim.db.models import Run

    finding_id = harness.seed_baseline()
    harness.add_verify_job(finding_id, recommendation_id=None, defense=TRAINING_DEFENSE)
    record = verify_record(partial=False, defense=TRAINING_DEFENSE)
    assert "defense_apply" in record.stages_done
    harness.install_sandbox(record, stages=[s for s in record.stages_done if s != "defense_apply"])

    result = harness.run_job(VERIFY_JOB_ID)

    assert result["status"] == "succeeded"
    run = harness.row(Run, VERIFY_RUN_ID)
    assert run is not None
    stages = run.stage_table["stages"]
    assert stages["defense_apply"]["status"] == "succeeded" and stages["defense_apply"]["job_id"] == VERIFY_JOB_ID
    assert not any(entry["status"] == "skipped" for entry in stages.values())
    assert run.stage_table["stages_done"] == list(record.stages_done)


# --------------------------------------------------------------------------- INTEROP-04: the child env carries the cap


@pytest.mark.parametrize("raw, forwarded", [("8", "8"), (" 0.5 ", "0.5"), ("0", None), ("-3", None),
                                            ("nan", None), ("inf", None), ("lots", None), ("", None)])
def test_child_env_forwards_a_valid_adv_artifact_cap_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Any,
                                                          raw: str, forwarded: str | None) -> None:
    from redsim.ml import sandbox

    monkeypatch.setenv(sandbox.MAX_ADV_ARTIFACT_ENV, raw)
    env = sandbox._ml_child_env(sandbox.MlSandboxConfig.from_env(), assets=str(tmp_path), hash_seed=0,
                                work_dir=tmp_path)
    assert env.get(sandbox.MAX_ADV_ARTIFACT_ENV) == forwarded
    # The pins are untouched and no other REDSIM_* value travels.
    assert env["REDSIM_DISABLE_LLM"] == "1" and env["REDSIM_PLUGINS"] == "0"
    assert set(k for k in env if k.startswith("REDSIM_")) - {sandbox.MAX_ADV_ARTIFACT_ENV} == set(sandbox._ALLOWED_REDSIM_KEYS)


def test_child_env_has_no_cap_when_the_parent_sets_none(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    from redsim.ml import sandbox

    monkeypatch.delenv(sandbox.MAX_ADV_ARTIFACT_ENV, raising=False)
    env = sandbox._ml_child_env(sandbox.MlSandboxConfig.from_env(), assets=str(tmp_path), hash_seed=0,
                                work_dir=tmp_path)
    assert sandbox.MAX_ADV_ARTIFACT_ENV not in env
    assert sorted(k for k in env if k.startswith("REDSIM_")) == sorted(sandbox._ALLOWED_REDSIM_KEYS)
