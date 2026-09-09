"""Bulk operations end to end: batches, bulk upload, capacity, bulk verify, the CLI matrix (wave B4).

Plan 12 wave B4, track ``e2e-review-reports-interop-bulk`` (register BULK-03..09,
-13..18, -20..22, -26, -30..32). Owner requirement 5 (per-project caps and the
daily budget) and owner decision BULK-16 (bulk verify is one defended run per
defense projected onto every selected finding), on the shared harness of
``tests/e2e/conftest.py`` / ``tests/e2e/harness.py``.

Every test drives the production route, the admission service, the eager worker
and the real sandbox child, then asserts on what those left behind. Two facts
about the harness shape the capacity tests and are stated rather than worked
around silently: Celery is eager, so no API-launched run is ever observed
``running`` by a later admission; a live ``attack.run`` job is therefore seeded
directly (the same way ``tests/e2e/test_ml_governance.py`` seeds a queued run
for the cancel route) and finished by hand when the test moves on. Nothing
measured on the tiny assets is a demo result.

1. ``test_bulk_upload_two_state_dicts_and_the_file_cap``: ``POST /v1/models/bulk``
   with two ``.pt`` state_dicts is two Targets, two ``ml.ingest`` runs, two
   ``model.register`` rows behind one ``bulk.upload`` row; over the file-count
   cap it is ``422 bulk_too_many_files`` before any row.
2. ``test_batch_over_two_models_completes_and_compares``: ``POST /v1/campaigns/batch``
   over ``vehicles_cnn`` and an uploaded ONNX (both image) is ``202``, both runs
   complete, the roll-up carries statuses and scorecard links only, and the
   compare view groups by comparability with no delta, mean or rank.
3. ``test_batch_mixing_modalities_is_refused_with_groups``: ``url_trees`` beside an
   image model is ``422 batch_modality_mismatch`` with the modality groups.
4. ``test_capacity_deferral_dispatch_and_batch_cancel``: with
   ``Project.ml_max_concurrent_runs = 1`` and a live job, both batch members are
   admitted deferred (queued, ``deferred=true``, the capacity stamp); the
   continuation hook dispatches the oldest once the slot frees and it completes;
   the still-queued member is cancelled through the batch cancel route.
5. ``test_daily_budget_refuses_with_an_audited_row``: a spent
   ``Project.ml_daily_run_budget`` refuses the member with ``daily_budget_exceeded``
   (a ``429`` code) and a ``success=False`` audit row; ``GET /v1/ml/capacity``
   reports the numbers throughout.
6. ``test_bulk_verify_projects_one_defended_run``: ``POST /v1/findings/{id}/verify/bulk``
   admits one defended run whose ``finding_ids`` list every selected finding and
   projects its outcome onto them.
7. ``test_single_run_admission_enforces_capacity``: the single-run route under the
   same cap.
8. ``test_cli_matrix_one_verifiable_chain_per_cell``: ``redsim ml attack --matrix``
   in-process over the two tiny targets writes one run directory and one
   verifiable ``audit.jsonl`` chain per cell and no cross-cell aggregate.

Run with::

    REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_ml_bulk.py

The harness fixtures are not edited here; every helper lives in this file. Heavy
imports happen inside fixtures and tests, after the session fixtures have
checked the extras, so collection stays green without them.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest

from tests.e2e import harness as h

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

    from tests.e2e.harness import E2EApp, E2EOrg

pytestmark = pytest.mark.e2e

N_EVAL = h.N_IMAGES // 2
FINDING_THRESHOLD = 0.2
FEATURE_SQUEEZING = "feature_squeezing"
LICENSE_STATEMENT = "e2e harness double: seeded random pixels, no licence restriction applies"
FORBIDDEN_TABLE_KEYS = frozenset({"mean", "rank", "average", "aggregate", "ranking"})
BATCH_ROUTE = "/v1/campaigns/batch"
CAPACITY_ROUTE = "/v1/ml/capacity"

_SINGLE_ROUTE_CAPACITY_DEFECT = (
    "product defect, not a harness problem: the single-run admission does not consult the capacity service. "
    "With Project.ml_max_concurrent_runs = 1 and one live attack.run job, POST /v1/models/{{id}}/attacks answered "
    "{status} with body keys {keys} and the run ended {run_status!r} at once: no deferred=true, no "
    "capacity_deferred marker (redsim.api.errors.MARKER_CODES), no Job.detail.deferred. BULK-20/-21 bind the "
    "single attack and verify routes as well as batch members: redsim/services/ml_campaigns.py "
    "create_attack_campaign / create_verify_campaign must call redsim/services/ml_capacity.py admit_or_defer "
    "before the admission row and mark_deferred on an over-cap admission, and the 202 body must carry the marker."
)
_BULK_VERIFY_PROJECTION_DEFECT = (
    "product defect, not a harness problem: owner decision BULK-16 is one defended run per (baseline, defense, "
    "params) projected onto EVERY selected finding, and the batch admission wrote Job.detail.finding_ids={finding_ids} "
    "with one verify.replay row per finding, but the worker projected the shared record onto the primary finding "
    "only: {unprojected} still carry no ml.verify block naming run {run_id} (projected=false in the batch view). "
    "redsim/workers/tasks/ml_campaign.py:_project_verify (line 943) reads detail.get('finding_id') alone and "
    "never loops detail['finding_ids'] (redsim/services/ml_batches.py docstring: 'Projecting the shared record "
    "onto each finding is the worker's (_project_verify loops finding_ids); until that lands the batch view "
    "reports per finding whether its ml.verify block names the shared run')."
)


# ---------------------------------------------------------------------------
# Read-only helpers over the API and the harness database
# ---------------------------------------------------------------------------


def _events(e2e_app: E2EApp, chain_id: str, action: str) -> list[dict[str, Any]]:
    return [ev for ev in e2e_app.read_chain(chain_id) if ev["action"] == action]


def _actions(e2e_app: E2EApp, chain_id: str) -> list[str]:
    return [str(ev["action"]) for ev in e2e_app.read_chain(chain_id)]


def _detail(response: Any) -> dict[str, Any]:
    try:
        detail = response.json().get("detail")
    except ValueError:
        return {}
    return dict(detail) if isinstance(detail, dict) else {}


def _code(response: Any) -> str | None:
    code = _detail(response).get("code")
    return str(code) if code is not None else None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _keys(payload: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(payload, dict):
        for key, value in payload.items():
            found.add(str(key).lower())
            found |= _keys(value)
    elif isinstance(payload, list):
        for item in payload:
            found |= _keys(item)
    return found


def _assert_no_aggregate(payload: Any) -> None:
    """Spec 15.7, 15.8 i / D9 i: a batch view or compare table carries no mean, rank or average anywhere."""
    offending = _keys(payload) & FORBIDDEN_TABLE_KEYS
    assert not offending, f"payload carries aggregate keys {sorted(offending)}"


def _campaign(client: TestClient, run_id: str) -> dict[str, Any]:
    response = client.get(f"/v1/runs/{run_id}/campaign")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _run(client: TestClient, run_id: str) -> dict[str, Any]:
    response = client.get(f"/v1/runs/{run_id}")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _capacity(client: TestClient, project_id: str) -> dict[str, Any]:
    response = client.get(CAPACITY_ROUTE, params={"project": project_id})
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    assert body["project"]["project_id"] == project_id and body["projects"][0] == body["project"]
    assert "source" in body and "jobs table" in body["source"], "capacity is data, never broker inspection"
    return dict(body["project"])


def _upload(client: TestClient, project_id: str, path: Path, **overrides: Any) -> Any:
    fields: dict[str, Any] = {
        "source": "upload", "project_id": project_id, "name": path.stem, "declared_format": "onnx",
        "modality": "image", "license_statement": LICENSE_STATEMENT,
    }
    for key, value in overrides.items():
        if value is None:
            fields.pop(key, None)
        else:
            fields[key] = value
    return client.post("/v1/models", data=fields,
                       files={"file": (path.name, path.read_bytes(), "application/octet-stream")})


def _wait_for_validation(client: TestClient, model_id: str) -> dict[str, Any]:
    import time

    deadline = time.monotonic() + 30.0
    while True:
        record = h.model_record(client, model_id)
        if record["status"] in {"available", "refused"}:
            return record
        assert time.monotonic() < deadline, f"model {model_id} still {record['status']!r}: {record.get('validation')}"
        time.sleep(0.1)


def _post_batch(client: TestClient, project_id: str, target_ids: list[str], campaign: dict[str, Any],
                **extra: Any) -> Any:
    return client.post(BATCH_ROUTE, json={"project_id": project_id, "target_ids": target_ids,
                                          "campaign": campaign, **extra})


def _batch_view(client: TestClient, batch_id: str) -> dict[str, Any]:
    response = client.get(f"{BATCH_ROUTE}/{batch_id}")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    _assert_no_aggregate(body)
    assert "never an aggregate score" in body["statement"]
    return body


def _job(e2e_app: E2EApp, job_id: str) -> dict[str, Any]:
    from redsim.db.models import Job

    with e2e_app.session() as sess:
        row = sess.get(Job, job_id)
        assert row is not None, f"Job {job_id} is missing"
        return {"id": str(row.id), "run_id": str(row.run_id), "type": str(row.type), "status": str(row.status),
                "detail": dict(row.detail or {}), "celery_task_id": row.celery_task_id, "created_by": row.created_by}


def _count(e2e_app: E2EApp, model: str) -> int:
    from sqlalchemy import func, select

    from redsim.db import models

    with e2e_app.session() as sess:
        return int(sess.execute(select(func.count()).select_from(getattr(models, model))).scalar() or 0)


def _campaign_batch_id(e2e_app: E2EApp, run_id: str) -> str | None:
    from redsim.services.reports import ml_campaign_row

    with e2e_app.session() as sess:
        row = ml_campaign_row(sess, run_id)
        return None if row is None else row.get("batch_id")


def _seed_running_job(e2e_app: E2EApp, *, project_id: str, target_id: str, actor: str) -> tuple[str, str]:
    """A ``running`` campaign Run with one ``running`` ``attack.run`` Job: a slot in use.

    The harness worker is eager, so no API-launched job is ever observed live by a
    later admission; the state a concurrency cap exists for is seeded directly (no
    audit row, no campaign record) and finished by hand with :func:`_finish_job`.
    """
    from redsim.db.models import Job, Run

    run_id = f"run-e2e-bulk-{uuid4().hex[:12]}"
    job_id = f"job-e2e-bulk-{uuid4().hex[:12]}"
    with e2e_app.session() as sess:
        sess.add(Run(id=run_id, project_id=project_id, target_id=target_id, mode="api", status="running",
                     scanner="ml.campaign", created_by=actor, stage_table={"stage": "attack", "jobs": {}}))
        sess.flush()
        sess.add(Job(id=job_id, run_id=run_id, project_id=project_id, type="attack.run", status="running",
                     created_by=actor, detail={"seeded_by": "tests/e2e/test_ml_bulk.py", "campaign_config": {}}))
        sess.flush()
    return run_id, job_id


def _finish_job(e2e_app: E2EApp, run_id: str, job_id: str, status: str = "succeeded") -> None:
    from redsim.db.models import Job, Run

    with e2e_app.session() as sess:
        job = sess.get(Job, job_id)
        run = sess.get(Run, run_id)
        if job is not None and job.status in {"queued", "running"}:
            job.status = status
        if run is not None and run.status in {"queued", "running"}:
            run.status = status
        sess.flush()


@contextlib.contextmanager
def _project_caps(e2e_app: E2EApp, project_id: str, *, max_concurrent: int | None = None,
                  daily_budget: int | None = None) -> Iterator[None]:
    """Set ``Project.ml_max_concurrent_runs`` / ``ml_daily_run_budget`` for the block, then clear them again."""
    from redsim.db.models import Project

    with e2e_app.session() as sess:
        project = sess.get(Project, project_id)
        assert project is not None
        project.ml_max_concurrent_runs = max_concurrent
        project.ml_daily_run_budget = daily_budget
        sess.flush()
    try:
        yield
    finally:
        with e2e_app.session() as sess:
            project = sess.get(Project, project_id)
            assert project is not None
            project.ml_max_concurrent_runs = None
            project.ml_daily_run_budget = None
            sess.flush()


# ---------------------------------------------------------------------------
# Module fixtures: the upload doubles, the registered ONNX, a campaign with findings
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def upload_double(e2e_assets: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """The memorising ONNX (``Upsample(x2) -> SmallCNN(16)``) plus two byte-distinct ``SmallCNN(8)`` state_dicts.

    Test stand-ins built from the harness's own seeded pixels; nothing measured on them is a demo result.
    """
    import numpy as np
    import torch
    from torch import nn

    from redsim.ml.targets.architectures import SmallCNN

    manifest = h.asset_manifest(e2e_assets)
    entry = manifest["models"][h.IMAGE_MODEL_ID]
    dataset_id, dataset_split = str(entry["dataset_id"]), str(entry["dataset_split"])
    class_names = list(manifest["datasets"][dataset_id]["class_names"])
    out = tmp_path_factory.mktemp("e2e-bulk-uploads")
    images = h.synthetic_images()
    x = torch.from_numpy(images.train.x.astype(np.float32) / 255.0)
    y = torch.from_numpy(images.train.y)
    x_eval = torch.from_numpy(images.eval.x.astype(np.float32) / 255.0)
    y_eval = torch.from_numpy(images.eval.y)

    torch.manual_seed(0)
    inner = SmallCNN(in_channels=3, n_classes=len(class_names), image_size=2 * h.IMAGE_SIZE)
    model = nn.Sequential(nn.Upsample(scale_factor=2.0, mode="nearest"), inner)
    optimiser = torch.optim.Adam(model.parameters(), lr=5e-3)
    for _ in range(400):
        model.train()
        optimiser.zero_grad()
        loss = nn.functional.cross_entropy(model(x), y)
        loss.backward()
        optimiser.step()
        model.eval()
        with torch.no_grad():
            train_acc = float((model(x).argmax(1) == y).float().mean())
        if train_acc == 1.0 and float(loss.detach()) < 0.02:
            break
    model.eval()
    with torch.no_grad():
        eval_acc = float((model(x_eval).argmax(1) == y_eval).float().mean())
    assert eval_acc * N_EVAL >= 20, f"the memorising double reached only {eval_acc:.3f} on the eval split"
    onnx_path = out / "small_cnn_8x8.onnx"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        torch.onnx.export(
            model, (x_eval[:1],), str(onnx_path), input_names=["input"], output_names=["logits"],
            opset_version=17, dynamo=False, dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}},
        )
    # Two catalog SmallCNN state_dicts at the harness resolution (random init, distinct seeds): they only need
    # to load strictly and predict three classes on 8x8x3 inputs to reach ``available``.
    state_dicts: list[Path] = []
    for seed in (11, 12):
        torch.manual_seed(seed)
        module = SmallCNN(in_channels=3, n_classes=len(class_names), image_size=h.IMAGE_SIZE)
        path = out / f"small_cnn_seed{seed}.pt"
        torch.save(module.state_dict(), path)
        assert path.read_bytes().startswith(b"PK\x03\x04"), "torch.save writes a zip container"
        state_dicts.append(path)
    assert _sha256(state_dicts[0].read_bytes()) != _sha256(state_dicts[1].read_bytes())
    return {"onnx": onnx_path, "state_dicts": state_dicts, "dataset_id": dataset_id, "dataset_split": dataset_split,
            "class_names": class_names}


@pytest.fixture(scope="module")
def onnx_model(e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str],
               upload_double: dict[str, Any]) -> dict[str, Any]:
    del e2e_bundled  # ordering only
    client = e2e_org.client("remediator")
    response = _upload(client, e2e_org.project_id, upload_double["onnx"], declared_format="onnx",
                       dataset_id=upload_double["dataset_id"], dataset_split=upload_double["dataset_split"])
    assert response.status_code == 201, response.text
    model_id = str(response.json()["id"])
    record = _wait_for_validation(client, model_id)
    if record["status"] != "available":
        pytest.fail(f"product defect outside this file: the ONNX upload was refused by the validate child: "
                    f"{record.get('refusal_reason')}: {record.get('reason')}", pytrace=False)
    return {"model_id": model_id, "record": record}


@pytest.fixture(scope="module")
def finding_campaign(e2e_org: E2EOrg, onnx_model: dict[str, Any]) -> h.CampaignRun:
    """FGSM + PGD (or HopSkipJump alone without gradients) on the memorising upload, launched by the scanner."""
    manifest = onnx_model["record"].get("manifest") or {}
    if manifest.get("gradients"):
        body = h.image_campaign(n_samples=N_EVAL, finding_asr_threshold=FINDING_THRESHOLD)
    else:
        body = h.image_campaign(n_samples=N_EVAL, finding_asr_threshold=FINDING_THRESHOLD, attack_ids=["hopskipjump"],
                                attack_params={"hopskipjump": h.tabular_campaign()["attack_params"]["hopskipjump"]})
    result = h.run_campaign_via_api(e2e_org.client("scanner"), onnx_model["model_id"], body, timeout_s=30.0)
    assert result.status == "succeeded", f"run {result.run_id}: {result.stage_table}"
    assert result.campaign is not None, result.campaign_error
    assert result.findings, "the memorising upload produced no finding to verify in bulk"
    return result


# ---------------------------------------------------------------------------
# 1. Bulk upload (BULK-13): one admission per file behind one request row; the file-count cap
# ---------------------------------------------------------------------------


def test_bulk_upload_two_state_dicts_and_the_file_cap(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], upload_double: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.api.errors import BULK_TOO_MANY_FILES
    from redsim.api.v1.models_bulk import BULK_MAX_FILES_ENV, BULK_UPLOAD_ACTION

    del e2e_bundled
    remediator, scanner, viewer = e2e_org.client("remediator"), e2e_org.client("scanner"), e2e_org.client("viewer")
    project_chain = f"project:{e2e_org.project_id}"
    paths: list[Path] = list(upload_double["state_dicts"])
    items = [{
        "filename": path.name, "name": path.stem, "modality": "image", "declared_format": "torch_state_dict",
        "architecture_id": "small_cnn", "dataset_id": upload_double["dataset_id"],
        "dataset_split": upload_double["dataset_split"], "license_statement": LICENSE_STATEMENT,
    } for path in paths]
    manifest = json.dumps({"project_id": e2e_org.project_id, "items": items})
    parts = [("files", (path.name, path.read_bytes(), "application/octet-stream")) for path in paths]

    # the gate: model.register is remediator and above; nothing is written for a scanner or a viewer
    targets_before, runs_before = _count(e2e_app, "Target"), _count(e2e_app, "Run")
    assert scanner.post("/v1/models/bulk", data={"manifest": manifest}, files=parts).status_code == 403
    assert viewer.post("/v1/models/bulk", data={"manifest": manifest}, files=parts).status_code == 403
    assert _count(e2e_app, "Target") == targets_before

    response = remediator.post("/v1/models/bulk", data={"manifest": manifest}, files=parts)
    assert response.status_code == 201, response.text
    body = response.json()
    bulk_id = str(body["bulk_id"])
    assert bulk_id.startswith("bulk-") and body["kind"] == "upload" and body["project_id"] == e2e_org.project_id
    assert body["n_files"] == 2 and body["n_admitted"] == 2 and body["n_refused"] == 0
    results = body["results"]
    assert [r["filename"] for r in results] == [p.name for p in paths]
    assert all(r["status"] == "validating" and r["enqueued"] is True and r["detected_format"] == "torch_state_dict"
               for r in results)
    assert [r["sha256"] for r in results] == [_sha256(p.read_bytes()) for p in paths]
    assert len({r["target_id"] for r in results}) == 2 and len({r["ingest_run_id"] for r in results}) == 2

    # every file went through the single-upload admission: its own Target, ml.ingest Run and validate Job
    assert _count(e2e_app, "Target") == targets_before + 2 and _count(e2e_app, "Run") == runs_before + 2
    validation_defects: list[str] = []
    for result, path in zip(results, paths, strict=True):
        record = _wait_for_validation(remediator, str(result["target_id"]))
        assert record["source"] == "upload" and record["manifest"]["format"] == "torch_state_dict"
        assert record["manifest"]["sha256"] == result["sha256"] and record["manifest"]["architecture_id"] == "small_cnn"
        assert record["manifest"]["class_names"] == upload_double["class_names"]
        stored = h.registered_target(e2e_app, str(result["target_id"]))
        assert stored["kind"] == "ml_model_artifact" and stored["detail"]["bulk_id"] == bulk_id
        ingest = _run(remediator, str(result["ingest_run_id"]))
        assert ingest["status"] == "succeeded" and ingest["stage_table"].get("bulk_id") == bulk_id
        job = _job(e2e_app, str(result["ingest_job_id"]))
        assert job["type"] == "model.validate" and job["status"] == "succeeded" and job["detail"]["bulk_id"] == bulk_id
        # its own model.register row, first on the ingest run's chain, carrying the bulk id (spec 5.11, 9.3)
        chain = e2e_app.read_chain(f"run:{result['ingest_run_id']}")
        assert [ev["action"] for ev in chain] == ["model.register", "model.validate", "job.complete"], chain
        register = chain[0]
        assert register["success"] is True and register["actor"] == e2e_org.actor("remediator")
        assert register["detail"]["bulk_id"] == bulk_id and register["detail"]["target_id"] == result["target_id"]
        assert register["detail"]["sha256"] == result["sha256"] and register["detail"]["source"] == "upload"
        assert register["detail"]["detected_format"] == "torch_state_dict"
        # the validate row says what the child decided; a refusal is on the chain as success=False (spec 9.5)
        assert chain[1]["success"] is (record["status"] == "available") and chain[1]["detail"]["status"] == record["status"]
        if record["status"] == "available":
            assert record["manifest"]["gradients"] is True and record["refusal_reason"] is None
        else:
            validation_defects.append(
                f"{path.name}: {record.get('refusal_reason')}: {record.get('reason')}")
    if validation_defects:
        # Recorded after the rest of the test ran; raised at the end so the cap check below still executes.
        validation_defects.insert(0, (
            "product defect, not a harness problem: a catalog small_cnn state_dict for the 3-class harness dataset "
            "was admitted (Target, ml.ingest Run, model.register row per file) but refused by the validate child. "
            "redsim/services/ml_models.py:500 artifact_target_from_path passes "
            "architecture_kwargs=dict(manifest.get('architecture_kwargs') or {}) and neither POST /v1/models nor "
            "POST /v1/models/bulk accepts or derives that block, so redsim/ml/targets/artifact.py:resolve_architecture "
            "builds SmallCNN() with its catalog defaults (in_channels=3, n_classes=10, image_size=32) and "
            "load_state_dict(strict=True) fails for any state_dict whose class count is the dataset binding's "
            "(class_names, 3 here) rather than 10: no torch_state_dict / safetensors upload can reach 'available' "
            "on a dataset with other than 10 classes (spec 9.2, 26.4 item 17)."))
    with e2e_app.session() as sess:
        from redsim.db.models import MlBatch

        row = sess.get(MlBatch, bulk_id)
        assert row is not None and row.kind == "upload" and row.project_id == e2e_org.project_id
        assert row.created_by == e2e_org.actor("remediator")
        assert row.config["n_admitted"] == 2 and row.config["n_refused"] == 0
        assert sorted(row.config["target_ids"]) == sorted(r["target_id"] for r in results)
        assert "license_statement" not in json.dumps(row.config["items"])
    bulk_rows = [ev for ev in _events(e2e_app, project_chain, BULK_UPLOAD_ACTION) if ev["detail"].get("bulk_id") == bulk_id]
    assert len(bulk_rows) == 1 and bulk_rows[0]["success"] is True and bulk_rows[0]["actor"] == e2e_org.actor("remediator")
    assert bulk_rows[0]["detail"]["n_files"] == 2 and bulk_rows[0]["detail"]["filenames"] == [p.name for p in paths]
    assert bulk_rows[0]["detail"]["declared_formats"] == ["torch_state_dict", "torch_state_dict"]
    listing = viewer.get("/v1/models", params={"project": e2e_org.project_id}).json()["models"]
    assert {r["target_id"] for r in results} <= {m["id"] for m in listing if m["source"] == "upload"}
    assert body["status_url"] == f"{CAPACITY_ROUTE}?project={e2e_org.project_id}"

    # over the file-count cap: 422 bulk_too_many_files before any row, audited as a refused bulk.upload
    targets_before, runs_before = _count(e2e_app, "Target"), _count(e2e_app, "Run")
    batches_before = _count(e2e_app, "MlBatch")
    refused_before = len([ev for ev in _events(e2e_app, project_chain, BULK_UPLOAD_ACTION) if not ev["success"]])
    monkeypatch.setenv(BULK_MAX_FILES_ENV, "1")
    capped = remediator.post("/v1/models/bulk", data={"manifest": manifest}, files=parts)
    assert capped.status_code == 422 and _code(capped) == BULK_TOO_MANY_FILES, capped.text
    assert _detail(capped)["field"] == "files" and _detail(capped)["max_files"] == 1 and _detail(capped)["n_files"] == 2
    assert _count(e2e_app, "Target") == targets_before and _count(e2e_app, "Run") == runs_before
    refused = [ev for ev in _events(e2e_app, project_chain, BULK_UPLOAD_ACTION) if not ev["success"]]
    assert len(refused) == refused_before + 1 and refused[-1]["detail"]["reason"] == BULK_TOO_MANY_FILES
    assert refused[-1]["detail"]["max_files"] == 1 and refused[-1]["detail"]["n_files"] == 2
    assert _count(e2e_app, "MlBatch") == batches_before, "no batch row for a refused request"
    monkeypatch.delenv(BULK_MAX_FILES_ENV, raising=False)
    assert _capacity(remediator, e2e_org.project_id) is not None
    limits = remediator.get(CAPACITY_ROUTE, params={"project": e2e_org.project_id}).json()["limits"]
    assert limits["bulk_upload"]["max_files"] >= 2 and BULK_MAX_FILES_ENV in limits["env"]["bulk_upload"]
    if validation_defects:
        pytest.fail("\n".join(validation_defects), pytrace=False)


# ---------------------------------------------------------------------------
# 2. A batch over two image models completes and compares by comparability (BULK-03..07)
# ---------------------------------------------------------------------------


def test_batch_over_two_models_completes_and_compares(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], onnx_model: dict[str, Any],
) -> None:
    from redsim.api.errors import INCOMPATIBLE_CAMPAIGNS, SCORE_UNAVAILABLE

    scanner, viewer = e2e_org.client("scanner"), e2e_org.client("viewer")
    cnn, onnx = e2e_bundled[h.IMAGE_MODEL_ID], onnx_model["model_id"]
    project_chain = f"project:{e2e_org.project_id}"
    campaign = h.image_campaign()
    assert viewer.post(BATCH_ROUTE, json={"project_id": e2e_org.project_id, "target_ids": [cnn, onnx],
                                          "campaign": campaign}).status_code == 403, "batch.run is scanner+"
    missing_project = scanner.post(BATCH_ROUTE, json={"target_ids": [cnn], "campaign": campaign})
    assert missing_project.status_code == 422 and _detail(missing_project)["field"] == "project_id"

    response = _post_batch(scanner, e2e_org.project_id, [cnn, onnx], campaign)
    assert response.status_code == 202, response.text
    body = response.json()
    batch_id = str(body["batch_id"])
    assert batch_id.startswith("batch-") and body["kind"] == "campaign" and body["modality"] == "image"
    assert [m["target_id"] for m in body["members"]] == [cnn, onnx] and body["refused"] == []
    assert body["n_members"] == 2 and body["run_ids"] == [m["run_id"] for m in body["members"]]
    assert all(m["deferred"] is False for m in body["members"]) and len(body["config_hash"]) == 64
    _assert_no_aggregate(body)

    # every member is a single-run admission that ran through the real child and carries the batch id
    for member in body["members"]:
        run = h.wait_for_run(scanner, str(member["run_id"]), timeout_s=30.0)
        assert run["status"] == "succeeded", f"member {member['run_id']}: {run.get('stage_table')}"
        assert run["stage_table"]["batch_id"] == batch_id
        assert _campaign_batch_id(e2e_app, str(member["run_id"])) == batch_id
        record = _campaign(viewer, str(member["run_id"]))
        assert record["config"]["target_id"] == member["target_id"] and record["config"]["n_samples"] == campaign["n_samples"]
        assert record["config"]["attack_ids"] == campaign["attack_ids"] and record["limitations"]
        job = _job(e2e_app, str(member["job_ids"][0]))
        assert job["status"] == "succeeded" and job["detail"]["batch_id"] == batch_id and "deferred" not in job["detail"]
        admission = _events(e2e_app, f"run:{member['run_id']}", "attack.run")[0]
        assert admission["success"] is True and admission["actor"] == e2e_org.actor("scanner")
    batch_rows = [ev for ev in _events(e2e_app, project_chain, "batch.create") if ev["detail"].get("batch_id") == batch_id]
    assert len(batch_rows) == 1 and batch_rows[0]["success"] is True
    assert batch_rows[0]["detail"]["target_ids"] == [cnn, onnx] and batch_rows[0]["detail"]["modality"] == "image"
    assert batch_rows[0]["detail"]["config_hash"] == body["config_hash"] and batch_rows[0]["run_id"] is None
    assert "campaign" not in batch_rows[0]["detail"], "the body never reaches the chain; ids and digests only"

    # the roll-up: statuses, counts and scorecard links, never a number (BULK-06)
    view = _batch_view(viewer, batch_id)
    assert view["status"] == "succeeded" and view["state"] == "terminal" and view["kind"] == "campaign"
    assert view["counts"] == {"queued": 0, "running": 0, "succeeded": 2, "failed": 0, "cancelled": 0, "refused": 0}
    assert [m["target_id"] for m in view["members"]] == [cnn, onnx]
    assert [m["run_id"] for m in view["members"]] == body["run_ids"]
    for member in view["members"]:
        assert member["status"] == "succeeded" and member["kind"] == "attack" and member["modality"] == "image"
        assert member["status_url"] == f"/v1/runs/{member['run_id']}" and member["attack_ids"] == campaign["attack_ids"]
        assert member["score_status"] in {"scored", "unavailable"}
        assert (member["scorecard_url"] == f"/v1/runs/{member['run_id']}/campaign") is (member["score_status"] == "scored")
        assert "mri" not in member and "grade" not in member
    assert view["requested"]["target_ids"] == [cnn, onnx] and view["cancel_requested_at"] is None
    listed = viewer.get(BATCH_ROUTE, params={"project": e2e_org.project_id}).json()
    assert any(row["batch_id"] == batch_id and row["status"] == "succeeded" for row in listed["batches"])
    _assert_no_aggregate(listed)
    assert e2e_org.client(h.OUTSIDER).get(f"{BATCH_ROUTE}/{batch_id}").status_code in (403, 404)

    # the compare view groups scorecards by comparability; nothing is computed across members (BULK-07, D9 i)
    records = {run_id: _campaign(viewer, run_id) for run_id in body["run_ids"]}
    scored = [run_id for run_id, rec in records.items() if rec.get("score") and rec["score"].get("mri") is not None]
    compare = viewer.get(f"{BATCH_ROUTE}/{batch_id}/compare")
    if compare.status_code == 200:
        table = compare.json()
        _assert_no_aggregate(table)
        assert table["mode"] == "batch_side_by_side" and table["n_groups"] == 1 and table["compatible"] is True
        assert table["batch_id"] == batch_id and table["run_ids"] == body["run_ids"]
        group = table["groups"][0]
        assert group["run_ids"] == scored and len(group["scorecards"]) == len(scored)
        for card in group["scorecards"]:
            # spec 15.7: an MRI never travels without its subscores, the family table and the curve
            assert card["mri"] is not None and set(card["subscores"]) == {"S_acc", "S_asr", "S_eps", "S_conf", "S_expl"}
            assert card["measurements"] and card["curve"] and card["limitations"]
            assert card.get("delta") is None, "no delta is computed in a batch compare"
        assert group["changed_variables"] == (["model"] if len(scored) > 1 else [])
        assert "sample_indices_sha256" in group["key"] and "n_samples" in group["key"]
        assert [u["run_id"] for u in table["unavailable"]] == [r for r in body["run_ids"] if r not in scored]
        assert "no delta" in table["statement"] and "mean" in table["statement"]
    else:
        assert compare.status_code == 409, compare.text
        detail = _detail(compare)
        _assert_no_aggregate(detail)
        if detail["code"] == INCOMPATIBLE_CAMPAIGNS:
            assert len(detail["groups"]) >= 2 and all(g["run_ids"] for g in detail["groups"])
            assert detail["reasons"] and detail["pairs"] and "not compared across settings" in detail["message"]
            assert {r for g in detail["groups"] for r in g["run_ids"]} == set(scored)
        else:
            assert detail["code"] == SCORE_UNAVAILABLE and not scored, "only when no member carries a complete score"
            assert detail["reasons"] and all(any(run_id in r for r in detail["reasons"]) for run_id in body["run_ids"])
    assert viewer.get(f"{BATCH_ROUTE}/batch-does-not-exist").status_code == 404


# ---------------------------------------------------------------------------
# 3. A batch is one modality (BULK-04, D9 i)
# ---------------------------------------------------------------------------


def test_batch_mixing_modalities_is_refused_with_groups(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], onnx_model: dict[str, Any],
) -> None:
    from redsim.api.errors import BATCH_MODALITY_MISMATCH, NOT_FOUND, PARAMS_OUT_OF_RANGE

    scanner = e2e_org.client("scanner")
    cnn, trees, onnx = e2e_bundled[h.IMAGE_MODEL_ID], e2e_bundled[h.TABULAR_MODEL_ID], onnx_model["model_id"]
    project_chain = f"project:{e2e_org.project_id}"
    runs_before, batches_before = _count(e2e_app, "Run"), _count(e2e_app, "MlBatch")
    refused_before = len([ev for ev in _events(e2e_app, project_chain, "batch.create") if not ev["success"]])

    mixed = _post_batch(scanner, e2e_org.project_id, [cnn, trees, onnx], h.image_campaign(explain_k=0))
    assert mixed.status_code == 422 and _code(mixed) == BATCH_MODALITY_MISMATCH, mixed.text
    detail = _detail(mixed)
    assert detail["field"] == "target_ids" and detail["groups"] == {"image": [cnn, onnx], "tabular": [trees]}
    assert "never aggregated across modalities" in detail["message"]
    assert _count(e2e_app, "Run") == runs_before and _count(e2e_app, "MlBatch") == batches_before, "nothing admitted"
    refused = [ev for ev in _events(e2e_app, project_chain, "batch.create") if not ev["success"]]
    assert len(refused) == refused_before + 1 and refused[-1]["detail"]["code"] == BATCH_MODALITY_MISMATCH
    assert refused[-1]["detail"]["groups"] == detail["groups"] and refused[-1]["detail"]["target_ids"] == [cnn, trees, onnx]

    # the other write-free pre-checks refuse before any row too
    unknown = _post_batch(scanner, e2e_org.project_id, [cnn, "model-does-not-exist"], h.image_campaign(explain_k=0))
    assert unknown.status_code == 404 and _code(unknown) == NOT_FOUND and _detail(unknown)["target_ids"] == ["model-does-not-exist"]
    with_target = _post_batch(scanner, e2e_org.project_id, [cnn], {**h.image_campaign(explain_k=0), "target_id": cnn})
    assert with_target.status_code == 422 and _code(with_target) == PARAMS_OUT_OF_RANGE
    repeated = _post_batch(scanner, e2e_org.project_id, [cnn, cnn], h.image_campaign(explain_k=0))
    assert repeated.status_code == 422 and _code(repeated) == PARAMS_OUT_OF_RANGE
    assert _count(e2e_app, "Run") == runs_before and _count(e2e_app, "MlBatch") == batches_before


# ---------------------------------------------------------------------------
# 4. Capacity: deferral under the concurrency cap, the continuation dispatch, batch cancel (BULK-08, -20..22)
# ---------------------------------------------------------------------------


def test_capacity_deferral_dispatch_and_batch_cancel(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], onnx_model: dict[str, Any],
) -> None:
    from redsim.api.errors import RUN_TERMINAL
    from redsim.services.ml_capacity import CAPACITY_KEY, DEFERRED_KEY
    from redsim.workers.tasks.capacity import continue_deferred

    scanner, remediator, viewer = e2e_org.client("scanner"), e2e_org.client("remediator"), e2e_org.client("viewer")
    cnn, onnx = e2e_bundled[h.IMAGE_MODEL_ID], onnx_model["model_id"]
    project_id = e2e_org.project_id
    project_chain = f"project:{project_id}"

    with _project_caps(e2e_app, project_id, max_concurrent=1):
        seeded_run, seeded_job = _seed_running_job(e2e_app, project_id=project_id, target_id=cnn,
                                                   actor=e2e_org.actor("scanner"))
        try:
            before = _capacity(scanner, project_id)
            assert before["max_concurrent_runs"] == 1 and before["sources"]["max_concurrent_runs"] == "project"
            assert before["running_jobs"] == 1 and before["active_runs"] == 1 and before["slots_free"] == 0
            assert before["deferred_runs"] == 0 and before["daily_run_budget"] is None
            assert before["budget_remaining"] is None and before["resets_at"].endswith("Z")

            # both members are admitted, written as queued jobs and deferred: no refusal, no broker message
            response = _post_batch(scanner, project_id, [onnx, cnn], h.image_campaign(explain_k=0))
            assert response.status_code == 202, response.text
            body = response.json()
            batch_id = str(body["batch_id"])
            assert body["status"] == "queued" and [m["deferred"] for m in body["members"]] == [True, True]
            first, second = body["members"]
            for member in body["members"]:
                run = _run(viewer, str(member["run_id"]))
                assert run["status"] == "queued", run
                assert run["stage_table"][DEFERRED_KEY] is True and run["stage_table"]["batch_id"] == batch_id
                stamp = run["stage_table"][CAPACITY_KEY]
                assert stamp["deferred"] is True and stamp["active_runs"] == 1 and stamp["max_concurrent_runs"] == 1
                assert "1 of 1 concurrent ML runs in use" in stamp["reason"]
                job = _job(e2e_app, str(member["job_ids"][0]))
                assert job["status"] == "queued" and job["detail"][DEFERRED_KEY] is True
                assert job["detail"][CAPACITY_KEY]["active_runs"] == 1 and job["celery_task_id"] is None
                assert _events(e2e_app, f"run:{member['run_id']}", "attack.run")[0]["success"] is True
            during = _capacity(scanner, project_id)
            assert during["deferred_runs"] == 2 and during["queued_jobs"] == 2 and during["active_runs"] == 1
            assert during["slots_free"] == 0 and during["used_today"] >= before["used_today"] + 2
            view = _batch_view(viewer, batch_id)
            assert view["status"] == "queued" and view["state"] == "active"
            assert all(m["deferred"] is True and m["score_status"] == "pending" for m in view["members"])

            # the slot frees: the finishing worker's continuation hook dispatches the oldest deferred job.
            # The hook is called as the seeded job's worker would call it, after its body and BEFORE its terminal
            # status is committed (redsim.workers.tasks.capacity.deferred_continuation: "the finishing job is
            # excluded from the slot count so the hook is correct whether it runs before or after task_context
            # commits"); the hand-written terminal status lands right after. Test-isolation note: with the eager
            # harness the dispatched member runs to completion INSIDE this call and its own continuation hook then
            # looks for a free slot; while the seeded job still reads ``running`` it finds none, so exactly one
            # member is dispatched here and the second stays deferred for the cancel below. Finishing the seeded
            # job first would let the eager cascade dispatch both (the product doing its job), leaving nothing
            # queued to cancel.
            report = continue_deferred(project_id, finishing_job_id=seeded_job)
            _finish_job(e2e_app, seeded_run, seeded_job)
            assert report["dispatched"] == {project_id: [first["job_ids"][0]]}, report
            assert report["still_deferred"] == {project_id: 1}
            dispatched = _run(viewer, str(first["run_id"]))
            assert dispatched["status"] == "succeeded", dispatched.get("stage_table")
            assert dispatched["stage_table"][DEFERRED_KEY] is False and dispatched["stage_table"][CAPACITY_KEY]["dispatched_at"]
            job = _job(e2e_app, str(first["job_ids"][0]))
            assert job["status"] == "succeeded" and job["detail"][DEFERRED_KEY] is False and job["celery_task_id"]
            assert _campaign(viewer, str(first["run_id"]))["config"]["target_id"] == onnx
            waiting = _job(e2e_app, str(second["job_ids"][0]))
            assert waiting["status"] == "queued" and waiting["detail"][DEFERRED_KEY] is True
            after = _capacity(scanner, project_id)
            assert after["deferred_runs"] == 1 and after["active_runs"] == 0 and after["slots_free"] == 1
            view = _batch_view(viewer, batch_id)
            assert view["status"] == "running" and view["counts"]["succeeded"] == 1 and view["counts"]["queued"] == 1

            # cancel the batch with its queued member: batch.cancel first, then run.cancel per live member
            assert viewer.post(f"{BATCH_ROUTE}/{batch_id}/cancel").status_code == 403
            assert scanner.post(f"{BATCH_ROUTE}/{batch_id}/cancel").status_code == 403, "run.cancel is remediator+"
            cancelled = remediator.post(f"{BATCH_ROUTE}/{batch_id}/cancel")
            assert cancelled.status_code == 200, cancelled.text
            assert cancelled.json()["cancelled"] == [second["run_id"]] and cancelled.json()["jobs_cancelled"] == 1
            assert [a["run_id"] for a in cancelled.json()["already_terminal"]] == [first["run_id"]]
            assert cancelled.json()["status"] == "partial"
            assert _run(viewer, str(second["run_id"]))["status"] == "cancelled"
            assert _job(e2e_app, str(second["job_ids"][0]))["status"] == "cancelled"
            batch_cancel = [ev for ev in _events(e2e_app, project_chain, "batch.cancel") if ev["detail"].get("batch_id") == batch_id]
            assert len(batch_cancel) == 1 and batch_cancel[0]["success"] is True
            assert batch_cancel[0]["detail"]["cancelling"] == [second["run_id"]]
            assert batch_cancel[0]["detail"]["already_terminal"] == [first["run_id"]]
            assert "run.cancel" in _actions(e2e_app, f"run:{second['run_id']}")
            view = _batch_view(viewer, batch_id)
            assert view["status"] == "partial" and view["state"] == "terminal" and view["cancel_requested_at"]
            assert view["counts"]["succeeded"] == 1 and view["counts"]["cancelled"] == 1
            again = remediator.post(f"{BATCH_ROUTE}/{batch_id}/cancel")
            assert again.status_code == 409 and _code(again) == RUN_TERMINAL
            assert _capacity(scanner, project_id)["deferred_runs"] == 0
        finally:
            _finish_job(e2e_app, seeded_run, seeded_job)


# ---------------------------------------------------------------------------
# 5. The daily budget refuses with an audited row (BULK-20, -21)
# ---------------------------------------------------------------------------


def test_daily_budget_refuses_with_an_audited_row(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str],
) -> None:
    from redsim.api.errors import BATCH_MEMBER_REFUSED, DAILY_BUDGET_EXCEEDED, HTTP_STATUS

    scanner = e2e_org.client("scanner")
    cnn = e2e_bundled[h.IMAGE_MODEL_ID]
    project_id = e2e_org.project_id
    project_chain = f"project:{project_id}"
    used = _capacity(scanner, project_id)["used_today"]
    assert used >= 1, "earlier admissions of this session count against today's budget"

    with _project_caps(e2e_app, project_id, daily_budget=used):
        view = _capacity(scanner, project_id)
        assert view["daily_run_budget"] == used and view["sources"]["daily_run_budget"] == "project"
        assert view["budget_remaining"] == 0 and "cancelled runs count" in view["budget_window"]
        runs_before = _count(e2e_app, "Run")
        events_before = len(e2e_app.read_chain(project_chain))

        refused = _post_batch(scanner, project_id, [cnn], h.image_campaign(explain_k=0))
        assert refused.status_code == 422 and _code(refused) == BATCH_MEMBER_REFUSED, refused.text
        members = _detail(refused)["members"]
        assert len(members) == 1 and members[0]["target_id"] == cnn and members[0]["attempted"] is True
        assert members[0]["code"] == DAILY_BUDGET_EXCEEDED, members[0]
        assert HTTP_STATUS[DAILY_BUDGET_EXCEEDED] == 429, "the refusal's own status is 429"
        assert members[0]["budget"] == used and members[0]["used"] == used and members[0]["requested"] == 1
        assert members[0]["resets_at"].endswith("Z") and members[0]["retry_after"] >= 1
        assert "resets at" in members[0]["message"]
        assert _count(e2e_app, "Run") == runs_before, "a refused admission writes no Run"

        # the chain: batch.create, then the budget refusal as a success=False attack.run row, then the batch refusal
        tail = e2e_app.read_chain(project_chain)[events_before:]
        assert [(ev["action"], ev["success"]) for ev in tail] == [
            ("batch.create", True), ("attack.run", False), ("batch.create", False)]
        budget_row = tail[1]
        assert budget_row["detail"]["code"] == DAILY_BUDGET_EXCEEDED and budget_row["detail"]["http_status"] == 429
        assert budget_row["detail"]["budget"] == used and budget_row["detail"]["used_today"] == used
        assert budget_row["detail"]["requested"] == 1 and budget_row["detail"]["target_id"] == cnn
        assert budget_row["detail"]["batch_id"] == tail[0]["detail"]["batch_id"]
        assert budget_row["actor"] == e2e_org.actor("scanner") and budget_row["run_id"] is None
        assert tail[2]["detail"]["code"] == BATCH_MEMBER_REFUSED and tail[2]["detail"]["refused_codes"] == [DAILY_BUDGET_EXCEEDED]
        assert _capacity(scanner, project_id)["used_today"] == used, "a refused admission is not an admission"
    assert _capacity(scanner, project_id)["daily_run_budget"] is None


# ---------------------------------------------------------------------------
# 6. Bulk verify per the owner decision BULK-16 (BULK-15)
# ---------------------------------------------------------------------------


def test_bulk_verify_projects_one_defended_run(
    e2e_app: E2EApp, e2e_org: E2EOrg, finding_campaign: h.CampaignRun,
) -> None:
    from redsim.workers.tasks.ml_campaign import VERIFY_STATUS_MAP
    from redsim.workers.tasks.verify import _STATE_MAP

    scanner, remediator, viewer = e2e_org.client("scanner"), e2e_org.client("remediator"), e2e_org.client("viewer")
    run_id = finding_campaign.run_id
    baseline = finding_campaign.campaign
    assert baseline is not None
    finding_ids = [str(f["id"]) for f in finding_campaign.findings if f["status"] == "open"]
    anchor = finding_ids[0]
    project_chain = f"project:{e2e_org.project_id}"
    route = f"/v1/findings/{anchor}/verify/bulk"
    body = {"defenses": [{"defense": FEATURE_SQUEEZING, "params": {"bit_depth": 6}}, {"defense": FEATURE_SQUEEZING,
                                                                                       "params": {"bit_depth": 6}}]}

    assert scanner.post(route, json=body).status_code == 403, "verify.replay is remediator+"
    assert viewer.post(route, json=body).status_code == 403
    assert remediator.post("/v1/findings/finding-does-not-exist/verify/bulk", json=body).status_code == 404
    response = remediator.post(route, json=body)
    assert response.status_code == 202, response.text
    handle = response.json()
    batch_id = str(handle["batch_id"])
    assert handle["kind"] == "verify" and handle["baseline_run_id"] == run_id and handle["modality"] == "image"
    assert handle["finding_ids"] == finding_ids and handle["primary_finding_id"] == anchor and handle["skipped"] == []
    assert len(handle["members"]) == 1 and handle["refused"] == [], "the duplicate defense collapsed"
    member = handle["members"][0]
    assert member["defense"]["id"] == FEATURE_SQUEEZING and member["defense"]["params"] == {"bit_depth": 6}
    assert member["primary_finding_id"] == anchor and member["deferred"] is False
    _assert_no_aggregate(handle)

    # one defended run, kind verify, at the baseline's settings, listing every selected finding
    verify_run = h.wait_for_run(viewer, str(member["run_id"]), timeout_s=30.0)
    assert verify_run["status"] == "succeeded", verify_run.get("stage_table")
    assert verify_run["stage_table"]["batch_id"] == batch_id and verify_run["stage_table"]["finding_ids"] == finding_ids
    record = _campaign(viewer, str(member["run_id"]))
    assert record["kind"] == "verify" and record["baseline_run_id"] == run_id
    assert record["settings_hash"] == baseline["settings_hash"] and record["config"]["defense"]["id"] == FEATURE_SQUEEZING
    job = _job(e2e_app, str(member["job_ids"][0]))
    assert job["type"] == "verify.replay" and job["status"] == "succeeded"
    assert job["detail"]["finding_ids"] == finding_ids and job["detail"]["finding_id"] == anchor
    assert job["detail"]["batch_id"] == batch_id and job["detail"]["baseline_run_id"] == run_id

    # audit: batch.create, then the single route's verify.replay row plus one per additional finding
    batch_rows = [ev for ev in _events(e2e_app, project_chain, "batch.create") if ev["detail"].get("batch_id") == batch_id]
    assert len(batch_rows) == 1 and batch_rows[0]["success"] is True and batch_rows[0]["detail"]["kind"] == "verify"
    assert batch_rows[0]["detail"]["finding_ids"] == finding_ids and batch_rows[0]["detail"]["defense_ids"] == [FEATURE_SQUEEZING]
    replay_rows = _events(e2e_app, f"run:{member['run_id']}", "verify.replay")
    assert [ev["detail"]["finding_id"] for ev in replay_rows] == finding_ids
    assert all(ev["success"] and ev["actor"] == e2e_org.actor("remediator") for ev in replay_rows)
    for extra in replay_rows[1:]:
        assert extra["detail"]["shared_run_id"] == member["run_id"] and extra["detail"]["batch_id"] == batch_id
        assert extra["detail"]["projection"] == "shared defended run (BULK-16)"
    actions = _actions(e2e_app, f"run:{member['run_id']}")
    assert actions[0] == "verify.replay" and "verify.execute" in actions and "job.complete" in actions
    # With eager Celery the member ran inside its own admission, so the rows binding the other findings land
    # after the worker's job.complete; the chain is one sequence either way (verified by test_audit_verify_all).
    assert actions.index("verify.execute") < actions.index("job.complete")

    # the projection onto the selected findings (owner decision BULK-16)
    view = _batch_view(viewer, batch_id)
    assert view["kind"] == "verify" and view["status"] == "succeeded"
    assert view["requested"]["finding_ids"] == finding_ids and view["requested"]["baseline_run_id"] == run_id
    shown = view["members"][0]
    assert shown["kind"] == "verify" and shown["defense"]["id"] == FEATURE_SQUEEZING and shown["finding_ids"] == finding_ids
    projected = {row["finding_id"]: row for row in shown["findings"]}
    assert set(projected) == set(finding_ids)
    primary = projected[anchor]
    assert primary["projected"] is True and primary["outcome"] in _STATE_MAP
    anchor_row = viewer.get(f"/v1/findings/{anchor}").json()
    assert anchor_row["schema_blob"]["ml"]["verify"]["run_id"] == member["run_id"]
    assert anchor_row["status"] == VERIFY_STATUS_MAP[primary["outcome"]]
    assert anchor_row["validation_state"] == _STATE_MAP[primary["outcome"]]
    assert anchor_row["schema_blob"]["ml"]["retests"][-1]["settings_hash"] == baseline["settings_hash"]
    unprojected = [fid for fid in finding_ids if projected[fid]["projected"] is not True]
    if unprojected:
        pytest.fail(_BULK_VERIFY_PROJECTION_DEFECT.format(finding_ids=finding_ids, unprojected=unprojected,
                                                          run_id=member["run_id"]), pytrace=False)
    for fid in finding_ids:
        row = viewer.get(f"/v1/findings/{fid}").json()
        assert row["schema_blob"]["ml"]["verify"]["run_id"] == member["run_id"]
        assert row["status"] == VERIFY_STATUS_MAP[projected[fid]["outcome"]]


# ---------------------------------------------------------------------------
# 7. The single-run admission under the same concurrency cap (BULK-20, -21)
# ---------------------------------------------------------------------------


def test_single_run_admission_enforces_capacity(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str],
) -> None:
    from redsim.api.errors import CAPACITY_DEFERRED, MARKER_CODES
    from redsim.services.ml_capacity import DEFERRED_KEY
    from redsim.workers.tasks.capacity import continue_deferred

    scanner, viewer = e2e_org.client("scanner"), e2e_org.client("viewer")
    cnn = e2e_bundled[h.IMAGE_MODEL_ID]
    project_id = e2e_org.project_id
    assert CAPACITY_DEFERRED in MARKER_CODES, "capacity_deferred is a 202 marker, never a refusal"

    with _project_caps(e2e_app, project_id, max_concurrent=1):
        seeded_run, seeded_job = _seed_running_job(e2e_app, project_id=project_id, target_id=cnn,
                                                   actor=e2e_org.actor("scanner"))
        try:
            assert _capacity(scanner, project_id)["slots_free"] == 0
            launch = scanner.post(f"/v1/models/{cnn}/attacks", json=h.image_campaign(explain_k=0))
            assert launch.status_code == 202, launch.text
            body = launch.json()
            run = _run(viewer, str(body["run_id"]))
            job = _job(e2e_app, str(body["job_ids"][0]))
            deferred = (body.get("deferred") is True and (body.get("capacity") or {}).get("code") == CAPACITY_DEFERRED
                        and run["status"] == "queued" and job["detail"].get(DEFERRED_KEY) is True)
            if not deferred:
                pytest.fail(_SINGLE_ROUTE_CAPACITY_DEFECT.format(status=launch.status_code, keys=sorted(body),
                                                                 run_status=run["status"]), pytrace=False)
            # the product gates the single route: the slot frees, the continuation dispatches, the run completes
            _finish_job(e2e_app, seeded_run, seeded_job)
            report = continue_deferred(project_id, finishing_job_id=seeded_job)
            assert report["dispatched"] == {project_id: [job["id"]]}
            assert h.wait_for_run(viewer, str(body["run_id"]), timeout_s=30.0)["status"] == "succeeded"
        finally:
            _finish_job(e2e_app, seeded_run, seeded_job)


# ---------------------------------------------------------------------------
# 8. The CLI matrix: one offline run and one verifiable chain per cell (BULK-17, -18)
# ---------------------------------------------------------------------------


def test_cli_matrix_one_verifiable_chain_per_cell(
    e2e_app: E2EApp, e2e_bundled: dict[str, str], tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    from redsim.audit.chain import verify_chain
    from redsim.cli.main import main
    from redsim.ml.schema import CampaignRecord

    del e2e_bundled  # the CLI resolves the registry from REDSIM_ML_ASSETS_DIR, not from the platform rows
    matrix = tmp_path / "grid.yaml"
    matrix.write_text(
        "name: e2e-two-targets\n"
        f"models: [{h.IMAGE_MODEL_ID}, {h.TABULAR_MODEL_ID}]\n"
        "attack_sets:\n  - [pgd]\n"
        "eps_grids:\n  - [0.03, 0.1]\n"
        "seeds: [0]\n"
        "n_samples: 12\n"
        "explain_k: 0\n",
        encoding="utf-8",
    )
    out = tmp_path / "runs"
    runs_before = _count(e2e_app, "Run")
    try:
        main(["ml", "attack", "--matrix", str(matrix), "--out", str(out), "--actor", "cli:e2e-matrix"])
    except SystemExit as exc:
        captured = capsys.readouterr()
        assert exc.code in (None, 0), f"redsim ml attack --matrix exited {exc.code}:\n{captured.out}\n{captured.err}"
    captured = capsys.readouterr()
    text = captured.out

    summaries = list(out.glob("matrix-*/summary.json"))
    assert len(summaries) == 1, sorted(p.name for p in out.iterdir())
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    assert (summary["n_cells"], summary["n_succeeded"], summary["n_refused"], summary["n_failed"]) == (2, 2, 0, 0)
    assert summary["source"]["name"] == "e2e-two-targets" and summary["source"]["matrix_file"] == str(matrix)
    assert "no value here is aggregated" in summary["note"]
    cells = summary["cells"]
    assert [c["cell"]["target_id"] for c in cells] == [h.IMAGE_MODEL_ID, h.TABULAR_MODEL_ID]
    run_dirs = sorted(p for p in out.iterdir() if p.is_dir() and p.name.startswith("run-"))
    assert len(run_dirs) == 2, "one run directory per cell"
    for cell in cells:
        assert cell["status"] == "succeeded" and cell["chain_verified"] is True and cell["chain_error"] is None
        assert cell["narrative_source"] == "rules" and cell["settings_hash"], "no Pythia offline (spec 10.8)"
        run_dir = Path(cell["run_dir"])
        assert run_dir.parent == out and run_dir.name == cell["run_id"]
        for name in ("audit.jsonl", "run_record.json", "report.md", "report.json", "report.html"):
            assert (run_dir / name).is_file(), name
        record = CampaignRecord.model_validate_json((run_dir / "run_record.json").read_text(encoding="utf-8"))
        assert record.status == "succeeded" and record.run_id == cell["run_id"]
        assert record.target.id == cell["cell"]["target_id"] and record.config.attack_ids == ["pgd"]
        assert record.config.eps_grid == [0.03, 0.1] and record.config.n_samples == 12 and record.config.explain_k == 0
        assert record.config.llm_narrative is False and record.limitations
        clean = next(m for m in record.measurements if m.family == "clean")
        assert clean.n == 12, "denominators on every row (spec 14.2)"
        # its own hash chain: attack.run first, job.complete last, every row on run:<run_id>, verified end to end
        lines = [json.loads(line) for line in (run_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
                 if line.strip()]
        assert lines[0]["action"] == "attack.run" and lines[-1]["action"] == "job.complete"
        assert {line["chain_id"] for line in lines} == {f"run:{cell['run_id']}"}
        assert all(line["actor"] == "cli:e2e-matrix" for line in lines)
        verdict = verify_chain(iter(lines))
        assert verdict.verified and len(lines) == cell["audit_events"], verdict
        assert lines[0]["detail"]["settings_hash"] == record.settings_hash
        if cell["mri"] is None:
            # explain_k = 0 leaves S_expl unavailable (spec 15.4): a partial score is never a number or a grade
            assert cell["grade"] is None and cell["score_state"] != "complete"
            assert record.score is None or record.score.mri is None
        else:
            assert cell["grade"] and cell["score_state"] == "complete" and record.score is not None
            assert record.score.mri == cell["mri"]
    assert cells[0]["settings_hash"] != cells[1]["settings_hash"], "different models, different settings hashes"

    # the table names every cell and each chain verdict, and no cross-cell aggregate word appears
    assert h.IMAGE_MODEL_ID in text and h.TABULAR_MODEL_ID in text
    assert text.count("verified") >= 2 and "2 cell(s): 2 succeeded, 0 refused, 0 failed" in text
    assert str(summaries[0]) in text
    lowered = text.lower().replace("nothing aggregated", "")
    for banned in ("mean", "average", "rank", "aggregate mri", "overall"):
        assert banned not in lowered, banned
    assert _count(e2e_app, "Run") == runs_before, "the offline CLI writes no platform rows"
