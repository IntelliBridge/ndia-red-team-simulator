"""Review workflow, PDF reports and snapshots, N-run compare, project weights, idempotency (wave B4).

Plan 12 wave B4, track ``e2e-review-reports-interop-bulk`` (register TESTS_DOCS-11,
-12, -13, -14; REVIEW_REPORTS-02..12, -16..22, -26, -30..32). Spec sections 6.4 and
7.7 (review states and the independent-approval rule), 14.8 and 15.7 (reports and
the scorecard), 15.6 and 15.8 (comparisons, no aggregate), 15.3 (per-project
weights), 17.3 (``Idempotency-Key``), 26.3 items 12 to 15 and 26.5 item 22, on the
shared harness of ``tests/e2e/conftest.py`` / ``tests/e2e/harness.py``.

Every test drives the production route, the admission service, the eager worker
and the real sandbox child, then asserts on what those left behind. The bundled
1-epoch CNN cannot yield a finding (8 of 24 clean-correct rows, below the spec
12.6 floor of 10), so the finding every review test needs comes from an
**uploaded** ``SmallCNN`` that memorises the harness's own seeded images,
registered through ``POST /v1/models`` and validated in the real child, exactly
as ``tests/e2e/test_ml_verify_upload_reports.py`` does. Nothing measured on it
is a demo result.

1. ``test_review_states_independence_and_conflicts``: the worker finding is
   ``unreviewed``; a stale ``expected_status`` is ``409 review_state_conflict``;
   the campaign creator is refused; an independent approver confirms; ``resolve``
   before any retest is ``409 resolution_blocked`` naming every unmet condition.
   An analyst draft goes ``draft -> in_review``, its author (an admin) is refused
   ``403 reviewer_not_independent`` on confirm, ``request_changes`` appends a
   revision and returns it to ``draft``, a resubmission is confirmed, and
   ``schema_blob.ml.review`` carries the history and the revisions.
2. ``test_retests_link_and_resolve_after_two_verifies``: two verifies (one by the
   remediator, one by the approver) append two ``FindingVerify`` links with the
   baseline's ``settings_hash``; ``GET /retests`` calls both compatible; the
   retest requester cannot resolve; an independent admin resolves only when the
   measured outcome is ``verified`` and is otherwise blocked with the unmet list.
3. ``test_report_pdf_snapshots_and_archive``: ``POST report.render`` then
   ``GET report.pdf`` starts with ``%PDF-`` and carries the six section titles
   and the grade statement; two renders are two immutable snapshot rows with
   per-format digests; an admin archives one and a non-admin fetch is
   ``409 snapshot_archived``.
4. ``test_compare_three_runs_table``: ``GET /v1/runs/compare?ids=`` over the
   baseline and its two verifies answers rows in request order with a delta
   only on the verify rows, no mean or rank anywhere; an incompatible triple is
   ``409 incompatible_campaigns`` naming the variable.
5. ``test_idempotency_key_replay_and_reuse``: a replayed ``Idempotency-Key``
   returns the identical response without a second admission; the same key
   with another body is ``409 idempotency_key_reused``.
6. ``test_project_scoring_weights_apply_to_the_next_campaign``: an admin sets a
   weight vector summing to one and the next campaign is scored with it
   (``non_default_weights`` true); a bad sum is ``422``; the override is cleared
   again so later files score with the default.

Run with::

    REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_ml_review_reports.py

The harness fixtures are not edited here; every helper lives in this file. Heavy
imports happen inside fixtures and tests, after the session fixtures have
checked the extras, so collection stays green without them.
"""

from __future__ import annotations

import hashlib
import io
import json
import warnings
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest

from tests.e2e import harness as h

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

    from tests.e2e.harness import E2EApp, E2EOrg

pytestmark = pytest.mark.e2e

#: The whole 24-row evaluation split: the largest denominators the tree offers.
N_EVAL = h.N_IMAGES // 2
#: The default finding threshold of spec 15.3; the memorising upload crosses it at eps 0.1.
FINDING_THRESHOLD = 0.2
#: The spec 16.5 Phase A defense the demo verifies with (also the route's default).
FEATURE_SQUEEZING = "feature_squeezing"
LICENSE_STATEMENT = "e2e harness double trained on seeded random pixels; no licence restriction applies"
#: The five MRI dimensions (spec 15.2).
SUBSCORE_KEYS = ("S_acc", "S_asr", "S_eps", "S_conf", "S_expl")
#: Keys a comparison payload never carries (spec 15.8 i; D9 i).
FORBIDDEN_TABLE_KEYS = frozenset({"mean", "rank", "average", "aggregate", "ranking"})
#: A non-default weight vector that sums to one (spec 15.3: never renormalised).
CUSTOM_WEIGHTS = {"acc": 0.4, "asr": 0.3, "eps": 0.1, "conf": 0.1, "expl": 0.1}

_PARTIAL_SCORE_DEFECT = (
    "product defect, not a harness problem: the campaign ran through the production sandbox child but its "
    "score is partial ({missing}), so no MRI exists to compare or to resolve on (spec 15.4, 15.6, 26.3 item 15). "
    "Every stage that feeds a subscore must complete inside redsim/ml/sandbox_worker.py for the record to carry "
    "a complete score; see the run's limitations: {limitations}"
)


# ---------------------------------------------------------------------------
# Read-only helpers over the API and the harness database
# ---------------------------------------------------------------------------


def _events(e2e_app: E2EApp, chain_id: str, action: str) -> list[dict[str, Any]]:
    return [ev for ev in e2e_app.read_chain(chain_id) if ev["action"] == action]


def _detail(response: Any) -> dict[str, Any]:
    try:
        detail = response.json().get("detail")
    except ValueError:
        return {}
    return dict(detail) if isinstance(detail, dict) else {}


def _code(response: Any) -> str | None:
    code = _detail(response).get("code")
    return str(code) if code is not None else None


def _finding(client: TestClient, finding_id: str) -> dict[str, Any]:
    response = client.get(f"/v1/findings/{finding_id}")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _campaign(client: TestClient, run_id: str) -> dict[str, Any]:
    response = client.get(f"/v1/runs/{run_id}/campaign")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _norm(text: str) -> str:
    return " ".join(text.split())


def _keys(payload: Any) -> set[str]:
    """Every mapping key anywhere in a JSON-like payload, lower-cased."""
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
    """Spec 15.8 i / D9 i: no mean, rank or average anywhere in a comparison payload."""
    offending = _keys(payload) & FORBIDDEN_TABLE_KEYS
    assert not offending, f"comparison payload carries aggregate keys {sorted(offending)}"


def _pdf_text(data: bytes) -> str:
    import pypdf

    reader = pypdf.PdfReader(io.BytesIO(data))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def _upload(client: TestClient, project_id: str, path: Path, **overrides: Any) -> Any:
    """``POST /v1/models`` multipart with the spec 17.2 fields; ``None`` drops a field."""
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
    """``GET /v1/models/{id}`` once it is ``available`` or ``refused`` (eager Celery: one round trip)."""
    import time

    deadline = time.monotonic() + 30.0
    while True:
        record = h.model_record(client, model_id)
        if record["status"] in {"available", "refused"}:
            return record
        assert time.monotonic() < deadline, f"model {model_id} still {record['status']!r}: {record.get('validation')}"
        time.sleep(0.1)


def _artifact_bytes(client: TestClient, run_id: str, kind: str) -> tuple[bytes, dict[str, Any]]:
    listing = client.get(f"/v1/runs/{run_id}/artifacts")
    assert listing.status_code == 200, listing.text
    rows = [row for row in listing.json()["artifacts"] if row["kind"] == kind]
    assert rows, f"no {kind!r} artifact on run {run_id}"
    row = rows[0]
    response = client.get(f"/v1/artifacts/{row['id']}")
    assert response.status_code == 200, response.text
    return response.content, row


def _job_rows(e2e_app: E2EApp, run_id: str, job_type: str) -> list[dict[str, Any]]:
    from sqlalchemy import select

    from redsim.db.models import Job

    with e2e_app.session() as sess:
        rows = sess.execute(select(Job).where(Job.run_id == run_id, Job.type == job_type)
                            .order_by(Job.created_at, Job.id)).scalars().all()
        return [{"id": str(row.id), "status": str(row.status), "created_by": row.created_by} for row in rows]


def _require_complete_score(campaign: dict[str, Any]) -> dict[str, Any]:
    """The complete MRIRecord of a record, or an attributed failure (never a weaker assertion)."""
    score = campaign.get("score")
    if score is None or score.get("mri") is None:
        missing = (score or {}).get("missing") or [(campaign.get("score_status") or {}).get("reason")]
        pytest.fail(_PARTIAL_SCORE_DEFECT.format(missing=missing, limitations=campaign.get("limitations")),
                    pytrace=False)
    return dict(score)


# ---------------------------------------------------------------------------
# Module fixtures: the memorising upload, its campaign with findings, two verifies
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def upload_double(e2e_assets: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """An ONNX ``Upsample(x2) -> SmallCNN(image_size=16)`` that memorises the 48 seeded harness images.

    The catalog ``SmallCNN`` cannot be exported natively at 8x8 (its ``AdaptiveAvgPool2d(4)``
    receives a 2x2 map), so one Resize node sits in front of the real architecture. A test
    stand-in only: nothing measured on it is a demo result.
    """
    import numpy as np
    import torch
    from torch import nn

    from redsim.ml.targets.architectures import SmallCNN

    manifest = h.asset_manifest(e2e_assets)
    entry = manifest["models"][h.IMAGE_MODEL_ID]
    dataset_id, dataset_split = str(entry["dataset_id"]), str(entry["dataset_split"])
    class_names = list(manifest["datasets"][dataset_id]["class_names"])
    out = tmp_path_factory.mktemp("e2e-review-uploads")
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
    assert onnx_path.read_bytes()[0] == 0x08, "ONNX ModelProto starts with the ir_version tag"
    return {"onnx": onnx_path, "dataset_id": dataset_id, "dataset_split": dataset_split,
            "class_names": class_names, "eval_accuracy": eval_acc}


@pytest.fixture(scope="module")
def onnx_model(e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str],
               upload_double: dict[str, Any]) -> dict[str, Any]:
    """The ONNX double registered through ``POST /v1/models`` (remediator) and validated in the real child."""
    del e2e_bundled  # ordering only: the bundled registrations precede the upload on the project chain
    client = e2e_org.client("remediator")
    response = _upload(client, e2e_org.project_id, upload_double["onnx"], declared_format="onnx",
                       dataset_id=upload_double["dataset_id"], dataset_split=upload_double["dataset_split"])
    assert response.status_code == 201, response.text
    posted = response.json()
    record = _wait_for_validation(client, str(posted["id"]))
    if record["status"] != "available":
        pytest.fail(f"product defect outside this file: the ONNX upload was refused by the validate child: "
                    f"{record.get('refusal_reason')}: {record.get('reason')} ({record.get('validation')})",
                    pytrace=False)
    return {"model_id": str(posted["id"]), "record": record, "posted": posted}


@pytest.fixture(scope="module")
def finding_campaign(e2e_org: E2EOrg, onnx_model: dict[str, Any]) -> h.CampaignRun:
    """FGSM + PGD (or HopSkipJump alone if the graph exposed no gradients) on the memorising upload, by the scanner."""
    manifest = onnx_model["record"].get("manifest") or {}
    if manifest.get("gradients"):
        body = h.image_campaign(n_samples=N_EVAL, finding_asr_threshold=FINDING_THRESHOLD)
    else:  # honest fallback: only black-box attacks are admitted on a target without loss gradients (spec 9.5)
        body = h.image_campaign(n_samples=N_EVAL, finding_asr_threshold=FINDING_THRESHOLD, attack_ids=["hopskipjump"],
                                attack_params={"hopskipjump": h.tabular_campaign()["attack_params"]["hopskipjump"]})
    result = h.run_campaign_via_api(e2e_org.client("scanner"), onnx_model["model_id"], body, timeout_s=30.0)
    assert result.status == "succeeded", f"run {result.run_id}: {result.stage_table}"
    assert result.campaign is not None, result.campaign_error
    asr = {m["id"]: m.get("attack_success_rate") for m in result.campaign["measurements"] if m["family"] == "evasion"}
    assert result.findings, f"the memorising upload produced no finding: ASR by row {asr}; threshold {FINDING_THRESHOLD}"
    return result


@dataclass
class VerifyRun:
    """What one ``POST /v1/findings/{id}/verify`` left behind."""

    requester: str
    finding_id: str
    body: dict[str, Any] | None
    run_id: str
    run: dict[str, Any]
    campaign: dict[str, Any]
    finding: dict[str, Any]

    @property
    def outcome(self) -> str:
        return str(((self.finding.get("schema_blob") or {}).get("ml") or {}).get("verify", {}).get("outcome"))


def _verify_via_api(e2e_org: E2EOrg, identity: str, finding_id: str, body: dict[str, Any] | None) -> VerifyRun:
    client = e2e_org.client(identity)
    response = client.post(f"/v1/findings/{finding_id}/verify", json=body) if body is not None else client.post(
        f"/v1/findings/{finding_id}/verify")
    assert response.status_code == 202, response.text
    run_id = str(response.json()["run_id"])
    run = h.wait_for_run(client, run_id, timeout_s=30.0)
    assert run["status"] == "succeeded", f"verify {run_id}: {run.get('stage_table')}"
    return VerifyRun(requester=identity, finding_id=finding_id, body=body, run_id=run_id, run=run,
                     campaign=_campaign(client, run_id), finding=_finding(client, finding_id))


@pytest.fixture(scope="module")
def verifies(e2e_org: E2EOrg, finding_campaign: h.CampaignRun) -> list[VerifyRun]:
    """Two retests of the first worker finding: explicit ``feature_squeezing`` by the remediator, the route default by the approver."""
    finding_id = str(finding_campaign.findings[0]["id"])
    first = _verify_via_api(e2e_org, "remediator", finding_id,
                            {"defense": FEATURE_SQUEEZING, "params": {"bit_depth": 6}})
    second = _verify_via_api(e2e_org, "approver", finding_id, None)
    baseline_hash = finding_campaign.campaign["settings_hash"] if finding_campaign.campaign else None
    for verify in (first, second):
        assert verify.campaign["kind"] == "verify" and verify.campaign["baseline_run_id"] == finding_campaign.run_id
        assert verify.campaign["settings_hash"] == baseline_hash, "the defense is outside the settings hash (spec 5.6)"
        assert verify.campaign["config"]["defense"]["id"] == FEATURE_SQUEEZING
    return [first, second]


# ---------------------------------------------------------------------------
# 1. Review states: compare-and-set, independence, the analyst draft
# ---------------------------------------------------------------------------


def test_review_states_independence_and_conflicts(
    e2e_app: E2EApp, e2e_org: E2EOrg, finding_campaign: h.CampaignRun,
) -> None:
    from redsim.api.errors import RESOLUTION_BLOCKED, REVIEW_STATE_CONFLICT, REVIEWER_NOT_INDEPENDENT
    from redsim.services.finding_review import AUTHOR_ACTION, REVIEW_ACTION

    viewer, scanner = e2e_org.client("viewer"), e2e_org.client("scanner")
    approver, admin = e2e_org.client("approver"), e2e_org.client("admin")
    run_id = finding_campaign.run_id
    chain = f"run:{run_id}"
    finding_id = str(finding_campaign.findings[0]["id"])
    events_before = len(e2e_app.read_chain(chain))

    # -- the worker finding starts unreviewed with an empty history (spec 5.7 review block, 6.4) ---------------
    row = _finding(viewer, finding_id)
    assert row["status"] == "open" and row["validation_state"] == "unvalidated"
    assert row["review_state"] == "unreviewed" and row["review"]["state"] == "unreviewed"
    review = row["schema_blob"]["ml"]["review"]
    assert review["history"] == [] and review["revisions"] == [] and review["reviewer"] is None

    # -- compare-and-set (REVIEW_REPORTS-06): a stale expected_status is 409 review_state_conflict -------------
    stale = approver.post(f"/v1/findings/{finding_id}/review/confirm",
                          json={"expected_status": "fixed", "reason": "read from a stale page"})
    assert stale.status_code == 409 and _code(stale) == REVIEW_STATE_CONFLICT, stale.text
    assert _detail(stale)["status"] == "open" and _detail(stale)["review_state"] == "unreviewed"
    refused = _events(e2e_app, chain, REVIEW_ACTION)[-1]
    assert refused["success"] is False and refused["detail"]["refusal"] == REVIEW_STATE_CONFLICT
    assert refused["detail"]["decision"] == "confirm" and refused["actor"] == e2e_org.actor("approver")
    assert _finding(viewer, finding_id)["review_state"] == "unreviewed", "a refused decision changes nothing"

    # -- the campaign creator (scanner) is below the finding.review gate (spec 7.3, 7.7) ------------------------
    creator = scanner.post(f"/v1/findings/{finding_id}/review/confirm",
                           json={"expected_status": "open", "reason": "my own campaign"})
    assert creator.status_code == 403, creator.text
    assert viewer.post(f"/v1/findings/{finding_id}/review/confirm",
                       json={"expected_status": "open", "reason": "x"}).status_code == 403

    # -- an independent approver confirms; the audit row precedes the write and names everyone ------------------
    ok = approver.post(f"/v1/findings/{finding_id}/review/confirm",
                       json={"expected_status": "open", "expected_review_state": "unreviewed",
                             "reason": "the measured rows support the finding"})
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["review_state"] == "confirmed" and body["from_review_state"] == "unreviewed"
    assert body["status"] == "open", "confirm keeps Finding.status (spec 6.4: no invented status)"
    row = _finding(viewer, finding_id)
    review = row["schema_blob"]["ml"]["review"]
    assert row["review_state"] == "confirmed" and review["reviewer"] == e2e_org.actor("approver")
    assert [ev["action"] for ev in review["history"]] == ["confirm"]
    assert review["history"][0]["from_state"] == "unreviewed" and review["history"][0]["to_state"] == "confirmed"
    assert review["history"][0]["actor"] == e2e_org.actor("approver")
    confirm_row = [ev for ev in _events(e2e_app, chain, REVIEW_ACTION) if ev["success"]][-1]
    assert confirm_row["detail"]["decision"] == "confirm" and confirm_row["actor"] == e2e_org.actor("approver")
    assert confirm_row["detail"]["campaign_creator"] == e2e_org.actor("scanner")
    assert confirm_row["detail"]["from_review_state"] == "unreviewed"
    assert confirm_row["detail"]["to_review_state"] == "confirmed"
    listed = viewer.get("/v1/findings", params={"run": run_id, "review_state": "confirmed"}).json()
    assert [f["id"] for f in listed["findings"]] == [finding_id]

    # -- resolve before any retest: 409 resolution_blocked naming every unmet condition (spec 6.4, 15.6) --------
    blocked = approver.post(f"/v1/findings/{finding_id}/review/resolve",
                            json={"expected_status": "open", "reason": "nothing measured yet"})
    assert blocked.status_code == 409 and _code(blocked) == RESOLUTION_BLOCKED, blocked.text
    assert _detail(blocked)["unmet"] == ["validation_state_not_poc_passed", "status_not_fixed", "no_retest_linked"]
    assert _detail(blocked)["verify_run_id"] is None and _detail(blocked)["review_state"] == "confirmed"
    refused = _events(e2e_app, chain, REVIEW_ACTION)[-1]
    assert refused["success"] is False and refused["detail"]["refusal"] == RESOLUTION_BLOCKED
    assert refused["detail"]["unmet"] == _detail(blocked)["unmet"]
    assert _finding(viewer, finding_id)["review_state"] == "confirmed"

    # -- an analyst draft (REVIEW_REPORTS-05): draft -> in_review -> draft -> in_review -> confirmed -----------
    record = finding_campaign.campaign
    assert record is not None
    attack_id = str(row["schema_blob"]["ml"]["attack_id"])
    evidence = [m["id"] for m in record["measurements"]
                if m["family"] == "clean" or m.get("attack_id") == attack_id][:3]
    assert evidence, "the record carries measurement ids to cite"
    draft_body = {
        "run_id": run_id, "attack_id": attack_id, "severity": "medium",
        "title": "e2e analyst draft on the memorising upload (test double, not a product finding)",
        "observation": "The clean row and the evasion rows are cited by id; this text is the analyst's.",
        "interpretation": "Analyst reading; inferred, not measured.",
        "candidate": "Re-run the campaign after the candidate defense; not evaluated.",
        "evidence_ids": evidence,
    }
    assert viewer.post("/v1/findings", json=draft_body).status_code == 403, "finding.author is remediator+"
    assert scanner.post("/v1/findings", json=draft_body).status_code == 403
    bogus = admin.post("/v1/findings", json={**draft_body, "evidence_ids": ["m.not.in.the.record"]})
    assert bogus.status_code == 422 and _code(bogus) == "params_out_of_range", bogus.text
    created = admin.post("/v1/findings", json=draft_body)
    assert created.status_code == 201, created.text
    draft_id = str(created.json()["id"])
    assert created.json()["review_state"] == "draft" and created.json()["revision"] == 1
    assert created.json()["status"] == "open" and created.json()["validation_state"] == "unvalidated"
    assert created.json()["revision_sha256"] and len(created.json()["revision_sha256"]) == 64

    revised = admin.patch(f"/v1/findings/{draft_id}/draft", json={"observation": "Revised after a second read."})
    assert revised.status_code == 200 and revised.json()["revision"] == 2, revised.text
    assert approver.patch(f"/v1/findings/{draft_id}/draft",
                          json={"observation": "not my draft"}).status_code == 403
    # ``submit`` is the author's own act (finding.author); anyone else is refused.
    assert approver.post(f"/v1/findings/{draft_id}/review/submit",
                         json={"expected_status": "open", "reason": "not mine"}).status_code == 403
    submitted = admin.post(f"/v1/findings/{draft_id}/review/submit",
                           json={"expected_status": "open", "expected_review_state": "draft", "reason": "ready"})
    assert submitted.status_code == 200 and submitted.json()["review_state"] == "in_review", submitted.text

    # -- independence is identity, never rank: the author (an admin) cannot confirm (spec 7.7) -----------------
    own = admin.post(f"/v1/findings/{draft_id}/review/confirm",
                     json={"expected_status": "open", "reason": "confirming my own draft"})
    assert own.status_code == 403 and _code(own) == REVIEWER_NOT_INDEPENDENT, own.text
    assert _detail(own)["relation"] == "revision_author" and _detail(own)["relations"] == ["revision_author"]
    refused = _events(e2e_app, chain, REVIEW_ACTION)[-1]
    assert refused["success"] is False and refused["detail"]["refusal"] == REVIEWER_NOT_INDEPENDENT
    assert refused["detail"]["independence_violations"] == ["revision_author"]
    assert refused["detail"]["author"] == e2e_org.actor("admin") and refused["detail"]["revision"] == 2
    assert _finding(viewer, draft_id)["review_state"] == "in_review"

    # -- a stale expected review state is the same 409 --------------------------------------------------------
    stale = approver.post(f"/v1/findings/{draft_id}/review/confirm",
                          json={"expected_status": "open", "expected_review_state": "draft", "reason": "stale"})
    assert stale.status_code == 409 and _code(stale) == REVIEW_STATE_CONFLICT
    assert _detail(stale)["review_state"] == "in_review" and _detail(stale)["expected_review_state"] == "draft"

    # -- request_changes returns the draft to its author with a new revision ---------------------------------
    changes = approver.post(f"/v1/findings/{draft_id}/review/request_changes",
                            json={"expected_status": "open", "expected_review_state": "in_review",
                                  "reason": "cite the control row too"})
    assert changes.status_code == 200, changes.text
    assert changes.json()["review_state"] == "draft" and changes.json()["revision"] == 3
    # ``confirm`` is not valid from ``draft``: the table refuses it rather than skipping the review.
    early = approver.post(f"/v1/findings/{draft_id}/review/confirm",
                          json={"expected_status": "open", "reason": "too early"})
    assert early.status_code == 409 and _code(early) == "review_transition_invalid", early.text
    resubmitted = admin.post(f"/v1/findings/{draft_id}/review/submit",
                             json={"expected_status": "open", "reason": "revision 3 ready"})
    assert resubmitted.status_code == 200 and resubmitted.json()["review_state"] == "in_review"
    confirmed = approver.post(f"/v1/findings/{draft_id}/review/confirm",
                              json={"expected_status": "open", "expected_review_state": "in_review",
                                    "reason": "the cited rows say what the text says"})
    assert confirmed.status_code == 200 and confirmed.json()["review_state"] == "confirmed", confirmed.text

    # -- schema_blob.ml.review carries the history and the revisions (REVIEW_REPORTS-01, -05) -----------------
    draft = _finding(viewer, draft_id)
    review = draft["schema_blob"]["ml"]["review"]
    assert review["state"] == "confirmed" and review["reviewer"] == e2e_org.actor("approver")
    assert [ev["action"] for ev in review["history"]] == ["submit", "request_changes", "submit", "confirm"]
    assert [ev["to_state"] for ev in review["history"]] == ["in_review", "draft", "in_review", "confirmed"]
    assert [ev["from_state"] for ev in review["history"]] == ["draft", "in_review", "draft", "in_review"]
    assert [ev["actor"] for ev in review["history"]] == [e2e_org.actor("admin"), e2e_org.actor("approver"),
                                                          e2e_org.actor("admin"), e2e_org.actor("approver")]
    revisions = review["revisions"]
    assert [r["revision"] for r in revisions] == [1, 2, 3]
    assert all(r["author"] == e2e_org.actor("admin") for r in revisions)
    assert revisions[0]["submitted_at"] is None and revisions[0]["sha256"] is None, "revision 1 was superseded, never submitted"
    assert revisions[1]["submitted_at"] and revisions[1]["sha256"] and revisions[2]["submitted_at"] and revisions[2]["sha256"]
    assert revisions[1]["observation"] == "Revised after a second read." == revisions[2]["observation"]
    assert all(r["evidence_ids"] == evidence for r in revisions)
    summary = dict(draft["review"])
    assert datetime.fromisoformat(str(summary.pop("at"))) == datetime.fromisoformat(str(review["at"]).replace("Z", "+00:00"))
    assert summary == {"state": "confirmed", "reviewer": e2e_org.actor("approver"),
                       "n_history": 4, "n_revisions": 3, "revision": 3}
    assert draft["status"] == "open" and draft["validation_state"] == "unvalidated"
    assert draft["schema_blob"]["source_tool"] == "manual"
    assert draft["schema_blob"]["description"].startswith("Analyst-authored draft"), "labelled as the analyst's text"
    assert draft["schema_blob"]["remediation_steps"].startswith("CANDIDATE (not evaluated)")
    assert {m["id"] for m in draft["schema_blob"]["ml"]["measurements"]} <= set(evidence), "only the cited rows"
    assert any("Analyst-authored draft" in lim for lim in draft["schema_blob"]["ml"]["limitations"])
    from redsim.ml.atlas import technique_for_attack

    # Wave B4 (INTEROP-18): the draft names an attack id, so its ATLAS technique is the catalog's mapping for
    # that id (deterministic, never a guess); a draft naming no attack id would carry None (spec 27.2).
    mapped = technique_for_attack(attack_id)
    assert mapped is not None and draft["schema_blob"]["ml"]["atlas_technique"]["id"] == mapped.id, "the mapping, not a guess"

    # -- every decision is on the run chain, audit-first, refusals as success=False rows (spec 6.7 inv. 4) ----
    tail = e2e_app.read_chain(chain)[events_before:]
    decisions = [(ev["action"], ev["success"], ev["detail"].get("decision") or ev["detail"].get("op"))
                 for ev in tail if ev["action"] in {REVIEW_ACTION, AUTHOR_ACTION}]
    assert decisions == [
        (REVIEW_ACTION, False, "confirm"),            # stale expected_status on the worker finding
        (REVIEW_ACTION, True, "confirm"),
        (REVIEW_ACTION, False, "resolve"),            # blocked before any retest
        (AUTHOR_ACTION, False, "create"),             # unknown evidence id
        (AUTHOR_ACTION, True, "create"),
        (AUTHOR_ACTION, True, "revise"),
        (AUTHOR_ACTION, False, "revise"),             # the approver is not the author
        (AUTHOR_ACTION, False, "submit"),             # not the author
        (AUTHOR_ACTION, True, "submit"),
        (REVIEW_ACTION, False, "confirm"),            # the author is not independent
        (REVIEW_ACTION, False, "confirm"),            # stale expected_review_state
        (REVIEW_ACTION, True, "request_changes"),
        (REVIEW_ACTION, False, "confirm"),            # not valid from draft
        (AUTHOR_ACTION, True, "submit"),
        (REVIEW_ACTION, True, "confirm"),
    ], decisions
    for ev in tail:
        text = json.dumps(ev, default=str)
        assert h.MOCK_PYTHIA_API_KEY not in text
        for analyst_text in (draft_body["observation"], draft_body["interpretation"], draft_body["candidate"],
                             "Revised after a second read."):
            assert analyst_text not in text, "the analyst's text never reaches the chain; ids and digests only"


# ---------------------------------------------------------------------------
# 2. Retest links after two verifies, the requester's independence, resolve on the measured gate
# ---------------------------------------------------------------------------


def test_retests_link_and_resolve_after_two_verifies(
    e2e_app: E2EApp, e2e_org: E2EOrg, finding_campaign: h.CampaignRun, verifies: list[VerifyRun],
) -> None:
    from redsim.api.errors import RESOLUTION_BLOCKED, REVIEWER_NOT_INDEPENDENT
    from redsim.services.finding_review import REVIEW_ACTION
    from redsim.workers.tasks.ml_campaign import VERIFY_STATUS_MAP
    from redsim.workers.tasks.verify import _STATE_MAP

    viewer, approver, admin = e2e_org.client("viewer"), e2e_org.client("approver"), e2e_org.client("admin")
    first, second = verifies
    finding_id = first.finding_id
    run_id = finding_campaign.run_id
    chain = f"run:{run_id}"
    baseline = finding_campaign.campaign
    assert baseline is not None
    baseline_hash = baseline["settings_hash"]

    # -- MLFindingDetail.retests carries both links in order; ``verify`` is the latest (REVIEW_REPORTS-08) -----
    row = _finding(viewer, finding_id)
    detail = row["schema_blob"]["ml"]
    assert [link["run_id"] for link in detail["retests"]] == [first.run_id, second.run_id]
    assert detail["verify"] == detail["retests"][-1]
    for link in detail["retests"]:
        assert link["settings_hash"] == baseline_hash and link["baseline_run_id"] == run_id
        assert link["defense"]["id"] == FEATURE_SQUEEZING and link["outcome"] in _STATE_MAP
    assert detail["retests"][0]["defense"]["params"] == {"bit_depth": 6}
    assert detail["retests"][1]["defense"]["params"] == {"bit_depth": 4}, "spec 16.5 route default"
    outcome = str(detail["verify"]["outcome"])
    # spec 6.4 pairing between the worker's outcome, validation_state and status
    assert row["validation_state"] == _STATE_MAP[outcome] and row["status"] == VERIFY_STATUS_MAP[outcome]
    assert row["review_state"] == "confirmed", "the worker's writes keep the review block"

    # -- GET /retests: both links compatible (equal settings_hash), a delta only where measured -------------
    retests = viewer.get(f"/v1/findings/{finding_id}/retests")
    assert retests.status_code == 200, retests.text
    listing = retests.json()
    assert listing["count"] == 2 and listing["baseline_run_id"] == run_id
    assert listing["baseline_settings_hash"] == baseline_hash and listing["review_state"] == "confirmed"
    for link, verify, stored in zip(listing["retests"], verifies, detail["retests"], strict=True):
        assert link["run_id"] == verify.run_id and link["compatible"] is True and link["mismatched"] == []
        assert link["settings_hash"] == baseline_hash and link["baseline_run_id"] == run_id
        assert link["requested_by"] == e2e_org.actor(verify.requester)
        assert link["run_status"] == "succeeded" and link["job_status"] == "succeeded"
        assert link["outcome"] == stored["outcome"] and link["defense"] == stored["defense"]
        if stored["outcome"] != "inconclusive" and stored["delta"] is not None:
            # the delta is whatever was measured, negative, zero or positive; never filtered by sign
            assert link["delta_mri"] == stored["delta"]["delta"] and link["delta"] == stored["delta"]
            assert stored["delta"]["baseline_run_id"] == run_id
        else:
            assert link["delta_mri"] is None and link["delta"] is None, "no delta without a measured outcome"
    assert e2e_org.client(h.OUTSIDER).get(f"/v1/findings/{finding_id}/retests").status_code in (403, 404)

    # -- the requester of the retest a resolve rests on cannot resolve, whatever the rank (spec 7.7) -----------
    resolve = f"/v1/findings/{finding_id}/review/resolve"
    mine = approver.post(resolve, json={"expected_status": row["status"], "reason": "my own retest"})
    assert mine.status_code == 403 and _code(mine) == REVIEWER_NOT_INDEPENDENT, mine.text
    assert _detail(mine)["relation"] == "verify_requester"
    refused = _events(e2e_app, chain, REVIEW_ACTION)[-1]
    assert refused["success"] is False and refused["detail"]["refusal"] == REVIEWER_NOT_INDEPENDENT
    assert refused["detail"]["verify_run_id"] == second.run_id
    assert e2e_org.actor("approver") in refused["detail"]["verify_requesters"]
    assert _finding(viewer, finding_id)["review_state"] == "confirmed"

    # -- an independent admin resolves only on the measured gate: poc_passed + equal settings_hash ------------
    resolved = admin.post(resolve, json={"expected_status": row["status"], "expected_review_state": "confirmed",
                                         "reason": "measured retest at equal settings"})
    if outcome == "verified":
        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["review_state"] == "resolved" and resolved.json()["status"] == "fixed"
        assert resolved.json()["verify_run_id"] == second.run_id
        after = _finding(viewer, finding_id)
        assert after["review_state"] == "resolved" and after["status"] == "fixed"
        assert after["validation_state"] == "poc_passed", "resolve never touches the worker's columns"
        history = after["schema_blob"]["ml"]["review"]["history"]
        assert history[-1]["action"] == "resolve" and history[-1]["verify_run_id"] == second.run_id
        assert history[-1]["actor"] == e2e_org.actor("admin")
        event = [ev for ev in _events(e2e_app, chain, REVIEW_ACTION) if ev["success"]][-1]
        assert event["detail"]["decision"] == "resolve" and event["detail"]["verify_run_id"] == second.run_id
        assert event["detail"]["to_review_state"] == "resolved" and event["detail"]["to_status"] == "fixed"
        listed = viewer.get("/v1/findings", params={"run": run_id, "review_state": "resolved"}).json()
        assert [f["id"] for f in listed["findings"]] == [finding_id]
        # resolved is terminal for the table
        again = admin.post(resolve, json={"expected_status": "fixed", "reason": "again"})
        assert again.status_code == 409 and _code(again) == RESOLUTION_BLOCKED
        assert _detail(again)["unmet"] == ["review_state_not_confirmed"]
    else:
        # The retest did not verify the fix: the finding stays confirmed and the refusal names each condition.
        assert resolved.status_code == 409 and _code(resolved) == RESOLUTION_BLOCKED, resolved.text
        unmet = _detail(resolved)["unmet"]
        assert unmet == ["validation_state_not_poc_passed", "status_not_fixed", "retest_outcome_not_verified"], (
            outcome, unmet)
        assert _detail(resolved)["verify_run_id"] == second.run_id
        assert _detail(resolved)["validation_state"] == _STATE_MAP[outcome]
        refused = _events(e2e_app, chain, REVIEW_ACTION)[-1]
        assert refused["success"] is False and refused["detail"]["unmet"] == unmet
        after = _finding(viewer, finding_id)
        assert after["review_state"] == "confirmed" and after["status"] == VERIFY_STATUS_MAP[outcome]
        assert after["schema_blob"]["ml"]["review"]["history"][-1]["action"] == "confirm"
    assert h.MOCK_PYTHIA_API_KEY not in json.dumps(e2e_app.read_chain(chain), default=str)


# ---------------------------------------------------------------------------
# 3. Reports: report.render, the PDF, immutable snapshots, the admin archive flag
# ---------------------------------------------------------------------------


def test_report_pdf_snapshots_and_archive(
    e2e_app: E2EApp, e2e_org: E2EOrg, finding_campaign: h.CampaignRun,
) -> None:
    from redsim.api.errors import SNAPSHOT_ARCHIVED, SNAPSHOT_NOT_FOUND
    from redsim.ml.pdf import PDF_MAGIC, PDF_SECTION_HEADINGS
    from redsim.ml.schema import GRADE_STATEMENT
    from redsim.services.reports import (
        REPORT_FORMATS,
        REPORT_RENDER_ACTION,
        SNAPSHOT_ARCHIVE_ACTION,
        SNAPSHOT_RESTORE_ACTION,
    )

    scanner, viewer = e2e_org.client("scanner"), e2e_org.client("viewer")
    remediator, approver, admin = e2e_org.client("remediator"), e2e_org.client("approver"), e2e_org.client("admin")
    run_id = finding_campaign.run_id
    campaign = finding_campaign.campaign
    assert campaign is not None
    chain = f"run:{run_id}"
    renders_before = len(_events(e2e_app, chain, REPORT_RENDER_ACTION))

    # -- before an on-demand render: the completion render is snapshot version 1 (wave B4, REVIEW_REPORTS-16/-20):
    #    the worker rendered every format it could at completion (the PDF when reportlab succeeded, else the
    #    text formats with ``pdf_unavailable`` on the report.render row) and recorded the first snapshot row.
    initial = scanner.get(f"/v1/runs/{run_id}/snapshots")
    assert initial.status_code == 200 and initial.json()["run_id"] == run_id and initial.json()["count"] == 1
    completion = initial.json()["snapshots"][0]
    assert completion["version"] == 1 and completion["archived"] is False
    assert {"md", "json", "html"} <= set(completion["formats"]) <= set(REPORT_FORMATS)
    completion_pdf = scanner.get(f"/v1/runs/{run_id}/report.pdf")
    if "pdf" in completion["formats"]:
        assert completion_pdf.status_code == 200 and completion_pdf.content.startswith(PDF_MAGIC)
        assert completion_pdf.headers["etag"] == f'"{completion["formats"]["pdf"]["sha256"]}"'
    else:
        assert completion_pdf.status_code == 404, completion_pdf.text
        assert completion_pdf.json()["detail"] == "report not yet rendered", "never a filesystem fallback for a PDF"
    assert viewer.post(f"/v1/runs/{run_id}/report.render", json={}).status_code == 403, "report.render is scanner+"

    # -- render #1: audit first, the Job, the eager worker, one snapshot over four content-addressed artifacts --
    first = scanner.post(f"/v1/runs/{run_id}/report.render", json={})
    assert first.status_code == 202, first.text
    assert first.json()["run_id"] == run_id and first.json()["formats"] == list(REPORT_FORMATS)
    assert first.json()["type"] == "report.render" and first.json()["status"] == "queued"
    job = next(j for j in _job_rows(e2e_app, run_id, "report.render") if j["id"] == first.json()["job_id"])
    assert job["status"] == "succeeded" and job["created_by"] == e2e_org.actor("scanner")
    assert h.wait_for_run(scanner, run_id)["status"] == "succeeded", "a render never reopens a terminal run (spec 6.2)"
    listed = scanner.get(f"/v1/runs/{run_id}/snapshots").json()
    assert listed["count"] == 2, "the completion snapshot plus this render"
    snap = listed["snapshots"][0]
    assert snap["version"] == 2 and snap["archived"] is False and snap["created_by"] == e2e_org.actor("scanner")
    assert listed["snapshots"][1] == completion, "the completion row did not change"
    assert set(snap["formats"]) == set(REPORT_FORMATS) == {"md", "json", "html", "pdf"}
    record_bytes, record_row = _artifact_bytes(viewer, run_id, "ml.run_record")
    assert snap["record_sha256"] == _sha256(record_bytes) == record_row["sha256"], "projected from the record bytes"
    assert len(snap["artifact_ids"]) == 4 and {f["artifact_id"] for f in snap["formats"].values()} == set(snap["artifact_ids"])
    for ext, entry in snap["formats"].items():
        assert entry["kind"] == f"ml.report_{ext}" and len(entry["sha256"]) == 64 and entry["size_bytes"] > 0
        served = scanner.get(f"/v1/runs/{run_id}/report.{ext}", params={"snapshot": snap["id"]})
        assert served.status_code == 200, (ext, served.text)
        assert _sha256(served.content) == entry["sha256"] == served.headers["etag"].strip('"')
        assert len(served.content) == entry["size_bytes"]

    # -- the PDF: %PDF-, download headers, the six section titles and the scorecard statement (spec 14.8, 15.8)
    pdf = scanner.get(f"/v1/runs/{run_id}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(PDF_MAGIC), pdf.status_code
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.headers["x-content-type-options"] == "nosniff"
    assert pdf.headers["content-disposition"].startswith("attachment") and "report.pdf" in pdf.headers["content-disposition"]
    assert pdf.headers["etag"] == f'"{snap["formats"]["pdf"]["sha256"]}"' == f'"{_sha256(pdf.content)}"'
    text = _norm(_pdf_text(pdf.content))
    for heading in PDF_SECTION_HEADINGS:
        assert _norm(heading) in text, heading
    positions = [text.index(_norm(heading)) for heading in PDF_SECTION_HEADINGS]
    assert positions == sorted(positions), "the six sections are in the spec 14.8 order"
    assert _norm(GRADE_STATEMENT) in text, "every scorecard states that no grade is a readiness statement (26.3 item 14)"
    score = campaign["score"]
    if score is not None and score.get("mri") is not None:
        assert f"MRI {score['mri']}" in text and f"grade {score['grade']}" in text
        for key in SUBSCORE_KEYS:
            assert key in text, key
    else:
        assert "MRI not computed" in text, "a partial score never shows a number"
    clean = next(m for m in campaign["measurements"] if m["family"] == "clean")
    assert f"{clean['n_correct']}/{clean['n']}" in text, "denominators travel into the PDF (26.2 item 7)"
    assert h.MOCK_PYTHIA_API_KEY not in text
    assert viewer.get(f"/v1/runs/{run_id}/report.pdf").status_code == 403, "report.export is scanner+"
    assert e2e_org.client(h.OUTSIDER).get(f"/v1/runs/{run_id}/report.pdf").status_code in (403, 404)

    # -- render #2: a second immutable row; the first is byte-for-byte what it was (REVIEW_REPORTS-20, -22) ----
    second = scanner.post(f"/v1/runs/{run_id}/report.render", json={})
    assert second.status_code == 202, second.text
    listed = scanner.get(f"/v1/runs/{run_id}/snapshots").json()
    assert listed["count"] == 3 and [s["version"] for s in listed["snapshots"]] == [3, 2, 1], "newest first"
    newest, oldest = listed["snapshots"][:2]
    assert oldest == snap, "the first snapshot row did not change"
    assert newest["id"] != snap["id"] and newest["archived"] is False
    assert newest["record_sha256"] == snap["record_sha256"], "same record bytes, a new projection"
    assert set(newest["formats"]) == set(REPORT_FORMATS)
    assert newest["formats"]["json"]["sha256"] == snap["formats"]["json"]["sha256"], "report.json is the record itself"
    for ext, entry in newest["formats"].items():
        served = scanner.get(f"/v1/runs/{run_id}/report.{ext}", params={"snapshot": str(newest["version"])})
        assert served.status_code == 200 and _sha256(served.content) == entry["sha256"], ext
    assert scanner.get(f"/v1/runs/{run_id}/snapshots/{snap['version']}").json() == snap
    assert scanner.get(f"/v1/runs/{run_id}/snapshots/{newest['id']}").json() == newest
    unknown = scanner.get(f"/v1/runs/{run_id}/snapshots/99")
    assert unknown.status_code == 404 and _code(unknown) == SNAPSHOT_NOT_FOUND
    latest = scanner.get(f"/v1/runs/{run_id}/report.pdf")
    assert latest.headers["etag"] == f'"{newest["formats"]["pdf"]["sha256"]}"', "the unqualified route serves the newest"

    # -- archive is an admin soft flag, audited; a non-admin fetch of the archived row is 409 ------------------
    ref = str(snap["version"])
    for who in (scanner, remediator, approver):
        assert who.post(f"/v1/runs/{run_id}/snapshots/{ref}/archive").status_code == 403
    assert e2e_org.client(h.OUTSIDER).post(f"/v1/runs/{run_id}/snapshots/{ref}/archive").status_code in (403, 404)
    missing_ref = admin.post(f"/v1/runs/{run_id}/snapshots/7/archive")
    assert missing_ref.status_code == 404 and _code(missing_ref) == SNAPSHOT_NOT_FOUND
    archived = admin.post(f"/v1/runs/{run_id}/snapshots/{ref}/archive")
    assert archived.status_code == 200, archived.text
    assert archived.json()["archived"] is True and archived.json()["changed"] is True
    archive_row = _events(e2e_app, chain, SNAPSHOT_ARCHIVE_ACTION)[-1]
    assert archive_row["success"] is True and archive_row["actor"] == e2e_org.actor("admin")
    assert archive_row["detail"]["snapshot_id"] == snap["id"] and archive_row["detail"]["version"] == snap["version"]
    assert archive_row["detail"]["archived_before"] is False and archive_row["detail"]["archived_after"] is True
    assert archive_row["detail"]["record_sha256"] == snap["record_sha256"]
    refused = scanner.get(f"/v1/runs/{run_id}/snapshots/{ref}")
    assert refused.status_code == 409 and _code(refused) == SNAPSHOT_ARCHIVED, refused.text
    assert _detail(refused)["snapshot_id"] == snap["id"]
    refused_pdf = scanner.get(f"/v1/runs/{run_id}/report.pdf", params={"snapshot": ref})
    assert refused_pdf.status_code == 409 and _code(refused_pdf) == SNAPSHOT_ARCHIVED
    assert admin.get(f"/v1/runs/{run_id}/snapshots/{ref}").json()["archived"] is True
    assert admin.get(f"/v1/runs/{run_id}/report.pdf", params={"snapshot": ref}).status_code == 200
    listed = scanner.get(f"/v1/runs/{run_id}/snapshots").json()
    assert listed["count"] == 3 and [s["archived"] for s in listed["snapshots"]] == [False, True, False], "flagged, never deleted"
    assert scanner.get(f"/v1/runs/{run_id}/report.pdf").headers["etag"] == f'"{newest["formats"]["pdf"]["sha256"]}"'
    with e2e_app.session() as sess:
        from redsim.db.models import Artifact, ReportSnapshot

        stored = sess.get(ReportSnapshot, snap["id"])
        assert stored is not None and stored.archived is True and list(stored.artifact_ids) == snap["artifact_ids"]
        assert all(sess.get(Artifact, artifact_id) is not None for artifact_id in snap["artifact_ids"]), "bytes stay"
    restored = admin.post(f"/v1/runs/{run_id}/snapshots/{snap['id']}/restore")
    assert restored.status_code == 200 and restored.json()["archived"] is False and restored.json()["changed"] is True
    assert _events(e2e_app, chain, SNAPSHOT_RESTORE_ACTION)[-1]["detail"]["archived_after"] is False
    assert scanner.get(f"/v1/runs/{run_id}/snapshots/{ref}").json() == snap

    # -- audit: two admission rows and two worker rows named report.render, four formats each (spec 26.5 item 22)
    renders = _events(e2e_app, chain, REPORT_RENDER_ACTION)[renders_before:]
    admitted = [ev for ev in renders if ev["detail"].get("phase") == "admitted"]
    rendered = [ev for ev in renders if ev["detail"].get("source") == "ml.run_record"]
    assert len(admitted) == 2 and all(ev["success"] and ev["actor"] == e2e_org.actor("scanner") for ev in admitted)
    assert len(rendered) == 2 and all(ev["detail"]["formats"] == list(REPORT_FORMATS) for ev in rendered)
    assert all(ev["detail"]["record_sha256"] == snap["record_sha256"] for ev in rendered)


# ---------------------------------------------------------------------------
# 4. The N-run comparison table (REVIEW_REPORTS-26; spec 15.6, 15.8)
# ---------------------------------------------------------------------------


def test_compare_three_runs_table(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], finding_campaign: h.CampaignRun,
    verifies: list[VerifyRun],
) -> None:
    from redsim.api.errors import INCOMPATIBLE_CAMPAIGNS, PARAMS_OUT_OF_RANGE, SCORE_UNAVAILABLE

    viewer, scanner = e2e_org.client("viewer"), e2e_org.client("scanner")
    baseline = finding_campaign.campaign
    assert baseline is not None
    first, second = verifies
    ids = [finding_campaign.run_id, first.run_id, second.run_id]
    baseline_score = _require_complete_score(baseline)
    for verify in verifies:
        _require_complete_score(verify.campaign)

    response = viewer.get("/v1/runs/compare", params={"ids": ",".join(ids)})
    if response.status_code == 409 and _code(response) == SCORE_UNAVAILABLE:
        pytest.fail(_PARTIAL_SCORE_DEFECT.format(missing=_detail(response).get("reasons"), limitations=None),
                    pytrace=False)
    assert response.status_code == 200, response.text
    table = response.json()
    _assert_no_aggregate(table)
    assert table["mode"] == "table" and table["compatible"] is True and table["run_ids"] == ids
    rows = table["rows"]
    assert [row["run_id"] for row in rows] == ids, "rows come back in request order"
    assert "no mean, rank" in table["statement"]
    for row in rows:
        # spec 15.7 / 26.3 item 13: an MRI never travels without its five subscores, the family table and the curve
        assert row["mri"] is not None and set(row["subscores"]) == set(SUBSCORE_KEYS)
        assert row["families"] and all(f["n"] is not None for f in row["families"])
        assert row["curve"] and row["settings_hash"] == baseline["settings_hash"]
        assert row["non_default_weights"] is False and row["limitations"]
    assert rows[0]["kind"] == "attack" and rows[0]["delta"] is None and rows[0]["baseline_run_id"] is None
    assert rows[0]["mri"] == baseline_score["mri"]
    for row, verify in zip(rows[1:], verifies, strict=True):
        # a delta only on a verify row whose own baseline is in the set (spec 15.6)
        assert row["kind"] == "verify" and row["baseline_run_id"] == finding_campaign.run_id
        assert row["defense"]["id"] == FEATURE_SQUEEZING
        delta = row["delta"]
        assert delta is not None and delta["baseline_run_id"] == finding_campaign.run_id
        assert delta["mri_before"] == baseline_score["mri"] and delta["mri_after"] == row["mri"]
        assert delta["delta_mri"] == row["mri"] - baseline_score["mri"], "measured, never filtered by sign"
        assert set(delta["delta_dimensions"]) == set(SUBSCORE_KEYS)
        assert delta["delta_acc_clean"]["before"]["n"] == delta["delta_acc_clean"]["after"]["n"] == N_EVAL
        assert row["delta_source"] in {"persisted", "computed"} and row["delta_note"] is None
        persisted = (verify.campaign["score"] or {}).get("delta")
        if persisted is not None:
            assert row["delta_source"] == "persisted" and delta["delta_mri"] == persisted["delta"]
    assert table["changed_variables_per_row"][ids[0]] == []
    assert table["changed_variables_per_row"][ids[1]] == ["defense"]
    for variable in ("settings_hash", "model_sha256", "sample_indices_sha256", "seed", "n_samples", "eps_grid"):
        assert variable in table["unchanged_variables"], (variable, table["unchanged_variables"])
    assert table["caveats"], "every compared run's limitations travel with the table (spec 14.5)"

    # request order is the caller's; a set without the baseline shows the verify rows without a delta
    reversed_table = viewer.get("/v1/runs/compare", params={"ids": ",".join(reversed(ids))}).json()
    assert [row["run_id"] for row in reversed_table["rows"]] == list(reversed(ids))
    assert reversed_table["rows"][0]["delta"] is not None and reversed_table["rows"][-1]["delta"] is None
    pair = viewer.get("/v1/runs/compare", params={"ids": ",".join([first.run_id, second.run_id])}).json()
    _assert_no_aggregate(pair)
    assert [row["delta"] for row in pair["rows"]] == [None, None]
    assert all(finding_campaign.run_id in str(row["delta_note"]) for row in pair["rows"]), "the note names the baseline"

    # an incompatible triple: the bundled campaign samples 12 rows of another model (spec 15.6, D9 i)
    other = h.run_campaign_via_api(scanner, e2e_bundled[h.IMAGE_MODEL_ID], h.image_campaign(explain_k=0),
                                   timeout_s=30.0)
    assert other.status == "succeeded", f"run {other.run_id}: {other.stage_table}"
    incompatible = viewer.get("/v1/runs/compare", params={"ids": ",".join([ids[0], ids[1], other.run_id])})
    assert incompatible.status_code == 409 and _code(incompatible) == INCOMPATIBLE_CAMPAIGNS, incompatible.text
    detail = _detail(incompatible)
    assert "n_samples" in detail["reasons"] and "not compared across settings" in detail["message"]
    assert detail["pairs"] and all(other.run_id in pair["runs"] for pair in detail["pairs"])
    assert all(ids[0] not in pair["runs"] or ids[1] not in pair["runs"] for pair in detail["pairs"]), (
        "the baseline and its verify are compatible; only pairs with the other run are named")

    # bounds and membership
    one = viewer.get("/v1/runs/compare", params={"ids": ids[0]})
    assert one.status_code == 422 and _code(one) == PARAMS_OUT_OF_RANGE
    duplicate = viewer.get("/v1/runs/compare", params={"ids": ",".join([ids[0], ids[0]])})
    assert duplicate.status_code == 422 and _code(duplicate) == PARAMS_OUT_OF_RANGE
    assert e2e_org.client(h.OUTSIDER).get("/v1/runs/compare", params={"ids": ",".join(ids)}).status_code in (403, 404)


# ---------------------------------------------------------------------------
# 5. Idempotency-Key on a mutating ML route (REVIEW_REPORTS-31, -32; spec 17.3)
# ---------------------------------------------------------------------------


def test_idempotency_key_replay_and_reuse(e2e_app: E2EApp, e2e_org: E2EOrg, verifies: list[VerifyRun]) -> None:
    from sqlalchemy import select

    from redsim.api.errors import IDEMPOTENCY_KEY_REUSED
    from redsim.api.middleware.idempotency import HEADER, REPLAYED_HEADER
    from redsim.db.models import IdempotencyKey
    from redsim.services.reports import REPORT_RENDER_ACTION

    scanner, approver = e2e_org.client("scanner"), e2e_org.client("approver")
    run_id = verifies[0].run_id
    chain = f"run:{run_id}"
    key = f"e2e-render-{uuid4().hex}"
    body = {"formats": ["md", "pdf"]}

    first = scanner.post(f"/v1/runs/{run_id}/report.render", json=body, headers={HEADER: key})
    assert first.status_code == 202, first.text
    assert REPLAYED_HEADER.lower() not in {k.lower() for k in first.headers}
    jobs_after_first = _job_rows(e2e_app, run_id, "report.render")
    admissions_after_first = len([ev for ev in _events(e2e_app, chain, REPORT_RENDER_ACTION)
                                  if ev["detail"].get("phase") == "admitted"])

    # the same key, route and body: the stored response, no second admission, no second job, no audit row
    replay = scanner.post(f"/v1/runs/{run_id}/report.render", json=body, headers={HEADER: key})
    assert replay.status_code == 202, replay.text
    assert replay.json() == first.json(), "byte-identical body: the same job id, the same formats"
    assert replay.headers[REPLAYED_HEADER] == "true"
    assert _job_rows(e2e_app, run_id, "report.render") == jobs_after_first, "no second Job row"
    assert len([ev for ev in _events(e2e_app, chain, REPORT_RENDER_ACTION)
                if ev["detail"].get("phase") == "admitted"]) == admissions_after_first, "no second audit row"

    # the same key with another body is refused; nothing runs
    reused = scanner.post(f"/v1/runs/{run_id}/report.render", json={"formats": ["md"]}, headers={HEADER: key})
    assert reused.status_code == 409 and _code(reused) == IDEMPOTENCY_KEY_REUSED, reused.text
    assert _detail(reused)["field"] == HEADER
    assert _job_rows(e2e_app, run_id, "report.render") == jobs_after_first

    # the identity is (project, principal, key): another principal's same header is its own admission
    other = approver.post(f"/v1/runs/{run_id}/report.render", json=body, headers={HEADER: key})
    assert other.status_code == 202 and other.json()["job_id"] != first.json()["job_id"], other.text
    assert REPLAYED_HEADER.lower() not in {k.lower() for k in other.headers}

    # the stored row keeps a digest of the header, never the raw key (spec 17.3)
    with e2e_app.session() as sess:
        rows = sess.execute(select(IdempotencyKey).where(IdempotencyKey.project_id == e2e_org.project_id)).scalars().all()
        stored = [row for row in rows if row.route == f"POST /v1/runs/{run_id}/report.render"]
        assert len(stored) >= 2 and all(row.key != key and len(row.key) == 64 for row in stored)
        assert all(row.response_status == 202 and row.response_body for row in stored)
        assert any(row.response_body == first.json() for row in stored)


# ---------------------------------------------------------------------------
# 6. Per-project scoring weights (REVIEW_REPORTS-29, -30; spec 15.3)
# ---------------------------------------------------------------------------


def test_project_scoring_weights_apply_to_the_next_campaign(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], finding_campaign: h.CampaignRun,
) -> None:
    from redsim.api.errors import PARAMS_OUT_OF_RANGE
    from redsim.api.v1.projects import PROJECT_SETTINGS_ACTION
    from redsim.ml.schema import ScoringConfig

    viewer, scanner, admin = e2e_org.client("viewer"), e2e_org.client("scanner"), e2e_org.client("admin")
    url = f"/v1/projects/{h.PROJECT_SLUG}/ml-scoring"
    project_chain = f"project:{e2e_org.project_id}"

    default = viewer.get(url)
    assert default.status_code == 200, default.text
    assert default.json()["source"] == "default" and default.json()["non_default_weights"] is False
    assert default.json()["ml_scoring"] == ScoringConfig().model_dump(mode="json")
    assert default.json()["project_id"] == e2e_org.project_id
    assert finding_campaign.campaign is not None and finding_campaign.campaign["non_default_weights"] is False
    assert e2e_org.client(h.OUTSIDER).get(url).status_code in (403, 404)

    # non-admins are refused before any audit row; a bad sum is 422 and never renormalised
    settings_before = len(_events(e2e_app, project_chain, PROJECT_SETTINGS_ACTION))
    assert scanner.put(url, json={"weights": CUSTOM_WEIGHTS}).status_code == 403
    assert e2e_org.client("approver").put(url, json={"weights": CUSTOM_WEIGHTS}).status_code == 403
    assert len(_events(e2e_app, project_chain, PROJECT_SETTINGS_ACTION)) == settings_before
    bad = admin.put(url, json={"weights": {**CUSTOM_WEIGHTS, "acc": 0.5}})
    assert bad.status_code == 422, bad.text
    assert _code(bad) in {"scoring_weights_invalid", PARAMS_OUT_OF_RANGE} and _detail(bad)["field"] == "ml_scoring.weights"
    refused = _events(e2e_app, project_chain, PROJECT_SETTINGS_ACTION)[-1]
    assert refused["success"] is False and refused["detail"]["refusal"] == _code(bad)
    partial = admin.put(url, json={"weights": {"acc": 0.5, "asr": 0.5}})
    assert partial.status_code == 422, "a partial vector is never filled in"
    assert viewer.get(url).json()["source"] == "default", "a refused override changes nothing"

    try:
        put = admin.put(url, json={"weights": CUSTOM_WEIGHTS})
        assert put.status_code == 200, put.text
        assert put.json()["source"] == "project" and put.json()["non_default_weights"] is True
        assert put.json()["ml_scoring"]["weights"] == CUSTOM_WEIGHTS
        assert abs(sum(put.json()["ml_scoring"]["weights"].values()) - 1.0) < 1e-9
        event = _events(e2e_app, project_chain, PROJECT_SETTINGS_ACTION)[-1]
        assert event["success"] is True and event["actor"] == e2e_org.actor("admin")
        assert event["detail"]["field"] == "ml_scoring" and event["detail"]["weights"] == CUSTOM_WEIGHTS
        assert event["detail"]["old_sha256"] is None and event["detail"]["new_sha256"]

        # the next campaign is admitted with the project's vector and scored with it (spec 15.3 badge)
        run = h.run_campaign_via_api(scanner, e2e_bundled[h.IMAGE_MODEL_ID], h.image_campaign(explain_k=0),
                                     timeout_s=30.0)
        assert run.status == "succeeded", f"run {run.run_id}: {run.stage_table}"
        campaign = run.campaign
        assert campaign is not None
        assert campaign["config"]["scoring"]["weights"] == CUSTOM_WEIGHTS, "frozen at admission"
        assert campaign["non_default_weights"] is True and campaign["weights"] == CUSTOM_WEIGHTS
        score = campaign["score"]
        if score is not None:
            assert score["weights"] == CUSTOM_WEIGHTS
        # a client-sent scoring block is refused: scoring is server-owned (spec 15.3)
        client_sent = scanner.post(f"/v1/models/{e2e_bundled[h.IMAGE_MODEL_ID]}/attacks",
                                   json={**h.image_campaign(explain_k=0), "scoring": {"weights": CUSTOM_WEIGHTS}})
        assert client_sent.status_code == 422 and _code(client_sent) == PARAMS_OUT_OF_RANGE, client_sent.text
        # two campaigns scored with different vectors are incomparable (spec 15.3)
        compare = viewer.get(f"/v1/runs/{run.run_id}/compare", params={"with": finding_campaign.run_id})
        assert compare.status_code == 409, compare.text
        assert "scoring.weights" in _detail(compare).get("reasons", []) or _code(compare) == "incompatible_campaigns"
    finally:
        cleared = admin.put(url, content=b"null", headers={"content-type": "application/json"})
        assert cleared.status_code == 200, cleared.text
        assert cleared.json()["source"] == "default" and cleared.json()["non_default_weights"] is False
    event = _events(e2e_app, project_chain, PROJECT_SETTINGS_ACTION)[-1]
    assert event["detail"]["cleared"] is True and event["detail"]["old_sha256"] and event["detail"]["new_sha256"] is None
    assert viewer.get(url).json()["ml_scoring"] == ScoringConfig().model_dump(mode="json")
