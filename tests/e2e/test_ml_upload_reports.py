"""Upload boundary and reports through the e2e harness (spec 26.2-26.4; demo steps 8, 9).

Everything below drives the production route, the admission service, the eager
worker and the real sandbox child, then asserts on what those left behind: rows,
audit events, artifacts, the campaign record and the rendered reports. Nothing
is stubbed beyond what the shared harness already replaces (broker, Redis
publisher, Pythia; see ``tests/e2e/README.md``). The Pythia mock is never
switched on here: every campaign runs with ``llm_narrative`` off, so the
recommendations are rule text with ``narrative_source == "rules"``.

Two facts about the tiny asset tree shape the tests, and both are asserted
rather than worked around silently:

* **The bundled 1-epoch CNN cannot yield a finding.** ``build_cnn_asset`` records
  8 clean-correct rows out of the 24-image evaluation split (it predicts one class
  for every image), and ``redsim.ml.scoring.MIN_CLEAN_CORRECT_FOR_FINDING`` is
  10, so no ``finding_asr_threshold`` or ``n_samples`` can produce a finding from
  it. :func:`test_bundled_tiny_cnn_yields_no_finding_and_says_so` asserts that
  honest zero-finding state. The campaign whose reports are checked therefore
  runs against an **uploaded** SmallCNN that the test trains to memorise the same
  seeded images (:func:`upload_files`), registered through the real upload path
  and validated in the real child, so the upload row of 26.4 and the report row
  of 26.3 are exercised on one model.
* **``torch.onnx.export`` cannot export ``SmallCNN`` natively at 8x8.** Its
  ``AdaptiveAvgPool2d(4)`` receives a 2x2 map at that size and the legacy
  exporter refuses "output size that are not factor of input size"; the dynamo
  exporter needs ``onnxscript``, which the ``ml`` extra does not install. The
  exported graph is therefore ``Upsample(x2, nearest) -> SmallCNN(image_size=16)``
  with an 8x8x3 input: the real catalog architecture and its weights, one Resize
  node in front. Both facts are recorded in the module's structured report.

Every run is a measurement in its own right (product decision of 2026-09-09):
there is no verify campaign, no measured delta and no validation label on a
recommendation. A candidate is ``status: candidate`` and nothing more, and the
standing limitation says so. The two runs this module already has (the bundled
CNN at a 0.05 threshold and the upload at 0.2) differ in ``finding_asr_threshold``
and are therefore not a side-by-side pair; the pairwise comparison in
``side_by_side`` mode is asserted in ``tests/e2e/test_ml_review_reports.py`` on
two campaigns with identical settings.

Run with::

    REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_ml_upload_reports.py

Heavy imports happen inside fixtures and tests, after the session fixtures have
checked the extras, so collection stays green without them.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import warnings
from html import unescape
from pathlib import Path
from typing import TYPE_CHECKING, Any

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
LICENSE_STATEMENT = "e2e harness double trained on seeded random pixels; no licence restriction applies"

#: A bare "+N": never in a recommendation's own text and nowhere in a report; no gain is ever claimed.
_BARE_GAIN = re.compile(r"(?<![\w.\-])\+\d")
_URL = re.compile(r"https?://\S+")
#: Modules the API process must never import (tests/test_api_process_has_no_ml.py, spec 8.4).
_BLOCKED_ML_MODULES = ("torch", "torchvision", "art", "onnx", "onnxruntime", "onnx2torch", "shap", "sklearn",
                       "xgboost", "safetensors")
#: Keys and words that left the recommendation contract with the verify paradigm (2026-09-09).
_RETIRED_RECOMMENDATION_KEYS = frozenset({"validation", "measured", "expected_gain", "delta", "delta_mri"})


# ---------------------------------------------------------------------------
# Read-only helpers over the harness
# ---------------------------------------------------------------------------


def _events(e2e_app: E2EApp, chain_id: str, action: str) -> list[dict[str, Any]]:
    return [ev for ev in e2e_app.read_chain(chain_id) if ev["action"] == action]


def _actions(e2e_app: E2EApp, chain_id: str) -> list[str]:
    return [str(ev["action"]) for ev in e2e_app.read_chain(chain_id)]


def _campaign(client: TestClient, run_id: str) -> dict[str, Any]:
    response = client.get(f"/v1/runs/{run_id}/campaign")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _count_targets(e2e_app: E2EApp) -> int:
    from sqlalchemy import func, select

    from redsim.db.models import Target

    with e2e_app.session() as sess:
        return int(sess.execute(select(func.count()).select_from(Target)).scalar() or 0)


def _blob_files(e2e_app: E2EApp) -> set[Path]:
    return {p for p in e2e_app.blob_root.rglob("*") if p.is_file()}


def _recs(detail: dict[str, Any]) -> list[dict[str, Any]]:
    recs = detail.get("recommendations")
    return list(recs) if isinstance(recs, list) else []


def _rec_text(rec: dict[str, Any]) -> str:
    return " ".join(str(rec.get(k) or "") for k in ("title", "rationale", "narrative")) + " " + " ".join(
        str(r) for r in rec.get("references") or [])


def _assert_candidates_only(recs: list[dict[str, Any]]) -> None:
    """A recommendation is ``status: candidate`` and nothing more: no validation label, no gain, no delta."""
    from redsim.ml.schema import CandidateRecommendation

    assert recs, "the rule layer always produces R7"
    allowed = set(CandidateRecommendation.model_fields)
    for rec in recs:
        assert rec["status"] == "candidate", rec.get("id")
        assert not (set(rec) & _RETIRED_RECOMMENDATION_KEYS), sorted(set(rec) & _RETIRED_RECOMMENDATION_KEYS)
        assert set(rec) <= allowed, sorted(set(rec) - allowed)
        text = _rec_text(rec)
        assert not _BARE_GAIN.search(text), f"bare gain in recommendation {rec.get('id')}: {text[:200]}"
        assert "expected gain" not in text.lower() and "not evaluated" not in text.lower(), text[:200]
        assert not [r for r in rec.get("references") or [] if str(r).startswith("defense:")], rec["references"]


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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _section(md: str, index: int) -> str:
    """The text of spec 14.8 section ``index`` (0-based) of a Markdown report."""
    from redsim.ml.reporting import SECTION_HEADINGS

    start = md.index(SECTION_HEADINGS[index])
    end = md.index(SECTION_HEADINGS[index + 1]) if index + 1 < len(SECTION_HEADINGS) else len(md)
    return md[start:end]


def _report(client: TestClient, run_id: str, ext: str) -> Any:
    return client.get(f"/v1/runs/{run_id}/report.{ext}")


def _artifact_bytes(client: TestClient, run_id: str, kind: str) -> tuple[bytes, dict[str, Any]]:
    listing = client.get(f"/v1/runs/{run_id}/artifacts")
    assert listing.status_code == 200, listing.text
    rows = [row for row in listing.json()["artifacts"] if row["kind"] == kind]
    assert rows, f"no {kind!r} artifact on run {run_id}"
    row = rows[0]  # newest first
    response = client.get(f"/v1/artifacts/{row['id']}")
    assert response.status_code == 200, response.text
    return response.content, row


# ---------------------------------------------------------------------------
# Module fixtures: the upload double, the registered upload, the campaigns
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def upload_files(e2e_assets: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Files for the upload boundary, built from the real catalog ``SmallCNN`` and the harness's own pixels.

    * ``onnx``: ``Upsample(x2) -> SmallCNN(image_size=16)`` trained (full batch, Adam) until it memorises the 48
      seeded images in eval mode, exported by the legacy ``torch.onnx`` exporter with an 8x8x3 input and a dynamic
      batch axis (see the module docstring for why the native 8x8 export is impossible on this tree);
    * ``legacy_pickle``: ``torch.save(module, _use_new_zipfile_serialization=False)`` -- a ``\\x80`` PROTO stream;
    * ``zip_pickle``: ``torch.save(module)`` -- a zip archive holding a pickled ``nn.Module`` (indistinguishable
      from a state_dict at the 16-byte sniff; the child's ``weights_only`` load is what refuses it, spec 9.2);
    * ``state_dict``: ``torch.save(inner.state_dict())``.
    """
    import numpy as np
    import torch
    from torch import nn

    from redsim.ml.targets.architectures import SmallCNN

    manifest = h.asset_manifest(e2e_assets)
    entry = manifest["models"][h.IMAGE_MODEL_ID]
    dataset_id = str(entry["dataset_id"])
    dataset_split = str(entry["dataset_split"])
    class_names = list(manifest["datasets"][dataset_id]["class_names"])
    assert manifest["datasets"][dataset_id]["splits"][dataset_split]["n"] == N_EVAL

    out = tmp_path_factory.mktemp("e2e-uploads")
    images = h.synthetic_images()  # the same seed the tree was built from: same pixels, same labels
    x = torch.from_numpy(images.train.x.astype(np.float32) / 255.0)
    y = torch.from_numpy(images.train.y)
    x_eval = torch.from_numpy(images.eval.x.astype(np.float32) / 255.0)
    y_eval = torch.from_numpy(images.eval.y)

    torch.manual_seed(0)
    inner = SmallCNN(in_channels=3, n_classes=len(class_names), image_size=2 * h.IMAGE_SIZE)
    model = nn.Sequential(nn.Upsample(scale_factor=2.0, mode="nearest"), inner)
    optimiser = torch.optim.Adam(model.parameters(), lr=5e-3)
    epochs = 0
    for epochs in range(1, 401):
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
    # The uploaded double must clear the finding floor with room to spare; the bundled model cannot.
    assert eval_acc * N_EVAL >= 20, f"memorising double reached only {eval_acc:.3f} on the eval split after {epochs} epochs"

    onnx_path = out / "small_cnn_8x8.onnx"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        torch.onnx.export(
            model, (x_eval[:1],), str(onnx_path), input_names=["input"], output_names=["logits"],
            opset_version=17, dynamo=False, dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}},
        )
    legacy_pickle = out / "legacy_module.pt"
    torch.save(model, legacy_pickle, _use_new_zipfile_serialization=False)
    zip_pickle = out / "full_module.pt"
    torch.save(model, zip_pickle)
    state_dict = out / "state_dict.pt"
    torch.save(inner.state_dict(), state_dict)

    assert onnx_path.read_bytes()[0] == 0x08, "ONNX ModelProto starts with the ir_version tag"
    assert legacy_pickle.read_bytes()[0] == 0x80, "legacy torch.save is a pickle PROTO stream"
    assert zip_pickle.read_bytes().startswith(b"PK\x03\x04") and state_dict.read_bytes().startswith(b"PK\x03\x04")
    return {
        "onnx": onnx_path, "legacy_pickle": legacy_pickle, "zip_pickle": zip_pickle, "state_dict": state_dict,
        "dataset_id": dataset_id, "dataset_split": dataset_split, "class_names": class_names,
        "eval_accuracy": eval_acc, "epochs": epochs,
    }


@pytest.fixture(scope="module")
def onnx_model(e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str],
               upload_files: dict[str, Any]) -> dict[str, Any]:
    """The ONNX double registered through ``POST /v1/models`` (remediator) and validated in the real child."""
    del e2e_bundled  # ordering only: the bundled registrations precede the upload on the project chain
    client = e2e_org.client("remediator")
    response = _upload(client, e2e_org.project_id, upload_files["onnx"], declared_format="onnx",
                       dataset_id=upload_files["dataset_id"], dataset_split=upload_files["dataset_split"])
    assert response.status_code == 201, response.text
    posted = response.json()
    model_id = str(posted["id"])
    record = _wait_for_validation(client, model_id)
    return {"model_id": model_id, "posted": posted, "record": record,
            "ingest_run_id": str(posted["ingest_run_id"]), "ingest_job_id": str(posted["ingest_job_id"]),
            "sha256": _sha256(upload_files["onnx"])}


@pytest.fixture(scope="module")
def bundled_zero_finding_campaign(e2e_org: E2EOrg, e2e_bundled: dict[str, str]) -> h.CampaignRun:
    """The bundled tiny CNN on its whole eval split with a permissive threshold: the most a finding could get."""
    body = h.image_campaign(n_samples=N_EVAL, finding_asr_threshold=0.05)
    result = h.run_campaign_via_api(e2e_org.client("scanner"), e2e_bundled[h.IMAGE_MODEL_ID], body, timeout_s=30.0)
    assert result.status == "succeeded", f"run {result.run_id}: {result.stage_table}"
    assert result.campaign is not None, result.campaign_error
    return result


@pytest.fixture(scope="module")
def finding_campaign(e2e_org: E2EOrg, onnx_model: dict[str, Any]) -> h.CampaignRun:
    """FGSM + PGD (or HopSkipJump alone if the ONNX graph exposed no gradients) on the memorising upload."""
    manifest = onnx_model["record"].get("manifest") or {}
    if manifest.get("gradients"):
        body = h.image_campaign(n_samples=N_EVAL, finding_asr_threshold=FINDING_THRESHOLD)
    else:  # honest fallback: only black-box attacks are admitted on a target without loss gradients (spec 9.5)
        body = h.image_campaign(n_samples=N_EVAL, finding_asr_threshold=FINDING_THRESHOLD, attack_ids=["hopskipjump"],
                                attack_params={"hopskipjump": h.tabular_campaign()["attack_params"]["hopskipjump"]})
    result = h.run_campaign_via_api(e2e_org.client("scanner"), onnx_model["model_id"], body, timeout_s=30.0)
    assert result.status == "succeeded", f"run {result.run_id}: {result.stage_table}"
    assert result.campaign is not None, result.campaign_error
    clean = [m for m in result.campaign["measurements"] if m["family"] == "clean"]
    asr = {m["id"]: m.get("attack_success_rate") for m in result.campaign["measurements"] if m["family"] == "evasion"}
    assert result.findings, (
        f"the memorising upload produced no finding: clean row {clean}; ASR by row {asr}; threshold {FINDING_THRESHOLD}"
    )
    return result


# ---------------------------------------------------------------------------
# 1. The bundled tiny CNN: the honest zero-finding state
# ---------------------------------------------------------------------------


def test_bundled_tiny_cnn_yields_no_finding_and_says_so(
    e2e_app: E2EApp, e2e_org: E2EOrg, bundled_zero_finding_campaign: h.CampaignRun,
) -> None:
    """No finding can come from the 1-epoch bundled CNN, and the record says why rather than inventing one.

    ``MIN_CLEAN_CORRECT_FOR_FINDING`` (10) is the spec 12.6 denominator floor; the
    build-time metric the tree recorded and the campaign's clean row agree on 8
    clean-correct rows out of 24, so ``crosses_threshold`` is irrelevant and no
    ``Finding`` row may exist. Every candidate is a candidate and nothing more.
    """
    from redsim.ml.schema import STANDING_LIMITATIONS
    from redsim.ml.scoring import MIN_CLEAN_CORRECT_FOR_FINDING

    result = bundled_zero_finding_campaign
    campaign = result.campaign
    assert campaign is not None
    clean_rows = [m for m in campaign["measurements"] if m["family"] == "clean"]
    assert len(clean_rows) == 1
    clean = clean_rows[0]
    assert clean["n"] == N_EVAL, "the whole evaluation split was sampled"
    build_metrics = h.asset_manifest(e2e_app.assets_dir)["models"][h.IMAGE_MODEL_ID]["metrics"]
    assert clean["n_correct"] == build_metrics["n_correct"], "the campaign re-measures what the builder recorded"
    assert clean["n_correct"] < MIN_CLEAN_CORRECT_FOR_FINDING, (
        f"{clean['n_correct']} clean-correct rows would clear the finding floor; this test's premise no longer holds")

    # The attacks did run and did flip predictions; that alone is not a finding under the floor.
    evasion = [m for m in campaign["measurements"] if m["family"] == "evasion"]
    assert evasion and all(m["n_clean_correct"] == clean["n_correct"] for m in evasion)
    assert campaign["findings"] == []
    listing = e2e_org.client("viewer").get("/v1/findings", params={"run": result.run_id})
    assert listing.status_code == 200, listing.text
    rows = listing.json()
    rows = rows.get("findings", rows) if isinstance(rows, dict) else rows
    assert rows == []
    # No finding: the honest state is still a complete evidence record with candidates and limitations.
    assert campaign["limitations"], "limitations are non-empty on every succeeded run (spec 14.5)"
    assert STANDING_LIMITATIONS[3] in campaign["limitations"], "the standing sentence: candidates, none evaluated"
    _assert_candidates_only(_recs(campaign))
    assert _events(e2e_app, f"run:{result.run_id}", "job.complete")[-1]["detail"]["n_findings"] == 0


# ---------------------------------------------------------------------------
# 2. Upload boundary: ONNX becomes available, pickles are refused, the API never loads a model
# ---------------------------------------------------------------------------


def test_onnx_available_and_pickle_refused(
    e2e_app: E2EApp, e2e_org: E2EOrg, upload_files: dict[str, Any], onnx_model: dict[str, Any],
) -> None:
    from redsim.api.errors import (
        ARCHITECTURE_NOT_ALLOWLISTED,
        ARCHITECTURE_REQUIRED,
        MODEL_LOAD_REFUSED,
        PICKLE_REFUSED,
    )

    remediator = e2e_org.client("remediator")
    project_chain = f"project:{e2e_org.project_id}"
    model_id = onnx_model["model_id"]
    posted, record = onnx_model["posted"], onnx_model["record"]

    # -- admission answered before any loading: registered -> validating, bytes hashed, nothing deserialised --
    assert posted["status"] == "validating" and posted["source"] == "upload" and posted["registered"] is True
    assert posted["enqueued"] is True and posted["sha256"] == onnx_model["sha256"]
    assert posted["manifest"]["format"] == "onnx" and posted["validation"]["ingest_run_id"] == onnx_model["ingest_run_id"]
    # The route audits with the ingest run id, so ``_chain_id`` keys the row to ``run:<ingest_run_id>`` (spec 5.11
    # and 9.3 step 4 name the project chain; the divergence is recorded in this track's report). Either way it
    # is the first row of its chain, written before the Target / Run / Job rows and before the enqueue.
    ingest_chain = f"run:{onnx_model['ingest_run_id']}"
    register = [ev for ev in _events(e2e_app, ingest_chain, "model.register")
                if ev["detail"].get("target_id") == model_id]
    assert not [ev for ev in _events(e2e_app, project_chain, "model.register")
                if ev["detail"].get("target_id") == model_id], "the row is on one chain only"
    assert len(register) == 1 and register[0]["success"] is True and register[0]["seq"] == 1
    assert register[0]["detail"]["source"] == "upload" and register[0]["detail"]["detected_format"] == "onnx"
    assert register[0]["detail"]["sha256"] == onnx_model["sha256"]
    assert register[0]["detail"]["blob_key"].startswith(f"{e2e_org.project_id}/models/{model_id}/")
    assert register[0]["actor"] == e2e_org.actor("remediator") and register[0]["allowlist_check"] == "n/a"

    # -- the child validated it: available, gradients as converted, agreement recorded (spec 9.2 onnx row) -----
    assert record["status"] == "available" and record["refusal_reason"] is None, record.get("reason")
    validation, manifest = record["validation"], record["manifest"]
    assert validation["detected_format"] == "onnx" == manifest["format"]
    assert manifest["sha256"] == onnx_model["sha256"]
    assert manifest["input_shape"] == [3, h.IMAGE_SIZE, h.IMAGE_SIZE]
    assert manifest["n_classes"] == len(upload_files["class_names"])
    assert manifest["class_names"] == upload_files["class_names"]
    assert manifest["dataset_id"] == upload_files["dataset_id"]
    assert manifest["dataset_split"] == upload_files["dataset_split"]
    assert manifest["status"] == "available" and manifest["bundled"] is False
    assert manifest["license"] == LICENSE_STATEMENT
    assert "onnx_torch_argmax_agreement" in manifest and "onnx_torch_argmax_agreement" in validation
    assert manifest["onnx"]["predictions"] == "onnxruntime"
    conversion = validation["onnx_conversion"]
    assert isinstance(conversion, dict) and conversion["status"] in {"converted", "unavailable", "failed",
                                                                     "disagreement"}
    if conversion["status"] == "converted":
        assert validation["gradients"] is True and manifest["gradients"] is True
        assert manifest["onnx"]["estimator"] == "PyTorchClassifier"
        agreement = manifest["onnx_torch_argmax_agreement"]
        assert isinstance(agreement, dict) and agreement == validation["onnx_torch_argmax_agreement"]
        assert 0.0 <= float(agreement["agreement"]) <= 1.0
        assert 1 <= int(agreement["n_agree"]) <= int(agreement["n"]) <= N_EVAL
    else:
        # Honest BlackBox: no differentiable module, white-box attacks are not offered (spec 9.5).
        assert validation["gradients"] is False and manifest["gradients"] is False
        assert manifest["onnx"]["estimator"] == "BlackBoxClassifier" and conversion["reason"]
    assert _actions(e2e_app, ingest_chain) == ["model.register", "model.validate", "job.complete"], (
        _actions(e2e_app, ingest_chain))
    validate = _events(e2e_app, ingest_chain, "model.validate")[0]
    assert validate["success"] is True and validate["detail"]["status"] == "available"
    assert validate["detail"]["detected_format"] == "onnx" and validate["detail"]["target_id"] == model_id
    assert validate["detail"]["gradients"] == manifest["gradients"]
    assert validate["detail"]["onnx_torch_argmax_agreement"] == manifest["onnx_torch_argmax_agreement"]
    assert validate["detail"]["onnx_conversion_status"] == conversion["status"]
    complete = _events(e2e_app, ingest_chain, "job.complete")[0]
    assert complete["detail"]["job_type"] == "model.validate" and complete["detail"]["validation_status"] == "available"
    report_bytes, row = _artifact_bytes(e2e_org.client("viewer"), onnx_model["ingest_run_id"], "ml.validation_report")
    assert row["sha256"] == hashlib.sha256(report_bytes).hexdigest()
    assert json.loads(report_bytes)["status"] == "available"
    stored = h.registered_target(e2e_app, model_id)
    assert stored["kind"] == "ml_model_artifact" and stored["detail"]["status"] == "available"
    assert Path(stored["value"]).is_file(), "the accepted blob stays in the store"
    listing = e2e_org.client("viewer").get("/v1/models", params={"project": e2e_org.project_id})
    assert any(m["id"] == model_id and m["source"] == "upload" and m["registered"] for m in listing.json()["models"])

    # -- a pickled nn.Module as .pt: refused at the sniff, audited, no row, no bytes retained ---------------------
    targets_before, blobs_before = _count_targets(e2e_app), _blob_files(e2e_app)
    refused_before = len([ev for ev in _events(e2e_app, project_chain, "model.register") if not ev["success"]])
    response = _upload(remediator, e2e_org.project_id, upload_files["legacy_pickle"],
                       declared_format="torch_state_dict", architecture_id="small_cnn",
                       dataset_id=upload_files["dataset_id"], dataset_split=upload_files["dataset_split"])
    assert response.status_code == 415, response.text
    assert response.json()["detail"]["code"] == PICKLE_REFUSED and response.json()["detail"]["field"] == "file"
    refused = [ev for ev in _events(e2e_app, project_chain, "model.register") if not ev["success"]]
    assert len(refused) == refused_before + 1
    assert refused[-1]["detail"]["reason"] == PICKLE_REFUSED and refused[-1]["detail"]["source"] == "upload"
    assert refused[-1]["detail"]["filename"] == upload_files["legacy_pickle"].name
    assert "sha256" not in refused[-1]["detail"] and "target_id" not in refused[-1]["detail"]
    assert _count_targets(e2e_app) == targets_before and _blob_files(e2e_app) == blobs_before

    # -- state_dict formats need a catalog architecture (spec 9.2, 17.3) ---------------------------------------
    response = _upload(remediator, e2e_org.project_id, upload_files["state_dict"], declared_format="torch_state_dict",
                       dataset_id=upload_files["dataset_id"], dataset_split=upload_files["dataset_split"])
    assert response.status_code == 422 and response.json()["detail"]["code"] == ARCHITECTURE_REQUIRED, response.text
    assert response.json()["detail"]["field"] == "architecture_id"
    response = _upload(remediator, e2e_org.project_id, upload_files["state_dict"], declared_format="torch_state_dict",
                       architecture_id="vgg99", dataset_id=upload_files["dataset_id"],
                       dataset_split=upload_files["dataset_split"])
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == ARCHITECTURE_NOT_ALLOWLISTED
    assert "small_cnn" in response.json()["detail"]["allowed"]
    refused = [ev for ev in _events(e2e_app, project_chain, "model.register") if not ev["success"]]
    assert [ev["detail"]["reason"] for ev in refused[-2:]] == [ARCHITECTURE_REQUIRED, ARCHITECTURE_NOT_ALLOWLISTED]
    assert _count_targets(e2e_app) == targets_before and _blob_files(e2e_app) == blobs_before

    # -- the role gate: a scanner may launch campaigns but not register models -----------------------------------
    response = _upload(e2e_org.client("scanner"), e2e_org.project_id, upload_files["onnx"], declared_format="onnx",
                       dataset_id=upload_files["dataset_id"], dataset_split=upload_files["dataset_split"])
    assert response.status_code == 403, response.text
    assert _count_targets(e2e_app) == targets_before

    # -- a zip-wrapped pickled nn.Module with a declared architecture: the sniff cannot see inside a zip ----------
    # (spec 9.2: "weights_only load raises ... this is what full pickle means operationally"). Either the API
    # refuses it outright or the child does; both end refused, audited and without retained bytes.
    response = _upload(remediator, e2e_org.project_id, upload_files["zip_pickle"], declared_format="torch_state_dict",
                       architecture_id="small_cnn", dataset_id=upload_files["dataset_id"],
                       dataset_split=upload_files["dataset_split"])
    if response.status_code == 415:
        assert response.json()["detail"]["code"] == PICKLE_REFUSED
        assert _count_targets(e2e_app) == targets_before
    else:
        assert response.status_code == 201, response.text
        zipped_id = str(response.json()["id"])
        zipped = _wait_for_validation(remediator, zipped_id)
        assert zipped["status"] == "refused" and zipped["refusal_reason"] == PICKLE_REFUSED, zipped.get("reason")
        assert zipped["validation"]["refusal_reason"] == PICKLE_REFUSED and zipped["validation"]["gradients"] is None
        stored = h.registered_target(e2e_app, zipped_id)
        assert stored["detail"]["status"] == "refused"
        assert not Path(stored["value"]).exists(), "a refused upload's bytes are deleted (spec 6.6, 9.5)"
        zipped_chain = f"run:{response.json()['ingest_run_id']}"
        validate = _events(e2e_app, zipped_chain, "model.validate")[0]
        assert validate["success"] is False and validate["detail"]["refusal_reason"] == PICKLE_REFUSED
        assert validate["detail"]["status"] == "refused"
        # Only an available target is launchable (spec 26.4 item 17): 409 with the status and the reason.
        launch = e2e_org.client("scanner").post(f"/v1/models/{zipped_id}/attacks", json={
            **h.image_campaign(), "dataset_id": upload_files["dataset_id"]})
        assert launch.status_code == 409, launch.text
        assert launch.json()["detail"]["code"] == MODEL_LOAD_REFUSED
        assert launch.json()["detail"]["status"] == "refused"
        assert launch.json()["detail"]["refusal_reason"] == PICKLE_REFUSED
    assert h.MOCK_PYTHIA_API_KEY not in json.dumps(e2e_app.read_chain(project_chain), default=str)


#: Run in a fresh interpreter with the ML libraries blocked in ``sys.modules`` (tests/test_api_process_has_no_ml.py):
#: the API's own admission path for the same four uploads, over a scratch sqlite and a scratch blob root. The
#: broker is the one piece of infrastructure the probe has not, so the task's ``.delay`` is a stub returning an id
#: (as in tests/ml/test_models_routes.py); everything before it -- sniff, hash, blob write, audit row, Target /
#: Run / Job rows -- is the production code. Prints one JSON line.
_NO_ML_PROBE = r"""
import json, os, sys
blocked = %r
for name in blocked:
    sys.modules[name] = None
from pathlib import Path
from types import SimpleNamespace
from fastapi.testclient import TestClient
from tests.conftest import patch_jsonb_for_sqlite
patch_jsonb_for_sqlite()
from redsim.db import session as db_session
from redsim.db.models import Base, Organization, Project
engine = db_session.init_engine(os.environ["REDSIM_DB_URL"])
Base.metadata.create_all(engine)
with db_session.get_session() as sess:
    sess.add(Organization(id="org-probe", name="probe", slug="probe"))
    sess.add(Project(id="default", org_id="org-probe", name="default", slug="default"))
import redsim.workers.tasks.ml_model as ml_model
ml_model.ml_model_validate.delay = lambda job_id: SimpleNamespace(id="probe-" + job_id)
from redsim.api.app import create_app
from redsim.api.settings import APISettings
app = create_app(APISettings(env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
                             rate_limit_per_user_per_min=1_000_000, rate_limit_per_project_per_min=1_000_000))
client = TestClient(app)
client.headers["Authorization"] = "Bearer dev:probe@e2e.redsim.test"

def upload(path, **fields):
    data = {"source": "upload", "project_id": "default", "name": "probe", "declared_format": "onnx",
            "modality": "image", "license_statement": "probe", "dataset_id": os.environ["PROBE_DATASET_ID"],
            "dataset_split": os.environ["PROBE_DATASET_SPLIT"]}
    for key, value in fields.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    p = Path(path)
    r = client.post("/v1/models", data=data, files={"file": (p.name, p.read_bytes(), "application/octet-stream")})
    try:
        body = r.json()
    except ValueError:
        body = r.text
    return {"status": r.status_code, "body": body}

out = {
    "onnx": upload(os.environ["PROBE_ONNX"]),
    "legacy_pickle": upload(os.environ["PROBE_LEGACY_PICKLE"], declared_format="torch_state_dict",
                            architecture_id="small_cnn"),
    "zip_pickle": upload(os.environ["PROBE_ZIP_PICKLE"], declared_format="torch_state_dict",
                         architecture_id="small_cnn"),
    "no_arch": upload(os.environ["PROBE_STATE_DICT"], declared_format="torch_state_dict"),
    "bad_arch": upload(os.environ["PROBE_STATE_DICT"], declared_format="torch_state_dict", architecture_id="vgg99"),
}
model_id = out["onnx"]["body"].get("id") if isinstance(out["onnx"]["body"], dict) else None
out["get"] = client.get("/v1/models/" + str(model_id)).status_code
out["health"] = client.get("/health").status_code
out["loaded"] = sorted(m for m in sys.modules if m.split(".")[0] in blocked and sys.modules[m] is not None)
print(json.dumps(out, default=str))
"""


def test_api_process_admits_uploads_without_importing_ml(
    e2e_app: E2EApp, upload_files: dict[str, Any], tmp_path: Path,
) -> None:
    """Spec 8.4 / 26.4 item 17: the same upload requests, in an API process that cannot import an ML library.

    The harness process itself imports torch (it builds the assets), so the rule
    is checked the way ``tests/test_api_process_has_no_ml.py`` checks it: a fresh
    interpreter with the libraries blocked, the app built and driven, and the
    set of blocked modules that ended up loaded asserted empty.
    """
    from redsim.api.errors import ARCHITECTURE_NOT_ALLOWLISTED, ARCHITECTURE_REQUIRED, PICKLE_REFUSED

    blob_root = tmp_path / "blobs"
    blob_root.mkdir()
    env = e2e_app.cli_env()
    env.update({
        "REDSIM_DB_URL": f"sqlite:///{tmp_path / 'probe.db'}",
        "REDSIM_BLOB_FS_PATH": str(blob_root),
        "REDSIM_ML_ASSETS_DIR": str(e2e_app.assets_dir),
        "REDSIM_ENV": "dev", "REDSIM_AUTH_MODE": "dev",
        "PROBE_ONNX": str(upload_files["onnx"]), "PROBE_LEGACY_PICKLE": str(upload_files["legacy_pickle"]),
        "PROBE_ZIP_PICKLE": str(upload_files["zip_pickle"]), "PROBE_STATE_DICT": str(upload_files["state_dict"]),
        "PROBE_DATASET_ID": upload_files["dataset_id"], "PROBE_DATASET_SPLIT": upload_files["dataset_split"],
    })
    assert not [k for k in env if k.startswith(("PYTHIA_", "KAGGLE_"))]
    completed = subprocess.run(
        [sys.executable, "-c", _NO_ML_PROBE % (_BLOCKED_ML_MODULES,)],
        cwd=str(e2e_app.harness_dir), env=env, capture_output=True, text=True, timeout=180, check=False,
    )
    assert completed.returncode == 0, f"the API probe failed:\n{completed.stderr[-4000:]}"
    probe = json.loads(completed.stdout.strip().splitlines()[-1])
    assert probe["loaded"] == [], f"the API process imported ML libraries: {probe['loaded']}"
    assert probe["health"] == 200
    assert probe["onnx"]["status"] == 201 and probe["onnx"]["body"]["status"] == "validating"
    assert probe["onnx"]["body"]["sha256"] == _sha256(upload_files["onnx"])
    assert probe["get"] == 200
    assert probe["legacy_pickle"]["status"] == 415
    assert probe["legacy_pickle"]["body"]["detail"]["code"] == PICKLE_REFUSED
    assert probe["no_arch"]["status"] == 422 and probe["no_arch"]["body"]["detail"]["code"] == ARCHITECTURE_REQUIRED
    assert probe["bad_arch"]["status"] == 422
    assert probe["bad_arch"]["body"]["detail"]["code"] == ARCHITECTURE_NOT_ALLOWLISTED
    # The zip-wrapped pickle passes a 16-byte sniff (it is a zip); the API answers 201 and leaves the refusal to
    # the worker's child, or 415 if the sniff ever learns to look inside. Either way nothing was loaded here.
    assert probe["zip_pickle"]["status"] in (201, 415), probe["zip_pickle"]
    # Bytes the probe accepted were written under its own blob root, none under the harness's.
    assert any(p.is_file() for p in blob_root.rglob("*"))


# ---------------------------------------------------------------------------
# 3. Reports: six sections in order, the scorecard sub-block, inert URLs, JSON == record, headers, the PDF
# ---------------------------------------------------------------------------


def _assert_markdown_report(md: str, campaign: dict[str, Any]) -> None:
    """Spec 14.8 / 15.7 on one rendered Markdown report: six sections, the scorecard sub-block, candidates only."""
    from redsim.ml.reporting import SCORECARD_HEADING, SECTION_HEADINGS
    from redsim.ml.schema import GRADE_STATEMENT, STANDING_LIMITATIONS

    positions = [md.index(heading) for heading in SECTION_HEADINGS]
    assert positions == sorted(positions), "the six sections are in the spec 14.8 order"
    assert md.count("\n## ") == len(SECTION_HEADINGS), "exactly six sections"

    measurements = _section(md, 1)
    assert SCORECARD_HEADING in measurements, "the scorecard is a sub-block of section 2 and appears nowhere else"
    assert md.count(SCORECARD_HEADING) == 1
    assert GRADE_STATEMENT in measurements
    assert "| ε |" in measurements and "Flipped / clean correct (ASR)" in measurements, "the curve table"
    score = campaign.get("score")
    if score is not None and score.get("mri") is not None:
        assert f"**MRI {score['mri']} — grade {score['grade']}**" in measurements
        # The subscore rows live in the scorecard sub-block and nowhere else in the section.
        scorecard = measurements[measurements.index(SCORECARD_HEADING):]
        for key in ("S_acc", "S_asr", "S_eps", "S_conf", "S_expl"):
            rows = [line for line in scorecard.splitlines() if line.startswith(f"| {key} |")]
            assert len(rows) == 1 and "(n=" in rows[0], f"{key}: {rows}"
        assert score["reading"] and "Reading (attack-scoped):" in measurements
    else:
        assert "**MRI not computed**" in measurements
        assert not re.search(r"\*\*MRI \d", measurements), "a partial score never shows a number"
    clean = next(m for m in campaign["measurements"] if m["family"] == "clean")
    assert f"{clean['n_correct']}/{clean['n']}" in measurements, "denominators travel with every rate"

    candidates = _section(md, 4)
    recs = _recs(campaign)
    if recs:
        for rec in recs:
            assert f"**{rec['id']}** [candidate]" in candidates, rec["id"]
    else:
        assert "No candidate recommendations were produced." in candidates
    # A candidate is a candidate and nothing more: no validation label, no gain line, no delta block anywhere.
    assert "Validation:" not in candidates and "not evaluated" not in candidates.lower(), candidates[:400]
    assert "Expected gain" not in md and "ΔMRI" not in md and "Measured" not in candidates, "no gain is claimed"
    for line in md.splitlines():
        assert not _BARE_GAIN.search(line), f"bare gain in the report: {line}"

    limitations = _section(md, 5)
    bullets = [line for line in limitations.splitlines() if line.startswith("- ")]
    assert bullets and len(bullets) >= len(campaign["limitations"]) >= 1
    assert "No limitations were recorded" not in limitations
    assert STANDING_LIMITATIONS[3] in limitations, "the standing sentence: candidates, none evaluated"
    if campaign.get("observations"):
        assert "heuristic" in _section(md, 2), "centre-mass ratios are labelled heuristic wherever they appear"
    if campaign.get("interpretation"):
        assert "inferred" in _section(md, 3), "every interpretation carries its inferred label"


def _assert_report_routes(e2e_app: E2EApp, e2e_org: E2EOrg, run_id: str) -> tuple[str, dict[str, Any]]:
    """Download md/json/html for ``run_id`` and check headers, digests, JSON identity; return (md, campaign)."""
    from redsim.api.security_headers import REPORT_CSP
    from redsim.ml.schema import CampaignRecord, MRIRecord

    scanner, viewer = e2e_org.client("scanner"), e2e_org.client("viewer")
    campaign = _campaign(viewer, run_id)
    digests: dict[str, str] = {}

    md_response = _report(scanner, run_id, "md")
    assert md_response.status_code == 200, md_response.text
    assert md_response.headers["content-type"].startswith("text/markdown")
    assert md_response.headers["x-content-type-options"] == "nosniff"
    assert md_response.headers["content-disposition"].startswith("attachment")
    digests["md"] = md_response.headers["etag"].strip('"')
    assert digests["md"] == hashlib.sha256(md_response.content).hexdigest(), "ETag is the artifact digest"
    md = md_response.text

    json_response = _report(scanner, run_id, "json")
    assert json_response.status_code == 200, json_response.text
    assert json_response.headers["content-type"].startswith("application/json")
    assert json_response.headers["x-content-type-options"] == "nosniff"
    assert json_response.headers["content-disposition"].startswith("attachment")
    digests["json"] = json_response.headers["etag"].strip('"')
    assert digests["json"] == hashlib.sha256(json_response.content).hexdigest()
    report_json = json.loads(json_response.content)
    record_bytes, record_row = _artifact_bytes(viewer, run_id, "ml.run_record")
    assert record_row["sha256"] == hashlib.sha256(record_bytes).hexdigest()
    assert report_json == json.loads(record_bytes), "report.json is the run record, nothing added or removed"
    restored = CampaignRecord.model_validate(report_json)
    assert restored.run_id == run_id
    if campaign["score"] is not None:
        assert report_json["score"] == campaign["score"], "the MRIRecord travels under score"
        MRIRecord.model_validate(report_json["score"])
    else:
        assert report_json["score"] is None and report_json["score_status"] is not None
    for key, value in report_json.items():
        assert campaign[key] == value, key
    # The campaign projection adds the finding rows, the project, reviewer notes and (wave B2) the
    # scoring weights it was scored with; the record itself is the report.
    # ... and (wave B4, BULK-02) the batch_id overlay from the ml_campaigns row (None for a single run).
    assert set(campaign) - set(report_json) <= {"findings", "project_id", "reviewer_notes", "weights",
                                                "non_default_weights", "batch_id"}
    assert "config" in report_json and "provenance" in report_json and "limitations" in report_json

    html_response = _report(scanner, run_id, "html")
    assert html_response.status_code == 200, html_response.text
    assert html_response.headers["content-type"].startswith("text/html")
    assert html_response.headers["content-security-policy"] == REPORT_CSP
    assert html_response.headers["x-content-type-options"] == "nosniff"
    digests["html"] = html_response.headers["etag"].strip('"')
    assert digests["html"] == hashlib.sha256(html_response.content).hexdigest()
    html = html_response.text
    assert "<a " not in html and "<a>" not in html and "href=" not in html, "no anchor element for any string"
    assert "<script" not in html
    for heading in ("Configuration and provenance", "Measurements", "Observations", "Interpretation",
                    "Candidate recommendations", "Limitations"):
        assert heading in html
    for url in {m.group(0).rstrip(").,;`") for m in _URL.finditer(md)}:
        # URL strings are data: rendered as inert (escaped) text and never linked.
        assert url in unescape(html), url

    # The completion path renders every format (REVIEW_REPORTS-16/-20): report.pdf is a worker-written artifact
    # served straight after completion, and the run's first snapshot (version 1) lists the formats it wrote. A
    # PDF the renderer could not typeset degrades to the three text formats with the failure named under
    # ``pdf_unavailable`` on the report.render row and a 404 on the route (never a filesystem fallback).
    render_rows = _events(e2e_app, f"run:{run_id}", "report.render")
    assert render_rows, "the completion path wrote a report.render row"
    completion_row = render_rows[0]["detail"]
    rendered_formats = list(completion_row["formats"])
    assert rendered_formats[:3] == ["md", "json", "html"], rendered_formats
    pdf = _report(scanner, run_id, "pdf")
    if "pdf" in rendered_formats:
        assert rendered_formats == ["md", "json", "html", "pdf"], rendered_formats
        assert "pdf_unavailable" not in completion_row
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-"), pdf.status_code
        assert pdf.headers["content-type"] == "application/pdf"
        digests["pdf"] = pdf.headers["etag"].strip('"')
        assert digests["pdf"] == hashlib.sha256(pdf.content).hexdigest()
    else:
        assert pdf.status_code == 404, pdf.text
        assert pdf.json()["detail"] == "report not yet rendered"
        assert completion_row["pdf_unavailable"], "a missing PDF names its failure"
    snapshots = scanner.get(f"/v1/runs/{run_id}/snapshots")
    assert snapshots.status_code == 200, snapshots.text
    assert snapshots.json()["count"] >= 1
    completion = snapshots.json()["snapshots"][-1]
    assert completion["version"] == 1 and completion["archived"] is False, completion
    assert set(completion["formats"]) == set(rendered_formats), (sorted(completion["formats"]), rendered_formats)
    for ext, digest in digests.items():
        assert completion["formats"][ext]["sha256"] == digest, ext

    # The export gate (spec 7.3, 17.1): membership alone does not export; the other project sees nothing.
    assert _report(viewer, run_id, "md").status_code == 403
    assert _report(e2e_org.client(h.OUTSIDER), run_id, "md").status_code in (403, 404)
    assert _report(e2e_org.client(h.STRANGER), run_id, "html").status_code in (403, 404)

    assert {ext: completion_row["sha256"][f"report.{ext}"] for ext in digests} == digests
    listing = viewer.get(f"/v1/runs/{run_id}/artifacts").json()["artifacts"]
    kinds = {row["kind"]: row["sha256"] for row in listing}
    for ext, digest in digests.items():
        assert kinds.get(f"report.{ext}") == digest, (ext, kinds)
    return md, campaign


def test_reports_sections_and_completion_pdf(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], finding_campaign: h.CampaignRun,
) -> None:
    """Demo step 9: the rendered reports of the image campaign that produced a finding and of a tabular campaign."""
    # -- the image campaign that produced the finding --------------------------------------------------------
    md, campaign = _assert_report_routes(e2e_app, e2e_org, finding_campaign.run_id)
    _assert_markdown_report(md, campaign)
    configuration = _section(md, 0)
    assert campaign["settings_hash"] in configuration and campaign["provenance"]["model_sha256"] in configuration
    assert campaign["config"]["dataset_id"] in configuration
    assert "defense" not in campaign["config"] and "defense" not in campaign["provenance"], "no defense block"
    _assert_candidates_only(_recs(campaign))
    for finding in finding_campaign.findings:
        assert finding["status"] == "open" and "validation_state" not in finding and "validated_at" not in finding
        detail = finding["schema_blob"]["ml"]
        assert "verify" not in detail and "retests" not in detail, sorted(detail)
        steps = str(finding["schema_blob"]["remediation_steps"])
        assert steps.startswith("CANDIDATE: ") and "not evaluated" not in steps, steps[:120]

    # -- a tabular campaign (HopSkipJump + control on the URL trees): URL strings stay inert text ---------------
    body = h.tabular_campaign(attack_ids=["hopskipjump"])
    body["attack_params"] = {"hopskipjump": dict(body["attack_params"]["hopskipjump"])}
    tabular = h.run_campaign_via_api(e2e_org.client("scanner"), e2e_bundled[h.TABULAR_MODEL_ID], body, timeout_s=30.0)
    assert tabular.status == "succeeded", f"run {tabular.run_id}: {tabular.stage_table}"
    md_tabular, tabular_campaign = _assert_report_routes(e2e_app, e2e_org, tabular.run_id)
    _assert_markdown_report(md_tabular, tabular_campaign)
    assert tabular_campaign["config"]["modality"] == "tabular"
    assert tabular_campaign["config"]["dataset_id"] == h.URL_DATASET_ID
    assert "hopskipjump" in md_tabular
    # Any URL-shaped string the record carries appears in the HTML only as escaped text (checked in the route
    # helper); the Markdown never wraps one in link syntax either.
    assert not re.search(r"\]\(https?://", md_tabular), "no Markdown link syntax around a URL string"
    assert h.MOCK_PYTHIA_API_KEY not in md and h.MOCK_PYTHIA_API_KEY not in md_tabular
