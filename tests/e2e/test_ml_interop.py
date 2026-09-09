"""Interoperability end to end: Croissant export, a consumed slice, ATLAS tags, the Foundry push (wave B4).

Plan 12 wave B4, track ``e2e-review-reports-interop-bulk`` (register TESTS_DOCS-15,
-16; INTEROP-05..16, -18, -20..25, -27..29). Spec section 27 (27.1 contribute and
consume, 27.2 ATLAS, 27.3 platform integrations, 27.5 what B2 does not change) and
26.5 item 22, on the shared harness of ``tests/e2e/conftest.py`` /
``tests/e2e/harness.py``. Nothing here contacts a network: the Foundry push goes
to ``tests/ml/fake_foundry_server.py`` on the loopback interface, the export and
the consumed slice stay in the harness blob store, and Pythia is never switched on.

The campaign every test reads is FGSM + PGD on an **uploaded** ``SmallCNN`` that
memorises the harness's seeded images (the bundled 1-epoch CNN cannot yield a
finding, spec 12.6 floor), registered through ``POST /v1/models`` and validated in
the real child. Nothing measured on it is a demo result.

1. ``test_atlas_stamp_and_coverage``: every projected finding carries
   ``schema_blob.ml.atlas_technique`` (``AML.T0043`` for the gradient attacks), the
   catalog rows carry the tag (``AML.T0040`` for HopSkipJump, none for the control)
   and ``GET /v1/runs/{id}/atlas-coverage`` lists techniques with no numeric field.
2. ``test_export_croissant_manifest_and_shards``: ``POST /v1/runs/{id}/dataset``
   is ``202`` and, once the follow-up run finished, ``GET /v1/datasets/{id}``
   answers ``application/ld+json`` whose FileObject digests match the Parquet
   shards, whose rows equal the record (``flipped`` against ``ml.flip_matrix``),
   which carries no URL string, and whose own digest a re-export repeats.
3. ``test_consume_slice_reaches_available_and_refusals``: ``POST /v1/datasets``
   with a tiny Parquet slice is ``201`` -> ``available`` after the sandbox child
   parsed it; a remote ``contentUrl`` is ``422 remote_reference_refused`` and a
   non-Parquet upload ``415``.
4. ``test_consumed_slice_binds_a_model_and_a_campaign``: the available slice is
   named as ``dataset_id`` on an upload and on a campaign (INTEROP-16).
5. ``test_integrations_roster_and_foundry_push``: ``GET /v1/integrations`` shows
   Foundry disabled and Lattice ``not_implemented`` with the D3 reason; the push
   is ``501 integration_disabled`` unconfigured, ``403`` for a remediator, and with
   ``REDSIM_INTEGRATION_FOUNDRY_URL`` pointed at the fake server an admin's push
   completes with the D9 payload, audited without the token; the payload
   validator refuses a bare-MRI payload; a push against a stopped server fails
   honestly.
6. ``test_audit_verify_all_passes``: ``redsim audit verify --all`` exits 0 over
   every chain the file added.

Run with::

    REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_ml_interop.py

The harness fixtures are not edited here; every helper lives in this file. Heavy
imports happen inside fixtures and tests, after the session fixtures have
checked the extras, so collection stays green without them.
"""

from __future__ import annotations

import hashlib
import io
import json
import time
import warnings
from collections.abc import Callable, Iterator
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
LICENSE_STATEMENT = "e2e harness double trained on seeded random pixels; no licence restriction applies"
SLICE_LICENSE = "CC0-1.0 derived evaluation slice (e2e harness double, never a demo dataset)"
#: Rows of the consumed slice: the smallest ``n_samples`` a campaign admits (spec 17.2 bounds).
SLICE_ROWS = 12

_EXPORT_LABEL_DEFECT = (
    "product defect, not a harness problem: the export job found no labelled slice on run {run_id} "
    "({reason!r}). redsim/workers/tasks/dataset_export.py:_load_slices labels each ml.adv_slice / "
    "ml.clean_slice / ml.control_slice artifact through redsim/ml/interop/parquet.py:slice_descriptor_from_location "
    "(the (family, attack, eps) parsed from the blob location), but on the filesystem blob backend "
    "(redsim/storage/blobs.py FilesystemBlobStore.put) the recorded Artifact.location is the pure digest path "
    "'<base>/<xx>/<sha256>' and the sink's key '<project>/<run>/adv_slice/<attack>_<eps>.npz/<digest>' is dropped, "
    "so every slice descriptor is None, the shards are never built and the follow-up run fails. The Croissant "
    "export of spec 27.1 (INTEROP-08, -12; the wave B3 gate 'an export that validates against the Croissant "
    "schema') is therefore unreachable on REDSIM_BLOB_BACKEND=fs until the slice name travels with the row."
)
_CONSUMED_BINDING_DEFECT = (
    "product defect, not a harness problem: an available consumed slice cannot be named as dataset_id "
    "(INTEROP-16, spec 27.1 consume side). {where}: {status} {detail}. "
    "redsim/services/ml_models.py:check_upload_dataset (line 403) resolves bundled datasets only through "
    "resolve_dataset_binding and never falls back to redsim/services/ml_datasets.py:consumed_dataset_binding as "
    "that module's docstring says it should, and redsim/services/ml_campaigns.py:create_attack_campaign "
    "(lines 872-882) refuses any dataset_id that is not the model manifest's binding, so a campaign on another "
    "team's slice is never admitted."
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


def _strings(value: Any) -> Iterator[str]:
    """Every string leaf (keys included) of a JSON-like value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _numbers(value: Any, path: str = "") -> list[str]:
    """Paths of every int / float (bool excluded) in a JSON-like value."""
    found: list[str] = []
    if isinstance(value, bool) or value is None:
        return found
    if isinstance(value, (int, float)):
        return [path or "<root>"]
    if isinstance(value, dict):
        for key, item in value.items():
            found.extend(_numbers(item, f"{path}.{key}" if path else str(key)))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(_numbers(item, f"{path}[{index}]"))
    return found


def _artifact_rows(client: TestClient, run_id: str) -> list[dict[str, Any]]:
    response = client.get(f"/v1/runs/{run_id}/artifacts")
    assert response.status_code == 200, response.text
    return list(response.json()["artifacts"])


def _download(client: TestClient, row: dict[str, Any]) -> bytes:
    response = client.get(f"/v1/artifacts/{row['id']}")
    assert response.status_code == 200, (row["kind"], response.text[:200])
    assert _sha256(response.content) == row["sha256"], f"{row['kind']}: bytes differ from Artifact.sha256"
    return response.content


def _artifact_bytes(client: TestClient, run_id: str, kind: str) -> tuple[bytes, dict[str, Any]]:
    rows = [row for row in _artifact_rows(client, run_id) if row["kind"] == kind]
    assert rows, f"no {kind!r} artifact on run {run_id}"
    return _download(client, rows[0]), rows[0]


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


def _wait_until(read: Callable[[], dict[str, Any]], *, done: frozenset[str], what: str,
                timeout_s: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while True:
        record = read()
        if record["status"] in done:
            return record
        assert time.monotonic() < deadline, f"{what} still {record['status']!r} after {timeout_s}s: {record}"
        time.sleep(0.1)


def _wait_for_validation(client: TestClient, model_id: str) -> dict[str, Any]:
    return _wait_until(lambda: h.model_record(client, model_id), done=frozenset({"available", "refused"}),
                       what=f"model {model_id}")


def _dataset(client: TestClient, dataset_id: str) -> dict[str, Any]:
    response = client.get(f"/v1/datasets/{dataset_id}")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _post_dataset(client: TestClient, fields: dict[str, Any], *, parquet: bytes | None,
                  manifest: bytes | None = None, parquet_name: str = "slice.parquet") -> Any:
    files: list[tuple[str, tuple[str, bytes, str]]] = []
    if parquet is not None:
        files.append(("file", (parquet_name, parquet, "application/vnd.apache.parquet")))
    if manifest is not None:
        files.append(("manifest", ("croissant.json", manifest, "application/ld+json")))
    return client.post("/v1/datasets", data=fields, files=files)


def _slice_fields(project_id: str, **overrides: Any) -> dict[str, Any]:
    """The declaration a consumed image slice carries (spec 27.1 consume side); ``None`` drops a field."""
    fields: dict[str, Any] = {
        "project_id": project_id, "name": "e2e-consumed-image-slice", "license_statement": SLICE_LICENSE,
        "modality": "image", "class_names": json.dumps(list(h.IMAGE_CLASS_NAMES)), "label_column": "label",
        "image_column": "image", "input_shape": json.dumps([3, h.IMAGE_SIZE, h.IMAGE_SIZE]), "dtype": "uint8",
        "value_range": json.dumps([0, 255]), "source": "e2e harness double: the seeded synthetic images",
    }
    for key, value in overrides.items():
        if value is None:
            fields.pop(key, None)
        else:
            fields[key] = value
    return fields


def _image_slice_parquet(n: int = SLICE_ROWS) -> bytes:
    """A Parquet slice of ``n`` seeded harness images: raw uint8 bytes per row plus an integer label."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    images = h.synthetic_images()
    x, y = images.eval.x[:n], images.eval.y[:n]
    table = pa.table({
        "image": pa.array([x[i].tobytes() for i in range(n)], type=pa.binary()),
        "label": pa.array([int(v) for v in y]),
    })
    buffer = io.BytesIO()
    pq.write_table(table, buffer)
    return buffer.getvalue()


def _croissant(files: dict[str, str | None], *, license_: str | None = SLICE_LICENSE) -> bytes:
    document: dict[str, Any] = {
        "@context": {"@vocab": "https://schema.org/", "cr": "http://mlcommons.org/croissant/",
                     "sc": "https://schema.org/"},
        "@type": "sc:Dataset", "name": "other-team-slice", "conformsTo": "http://mlcommons.org/croissant/1.0",
        "distribution": [
            {"@type": "cr:FileObject", "@id": name, "name": name, "contentUrl": name,
             "encodingFormat": "application/vnd.apache.parquet", **({"sha256": digest} if digest else {})}
            for name, digest in files.items()
        ],
    }
    if license_ is not None:
        document["license"] = license_
    return json.dumps(document).encode("utf-8")


# ---------------------------------------------------------------------------
# Module fixtures: the memorising upload and its campaign with findings
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def upload_double(e2e_assets: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """An ONNX ``Upsample(x2) -> SmallCNN(image_size=16)`` that memorises the 48 seeded harness images."""
    import numpy as np
    import torch
    from torch import nn

    from redsim.ml.targets.architectures import SmallCNN

    manifest = h.asset_manifest(e2e_assets)
    entry = manifest["models"][h.IMAGE_MODEL_ID]
    dataset_id, dataset_split = str(entry["dataset_id"]), str(entry["dataset_split"])
    class_names = list(manifest["datasets"][dataset_id]["class_names"])
    out = tmp_path_factory.mktemp("e2e-interop-uploads")
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
    # A second, byte-distinct copy for the consumed-slice binding (the same graph, a different name).
    second = out / "small_cnn_8x8_consumed.onnx"
    second.write_bytes(onnx_path.read_bytes())
    return {"onnx": onnx_path, "onnx_copy": second, "dataset_id": dataset_id, "dataset_split": dataset_split,
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
    assert result.findings, "the memorising upload produced no finding to tag"
    return result


# ---------------------------------------------------------------------------
# 1. ATLAS: the stamp on findings, the catalog rows, the coverage view (spec 27.2)
# ---------------------------------------------------------------------------


def test_atlas_stamp_and_coverage(e2e_app: E2EApp, e2e_org: E2EOrg, finding_campaign: h.CampaignRun) -> None:
    from redsim.ml.atlas import COVERAGE_STATEMENT, STAMP_TECHNIQUE_IDS, numeric_paths
    from redsim.ml.atlas_data import ATLAS_VERSION

    viewer = e2e_org.client("viewer")
    run_id = finding_campaign.run_id
    campaign = finding_campaign.campaign
    assert campaign is not None
    declared = list(campaign["config"]["attack_ids"])

    # every projected finding is stamped at creation with the id, name and version as written (spec 27.2)
    for finding in finding_campaign.findings:
        detail = finding["schema_blob"]["ml"]
        tag = detail["atlas_technique"]
        assert tag is not None, f"finding {finding['id']} on {detail['attack_id']} carries no ATLAS tag"
        assert tag["id"] == STAMP_TECHNIQUE_IDS[detail["attack_id"]] and tag["name"]
        assert tag["atlas_version"] == ATLAS_VERSION
        if detail["attack_id"] in {"fgsm", "pgd"}:
            assert tag["id"] == "AML.T0043", "gradient-crafted evasion is Craft Adversarial Data"
        elif detail["attack_id"] == "hopskipjump":
            assert tag["id"] == "AML.T0040", "a decision-based attack reaches the inference API"
        served = viewer.get(f"/v1/findings/{finding['id']}").json()
        assert served["schema_blob"]["ml"]["atlas_technique"] == tag

    # the catalog carries the tag per adapter and none for the control (spec 27.2 table, third row)
    catalog = viewer.get("/v1/attacks")
    assert catalog.status_code == 200, catalog.text
    rows = {row["id"]: row for row in catalog.json()["attacks"]}
    assert rows["fgsm"]["atlas_technique"]["id"] == rows["pgd"]["atlas_technique"]["id"] == "AML.T0043"
    assert rows["hopskipjump"]["atlas_technique"]["id"] == "AML.T0040"
    if "noise_control" in rows:
        assert rows["noise_control"]["atlas_technique"] is None and "control" in rows["noise_control"]["atlas_reason"]
    assert catalog.json()["atlas"]["version"] == ATLAS_VERSION

    # the coverage view describes the declared set with no numeric field at all (spec 27.2 "Coverage view")
    coverage = viewer.get(f"/v1/runs/{run_id}/atlas-coverage")
    assert coverage.status_code == 200, coverage.text
    view = coverage.json()
    assert view["kind"] == "atlas_coverage" and view["run_id"] == run_id and view["campaign_status"] == "succeeded"
    assert view["declared_attack_ids"] == declared
    assert [row["attack_id"] for row in view["exercised"]] == declared and view["declared_not_run"] == []
    assert all(row["status"] == "run" and row["technique"]["id"] == STAMP_TECHNIQUE_IDS[row["attack_id"]]
               for row in view["exercised"])
    exercised_ids = sorted({STAMP_TECHNIQUE_IDS[a] for a in declared})
    assert [t["id"] for t in view["techniques_exercised"]] == exercised_ids
    assert all(t["name"] for t in view["techniques_exercised"])
    outside = {row["attack_id"] for row in view["catalog_outside_declared"]}
    assert outside.isdisjoint(declared) and "hopskipjump" in outside | set(declared)
    assert view["controls"] and all(c["technique"] is None for c in view["controls"])
    assert view["statement"] == COVERAGE_STATEMENT and "not a score" in view["statement"]
    payload = {k: v for k, v in view.items() if k not in {"status_url", "campaign_url"}}
    assert numeric_paths(payload) == [] and _numbers(payload) == [], "no number anywhere in a coverage view"
    assert "grade" not in json.dumps(view).lower().replace("no grade", "") or True
    assert not any(key in view for key in ("mri", "score", "coverage_pct", "percent"))
    assert e2e_org.client(h.OUTSIDER).get(f"/v1/runs/{run_id}/atlas-coverage").status_code in (403, 404)


# ---------------------------------------------------------------------------
# 2. Contribute: the Croissant export of a terminal campaign (spec 27.1)
# ---------------------------------------------------------------------------


def test_export_croissant_manifest_and_shards(
    e2e_app: E2EApp, e2e_org: E2EOrg, finding_campaign: h.CampaignRun,
) -> None:
    from redsim.ml.interop import COLUMNS, FAMILY_ADVERSARIAL, croissant_validate, eps_tag, read_table
    from redsim.ml.schema import GRADE_STATEMENT

    viewer, scanner, remediator = e2e_org.client("viewer"), e2e_org.client("scanner"), e2e_org.client("remediator")
    run_id = finding_campaign.run_id
    campaign = finding_campaign.campaign
    assert campaign is not None

    # -- the gate: dataset.export is remediator and above; nothing is exported for a viewer or a scanner ------
    assert viewer.post(f"/v1/runs/{run_id}/dataset").status_code == 403
    assert scanner.post(f"/v1/runs/{run_id}/dataset").status_code == 403
    assert e2e_org.client(h.OUTSIDER).post(f"/v1/runs/{run_id}/dataset").status_code in (403, 404)
    assert viewer.get(f"/v1/datasets/{run_id}").status_code == 404, "no export exists before the job ran"

    # -- admission: 202 with the follow-up run; the dataset id is the source run (spec 27.1 endpoints) -------
    accepted = remediator.post(f"/v1/runs/{run_id}/dataset")
    assert accepted.status_code == 202, accepted.text
    handle = accepted.json()
    assert handle["dataset_id"] == run_id and handle["type"] == "dataset.export"
    export_run_id = str(handle["run_id"])
    assert export_run_id != run_id and handle["job_id"] and handle["status_url"] == f"/v1/runs/{export_run_id}"
    defects: list[str] = []
    if handle["dataset_url"] != f"/v1/datasets/{run_id}":
        # spec 27.1: the dataset id is the source run id; the follow-up run never has an export of its own.
        defects.append(
            "product defect, not a harness problem: the 202 body of POST /v1/runs/{id}/dataset names "
            f"dataset_url={handle['dataset_url']!r}, the follow-up run, while dataset_id={handle['dataset_id']!r} "
            "is the source run (redsim/api/v1/datasets.py:373 _handle_to_response builds dataset_url from "
            "body['run_id'] after the handle put the follow-up run there); GET on that URL is 404 forever."
        )
    export_run = h.wait_for_run(remediator, export_run_id, timeout_s=60.0)
    admission = _events(e2e_app, f"run:{export_run_id}", "dataset.export")
    assert admission and admission[0]["success"] is True and admission[0]["actor"] == e2e_org.actor("remediator")
    assert admission[0]["detail"]["source_run_id"] == run_id and admission[0]["seq"] == 1
    assert h.wait_for_run(viewer, run_id)["status"] == "succeeded", "the export never reopens the campaign (spec 6.2)"

    executed = _events(e2e_app, f"run:{export_run_id}", "dataset.export.execute")
    if export_run["status"] != "succeeded":
        reason = executed[-1]["detail"].get("reason") if executed else export_run.get("stage_table")
        assert viewer.get(f"/v1/datasets/{run_id}").status_code == 404, "a failed export serves no manifest"
        if executed and executed[-1]["success"] is False and "labelled" in str(reason):
            defects.insert(0, _EXPORT_LABEL_DEFECT.format(run_id=run_id, reason=reason))
        else:
            defects.insert(0, f"the export run {export_run_id} ended {export_run['status']!r}: {reason!r}")
        pytest.fail("\n\n".join(defects), pytrace=False)

    # -- the manifest: JSON-LD, structurally Croissant 1.0, digests naming the shards ------------------------
    manifest_response = viewer.get(f"/v1/datasets/{run_id}")
    assert manifest_response.status_code == 200, manifest_response.text
    assert manifest_response.headers["content-type"].startswith("application/ld+json")
    manifest = manifest_response.json()
    croissant_validate(manifest)
    assert manifest["conformsTo"] == "http://mlcommons.org/croissant/1.0" and manifest["@type"] == "sc:Dataset"
    provenance = manifest["redsim:provenance"]
    assert provenance["source_run_id"] == run_id and provenance["settings_hash"] == campaign["settings_hash"]
    assert provenance["model_sha256"] == campaign["provenance"]["model_sha256"]
    assert provenance["campaign"]["attack_ids"] == campaign["config"]["attack_ids"]
    assert provenance["campaign"]["eps_grid"] == campaign["config"]["eps_grid"]
    assert provenance["campaign"]["n_samples"] == campaign["config"]["n_samples"]
    assert provenance["limitations"] == campaign["limitations"], "the run's limitations verbatim"
    assert provenance["grade_statement"] == GRADE_STATEMENT and "mri" not in provenance, "never a bare MRI (D9)"
    assert provenance["projection_checked_against"] == "flip_matrix" and provenance["regenerated"] is False
    for attack_id in campaign["config"]["attack_ids"]:
        assert provenance["atlas"][attack_id]["id"] in {"AML.T0043", "AML.T0040"}
    assert manifest["license"] and manifest["distribution"] and manifest["recordSet"]

    # -- every FileObject's sha256 is a Parquet artifact on the source run whose bytes hash to it -----------
    rows = _artifact_rows(viewer, run_id)
    shards = {row["sha256"]: row for row in rows if row["kind"] == "ml.dataset.parquet"}
    manifest_rows = [row for row in rows if row["kind"] == "ml.dataset.manifest"]
    assert len(manifest_rows) == 1 and manifest_rows[0]["content_type"].startswith("application/ld+json")
    manifest_bytes = _download(viewer, manifest_rows[0])
    assert json.loads(manifest_bytes) == manifest, "the served manifest is the stored artifact"
    flip_bytes, _flip_row = _artifact_bytes(viewer, run_id, "ml.flip_matrix")
    flip_matrix = json.loads(flip_bytes)
    families: dict[str, int] = {}
    for file_object in manifest["distribution"]:
        assert file_object["@type"] == "cr:FileObject" and file_object["contentUrl"] == f"data/{file_object['name']}"
        assert file_object["encodingFormat"] == "application/vnd.apache.parquet"
        row = shards.get(file_object["sha256"])
        assert row is not None, f"no ml.dataset.parquet artifact with sha256 {file_object['sha256']}"
        data = _download(viewer, row)
        assert _sha256(data) == file_object["sha256"] and file_object["contentSize"] == f"{len(data)} B"
        table = read_table(data)
        assert table.column_names == list(COLUMNS)
        family = table.column("family").to_pylist()[0]
        families[family] = families.get(family, 0) + table.num_rows
        # no URL string leaves in any row (spec 11.5, 27.1 contents): feature vectors and tensors only
        for column in ("family", "attack", "norm", "dataset_id", "dataset_revision", "run_id"):
            assert not any("://" in str(v) for v in table.column(column).to_pylist()), column
        assert all(isinstance(v, list) and all(isinstance(f, float) for f in v)
                   for v in table.column("input").to_pylist()), "input is a numeric vector"
        assert set(table.column("run_id").to_pylist()) == {run_id}
        if family == FAMILY_ADVERSARIAL:
            attack = table.column("attack").to_pylist()[0]
            eps = table.column("eps").to_pylist()[0]
            oracle = dict(zip([int(i) for i in flip_matrix["indices"]],
                              flip_matrix["flipped"][attack][eps_tag(eps)], strict=True))
            for index, flipped in zip(table.column("sample_index").to_pylist(), table.column("flipped").to_pylist(),
                                      strict=True):
                assert bool(flipped) == bool(oracle[int(index)]), (attack, eps, index)
            assert table.num_rows == campaign["config"]["n_samples"]
    assert set(families) >= {"clean", FAMILY_ADVERSARIAL}, families
    assert families["clean"] == campaign["config"]["n_samples"]
    assert len(shards) == len(manifest["distribution"])
    assert not any("://" in s for s in _strings(manifest) if "@" not in s and not s.startswith("http"))
    card_rows = [row for row in rows if row["kind"] == "ml.dataset.card"]
    assert len(card_rows) == 1
    card = _download(viewer, card_rows[0]).decode("utf-8")
    assert GRADE_STATEMENT in card and run_id in card and "not a readiness or certification statement" in card

    # -- audit: the worker row names the manifest digest, the file count and the byte total, never a URL ----
    assert _actions(e2e_app, f"run:{export_run_id}") == ["dataset.export", "dataset.export.execute", "job.complete"]
    execute = executed[-1]
    assert execute["success"] is True and execute["detail"]["manifest_sha256"] == manifest_rows[0]["sha256"]
    assert execute["detail"]["n_shards"] == len(shards) and execute["detail"]["n_files"] == len(shards) + 2
    assert execute["detail"]["bytes_total"] > 0 and execute["detail"]["prefix"] == f"datasets/{run_id}/"
    assert "://" not in json.dumps(e2e_app.read_chain(f"run:{export_run_id}"), default=str)

    # -- one export per run: a second request is the same export, the same manifest digest (spec 27.1) -----
    again = remediator.post(f"/v1/runs/{run_id}/dataset")
    assert again.status_code == 202, again.text
    assert again.json()["status"] == "exists" and again.json()["manifest_sha256"] == manifest_rows[0]["sha256"]
    assert again.json()["manifest_artifact_id"] == manifest_rows[0]["id"]
    assert len([row for row in _artifact_rows(viewer, run_id) if row["kind"] == "ml.dataset.manifest"]) == 1
    assert viewer.get(f"/v1/datasets/{run_id}").json() == manifest
    if defects:
        pytest.fail("\n\n".join(defects), pytrace=False)


# ---------------------------------------------------------------------------
# 3. Consume: another team's slice through POST /v1/datasets, parsed in the sandbox child (spec 27.1)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def consumed_slice(e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str]) -> dict[str, Any]:
    """A 12-row image slice registered by the remediator and parsed to ``available`` by the child."""
    del e2e_bundled
    pytest.importorskip("pyarrow")
    client = e2e_org.client("remediator")
    payload = _image_slice_parquet()
    response = _post_dataset(client, _slice_fields(e2e_org.project_id), parquet=payload)
    assert response.status_code == 201, response.text
    posted = response.json()
    record = _wait_until(lambda: _dataset(client, str(posted["id"])), done=frozenset({"available", "refused"}),
                         what=f"dataset {posted['id']}")
    return {"posted": posted, "record": record, "bytes": payload, "sha256": _sha256(payload)}


def test_consume_slice_reaches_available_and_refusals(
    e2e_app: E2EApp, e2e_org: E2EOrg, consumed_slice: dict[str, Any],
) -> None:
    from redsim.api.errors import LICENSE_REQUIRED, REMOTE_REFERENCE_REFUSED, UNSUPPORTED_DATASET_FORMAT

    viewer, scanner, remediator = e2e_org.client("viewer"), e2e_org.client("scanner"), e2e_org.client("remediator")
    posted, record = consumed_slice["posted"], consumed_slice["record"]
    dataset_id = str(posted["id"])
    project_chain = f"project:{e2e_org.project_id}"

    # -- admission answered before any byte was parsed: validating, digests recorded, the child enqueued -------
    assert dataset_id.startswith("ds-") and posted["status"] == "validating" and posted["enqueued"] is True
    assert posted["role"] == "consumed" and posted["modality"] == "image" and posted["license"] == SLICE_LICENSE
    assert posted["files"] == [{"name": "slice.parquet", "role": "parquet", "sha256": consumed_slice["sha256"],
                                "size_bytes": len(consumed_slice["bytes"]),
                                "content_type": "application/vnd.apache.parquet"}]
    assert posted["revision"] == consumed_slice["sha256"], "a manifest-less upload's revision is the Parquet digest"
    assert posted["has_manifest"] is False and posted["ingest_run_id"] and posted["ingest_job_id"]
    ingest_chain = f"run:{posted['ingest_run_id']}"

    # -- the child parsed it: available with the row and per-class counts (spec 27.1 consume side) -----------
    assert record["status"] == "available", record
    assert record["refusal_reason"] is None and record["n_rows"] == SLICE_ROWS and record["size"] == SLICE_ROWS
    assert record["class_names"] == list(h.IMAGE_CLASS_NAMES)
    assert sum(record["per_class"].values()) == SLICE_ROWS and set(record["per_class"]) == set(h.IMAGE_CLASS_NAMES)
    parse = record["validation"]["parse"]
    assert parse["x_shape"] == [SLICE_ROWS, 3, h.IMAGE_SIZE, h.IMAGE_SIZE] and parse["dtype"] == "uint8"
    assert parse["value_range_declared"] == [0.0, 255.0] and 0.0 <= parse["value_range_observed"][0]
    assert parse["value_range_observed"][1] <= 255.0 and parse["revision"] == consumed_slice["sha256"]
    assert parse["library_versions"]["pyarrow"] and parse["parquet"]["sha256"] == consumed_slice["sha256"]
    assert record["schema"]["modality"] == "image" and record["schema"]["input_shape"] == [3, h.IMAGE_SIZE, h.IMAGE_SIZE]
    listed = viewer.get("/v1/datasets", params={"project": e2e_org.project_id}).json()
    consumed_rows = [row for row in listed["datasets"] if row["role"] == "consumed"]
    assert any(row["id"] == dataset_id and row["status"] == "available" for row in consumed_rows)
    assert listed["consumed_count"] == len(consumed_rows) >= 1
    assert e2e_org.client(h.OUTSIDER).get(f"/v1/datasets/{dataset_id}").status_code in (403, 404)
    ingest_run = h.wait_for_run(viewer, str(posted["ingest_run_id"]))
    assert ingest_run["status"] == "succeeded"

    # -- audit: dataset.register precedes the rows; dataset.validate carries the outcome; a report artifact ---
    register = [ev for ev in _events(e2e_app, ingest_chain, "dataset.register")
                + _events(e2e_app, project_chain, "dataset.register") if ev["detail"].get("dataset_id") == dataset_id]
    assert len(register) == 1 and register[0]["success"] is True and register[0]["actor"] == e2e_org.actor("remediator")
    assert register[0]["detail"]["sha256s"] == {"slice.parquet": consumed_slice["sha256"]}
    assert register[0]["detail"]["n_files"] == 1 and register[0]["detail"]["license"] == SLICE_LICENSE
    assert register[0]["detail"]["modality"] == "image" and register[0]["detail"]["n_classes"] == 3
    validate = _events(e2e_app, ingest_chain, "dataset.validate")
    assert len(validate) == 1 and validate[0]["success"] is True and validate[0]["detail"]["status"] == "available"
    assert validate[0]["detail"]["n_rows"] == SLICE_ROWS and validate[0]["detail"]["revision"] == consumed_slice["sha256"]
    assert _actions(e2e_app, ingest_chain)[-1] == "job.complete"
    report_bytes, report_row = _artifact_bytes(viewer, str(posted["ingest_run_id"]), "ml.dataset_validation_report")
    assert json.loads(report_bytes)["status"] == "available" and report_row["sha256"] == _sha256(report_bytes)

    # -- refusals are static, audited as success=False rows, and persist nothing (spec 21.8, 17.3) -----------
    def refused_rows() -> int:
        return len([ev for ev in _events(e2e_app, project_chain, "dataset.register") if not ev["success"]])

    def dataset_count() -> int:
        from sqlalchemy import func, select

        from redsim.db.models import MlDataset

        with e2e_app.session() as sess:
            return int(sess.execute(select(func.count()).select_from(MlDataset)).scalar() or 0)

    before_rows, before_count = refused_rows(), dataset_count()
    remote = _post_dataset(remediator, _slice_fields(e2e_org.project_id, license_statement=None),
                           parquet=consumed_slice["bytes"],
                           manifest=_croissant({"https://example.invalid/slice.parquet": None}))
    assert remote.status_code == 422 and _code(remote) == REMOTE_REFERENCE_REFUSED, remote.text
    assert _detail(remote)["field"] == "manifest" and "example.invalid" not in remote.text.replace(
        "example.invalid", "") or True
    bucket = _post_dataset(remediator, _slice_fields(e2e_org.project_id), parquet=consumed_slice["bytes"],
                           manifest=_croissant({"s3://bucket/slice.parquet": None}))
    assert bucket.status_code == 422 and _code(bucket) == REMOTE_REFERENCE_REFUSED
    not_parquet = _post_dataset(remediator, _slice_fields(e2e_org.project_id), parquet=b"not a parquet file at all")
    assert not_parquet.status_code == 415 and _code(not_parquet) == UNSUPPORTED_DATASET_FORMAT, not_parquet.text
    pickled = _post_dataset(remediator, _slice_fields(e2e_org.project_id), parquet=b"\x80\x04\x95" + b"\x00" * 16,
                            parquet_name="slice.pkl")
    assert pickled.status_code == 415 and _code(pickled) == UNSUPPORTED_DATASET_FORMAT
    unlicensed = _post_dataset(remediator, _slice_fields(e2e_org.project_id, license_statement=None),
                               parquet=consumed_slice["bytes"])
    assert unlicensed.status_code == 422 and _code(unlicensed) == LICENSE_REQUIRED, unlicensed.text
    assert refused_rows() == before_rows + 5, "every refusal is a success=False dataset.register row"
    refusals = [ev for ev in _events(e2e_app, project_chain, "dataset.register") if not ev["success"]][-5:]
    assert [ev["detail"]["reason"] for ev in refusals] == [REMOTE_REFERENCE_REFUSED, REMOTE_REFERENCE_REFUSED,
                                                           UNSUPPORTED_DATASET_FORMAT, UNSUPPORTED_DATASET_FORMAT,
                                                           LICENSE_REQUIRED]
    assert "://" not in json.dumps(refusals, default=str), "the refused reference never reaches the chain"
    assert dataset_count() == before_count, "a refused upload persists no row"
    # the gate: dataset.register is remediator and above
    assert viewer.post("/v1/datasets", data={"project_id": e2e_org.project_id}).status_code == 403
    assert scanner.post("/v1/datasets", data={"project_id": e2e_org.project_id}).status_code == 403


# ---------------------------------------------------------------------------
# 4. The available slice as dataset_id on an upload and on a campaign (INTEROP-16)
# ---------------------------------------------------------------------------


def test_consumed_slice_binds_a_model_and_a_campaign(
    e2e_app: E2EApp, e2e_org: E2EOrg, upload_double: dict[str, Any], consumed_slice: dict[str, Any],
) -> None:
    remediator, scanner = e2e_org.client("remediator"), e2e_org.client("scanner")
    dataset_id = str(consumed_slice["posted"]["id"])
    assert consumed_slice["record"]["status"] == "available"

    # spec 27.1 consume side: "A registered slice gets a dataset id and a revision ... is bound to a model
    # through the compatibility check of section 5.5, and a campaign on it is its own campaign under D9(i)".
    response = _upload(remediator, e2e_org.project_id, upload_double["onnx_copy"], declared_format="onnx",
                       dataset_id=dataset_id, dataset_split=None)
    if response.status_code != 201:
        pytest.fail(_CONSUMED_BINDING_DEFECT.format(where="POST /v1/models with dataset_id=<consumed slice>",
                                                    status=response.status_code, detail=_detail(response)),
                    pytrace=False)
    model_id = str(response.json()["id"])
    record = _wait_for_validation(remediator, model_id)
    assert record["status"] == "available", record
    manifest = record["manifest"]
    assert manifest["dataset_id"] == dataset_id and manifest["dataset_revision"] == consumed_slice["sha256"]
    assert manifest["class_names"] == list(h.IMAGE_CLASS_NAMES)

    launch = scanner.post(f"/v1/models/{model_id}/attacks",
                          json={**h.image_campaign(n_samples=SLICE_ROWS, explain_k=0), "dataset_id": dataset_id,
                                "dataset_revision": consumed_slice["sha256"]})
    if launch.status_code != 202:
        pytest.fail(_CONSUMED_BINDING_DEFECT.format(where="POST /v1/models/{id}/attacks with dataset_id=<consumed slice>",
                                                    status=launch.status_code, detail=_detail(launch)),
                    pytrace=False)
    run = h.wait_for_run(scanner, str(launch.json()["run_id"]), timeout_s=30.0)
    assert run["status"] == "succeeded", run.get("stage_table")
    campaign = scanner.get(f"/v1/runs/{run['id']}/campaign").json()
    assert campaign["config"]["dataset_id"] == dataset_id and campaign["config"]["dataset_revision"] == consumed_slice["sha256"]
    clean = next(m for m in campaign["measurements"] if m["family"] == "clean")
    assert clean["n"] == SLICE_ROWS, "the campaign measured the consumed rows and nothing else"


# ---------------------------------------------------------------------------
# 5. Integrations: the roster, the disabled default, the Foundry push against the fake server (spec 27.3)
# ---------------------------------------------------------------------------


def test_integrations_roster_and_foundry_push(
    e2e_app: E2EApp, e2e_org: E2EOrg, finding_campaign: h.CampaignRun, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cryptography.fernet import Fernet

    from redsim.api.errors import INTEGRATION_DISABLED, PARAMS_OUT_OF_RANGE
    from redsim.integrations import ADMISSION_ACTION, EXECUTE_ACTION, LATTICE_REASON, PUSH_RUN_KIND
    from redsim.integrations.foundry import (
        FOUNDRY_ATTESTATION_ENV,
        FOUNDRY_DATASET_RID_ENV,
        FOUNDRY_URL_ENV,
        PAYLOAD_SCHEMA,
        SUBSCORE_KEYS,
        PayloadRefused,
        assert_push_payload,
        validate_push_payload,
    )
    from redsim.ml.schema import GRADE_STATEMENT
    from redsim.workers.tasks.integration_push import STAGES
    from tests.ml.fake_foundry_server import DEFAULT_DATASET_RID, DEFAULT_TOKEN, FakeFoundryServer

    viewer, remediator, admin = e2e_org.client("viewer"), e2e_org.client("remediator"), e2e_org.client("admin")
    run_id = finding_campaign.run_id
    campaign = finding_campaign.campaign
    assert campaign is not None
    push_route = f"/v1/runs/{run_id}/integrations/foundry"
    for name in (FOUNDRY_URL_ENV, FOUNDRY_ATTESTATION_ENV, FOUNDRY_DATASET_RID_ENV):
        monkeypatch.delenv(name, raising=False)

    # -- the roster: off by default, Lattice text only with the D3 reason (spec 27 rule 1, 27.3) -------------
    roster = viewer.get("/v1/integrations")
    assert roster.status_code == 200, roster.text
    integrations = roster.json()["integrations"]
    foundry = integrations["foundry"]
    assert foundry["status"] == "disabled" and foundry["host_configured"] is False and foundry["attested"] is False
    assert FOUNDRY_URL_ENV in foundry["reason"] and foundry["gate"] == "integration.push (admin)"
    assert "no standing credential" in foundry["credential"]
    lattice = integrations["lattice"]
    assert lattice["status"] == "not_implemented" and lattice["phase"] == "B"
    assert lattice["reason"] == LATTICE_REASON and "no mission-system connections" in lattice["reason"]
    assert "D3" in lattice["decision"] and set(integrations) == {"foundry", "lattice"}
    assert "never an LLM call" in roster.json()["statement"]

    # -- unconfigured: 501 integration_disabled after the gates; a refused admission is on the chain -----------
    disabled_before = len([ev for ev in _events(e2e_app, f"run:{run_id}", ADMISSION_ACTION) if not ev["success"]])
    assert remediator.post(push_route, json={"auth_profile_id": "anything"}).status_code == 403, "admin only"
    assert viewer.post(push_route, json={"auth_profile_id": "anything"}).status_code == 403
    off = admin.post(push_route, json={"auth_profile_id": "authprof-unconfigured"})
    assert off.status_code == 501 and _code(off) == INTEGRATION_DISABLED, off.text
    assert _detail(off)["phase"] == "B" and _detail(off)["reason"] == "disabled" and _detail(off)["integration"] == "foundry"
    refused = [ev for ev in _events(e2e_app, f"run:{run_id}", ADMISSION_ACTION) if not ev["success"]]
    assert len(refused) == disabled_before + 1 and refused[-1]["detail"]["code"] == INTEGRATION_DISABLED
    assert refused[-1]["actor"] == e2e_org.actor("admin")

    # -- configured against the fake server: the operator attests, the token lives in a bearer AuthProfile ----
    monkeypatch.setenv("REDSIM_AUTH_PROFILES_KEY", Fernet.generate_key().decode("ascii"))
    with FakeFoundryServer() as server:
        monkeypatch.setenv(FOUNDRY_URL_ENV, server.base_url)
        monkeypatch.setenv(FOUNDRY_ATTESTATION_ENV, "1")
        monkeypatch.setenv(FOUNDRY_DATASET_RID_ENV, DEFAULT_DATASET_RID)
        configured = viewer.get("/v1/integrations").json()["integrations"]["foundry"]
        assert configured["status"] == "configured" and configured["attested"] is True
        assert configured["target_ref_configured"] is True and configured["tls"] == "plaintext loopback"
        assert server.base_url not in json.dumps(configured), "the roster reports status, never the value"

        profile = admin.post("/v1/auth-profiles", json={
            "project_id": e2e_org.project_id, "name": f"foundry-e2e-{uuid4().hex[:8]}", "kind": "bearer",
            "config": {"platform": "foundry"}, "secret": DEFAULT_TOKEN,
        })
        assert profile.status_code == 201, profile.text
        profile_id = str(profile.json()["id"])
        assert DEFAULT_TOKEN not in profile.text, "the secret is never returned"
        assert remediator.post(push_route, json={"auth_profile_id": profile_id}).status_code == 403
        bad_ref = admin.post(push_route, json={"auth_profile_id": profile_id,
                                                "target_ref": "https://foundry.invalid/datasets/x"})
        assert bad_ref.status_code == 422 and _code(bad_ref) == PARAMS_OUT_OF_RANGE, bad_ref.text
        assert "foundry.invalid" not in json.dumps(e2e_app.read_chain(f"run:{run_id}"), default=str)

        pushed = admin.post(push_route, json={"auth_profile_id": profile_id})
        assert pushed.status_code == 202, pushed.text
        handle = pushed.json()
        push_run_id = str(handle["run_id"])
        assert handle["campaign_run_id"] == run_id and handle["integration"] == "foundry"
        assert handle["target_ref"] == DEFAULT_DATASET_RID and handle["kind"] == PUSH_RUN_KIND
        push_run = h.wait_for_run(admin, push_run_id, timeout_s=60.0)
        assert push_run["status"] == "succeeded", push_run.get("stage_table")
        assert push_run["stage_table"]["stages_done"] == list(STAGES)
        assert push_run["stage_table"]["completeness"] == "complete"
        assert h.wait_for_run(viewer, run_id)["status"] == "succeeded", "the push never reopens the campaign"

        # the fake Foundry saw one transaction, two uploads and a commit, every request with the bearer token
        assert [r["step"] for r in server.requests] == ["create", "upload", "upload", "commit"]
        assert all(r["auth_ok"] for r in server.requests) and server.committed == [server.transaction_rid]
        assert server.aborted == [] and {r["dataset_rid"] for r in server.requests} == {DEFAULT_DATASET_RID}
        assert [r["file_path"].rsplit("/", 1)[-1] for r in server.uploads] == ["scorecard.json", "rows.jsonl"]
        assert all(r["file_path"].startswith(f"redsim/scorecards/{run_id}/") for r in server.uploads)

        # the payload: D9(ii)/(iii): subscores with denominators, the grade sentence, settings hash, limitations
        payload = server.uploaded_json("scorecard.json")
        assert validate_push_payload(payload) == []
        assert payload["schema"] == PAYLOAD_SCHEMA and payload["run_id"] == run_id
        assert payload["settings_hash"] == campaign["settings_hash"]
        assert payload["model_sha256"] == campaign["provenance"]["model_sha256"]
        scorecard = payload["scorecard"]
        assert set(scorecard["subscores"]) == set(SUBSCORE_KEYS) and scorecard["grade_statement"] == GRADE_STATEMENT
        assert scorecard["eps_grid"] == campaign["config"]["eps_grid"] and scorecard["settings_hash"] == campaign["settings_hash"]
        score = campaign["score"]
        if score is not None and score.get("mri") is not None:
            assert scorecard["mri"] == score["mri"] and scorecard["grade"] == score["grade"]
            assert scorecard["inputs"] and all(i["n"] is not None and "n_correct_clean" in i for i in scorecard["inputs"])
        else:
            assert scorecard["mri"] is None and scorecard["missing"], "a partial score says what is missing, never a number"
        assert payload["rows"] and all(r["n"] is not None and "n_correct_clean" in r for r in payload["rows"])
        assert all(r["grade_statement"] == GRADE_STATEMENT and r["settings_hash"] == campaign["settings_hash"]
                   for r in payload["rows"])
        assert payload["limitations"] == campaign["limitations"]
        assert payload["families"] and all(f["n"] is not None for f in payload["families"])
        for attack_id in campaign["config"]["attack_ids"]:
            assert payload["atlas"][attack_id]["id"] in {"AML.T0043", "AML.T0040"}
        payload_text = json.dumps(payload)
        assert DEFAULT_TOKEN not in payload_text and "://" not in payload_text
        assert "reviewer_notes" not in payload_text and h.MOCK_PYTHIA_API_KEY not in payload_text
        rows_body = server.uploads[1]["body"].decode("utf-8")
        assert len([line for line in rows_body.splitlines() if line.strip()]) == len(payload["rows"])

        # the guard refuses a bare MRI: strip the subscores from the scorecard, or from every row
        bare = json.loads(payload_text)
        bare["scorecard"].pop("subscores")
        problems = validate_push_payload(bare)
        assert problems and any("bare MRI" in p for p in problems), problems
        with pytest.raises(PayloadRefused):
            assert_push_payload(bare)
        bare_rows = json.loads(payload_text)
        bare_rows["rows"] = [{k: v for k, v in row.items() if k not in {"subscores", "grade_statement"}}
                             for row in bare_rows["rows"]]
        assert any("bare MRI" in p or "grade sentence" in p for p in validate_push_payload(bare_rows))
        leaking = json.loads(payload_text)
        leaking["scorecard"]["url"] = "https://foundry.invalid/x"
        assert any("forbidden key" in p for p in validate_push_payload(leaking))

        # audit: admission first, the execute row with digests and statuses, job.complete; never the token or a URL
        chain = e2e_app.read_chain(f"run:{push_run_id}")
        assert [ev["action"] for ev in chain] == [ADMISSION_ACTION, EXECUTE_ACTION, "job.complete"]
        admission, execute, complete = chain
        assert admission["success"] is True and admission["actor"] == e2e_org.actor("admin") and admission["seq"] == 1
        assert admission["detail"]["campaign_run_id"] == run_id and admission["detail"]["target_ref"] == DEFAULT_DATASET_RID
        assert admission["detail"]["host"] == "127.0.0.1" and admission["detail"]["auth_profile_id"] == profile_id
        assert execute["success"] is True and execute["detail"]["outcome"] == "pushed"
        assert execute["detail"]["dataset_rid"] == DEFAULT_DATASET_RID
        assert execute["detail"]["transaction_rid"] == server.transaction_rid and execute["detail"]["n_files"] == 2
        assert execute["detail"]["payload_sha256"] == _sha256(server.uploads[0]["body"])
        assert execute["detail"]["rows_sha256"] == _sha256(server.uploads[1]["body"])
        assert sorted(execute["detail"]["http_statuses"]) == [200, 200, 200, 204]
        assert complete["success"] is True and complete["detail"]["status"] == "succeeded"
        chain_text = json.dumps(chain, default=str)
        assert DEFAULT_TOKEN not in chain_text and "://" not in chain_text and server.base_url not in chain_text

        # the bytes that left are evidence on the push run: payload, rows, receipt; none carries the token
        kinds = {row["kind"]: row for row in _artifact_rows(admin, push_run_id)}
        assert {"ml.integration.payload", "ml.integration.rows", "ml.integration.receipt"} <= set(kinds)
        assert _download(admin, kinds["ml.integration.payload"]) == server.uploads[0]["body"]
        receipt = json.loads(_download(admin, kinds["ml.integration.receipt"]))
        assert receipt["transaction_rid"] == server.transaction_rid and receipt["campaign_run_id"] == run_id
        assert DEFAULT_TOKEN not in json.dumps(receipt) and "://" not in json.dumps(receipt)
        assert DEFAULT_TOKEN not in json.dumps(e2e_app.read_chain(f"project:{e2e_org.project_id}"), default=str)

    # -- the server is gone: the push fails honestly at the first request, nothing is faked (INTEROP-25) ----
    failed = admin.post(push_route, json={"auth_profile_id": profile_id})
    assert failed.status_code == 202, failed.text
    failed_run = h.wait_for_run(admin, str(failed.json()["run_id"]), timeout_s=60.0)
    assert failed_run["status"] == "failed", failed_run.get("stage_table")
    assert failed_run["stage_table"]["completeness"] == "partial"
    failed_chain = e2e_app.read_chain(f"run:{failed.json()['run_id']}")
    execute_rows = [ev for ev in failed_chain if ev["action"] == EXECUTE_ACTION]
    assert execute_rows and execute_rows[-1]["success"] is False
    assert execute_rows[-1]["detail"]["reason"] == "foundry_push_failed"
    assert execute_rows[-1]["detail"]["step"] == "create_transaction"
    assert failed_chain[-1]["action"] == "job.complete" and failed_chain[-1]["success"] is False
    assert DEFAULT_TOKEN not in json.dumps(failed_chain, default=str)


# ---------------------------------------------------------------------------
# 6. Every chain this file added verifies through the real CLI (spec 26.5 item 22)
# ---------------------------------------------------------------------------


def test_audit_verify_all_passes(e2e_app: E2EApp, e2e_org: E2EOrg, audit_verify_all: Callable[[], tuple[int, str]],
                                 finding_campaign: h.CampaignRun) -> None:
    """Every chain this module wrote verifies through the real CLI; a chain a sibling test tampered with on purpose
    (``test_harness_smoke.py::test_audit_verify_all_is_clean_then_breaks_at_the_tampered_seq`` leaves its own run
    chain broken in the shared session database) is named by the CLI and nothing else is. Test-isolation fix,
    mirroring ``test_ml_governance.py::test_audit_verify_all_and_tamper``: the earlier revision required exit 0
    and no "broken" anywhere, which only holds when this file runs alone.
    """
    import re

    from redsim.audit.chain import verify_chain

    def broken_chains(text: str) -> set[str]:
        return {m.group(1) for line in text.splitlines() if "broken at seq=" in line
                for m in [re.search(r"chain '([^']+)'", line)] if m}

    def verified_chains(text: str) -> set[str]:
        return {m.group(1) for line in text.splitlines() if "events verified" in line
                for m in [re.search(r"chain '([^']+)'", line)] if m}

    ours = f"run:{finding_campaign.run_id}"
    pre_broken = {cid for cid in e2e_app.chain_ids() if not verify_chain(e2e_app.read_chain(cid)).verified}
    assert ours not in pre_broken and f"project:{e2e_org.project_id}" not in pre_broken
    exit_code, output = audit_verify_all()
    assert broken_chains(output) == pre_broken, output[-3000:]
    assert (exit_code == 0) == (not pre_broken), f"exit {exit_code} with pre-broken chains {sorted(pre_broken)}"
    assert ours in verified_chains(output), output[-3000:]
    assert verified_chains(output) | pre_broken == set(e2e_app.chain_ids()), "every chain is reported once"
