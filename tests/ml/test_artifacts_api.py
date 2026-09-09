"""``GET /v1/artifacts/{id}`` and ``GET /v1/runs/{id}/artifacts`` (spec 17.2): headers, 404s, tenancy.

PNGs stream inline, everything else as an attachment; every response carries
``nosniff``, ``default-src 'none'`` and an ``ETag`` equal to the sha256. Unknown
ids, rows outside the caller's projects and rows whose blob is gone are all 404.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient

from redsim.api.auth import CurrentUser, get_current_user
from redsim.db.models import Artifact, Organization, Project, Run
from redsim.storage.blobs import FilesystemBlobStore

PROJECT = "proj-1"
OTHER = "proj-2"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JSON_BYTES = b'{"run_id": "run-1", "score": null}'


@pytest.fixture
def api(sqlite_session_factory: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SimpleNamespace]:
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

    monkeypatch.setattr("redsim.db.session.get_session", sqlite_session_factory.session_cm)
    blob_root = tmp_path / "blobs"
    blobs = FilesystemBlobStore(blob_root)
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: blobs)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)

    png_ref = blobs.put(f"{PROJECT}/run-1/ml.shap.image/png", PNG, content_type="image/png")
    json_ref = blobs.put(f"{PROJECT}/run-1/ml.run_record/json", JSON_BYTES, content_type="application/json")
    with sqlite_session_factory.Session() as sess:
        sess.add(Organization(id="org-1", name="Org", slug="org"))
        sess.add(Project(id=PROJECT, org_id="org-1", name="Project", slug=PROJECT))
        sess.add(Project(id=OTHER, org_id="org-1", name="Other", slug=OTHER))
        sess.flush()
        sess.add(Run(id="run-1", project_id=PROJECT, mode="api", status="succeeded", scanner="ml.campaign",
                     stage_table={}))
        sess.add(Run(id="run-2", project_id=OTHER, mode="api", status="succeeded", scanner="ml.campaign",
                     stage_table={}))
        sess.flush()
        sess.add(Artifact(id="art-png", run_id="run-1", project_id=PROJECT, kind="ml.shap.image",
                          sha256=png_ref.sha256, location=png_ref.location, content_type="image/png",
                          size_bytes=len(PNG)))
        sess.add(Artifact(id="art-json", run_id="run-1", project_id=PROJECT, kind="ml.run_record",
                          sha256=json_ref.sha256, location=json_ref.location, content_type="application/json",
                          size_bytes=len(JSON_BYTES)))
        sess.add(Artifact(id="art-gone", run_id="run-1", project_id=PROJECT, kind="ml.curve",
                          sha256="0" * 64, location=str(blob_root / "00" / ("0" * 64)), content_type="image/png",
                          size_bytes=1))
        sess.add(Artifact(id="art-escape", run_id="run-1", project_id=PROJECT, kind="ml.curve",
                          sha256="1" * 64, location=str(blob_root / ".." / ".." / "etc" / "hosts"),
                          content_type="text/plain", size_bytes=1))
        sess.add(Artifact(id="art-other", run_id="run-2", project_id=OTHER, kind="ml.run_record",
                          sha256=json_ref.sha256, location=json_ref.location, content_type="application/json",
                          size_bytes=len(JSON_BYTES)))
        sess.commit()

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"]))
    user = CurrentUser(sub="dev:viewer@test", email="viewer@test", project_memberships={PROJECT: "viewer"})
    app.dependency_overrides[get_current_user] = lambda: user
    yield SimpleNamespace(client=TestClient(app), png_sha=png_ref.sha256, json_sha=json_ref.sha256)
    rl._BUCKETS.clear()


def test_stream_headers_and_404s(api: SimpleNamespace) -> None:
    png = api.client.get("/v1/artifacts/art-png")
    assert png.status_code == 200, png.text
    assert png.content == PNG
    assert png.headers["content-type"].startswith("image/png")
    assert png.headers["x-content-type-options"] == "nosniff"
    assert png.headers["content-security-policy"] == "default-src 'none'"
    assert png.headers["etag"] == f'"{api.png_sha}"'
    assert png.headers["content-disposition"] == "inline"

    record = api.client.get("/v1/artifacts/art-json")
    assert record.status_code == 200 and record.content == JSON_BYTES
    assert record.headers["content-disposition"].startswith('attachment; filename="art-json-')
    assert record.headers["x-content-type-options"] == "nosniff"
    assert record.headers["etag"] == f'"{api.json_sha}"'
    assert record.headers["cache-control"] == "private, no-store"

    unknown = api.client.get("/v1/artifacts/nope")
    assert unknown.status_code == 404 and unknown.json()["detail"] == "artifact not found"

    gone = api.client.get("/v1/artifacts/art-gone")
    assert gone.status_code == 404, gone.text
    assert gone.json()["detail"] == {"code": "not_found", "message": "artifact blob is missing",
                                     "reason": "artifact_blob_missing"}

    escape = api.client.get("/v1/artifacts/art-escape")
    assert escape.status_code == 404 and escape.json()["detail"]["reason"] == "artifact_blob_missing"

    # Membership is enforced through the run's project: another project's row is 403, not served.
    other = api.client.get("/v1/artifacts/art-other")
    assert other.status_code == 403, other.text

    listing = api.client.get("/v1/runs/run-1/artifacts")
    assert listing.status_code == 200
    body = listing.json()
    assert body["count"] == 4 and {row["id"] for row in body["artifacts"]} == {
        "art-png", "art-json", "art-gone", "art-escape"}
    assert all({"id", "run_id", "kind", "sha256", "content_type", "size_bytes", "created_at"} <= set(row)
               for row in body["artifacts"])
    assert api.client.get("/v1/runs/run-2/artifacts").status_code == 403
    assert api.client.get("/v1/runs/run-none/artifacts").status_code == 404
