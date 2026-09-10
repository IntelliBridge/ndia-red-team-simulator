"""The signed per-run evidence pack: builder, offline verifier, route, inventory block and CLI.

Pinned over the shared sqlite harness with a filesystem blob store under tmp_path and a JSONL audit
writer holding the run's chain. The Ed25519 key is generated inside the test process and written to
tmp_path only; no key material sits in source.
"""
from __future__ import annotations

import io
import json
import zipfile
from argparse import Namespace
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("cryptography")

from fastapi.testclient import TestClient

from redsim.api.auth import CurrentUser, get_current_user
from redsim.audit.chain import JsonlAuditWriter
from redsim.config import RedsimConfig
from redsim.db.models import Artifact, Organization, Project, ReportSnapshot, Run, Target
from redsim.services.evidence_pack import (
    PACK_FORMAT,
    EvidenceSigner,
    build_run_evidence_pack,
    generate_keypair,
    load_evidence_signer,
    public_key_id,
    signer_status,
    verify_evidence_pack,
)
from redsim.storage.blobs import FilesystemBlobStore

pytestmark = pytest.mark.integration

PROJECT = "project-1"
OTHER = "project-2"
RUN = "run-1"
ENDPOINT_URL = "https://models.example.test:8443/tenants/acme/v1/predict?key=REDACTED-FAKE"
VIEWER = CurrentUser(sub="dev:viewer@test", email="viewer@test", project_memberships={PROJECT: "viewer"})
SCANNER = CurrentUser(sub="dev:scanner@test", email="scanner@test", project_memberships={PROJECT: "scanner"})
STRANGER = CurrentUser(sub="dev:other@test", email="other@test", project_memberships={OTHER: "admin"})
T0 = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)


@pytest.fixture
def harness(sqlite_session_factory: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """A finished campaign run with a record, three report formats in a snapshot, a PDF row and a chain."""
    blobs = FilesystemBlobStore(tmp_path / "blobs")
    record = json.dumps({"run_id": RUN, "schema_version": "campaign-record-1", "score": {"mri": 0.42}}).encode()
    reports = {ext: f"<report {ext}>".encode() for ext in ("md", "json", "html", "pdf")}
    refs = {"record": blobs.put(f"runs/{RUN}/run_record.json", record)}
    for ext, data in reports.items():
        refs[ext] = blobs.put(f"runs/{RUN}/report.{ext}", data)

    with sqlite_session_factory.Session() as sess:
        sess.add(Organization(id="org-1", name="Org", slug="org"))
        sess.add(Project(id=PROJECT, org_id="org-1", name="Project", slug=PROJECT))
        sess.add(Project(id=OTHER, org_id="org-1", name="Other", slug=OTHER))
        sess.flush()
        sess.add(Target(id="tgt-endpoint", project_id=PROJECT, kind="ml_model_endpoint", value=ENDPOINT_URL,
                        verified=True, detail={"modality": "tabular", "status": "available",
                                               "endpoint": {"url_host": "models.example.test:8443"}}))
        sess.flush()
        sess.add(Run(id=RUN, project_id=PROJECT, target_id="tgt-endpoint", mode="api", scanner="ml.campaign",
                     status="succeeded", stage_table={"kind": "campaign"}, created_at=T0, completed_at=T0))
        sess.add(Run(id="run-empty", project_id=PROJECT, target_id="tgt-endpoint", mode="api",
                     scanner="ml.campaign", status="running", stage_table={}, created_at=T0))
        sess.flush()

        def art(aid: str, kind: str, ref: Any) -> Artifact:
            return Artifact(id=aid, run_id=RUN, project_id=PROJECT, kind=kind, sha256=ref.sha256,
                            location=ref.location, content_type="application/octet-stream",
                            size_bytes=ref.size_bytes, created_at=T0)

        sess.add(art("art-record", "ml.run_record", refs["record"]))
        for ext in ("md", "json", "html"):
            sess.add(art(f"art-{ext}", f"report.{ext}", refs[ext]))
        sess.add(art("art-pdf", "report.pdf", refs["pdf"]))
        sess.flush()
        sess.add(ReportSnapshot(id="snap-1", run_id=RUN, project_id=PROJECT,
                                artifact_ids=["art-md", "art-json", "art-html"], record_sha256=refs["record"].sha256,
                                rendered_at=T0, archived=False, created_by="worker"))
        sess.commit()

    writer = JsonlAuditWriter(tmp_path / "audit")
    for action in ("attack.run", "model.load", "campaign.score", "job.complete"):
        writer.append(action=action, actor="worker:attack.run", target="tgt-endpoint", allowlist_check="pass",
                      override=False, success=True, detail={"run_id": RUN}, run_id=RUN, project_id=PROJECT)

    private_pem, public_pem, key_id = generate_keypair()
    key_path = tmp_path / "evidence-signing-key.pem"
    key_path.write_bytes(private_pem)
    (tmp_path / "evidence-signing-key.pub.pem").write_bytes(public_pem)

    config = RedsimConfig(output_dir=str(tmp_path / "out"))
    monkeypatch.setattr("redsim.db.session.get_session", sqlite_session_factory.session_cm)
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: writer)
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: blobs)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.delenv("REDSIM_EVIDENCE_SIGNING_KEY", raising=False)
    monkeypatch.delenv("REDSIM_EVIDENCE_SIGNING_KEY_FILE", raising=False)
    return SimpleNamespace(
        Session=sqlite_session_factory.Session, blobs=blobs, writer=writer, config=config, record=record,
        record_sha256=refs["record"].sha256, key_path=key_path, public_pem=public_pem.decode(), key_id=key_id,
        tmp_path=tmp_path, monkeypatch=monkeypatch,
    )


def _signer(h: SimpleNamespace) -> EvidenceSigner:
    return EvidenceSigner.from_pem(h.key_path.read_bytes())


def _build(h: SimpleNamespace, *, signer: EvidenceSigner | None) -> Any:
    with h.Session() as sess:
        return build_run_evidence_pack(sess, RUN, config=h.config, blob_store=h.blobs, signer=signer,
                                       audit_writer=h.writer, generated_at=T0)


def _files(zip_bytes: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        return {info.filename.split("/", 1)[1]: archive.read(info) for info in archive.infolist()}


def _retamper(zip_bytes: bytes, path: str, mutate: Any) -> bytes:
    files = _files(zip_bytes)
    files[path] = mutate(files[path])
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for rel, data in files.items():
            archive.writestr(f"redsim-evidence-{RUN}/{rel}", data)
    return out.getvalue()


# --------------------------------------------------------------------------- builder


def test_pack_layout_manifest_and_signature(harness: SimpleNamespace) -> None:
    pack = _build(harness, signer=_signer(harness))
    files = _files(pack.zip_bytes)
    assert set(files) == {
        "run.json", "record/run_record.json", "reports/report.md", "reports/report.json", "reports/report.html",
        "reports/report.pdf", "artifacts/index.json", "audit/run.jsonl", "audit/verification.json",
        "manifest.json", "manifest.sig", "signer.json",
    }
    manifest = json.loads(files["manifest.json"])
    assert manifest["format"] == PACK_FORMAT
    assert manifest["run_id"] == RUN and manifest["project_id"] == PROJECT
    assert manifest["record_sha256"] == harness.record_sha256
    assert manifest["reports"] == {"included": ["md", "json", "html", "pdf"], "missing": []}
    assert manifest["chain"] == {"id": f"run:{RUN}", "verified": True, "count": 4}
    assert manifest["artifact_count"] == 5
    assert set(manifest["files"]) == set(files) - {"manifest.json", "manifest.sig", "signer.json"}
    assert files["record/run_record.json"] == harness.record
    assert files["reports/report.pdf"] == b"<report pdf>"
    assert len(files["audit/run.jsonl"].splitlines()) == 4
    assert json.loads(files["audit/verification.json"])["verified"] is True
    signer = json.loads(files["signer.json"])
    assert signer["signed"] is True and signer["algorithm"] == "ed25519" and signer["key_id"] == harness.key_id
    assert public_key_id(signer["public_key_pem"]) == harness.key_id
    assert pack.signed and pack.key_id == harness.key_id and pack.filename == f"redsim-evidence-{RUN}.zip"
    # No score leaves the record for the manifest, and the endpoint URL never leaves at all.
    assert "mri" not in files["manifest.json"].decode()
    for rel, data in files.items():
        if rel != "record/run_record.json":
            assert b"models.example.test" not in data, rel
    run_row = json.loads(files["run.json"])
    assert run_row["target_id"] == "tgt-endpoint" and "value" not in run_row


def test_pack_is_deterministic_for_one_run(harness: SimpleNamespace) -> None:
    a = _build(harness, signer=_signer(harness))
    b = _build(harness, signer=_signer(harness))
    assert a.zip_bytes == b.zip_bytes


def test_unsigned_pack_says_why(harness: SimpleNamespace) -> None:
    pack = _build(harness, signer=None)
    files = _files(pack.zip_bytes)
    assert "manifest.sig" not in files
    signer = json.loads(files["signer.json"])
    assert signer["signed"] is False and "REDSIM_EVIDENCE_SIGNING_KEY" in signer["reason"]
    assert pack.signed is False and pack.key_id is None


def test_missing_record_and_digest_mismatch_are_typed(harness: SimpleNamespace) -> None:
    with harness.Session() as sess:
        with pytest.raises(LookupError):
            build_run_evidence_pack(sess, "run-empty", config=harness.config, blob_store=harness.blobs,
                                    audit_writer=harness.writer)
        with pytest.raises(LookupError):
            build_run_evidence_pack(sess, "run-unknown", config=harness.config, blob_store=harness.blobs,
                                    audit_writer=harness.writer)
        row = sess.get(Artifact, "art-md")
        row.sha256 = "0" * 64
        sess.commit()
    with harness.Session() as sess, pytest.raises(ValueError):
        build_run_evidence_pack(sess, RUN, config=harness.config, blob_store=harness.blobs,
                                audit_writer=harness.writer)


# --------------------------------------------------------------------------- verifier


def test_verify_ok_and_pinned_to_the_trusted_key(harness: SimpleNamespace) -> None:
    pack = _build(harness, signer=_signer(harness))
    result = verify_evidence_pack(pack.zip_bytes)
    assert result.ok, result.problems
    assert result.chain_count == 4 and result.key_id == harness.key_id and result.trusted_key_matches is None
    pinned = verify_evidence_pack(pack.zip_bytes, trusted_public_key_pem=harness.public_pem)
    assert pinned.ok and pinned.trusted_key_matches is True
    _priv, other_pub, _kid = generate_keypair()
    wrong = verify_evidence_pack(pack.zip_bytes, trusted_public_key_pem=other_pub)
    assert wrong.ok is False and wrong.trusted_key_matches is False and wrong.signature_valid is True
    path = harness.tmp_path / pack.filename
    path.write_bytes(pack.zip_bytes)
    assert verify_evidence_pack(path).ok


def test_verify_catches_a_flipped_report_byte(harness: SimpleNamespace) -> None:
    pack = _build(harness, signer=_signer(harness))
    tampered = _retamper(pack.zip_bytes, "reports/report.md", lambda d: d[:-1] + b"X")
    result = verify_evidence_pack(tampered)
    assert result.files_match is False and result.ok is False
    assert result.signature_valid is True  # the manifest itself is untouched
    assert any("reports/report.md" in p for p in result.problems)


def test_verify_catches_a_rewritten_manifest(harness: SimpleNamespace) -> None:
    pack = _build(harness, signer=_signer(harness))

    def rewrite(data: bytes) -> bytes:
        doc = json.loads(data)
        doc["run_id"] = "run-forged"
        return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()

    result = verify_evidence_pack(_retamper(pack.zip_bytes, "manifest.json", rewrite))
    assert result.signature_present is True and result.signature_valid is False and result.ok is False


def test_verify_catches_a_dropped_audit_event(harness: SimpleNamespace) -> None:
    pack = _build(harness, signer=_signer(harness))
    tampered = _retamper(pack.zip_bytes, "audit/run.jsonl", lambda d: b"".join(d.splitlines(True)[:-1]))
    result = verify_evidence_pack(tampered)
    assert result.files_match is False and result.chain_verified is False and result.ok is False


def test_unsigned_pack_never_verifies(harness: SimpleNamespace) -> None:
    pack = _build(harness, signer=None)
    result = verify_evidence_pack(pack.zip_bytes)
    assert result.files_match and result.pack_hash_matches and result.record_digest_matches and result.chain_verified
    assert result.signature_present is False and result.ok is False
    assert verify_evidence_pack(pack.zip_bytes, trusted_public_key_pem=harness.public_pem).trusted_key_matches is False


def test_verify_rejects_garbage() -> None:
    result = verify_evidence_pack(b"not a zip")
    assert result.ok is False and result.problems


# --------------------------------------------------------------------------- signer loading


def test_signer_loads_from_file_or_inline_pem(harness: SimpleNamespace) -> None:
    assert load_evidence_signer({}) is None
    from_file = load_evidence_signer({"REDSIM_EVIDENCE_SIGNING_KEY_FILE": str(harness.key_path)})
    assert from_file is not None and from_file.key_id == harness.key_id
    inline = harness.key_path.read_text().replace("\n", "\\n")
    from_inline = load_evidence_signer({"REDSIM_EVIDENCE_SIGNING_KEY": inline})
    assert from_inline is not None and from_inline.key_id == harness.key_id
    assert signer_status(from_file) == {"configured": True, "algorithm": "ed25519", "key_id": harness.key_id}
    assert signer_status(None)["configured"] is False
    with pytest.raises(ValueError):
        load_evidence_signer({"REDSIM_EVIDENCE_SIGNING_KEY": "not a pem"})


# --------------------------------------------------------------------------- routes


@pytest.fixture
def client(harness: SimpleNamespace) -> Iterator[SimpleNamespace]:
    import redsim.api.middleware.rate_limit as rl
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

    rl._BUCKETS.clear()
    app = create_app(APISettings(env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
                                 rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000))
    holder: dict[str, CurrentUser] = {"user": SCANNER}
    app.dependency_overrides[get_current_user] = lambda: holder["user"]
    test_client = TestClient(app)

    def get(user: CurrentUser, path: str) -> Any:
        holder["user"] = user
        return test_client.get(path)

    yield SimpleNamespace(get=get)
    rl._BUCKETS.clear()


def test_route_streams_a_signed_zip_for_a_scanner(harness: SimpleNamespace, client: SimpleNamespace) -> None:
    harness.monkeypatch.setenv("REDSIM_EVIDENCE_SIGNING_KEY_FILE", str(harness.key_path))
    resp = client.get(SCANNER, f"/v1/runs/{RUN}/evidence-pack")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/zip"
    assert resp.headers["content-disposition"] == f'attachment; filename="redsim-evidence-{RUN}.zip"'
    assert resp.headers["x-redsim-evidence-signed"] == "true"
    assert resp.headers["x-redsim-evidence-key-id"] == harness.key_id
    result = verify_evidence_pack(resp.content, trusted_public_key_pem=harness.public_pem)
    assert result.ok, result.problems
    assert resp.headers["x-redsim-evidence-pack-hash"] == json.loads(_files(resp.content)["manifest.json"])["pack_hash"]
    # The signer roster names the key, never the key.
    roster = client.get(VIEWER, "/v1/evidence/signer").json()
    assert roster == {"configured": True, "algorithm": "ed25519", "key_id": harness.key_id}
    assert "PRIVATE" not in roster.get("key_id", "")


def test_route_is_unsigned_without_a_key_and_the_roster_says_so(harness: SimpleNamespace,
                                                                 client: SimpleNamespace) -> None:
    resp = client.get(SCANNER, f"/v1/runs/{RUN}/evidence-pack")
    assert resp.status_code == 200
    assert resp.headers["x-redsim-evidence-signed"] == "false"
    assert "x-redsim-evidence-key-id" not in resp.headers
    roster = client.get(SCANNER, "/v1/evidence/signer").json()
    assert roster["configured"] is False and "REDSIM_EVIDENCE_SIGNING_KEY" in roster["reason"]


def test_route_gates(harness: SimpleNamespace, client: SimpleNamespace) -> None:
    assert client.get(VIEWER, f"/v1/runs/{RUN}/evidence-pack").status_code == 403
    assert client.get(STRANGER, f"/v1/runs/{RUN}/evidence-pack").status_code == 403
    assert client.get(SCANNER, "/v1/runs/run-unknown/evidence-pack").status_code == 404
    resp = client.get(SCANNER, "/v1/runs/run-empty/evidence-pack")
    assert resp.status_code == 404 and resp.json()["detail"]["code"] == "not_found"
    # The audit chain gained nothing: reads write no row.
    assert len(list(harness.writer.read_chain(f"run:{RUN}"))) == 4


def test_route_refuses_a_digest_mismatch(harness: SimpleNamespace, client: SimpleNamespace) -> None:
    with harness.Session() as sess:
        sess.get(Artifact, "art-pdf").sha256 = "1" * 64
        sess.commit()
    resp = client.get(SCANNER, f"/v1/runs/{RUN}/evidence-pack")
    assert resp.status_code == 409 and resp.json()["detail"]["code"] == "report_artifact_digest_mismatch"


def test_exports_inventory_carries_the_evidence_block(harness: SimpleNamespace, client: SimpleNamespace) -> None:
    harness.monkeypatch.setenv("REDSIM_EVIDENCE_SIGNING_KEY_FILE", str(harness.key_path))
    body = client.get(VIEWER, "/v1/exports").json()
    assert body["evidence_signing"] == {"configured": True, "algorithm": "ed25519", "key_id": harness.key_id}
    rows = {row["run_id"]: row for row in body["exports"]}
    assert rows[RUN]["evidence"] == {"available": True, "path": f"/v1/runs/{RUN}/evidence-pack"}
    assert rows["run-empty"]["evidence"] == {"available": False, "path": None}


# --------------------------------------------------------------------------- CLI


def test_cli_verify_and_keygen(harness: SimpleNamespace, capsys: pytest.CaptureFixture[str]) -> None:
    from redsim.cli.evidence import cmd_evidence_keygen, cmd_evidence_verify

    pack = _build(harness, signer=_signer(harness))
    path = harness.tmp_path / pack.filename
    path.write_bytes(pack.zip_bytes)
    pub = harness.tmp_path / "evidence-signing-key.pub.pem"

    with pytest.raises(SystemExit) as exit_ok:
        cmd_evidence_verify(Namespace(path=str(path), public_key=str(pub)), harness.config)
    assert exit_ok.value.code == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out and harness.key_id in out

    tampered = harness.tmp_path / "tampered.zip"
    tampered.write_bytes(_retamper(pack.zip_bytes, "reports/report.json", lambda d: d + b"!"))
    with pytest.raises(SystemExit) as exit_bad:
        cmd_evidence_verify(Namespace(path=str(tampered), public_key=None), harness.config)
    assert exit_bad.value.code == 1
    captured = capsys.readouterr()
    assert "NOT VERIFIED" in captured.out + captured.err

    with pytest.raises(SystemExit) as exit_missing:
        cmd_evidence_verify(Namespace(path=str(harness.tmp_path / "nope.zip"), public_key=None), harness.config)
    assert exit_missing.value.code == 2

    key_dir = harness.tmp_path / "keys"
    with pytest.raises(SystemExit) as exit_gen:
        cmd_evidence_keygen(Namespace(out=str(key_dir)), harness.config)
    assert exit_gen.value.code == 0
    private = key_dir / "evidence-signing-key.pem"
    assert private.exists() and (private.stat().st_mode & 0o777) == 0o600
    assert (key_dir / "evidence-signing-key.pub.pem").exists()
    generated = load_evidence_signer({"REDSIM_EVIDENCE_SIGNING_KEY_FILE": str(private)})
    assert generated is not None and generated.key_id in capsys.readouterr().out
    with pytest.raises(SystemExit) as exit_refuse:
        cmd_evidence_keygen(Namespace(out=str(key_dir)), harness.config)
    assert exit_refuse.value.code == 1


def test_cli_evidence_pack_run_writes_the_zip(harness: SimpleNamespace, capsys: pytest.CaptureFixture[str]) -> None:
    from redsim.cli.evidence import cmd_evidence_pack

    harness.monkeypatch.setenv("REDSIM_DB_URL", "sqlite://")
    harness.monkeypatch.setenv("REDSIM_EVIDENCE_SIGNING_KEY_FILE", str(harness.key_path))
    out_dir = harness.tmp_path / "packs"
    with pytest.raises(SystemExit) as exit_ok:
        cmd_evidence_pack(Namespace(out=str(out_dir), project=None, run=RUN), harness.config)
    assert exit_ok.value.code == 0
    written = out_dir / f"redsim-evidence-{RUN}.zip"
    assert written.exists()
    assert verify_evidence_pack(written, trusted_public_key_pem=harness.public_pem).ok
    assert harness.key_id in capsys.readouterr().out
