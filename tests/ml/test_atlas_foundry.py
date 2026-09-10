"""ATLAS stamping, coverage and the Foundry push (plan 12 wave B3 ``atlas-foundry``; INTEROP-18, -20..25, -28, -29, -31).

Three harnesses, all offline:

* pure: the stamp table against ``atlas_data``, ``build_finding_detail`` stamping,
  the number-free coverage view, the payload builder and its D9 / D3 guard, the
  JWT-shaped redaction, the settings rules and the sandbox child environment;
* ``api``: the real app in dev auth over the shared sqlite harness with an
  in-memory audit writer and the Celery ``apply_async`` replaced, for
  ``GET /v1/attacks``, ``GET /v1/integrations``, ``GET /v1/runs/{id}/atlas-coverage``
  and ``POST /v1/runs/{id}/integrations/foundry`` (gates, refusals with their
  ``success=False`` rows, admission order: audit row, then rows, then enqueue);
* ``worker``: ``redsim.integration_push`` run eagerly on a file sqlite database
  with the JSONL chain writer against the stdlib fake Foundry server: the pushed
  payload carries subscores, denominators and the grade sentence, the audit
  rows carry digests and statuses and never the (JWT-shaped) token, a 503 fails
  the job honestly with the transaction aborted and no retry, and an unset
  Foundry URL fails the job without a request.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("numpy")
pytest.importorskip("cryptography")
pytest.importorskip("httpx")

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text, create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.errors import (
    AUTH_PROFILE_KIND_UNSUPPORTED,
    CAMPAIGN_NOT_TERMINAL,
    FIXTURE_NOT_EXPORTABLE,
    INTEGRATION_DISABLED,
    JOB_IN_FLIGHT,
    LLM_TARGET_REQUIRED,
    NOT_FOUND,
    PARAMS_OUT_OF_RANGE,
    QUEUE_UNAVAILABLE,
)
from redsim.audit.chain import InMemoryAuditWriter, JsonlAuditWriter, verify_chain
from redsim.config import RedsimConfig
from redsim.db.models import Artifact, Base, Job, Organization, Project, Run, Target
from redsim.integrations import (
    ADMISSION_ACTION,
    EXECUTE_ACTION,
    LATTICE_REASON,
    PUSH_JOB_TYPE,
    PUSH_SCANNER,
    FoundryPushRequest,
    create_foundry_push,
    roster,
)
from redsim.integrations import foundry as foundry_mod
from redsim.integrations.foundry import (
    FOUNDRY_ATTESTATION_ENV,
    FOUNDRY_DATASET_RID_ENV,
    FOUNDRY_ENV_NAMES,
    FOUNDRY_URL_ENV,
    PAYLOAD_SCHEMA,
    FoundryMisconfigured,
    FoundrySettings,
    PayloadRefused,
    assert_push_payload,
    build_scorecard_payload,
    payload_bytes,
    scrub_detail,
    validate_push_payload,
    validate_target_ref,
)
from redsim.ml import atlas, atlas_data
from redsim.ml.schema import GRADE_STATEMENT, AttackInfo, CampaignRecord, MLFindingDetail
from redsim.ml.scoring import finding_inputs
from redsim.services.auth_profiles import create_auth_profile
from redsim.services.ml_findings import build_finding_detail, read_finding_detail
from redsim.storage import FilesystemBlobStore
from redsim.workers.tasks import integration_push as worker
from tests.conftest import patch_jsonb_for_sqlite
from tests.ml.fake_foundry_server import DEFAULT_DATASET_RID, DEFAULT_TOKEN, FakeFoundryServer

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).parent / "fixtures" / "run_record.json"
PROJECT = "project-atlas"
OTHER = "project-other"
ORG = "org-atlas"
TARGET = "tgt-atlas-1"
FIXTURE_TARGET = "tgt-atlas-fixture"
RUN = "run-atlas-campaign-1"
FIXTURE_RUN = "run-atlas-fixture-1"
RUNNING_RUN = "run-atlas-running-1"
PROBE_RUN = "run-atlas-probe-1"
PLAIN_RUN = "run-atlas-plain-1"
FERNET_KEY = Fernet.generate_key().decode()
FOUNDRY_URL = "http://127.0.0.1:9"
URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")

VIEWER = CurrentUser(sub="dev:viewer@test", email="viewer@test", project_memberships={PROJECT: "viewer"})
REMEDIATOR = CurrentUser(sub="dev:rem@test", email="rem@test", project_memberships={PROJECT: "remediator"})
ADMIN = CurrentUser(sub="dev:admin@test", email="admin@test", project_memberships={PROJECT: "admin", OTHER: "admin"})
STRANGER = CurrentUser(sub="dev:other@test", email="other@test", project_memberships={OTHER: "admin"})


# --------------------------------------------------------------------------- helpers


def _fixture_record() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _live_record(run_id: str = RUN) -> dict[str, Any]:
    """The frozen fixture with its fixture flags removed, standing in for a live campaign record."""
    data = _fixture_record()
    data["run_id"] = run_id
    data["target"]["metadata"].pop("fixture", None)
    data["config"]["target_snapshot"].pop("fixture", None)
    data["provenance"]["model_manifest"].pop("fixture", None)
    data["limitations"] = [line for line in data["limitations"] if not line.startswith("FIXTURE:")]
    return data


def _campaign_table(engine: Any) -> Table:
    """A mirror of the migration-owned ``ml_campaigns`` table so the campaign lookups find a row."""
    table = Table(
        "ml_campaigns", MetaData(),
        Column("run_id", String, primary_key=True), Column("project_id", String, nullable=False),
        Column("org_id", String), Column("target_id", String, nullable=False), Column("kind", String, nullable=False),
        Column("modality", String, nullable=False), Column("config", JSON, nullable=False),
        Column("settings_hash", String), Column("provenance", JSON), Column("score", JSON),
        Column("limitations", JSON, nullable=False),
        Column("parent_run_id", String), Column("reviewer_notes", Text), Column("created_at", DateTime),
        Column("completed_at", DateTime),
    )
    table.create(engine)
    return table


def _store_record(session: Session, blobs: FilesystemBlobStore, *, run_id: str, record: dict[str, Any],
                  artifact_id: str) -> str:
    data = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    ref = blobs.put(f"{PROJECT}/{run_id}/run_record.json/{digest}", data, content_type="application/json")
    session.add(Artifact(id=artifact_id, run_id=run_id, project_id=PROJECT, kind="ml.run_record", sha256=digest,
                         location=ref.location, content_type="application/json", size_bytes=len(data)))
    return digest


def _walk(value: Any) -> Iterator[Any]:
    if isinstance(value, dict):
        for inner in value.values():
            yield from _walk(inner)
    elif isinstance(value, (list, tuple)):
        for inner in value:
            yield from _walk(inner)
    else:
        yield value


def _assert_secret_free(blob: Any) -> None:
    text = json.dumps(blob, default=str)
    assert DEFAULT_TOKEN not in text
    assert not foundry_mod.JWT_PATTERN.search(text), "a JWT-shaped token reached an audit row or artifact"
    assert not URL_RE.search(text), "a URL string reached an audit row or artifact"


# --------------------------------------------------------------------------- the stamp (INTEROP-18, -20)


def test_stamp_table_agrees_with_the_vendored_atlas_data() -> None:
    for attack_id, technique_id in atlas.STAMP_TECHNIQUE_IDS.items():
        assert technique_id in atlas_data.ATTACK_TECHNIQUE_IDS[attack_id], attack_id
        assert atlas_data.ATLAS_TECHNIQUES[technique_id].parent is None
    assert set(atlas.STAMP_TECHNIQUE_IDS) == set(atlas_data.ATTACK_TECHNIQUE_IDS)


def test_technique_for_attack_mapping() -> None:
    for attack_id in ("fgsm", "pgd", "cw_l2", "deepfool", "word_substitution", "dpatch"):
        tag = atlas.technique_for_attack(attack_id)
        assert tag is not None and tag.id == "AML.T0043" and tag.name == "Craft Adversarial Data", attack_id
        assert tag.atlas_version == atlas_data.ATLAS_VERSION
    for attack_id in ("hopskipjump", "zoo"):
        tag = atlas.technique_for_attack(attack_id)
        assert tag is not None and tag.id == "AML.T0040", attack_id
        assert atlas_data.is_same_technique(tag, "AML.T0040")
        assert "ML Model Inference API Access" in atlas_data.ATLAS_PRIOR_NAMES["AML.T0040"]
    assert atlas.technique_for_attack("noise_control") is None
    assert atlas.technique_for_attack("no-such-attack") is None
    row = atlas.attack_atlas_row("hopskipjump")
    assert row["atlas_technique"]["id"] == "AML.T0040"
    assert [t["id"] for t in row["atlas_techniques"]][0] == "AML.T0040"
    assert {t["id"] for t in row["atlas_techniques"]} == {"AML.T0043", "AML.T0043.001", "AML.T0040"}
    control = atlas.attack_atlas_row("noise_control")
    assert control["atlas_technique"] is None and control["atlas_techniques"] == []
    assert control["atlas_reason"] == atlas.CONTROL_REASON
    # The frozen AttackInfo gains no field (P0 freeze; tests/ml/test_attacks.py pins the same).
    assert not {f for f in AttackInfo.model_fields if "atlas" in f}


def test_build_finding_detail_stamps_atlas_and_old_rows_stay_none() -> None:
    record = CampaignRecord.model_validate(_fixture_record())
    for attack_id, expected in (("fgsm", "AML.T0043"), ("pgd", "AML.T0043")):
        inputs = finding_inputs(record.config, record.measurements, attack_id)
        detail = build_finding_detail(record, attack_id, inputs)
        assert detail.atlas_technique is not None
        assert detail.atlas_technique.id == expected and detail.atlas_technique.atlas_version == atlas_data.ATLAS_VERSION
        dumped = detail.model_dump(mode="json")
        assert dumped["atlas_technique"] == {"id": expected, "name": "Craft Adversarial Data",
                                             "atlas_version": atlas_data.ATLAS_VERSION}
    # A finding written before B3 keeps atlas_technique None when read back: never back-filled.
    old = MLFindingDetail(attack_id="fgsm", attack_name="FGSM", norm="linf", eps_grid=[0.01, 0.03, 0.1],
                          reference_eps=0.03, threshold=0.2).model_dump(mode="json")
    assert old["atlas_technique"] is None
    read = read_finding_detail({"finding_type": "adversarial_ml", "ml": old})
    assert read is not None and read.atlas_technique is None


# --------------------------------------------------------------------------- coverage (INTEROP-21)


def test_coverage_lists_membership_without_a_single_number() -> None:
    record = _fixture_record()
    # Declare a third attack the campaign recorded not_run (spec 9.5): the frame's interpretation row says why.
    record["config"]["attack_ids"] = ["fgsm", "pgd", "hopskipjump"]
    record["interpretation"].append({
        "id": "i.attack.not_run.hopskipjump",
        "statement": "Attack 'hopskipjump' was not run against this target (no decision boundary reached); "
                     "it is recorded as not_run and removed from the in-scope set.",
        "basis": ["m.clean"], "kind": "inferred",
    })
    catalog = [("fgsm", "evasion"), ("pgd", "evasion"), ("hopskipjump", "evasion"), ("cw_l2", "evasion"),
               ("zoo", "evasion"), ("noise_control", "control")]
    view = atlas.coverage(record, catalog_attacks=catalog)
    assert view["kind"] == "atlas_coverage" and view["run_id"] == record["run_id"]
    assert [row["attack_id"] for row in view["exercised"]] == ["fgsm", "pgd"]
    assert all(row["technique"]["id"] == "AML.T0043" and row["status"] == "run" for row in view["exercised"])
    assert [row["attack_id"] for row in view["declared_not_run"]] == ["hopskipjump"]
    not_run = view["declared_not_run"][0]
    assert not_run["technique"]["id"] == "AML.T0040" and not_run["status"] == "not_run"
    assert "no decision boundary reached" in not_run["not_run_reason"]
    assert [row["attack_id"] for row in view["catalog_outside_declared"]] == ["cw_l2", "zoo"]
    assert view["controls"] == [{"attack_id": "noise_control", "technique": None, "reason": atlas.CONTROL_REASON}]
    assert view["techniques_exercised"] == [{"id": "AML.T0043", "name": "Craft Adversarial Data"}]
    assert view["statement"] == atlas.COVERAGE_STATEMENT and view["atlas"]["release"] == atlas_data.ATLAS_RELEASE
    # Not a score: no numeric field anywhere, no mri / grade / score key.
    assert atlas.numeric_paths(view) == []
    assert not any(isinstance(v, (int, float)) and not isinstance(v, bool) for v in _walk(view))
    keys = set(json.dumps(view).lower().split('"'))
    assert not ({"mri", "grade", "score", "subscores"} & keys)
    # Without a registry the vendored mapping stands in and says so.
    fallback = atlas.coverage(record)
    assert fallback["catalog_source"].startswith("atlas_data") and atlas.numeric_paths(fallback) == []
    # A failed campaign explains the missing rows by its status, never by a number.
    failed = dict(record, status="failed", error="SandboxTimeout", measurements=[])
    reasons = atlas.not_run_reasons(failed)
    assert set(reasons) == {"fgsm", "pgd", "hopskipjump"}
    assert "failed" in reasons["fgsm"] and "SandboxTimeout" in reasons["fgsm"]


# --------------------------------------------------------------------------- settings and redaction (INTEROP-28, -29)


def test_foundry_settings_rules() -> None:
    allow = ["127.0.0.1", "localhost"]
    assert FoundrySettings.from_env({}, allowlist=allow) is None
    with pytest.raises(FoundryMisconfigured) as missing:
        FoundrySettings.from_env({FOUNDRY_URL_ENV: FOUNDRY_URL}, allowlist=allow)
    assert missing.value.rule == "attestation" and FOUNDRY_ATTESTATION_ENV in missing.value.reason
    with pytest.raises(FoundryMisconfigured) as plaintext:
        FoundrySettings.from_env({FOUNDRY_URL_ENV: "http://foundry.example.invalid", FOUNDRY_ATTESTATION_ENV: "1"},
                                 allowlist=["foundry.example.invalid"])
    assert plaintext.value.rule == "plaintext" and "example.invalid" not in plaintext.value.reason
    with pytest.raises(FoundryMisconfigured) as not_allowed:
        FoundrySettings.from_env({FOUNDRY_URL_ENV: "https://foundry.example.invalid", FOUNDRY_ATTESTATION_ENV: "1"},
                                 allowlist=allow)
    assert not_allowed.value.rule == "not_allowlisted"
    with pytest.raises(FoundryMisconfigured) as rid:
        FoundrySettings.from_env({FOUNDRY_URL_ENV: FOUNDRY_URL, FOUNDRY_ATTESTATION_ENV: "1",
                                  FOUNDRY_DATASET_RID_ENV: "https://not-a-rid"}, allowlist=allow)
    assert rid.value.rule == "dataset_rid"
    settings = FoundrySettings.from_env({FOUNDRY_URL_ENV: FOUNDRY_URL + "/", FOUNDRY_ATTESTATION_ENV: "yes",
                                         FOUNDRY_DATASET_RID_ENV: DEFAULT_DATASET_RID}, allowlist=allow)
    assert settings is not None and settings.host == "127.0.0.1" and settings.plaintext_loopback
    assert settings.dataset_rid == DEFAULT_DATASET_RID and settings.base_url == FOUNDRY_URL
    assert "url" not in settings.redacted() and settings.redacted()["host"] == "127.0.0.1"
    assert validate_target_ref(None) is None and validate_target_ref("  ") is None
    with pytest.raises(ValueError, match="never a URL"):
        validate_target_ref("https://foundry.example.invalid/dataset")
    with pytest.raises(ValueError):
        validate_target_ref("not-a-rid")


def test_scrub_detail_redacts_jwt_shaped_and_bearer_tokens() -> None:
    detail = {
        "host": "127.0.0.1", "foundry_token": DEFAULT_TOKEN, "x-foundry-token": DEFAULT_TOKEN,
        "note": f"Authorization: Bearer {DEFAULT_TOKEN} was sent", "nested": [{"token": "abc"}, DEFAULT_TOKEN],
        "digest": "a" * 64, "pythia": "pk_fake_probe_key_not_real_0001",
    }
    cleaned = scrub_detail(detail)
    text = json.dumps(cleaned)
    assert DEFAULT_TOKEN not in text and "pk_fake" not in text
    assert cleaned["foundry_token"] == "<REDACTED>" and cleaned["x-foundry-token"] == "<REDACTED>"
    assert cleaned["nested"][0]["token"] == "<REDACTED>" and cleaned["nested"][1] == "<REDACTED>"
    assert "Bearer <REDACTED>" in cleaned["note"]
    assert cleaned["host"] == "127.0.0.1" and cleaned["digest"] == "a" * 64
    # A URL string never survives into an integration row either (spec 21.8): host and ids only.
    assert scrub_detail({"ref": "see https://foundry.example.invalid/x now"})["ref"] == "see <URL_REDACTED> now"


def test_sandbox_child_env_drops_every_foundry_setting(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from redsim.ml import sandbox

    for name in FOUNDRY_ENV_NAMES:
        monkeypatch.setenv(name, "fake-value-not-real")
    monkeypatch.setenv("REDSIM_FOUNDRY_TOKEN", DEFAULT_TOKEN)
    env = sandbox._ml_child_env(sandbox.MlSandboxConfig(), assets=str(tmp_path / "assets"), hash_seed=0,
                                work_dir=tmp_path)
    assert not any(k.startswith("REDSIM_INTEGRATION_") or k.startswith("REDSIM_FOUNDRY") for k in env)
    assert DEFAULT_TOKEN not in env.values() and "fake-value-not-real" not in env.values()


# --------------------------------------------------------------------------- the payload guard (INTEROP-23, -31)


def test_payload_builder_carries_denominators_grade_sentence_and_atlas() -> None:
    record = CampaignRecord.model_validate(_live_record())
    payload = build_scorecard_payload(record)
    assert validate_push_payload(payload) == []
    assert payload["schema"] == PAYLOAD_SCHEMA and payload["settings_hash"] == record.settings_hash
    assert len(payload["rows"]) == 6                                  # (fgsm, pgd) x three eps points
    for row in payload["rows"]:
        assert row["n"] == 200 and row["n_correct_clean"] == 172 and row["acc_adv"] is not None
        assert set(row["subscores"]) == set(foundry_mod.SUBSCORE_KEYS)
        assert all(row["subscores"][k] is not None for k in foundry_mod.SUBSCORE_KEYS)
        assert row["mri"] == 42 and row["grade"] == "D" and row["grade_statement"] == GRADE_STATEMENT
        assert row["settings_hash"] == record.settings_hash and row["computed_at"]
        assert row["atlas_technique_id"] == "AML.T0043"
    assert payload["scorecard"]["mri"] == 42 and len(payload["scorecard"]["inputs"]) == 6
    assert payload["scorecard"]["eps_grid"] == [0.01, 0.03, 0.1] and payload["scorecard"]["weights"]["acc"] == 0.35
    assert {f["family"] for f in payload["families"]} == {"clean", "evasion", "control"}
    assert all("n" in f and "n_correct" in f for f in payload["families"])
    assert payload["atlas"] == {"fgsm": {"id": "AML.T0043", "name": "Craft Adversarial Data",
                                         "atlas_version": atlas_data.ATLAS_VERSION},
                                "pgd": {"id": "AML.T0043", "name": "Craft Adversarial Data",
                                        "atlas_version": atlas_data.ATLAS_VERSION}}
    assert payload["limitations"] and payload["curve"] and payload["target"] == {
        "id": "tiny", "name": "Tiny random CNN (test double)", "domain": "image", "status": "available"}
    text = payload_bytes(payload).decode()
    assert "recommendations" not in payload and "hostname" not in text and "expected_gain" not in text
    assert not URL_RE.search(text) and "pk_" not in text
    # Without a score the rows come from the measurements and the mri stays None with its reasons.
    no_score = _live_record()
    no_score["score"] = None
    no_score["score_status"] = {"state": "unavailable", "reason": "explain stage not run"}
    partial = build_scorecard_payload(CampaignRecord.model_validate(no_score))
    assert validate_push_payload(partial) == []
    assert partial["scorecard"]["mri"] is None and partial["scorecard"]["missing"]
    assert len(partial["rows"]) == 6 and all(r["mri"] is None and r["n_correct_clean"] == 172 for r in partial["rows"])


def test_payload_guard_refuses_bare_mri_and_every_forbidden_content() -> None:
    record = CampaignRecord.model_validate(_live_record())
    good = build_scorecard_payload(record)
    assert_push_payload(good)

    bare = {"schema": PAYLOAD_SCHEMA, "run_id": "r", "settings_hash": "x" * 64, "limitations": ["some"],
            "rows": [{"mri": 78, "grade": "B"}], "scorecard": {"mri": 78, "grade": "B", "eps_grid": [0.1],
                                                               "inputs": [{"n": 1}], "missing": []}}
    problems = validate_push_payload(bare)
    assert any("bare MRI" in p for p in problems) and any("grade sentence" in p for p in problems)
    assert any("denominators" in p for p in problems)
    with pytest.raises(PayloadRefused) as excinfo:
        assert_push_payload(bare)
    assert excinfo.value.problems == problems

    def mutated(**changes: Any) -> dict[str, Any]:
        payload = copy.deepcopy(good)
        for key, value in changes.items():
            payload[key] = value
        return payload

    cases = {
        "url": (mutated(limitations=[*good["limitations"], "see https://example.invalid/report"]), "URL string"),
        "jwt": (mutated(limitations=[*good["limitations"], f"token {DEFAULT_TOKEN}"]), "credential-shaped"),
        "pk": (mutated(limitations=[*good["limitations"], "key pk_fake_probe_key_not_real_0001"]), "token-shaped"),
        "token_key": (mutated(foundry_token="abc"), "credential-shaped key"),
        "model_file": (mutated(limitations=[*good["limitations"], "weights in model.onnx"]), "model or tensor file"),
        "bytes": (mutated(model_bytes=b"\x80\x04"), "forbidden key"),
        "blob": (mutated(limitations=[*good["limitations"], "A" * 300]), "base64 blob"),
        "banned": (mutated(limitations=[*good["limitations"], "the model is certified safe"]), "banned readiness word"),
        "gain": (mutated(expected_gain=12), "forbidden key"),
        "notes": (mutated(reviewer_notes="private"), "forbidden key"),
        "actor": (mutated(requested_by="user:someone"), "forbidden key"),
        "grade_only": (mutated(scorecard={**good["scorecard"], "mri": None}), "grade without an mri"),
        "no_rows": (mutated(rows=[]), "rows is empty"),
        "no_limitations": (mutated(limitations=[]), "limitations is empty"),
    }
    for name, (payload, expected) in cases.items():
        problems = validate_push_payload(payload)
        assert any(expected in p for p in problems), (name, problems)
    stripped = copy.deepcopy(good)
    stripped["scorecard"]["subscores"]["S_expl"] = None
    assert any("subscore is missing" in p for p in validate_push_payload(stripped))


# --------------------------------------------------------------------------- API harness


@pytest.fixture
def api(sqlite_session_factory: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SimpleNamespace]:
    """The real app in dev auth over sqlite: a campaign run with its record, a fixture run, a probe run, profiles."""
    from redsim.api.app import create_app
    from redsim.api.settings import APISettings

    monkeypatch.setenv("REDSIM_AUTH_PROFILES_KEY", FERNET_KEY)
    monkeypatch.setenv("REDSIM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(tmp_path / "no-assets"))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    monkeypatch.delenv("REDSIM_TEST_AUDIT", raising=False)
    monkeypatch.delenv("REDSIM_PLUGINS", raising=False)
    for name in FOUNDRY_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("redsim.db.session.get_session", sqlite_session_factory.session_cm)
    writer = InMemoryAuditWriter()
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _config: writer)
    blobs = FilesystemBlobStore(tmp_path / "blobs")
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: blobs)
    monkeypatch.setattr("redsim.storage.open_blob_store", lambda *_a, **_k: blobs)
    enqueued: list[tuple[str, str | None]] = []

    def fake_apply_async(*, args: list[str], queue: str | None = None, **_kw: Any) -> SimpleNamespace:
        enqueued.append((args[0], queue))
        return SimpleNamespace(id=f"celery-{args[0]}")

    monkeypatch.setattr(worker.integration_push, "apply_async", fake_apply_async)

    campaigns = _campaign_table(sqlite_session_factory.engine)
    record = _live_record()
    fixture_record = _fixture_record()
    fixture_record["run_id"] = FIXTURE_RUN
    with sqlite_session_factory.Session() as sess:
        sess.add(Organization(id=ORG, name="Org", slug=ORG))
        sess.add(Project(id=PROJECT, org_id=ORG, name="Project", slug=PROJECT))
        sess.add(Project(id=OTHER, org_id=ORG, name="Other", slug=OTHER))
        sess.flush()
        sess.add(Target(id=TARGET, project_id=PROJECT, kind="ml_model_artifact", value="bundled:vehicles_cnn",
                        verified=True, detail={"modality": "image", "status": "available"}))
        sess.add(Target(id=FIXTURE_TARGET, project_id=PROJECT, kind="ml_model_artifact", value="bundled:tiny",
                        verified=True, detail={"modality": "image", "status": "available", "fixture_only": True}))
        sess.flush()
        for run_id, target_id, scanner, status in (
            (RUN, TARGET, "ml.campaign", "succeeded"), (FIXTURE_RUN, FIXTURE_TARGET, "ml.campaign", "succeeded"),
            (RUNNING_RUN, TARGET, "ml.campaign", "running"), (PROBE_RUN, TARGET, "ml.llm_probe", "succeeded"),
            (PLAIN_RUN, TARGET, "ml.ingest", "succeeded"),
        ):
            sess.add(Run(id=run_id, project_id=PROJECT, target_id=target_id, mode="api", scanner=scanner,
                         status=status, stage_table={}, created_by="user:creator"))
        sess.flush()
        for run_id, target_id, rec in ((RUN, TARGET, record), (FIXTURE_RUN, FIXTURE_TARGET, fixture_record),
                                       (RUNNING_RUN, TARGET, record)):
            sess.execute(campaigns.insert().values(
                run_id=run_id, project_id=PROJECT, target_id=target_id, kind="attack", modality="image",
                config=rec["config"], settings_hash=rec["settings_hash"], limitations=[],
            ))
        digest = _store_record(sess, blobs, run_id=RUN, record=record, artifact_id="art-record-live")
        _store_record(sess, blobs, run_id=FIXTURE_RUN, record=fixture_record, artifact_id="art-record-fixture")
        profile = create_auth_profile(sess, project_id=PROJECT, name="foundry-token", kind="bearer",
                                      config={"platform": "foundry"}, secret=DEFAULT_TOKEN, actor="user:seed",
                                      audit_writer=writer)
        form_profile = create_auth_profile(sess, project_id=PROJECT, name="form-login", kind="form",
                                           config={"login_url": "http://127.0.0.1:9/login"}, secret="not-a-key",
                                           actor="user:seed", audit_writer=writer)
        other_profile = create_auth_profile(sess, project_id=OTHER, name="other-token", kind="bearer",
                                            config={}, secret=DEFAULT_TOKEN, actor="user:seed", audit_writer=writer)
        sess.commit()
        profile_id, form_profile_id, other_profile_id = profile.id, form_profile.id, other_profile.id
    writer.events.clear()

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()
    app = create_app(APISettings(env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
                                 rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000))
    holder: dict[str, CurrentUser] = {"user": ADMIN}
    app.dependency_overrides[get_current_user] = lambda: holder["user"]
    client = TestClient(app)

    def call(user: CurrentUser, method: str, path: str, body: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        holder["user"] = user
        if body is not None:
            kwargs["json"] = body
        return client.request(method, path, **kwargs)

    def enable_foundry() -> None:
        monkeypatch.setenv(FOUNDRY_URL_ENV, FOUNDRY_URL)
        monkeypatch.setenv(FOUNDRY_ATTESTATION_ENV, "1")
        monkeypatch.setenv(FOUNDRY_DATASET_RID_ENV, DEFAULT_DATASET_RID)

    yield SimpleNamespace(app=app, client=client, call=call, writer=writer, enqueued=enqueued, blobs=blobs,
                          Session=sqlite_session_factory.Session, engine=sqlite_session_factory.engine,
                          profile_id=profile_id, form_profile_id=form_profile_id, other_profile_id=other_profile_id,
                          record_sha256=digest, enable_foundry=enable_foundry)
    rl._BUCKETS.clear()


def _events(api: SimpleNamespace, action: str) -> list[Any]:
    return [e for e in api.writer.events if e.action == action]


def _detail(resp: Any) -> dict[str, Any]:
    """The 17.3 envelope; ``not_found`` without extra fields keeps the retained routes' plain-string detail."""
    detail = resp.json()["detail"]
    if isinstance(detail, str):
        assert resp.status_code == 404, resp.text
        return {"code": NOT_FOUND, "message": detail}
    assert isinstance(detail, dict), resp.text
    return detail


# --------------------------------------------------------------------------- GET /v1/attacks (INTEROP-20)


def test_attack_catalog_carries_atlas(api: SimpleNamespace) -> None:
    resp = api.call(VIEWER, "GET", "/v1/attacks")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    rows = {row["id"]: row for row in body["attacks"]}
    assert rows["fgsm"]["atlas_technique"]["id"] == "AML.T0043" and rows["pgd"]["atlas_technique"]["id"] == "AML.T0043"
    assert rows["hopskipjump"]["atlas_technique"]["id"] == "AML.T0040"
    assert rows["hopskipjump"]["atlas_technique"]["atlas_version"] == atlas_data.ATLAS_VERSION
    assert rows["noise_control"]["atlas_technique"] is None
    assert rows["noise_control"]["atlas_reason"] == atlas.CONTROL_REASON
    assert body["atlas"]["release"] == atlas_data.ATLAS_RELEASE and body["count"] == len(body["attacks"])
    # The frozen AttackInfo is untouched: the keys are route-level enrichment.
    assert not {f for f in AttackInfo.model_fields if "atlas" in f}


# --------------------------------------------------------------------------- GET /v1/integrations (INTEROP-27, -29)


def test_integrations_roster_is_off_by_default_and_lattice_stays_text(api: SimpleNamespace,
                                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    assert api.call(STRANGER, "GET", "/v1/integrations").status_code == 200   # authenticated, no project scope
    body = api.call(VIEWER, "GET", "/v1/integrations").json()
    foundry = body["integrations"]["foundry"]
    assert foundry["status"] == "disabled" and foundry["host_configured"] is False
    assert FOUNDRY_URL_ENV in foundry["reason"] and foundry["gate"] == "integration.push (admin)"
    lattice = body["integrations"]["lattice"]
    assert lattice["status"] == "not_implemented" and lattice["phase"] == "B" and lattice["reason"] == LATTICE_REASON
    assert "no mission-system connections" in lattice["reason"]
    assert set(body["integrations"]) == {"foundry", "lattice"}
    # Set but unattested: misconfigured by rule, still no value in the response.
    monkeypatch.setenv(FOUNDRY_URL_ENV, FOUNDRY_URL)
    monkeypatch.setenv("REDSIM_FOUNDRY_TOKEN", DEFAULT_TOKEN)
    resp = api.call(VIEWER, "GET", "/v1/integrations")
    assert resp.json()["integrations"]["foundry"]["status"] == "misconfigured"
    assert resp.json()["integrations"]["foundry"]["rule"] == "attestation"
    assert FOUNDRY_URL not in resp.text and "127.0.0.1" not in resp.text and DEFAULT_TOKEN not in resp.text
    # Configured: status strings and booleans only.
    api.enable_foundry()
    resp = api.call(VIEWER, "GET", "/v1/integrations")
    foundry = resp.json()["integrations"]["foundry"]
    assert foundry["status"] == "configured" and foundry["host_configured"] is True
    assert foundry["target_ref_configured"] is True and foundry["attested"] is True
    assert FOUNDRY_URL not in resp.text and "127.0.0.1" not in resp.text and DEFAULT_DATASET_RID not in resp.text
    assert DEFAULT_TOKEN not in resp.text
    assert not any(isinstance(v, str) and "://" in v for v in _walk(resp.json()))
    assert roster(environ={}, allowlist=[])["integrations"]["foundry"]["status"] == "disabled"


# --------------------------------------------------------------------------- GET /v1/runs/{id}/atlas-coverage


def test_atlas_coverage_route(api: SimpleNamespace) -> None:
    resp = api.call(VIEWER, "GET", f"/v1/runs/{RUN}/atlas-coverage")
    assert resp.status_code == 200, resp.text
    view = resp.json()
    assert view["run_id"] == RUN and [r["attack_id"] for r in view["exercised"]] == ["fgsm", "pgd"]
    assert view["declared_not_run"] == []
    assert "hopskipjump" in [r["attack_id"] for r in view["catalog_outside_declared"]]
    assert view["catalog_source"] == "attack registry"
    assert atlas.numeric_paths({k: v for k, v in view.items()}) == []
    assert not ({"mri", "grade", "score"} & set(view))
    assert api.call(STRANGER, "GET", f"/v1/runs/{RUN}/atlas-coverage").status_code == 403
    assert api.call(VIEWER, "GET", "/v1/runs/no-such-run/atlas-coverage").status_code == 404
    plain = api.call(VIEWER, "GET", f"/v1/runs/{PLAIN_RUN}/atlas-coverage")
    assert plain.status_code == 404 and _detail(plain)["code"] == NOT_FOUND
    probe = api.call(VIEWER, "GET", f"/v1/runs/{PROBE_RUN}/atlas-coverage")
    assert probe.status_code == 409 and _detail(probe)["code"] == LLM_TARGET_REQUIRED
    # A record whose bytes no longer match the digest is never served as coverage.
    with api.Session() as sess:
        row = sess.get(Artifact, "art-record-live")
        assert row is not None
        good_sha = row.sha256
        row.sha256 = "0" * 64
        sess.commit()
    tampered = api.call(VIEWER, "GET", f"/v1/runs/{RUN}/atlas-coverage")
    assert tampered.status_code == 409 and _detail(tampered)["reasons"] == ["artifact_digest_mismatch"]
    with api.Session() as sess:
        row = sess.get(Artifact, "art-record-live")
        assert row is not None
        row.sha256 = good_sha
        sess.commit()
    assert api.writer.events == []      # reads write nothing


# --------------------------------------------------------------------------- POST /v1/runs/{id}/integrations/foundry


def test_foundry_push_gates_and_disabled_501(api: SimpleNamespace) -> None:
    body = {"auth_profile_id": api.profile_id}
    assert api.call(VIEWER, "POST", f"/v1/runs/{RUN}/integrations/foundry", body).status_code == 403
    assert api.call(REMEDIATOR, "POST", f"/v1/runs/{RUN}/integrations/foundry", body).status_code == 403
    assert api.call(STRANGER, "POST", f"/v1/runs/{RUN}/integrations/foundry", body).status_code == 403
    assert api.call(ADMIN, "POST", "/v1/runs/no-such-run/integrations/foundry", body).status_code == 404
    assert api.writer.events == [] and api.enqueued == []
    resp = api.call(ADMIN, "POST", f"/v1/runs/{RUN}/integrations/foundry", body)
    assert resp.status_code == 501, resp.text
    detail = _detail(resp)
    assert detail["code"] == INTEGRATION_DISABLED and detail["phase"] == "B" and detail["reason"] == "disabled"
    assert FOUNDRY_URL_ENV in detail["message"]
    rows = _events(api, ADMISSION_ACTION)
    assert len(rows) == 1 and rows[0].success is False and rows[0].run_id == RUN
    assert rows[0].detail["code"] == INTEGRATION_DISABLED and rows[0].detail["integration"] == "foundry"
    _assert_secret_free(rows[0].detail)
    with api.Session() as sess:
        assert sess.execute(select(Run).where(Run.scanner == PUSH_SCANNER)).scalars().all() == []
        assert sess.execute(select(Job).where(Job.type == PUSH_JOB_TYPE)).scalars().all() == []
    assert api.enqueued == []


def test_foundry_push_refusals_write_success_false_rows(api: SimpleNamespace) -> None:
    api.enable_foundry()
    good = {"auth_profile_id": api.profile_id}
    cases: list[tuple[str, dict[str, Any] | None, int, str, str | None]] = [
        (RUN, None, 422, PARAMS_OUT_OF_RANGE, "auth_profile_id"),
        (RUN, {"auth_profile_id": api.profile_id, "unknown": 1}, 422, PARAMS_OUT_OF_RANGE, None),
        (RUN, {"auth_profile_id": api.form_profile_id}, 422, AUTH_PROFILE_KIND_UNSUPPORTED, "auth_profile_id"),
        (RUN, {"auth_profile_id": api.other_profile_id}, 404, NOT_FOUND, "auth_profile_id"),
        (RUN, {"auth_profile_id": "authprof-missing"}, 404, NOT_FOUND, "auth_profile_id"),
        (RUN, {**good, "target_ref": "https://foundry.example.invalid/x"}, 422, PARAMS_OUT_OF_RANGE, "target_ref"),
        (FIXTURE_RUN, good, 422, FIXTURE_NOT_EXPORTABLE, None),
        (RUNNING_RUN, good, 409, CAMPAIGN_NOT_TERMINAL, None),
        (PROBE_RUN, good, 409, LLM_TARGET_REQUIRED, None),
        (PLAIN_RUN, good, 404, NOT_FOUND, None),
    ]
    for run_id, body, status, code, field in cases:
        api.writer.events.clear()
        resp = api.call(ADMIN, "POST", f"/v1/runs/{run_id}/integrations/foundry", body)
        assert resp.status_code == status, (run_id, body, resp.text)
        detail = _detail(resp)
        assert detail["code"] == code, (run_id, body, detail)
        if field is not None:
            assert detail["field"] == field, (run_id, body, detail)
        rows = _events(api, ADMISSION_ACTION)
        if status == 422 and code == PARAMS_OUT_OF_RANGE and field != "target_ref":
            assert rows == []                      # a malformed body never reaches the admission boundary
        else:
            assert len(rows) == 1 and rows[0].success is False and rows[0].run_id == run_id, (run_id, body)
            assert rows[0].detail["code"] == code
            _assert_secret_free(rows[0].detail)
    with api.Session() as sess:
        assert sess.execute(select(Run).where(Run.scanner == PUSH_SCANNER)).scalars().all() == []
    assert api.enqueued == []


def test_foundry_push_admission_audits_then_writes_rows_then_enqueues(api: SimpleNamespace,
                                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    api.enable_foundry()
    seen: dict[str, Any] = {}

    def apply_async(*, args: list[str], queue: str | None = None, **_kw: Any) -> SimpleNamespace:
        # Order (spec 6.7 invariant 4, 21.4): the audit row and the rows exist before Celery is touched.
        rows = _events(api, ADMISSION_ACTION)
        assert len(rows) == 1 and rows[0].success is True
        with api.Session() as sess:
            job = sess.get(Job, args[0])
            assert job is not None and job.status == "queued"
            assert sess.get(Run, job.run_id) is not None
        seen["job_id"], seen["queue"] = args[0], queue
        return SimpleNamespace(id="celery-push-1")

    monkeypatch.setattr(worker.integration_push, "apply_async", apply_async)
    resp = api.call(ADMIN, "POST", f"/v1/runs/{RUN}/integrations/foundry", {"auth_profile_id": api.profile_id})
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["job_ids"] == [seen["job_id"]] and seen["queue"] == "default"
    assert body["integration"] == "foundry" and body["campaign_run_id"] == RUN and body["kind"] == "integration_push"
    assert body["target_ref"] == DEFAULT_DATASET_RID and body["status_url"] == f"/v1/runs/{body['run_id']}"
    assert body["run_id"] != RUN
    with api.Session() as sess:
        run = sess.get(Run, body["run_id"])
        job = sess.get(Job, body["job_ids"][0])
        assert run is not None and run.scanner == PUSH_SCANNER and run.status == "queued"
        assert run.target_id == TARGET and run.stage_table["parent_run_id"] == RUN
        assert job is not None and job.type == PUSH_JOB_TYPE and job.celery_task_id == "celery-push-1"
        detail = dict(job.detail)
        assert detail["run_id"] == RUN and detail["integration"] == "foundry"
        assert detail["target_ref"] == DEFAULT_DATASET_RID and detail["auth_profile_id"] == api.profile_id
        assert detail["host"] == "127.0.0.1" and detail["record_sha256"] == api.record_sha256
        _assert_secret_free(detail)
        # The campaign run itself is untouched: no ml_campaigns row for the push run.
        campaigns = Table("ml_campaigns", MetaData(), autoload_with=api.engine)
        assert {r["run_id"] for r in sess.execute(campaigns.select()).mappings().all()} == {RUN, FIXTURE_RUN,
                                                                                            RUNNING_RUN}
    row = _events(api, ADMISSION_ACTION)[0]
    assert row.target == "127.0.0.1" and row.allowlist_check == "pass" and row.run_id == body["run_id"]
    assert row.detail["campaign_run_id"] == RUN and row.detail["job_id"] == body["job_ids"][0]
    assert row.detail["record_sha256"] == api.record_sha256 and row.detail["host"] == "127.0.0.1"
    _assert_secret_free(row.detail)
    # One push per (run, integration) in flight.
    second = api.call(ADMIN, "POST", f"/v1/runs/{RUN}/integrations/foundry", {"auth_profile_id": api.profile_id})
    assert second.status_code == 409 and _detail(second)["code"] == JOB_IN_FLIGHT
    assert _detail(second)["run_id"] == body["run_id"]
    # The push run reads through the platform route.
    assert api.call(VIEWER, "GET", f"/v1/runs/{body['run_id']}").status_code == 200


def test_foundry_push_broker_refusal_undoes_the_admission(api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
                                                          ) -> None:
    api.enable_foundry()

    def broken(*_a: Any, **_k: Any) -> SimpleNamespace:
        raise ConnectionError("broker down")

    monkeypatch.setattr(worker.integration_push, "apply_async", broken)
    resp = api.call(ADMIN, "POST", f"/v1/runs/{RUN}/integrations/foundry", {"auth_profile_id": api.profile_id})
    assert resp.status_code == 503 and _detail(resp)["code"] == QUEUE_UNAVAILABLE
    with api.Session() as sess:
        assert sess.execute(select(Run).where(Run.scanner == PUSH_SCANNER)).scalars().all() == []
        assert sess.execute(select(Job).where(Job.type == PUSH_JOB_TYPE)).scalars().all() == []


# --------------------------------------------------------------------------- worker harness


class WorkerHarness:
    """File sqlite + filesystem blobs + JSONL audit chains wired into the worker's collaborators."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_jsonb_for_sqlite()
        self.tmp_path = tmp_path
        self.engine = create_engine(f"sqlite:///{tmp_path / 'push.db'}", future=True)
        Base.metadata.create_all(self.engine)
        _campaign_table(self.engine)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.store = FilesystemBlobStore(tmp_path / "blobs")
        self.audit_dir = tmp_path / "audit"
        self.config = RedsimConfig(output_dir=str(tmp_path / "out"), auth_profiles_key=FERNET_KEY)

        @contextmanager
        def get_session() -> Iterator[Session]:
            session = self.sessions()
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

        self.get_session = get_session
        audit_dir = self.audit_dir

        def jsonl_writer(*_a: Any, **_k: Any) -> JsonlAuditWriter:
            return JsonlAuditWriter(audit_dir)

        self.writer = JsonlAuditWriter(audit_dir)
        monkeypatch.delenv("REDSIM_DB_URL", raising=False)
        for name in FOUNDRY_ENV_NAMES:
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("REDSIM_AUTH_PROFILES_KEY", FERNET_KEY)
        monkeypatch.setattr("redsim.db.session.get_session", get_session)
        monkeypatch.setattr("redsim.audit.chain.PostgresAuditWriter", jsonl_writer)
        monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda *_a, **_k: self.writer)
        monkeypatch.setattr("redsim.storage.open_blob_store", lambda *_a, **_k: self.store)
        monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: self.store)
        monkeypatch.setattr("redsim.config.load_config", lambda *_a, **_k: self.config)
        monkeypatch.setattr("redsim.workers.events._redis_client", lambda: None)
        self.monkeypatch = monkeypatch
        self._seed()

    def _seed(self) -> None:
        campaigns = Table("ml_campaigns", MetaData(), autoload_with=self.engine)
        record = _live_record()
        with self.get_session() as session:
            session.add(Organization(id=ORG, name="Org", slug=ORG))
            session.flush()
            session.add(Project(id=PROJECT, org_id=ORG, name="Project", slug=PROJECT))
            session.flush()
            session.add(Target(id=TARGET, project_id=PROJECT, kind="ml_model_artifact", value="bundled:vehicles_cnn",
                               verified=True, detail={"modality": "image", "status": "available"}))
            session.flush()
            session.add(Run(id=RUN, project_id=PROJECT, target_id=TARGET, mode="api", scanner="ml.campaign",
                            status="succeeded", stage_table={}, created_by="user:creator"))
            session.flush()
            session.execute(campaigns.insert().values(
                run_id=RUN, project_id=PROJECT, target_id=TARGET, kind="attack", modality="image",
                config=record["config"], settings_hash=record["settings_hash"], limitations=[],
            ))
            self.record_sha256 = _store_record(session, self.store, run_id=RUN, record=record,
                                               artifact_id="art-record-live")
            profile = create_auth_profile(session, project_id=PROJECT, name="foundry-token", kind="bearer",
                                          config={"platform": "foundry"}, secret=DEFAULT_TOKEN, actor="user:seed",
                                          audit_writer=self.writer)
            self.profile_id = profile.id

    def configure(self, base_url: str, *, dataset_rid: str | None = DEFAULT_DATASET_RID) -> None:
        self.monkeypatch.setenv(FOUNDRY_URL_ENV, base_url)
        self.monkeypatch.setenv(FOUNDRY_ATTESTATION_ENV, "1")
        if dataset_rid is not None:
            self.monkeypatch.setenv(FOUNDRY_DATASET_RID_ENV, dataset_rid)

    def admit(self, **body: Any) -> tuple[str, str]:
        request = FoundryPushRequest(**({"auth_profile_id": self.profile_id} | body))
        handle = create_foundry_push(run_id=RUN, body=request, actor="user:alice", config=self.config,
                                     audit_writer=self.writer, enqueue=False)
        return handle.run_id, handle.job_ids[0]

    @staticmethod
    def run_job(job_id: str) -> Any:
        return worker.integration_push.apply(args=[job_id])

    def events(self, chain: str) -> list[dict[str, Any]]:
        return list(JsonlAuditWriter(self.audit_dir).read_chain(chain))

    def artifacts(self, run_id: str) -> dict[str, Artifact]:
        with self.sessions() as session:
            rows = session.query(Artifact).filter(Artifact.run_id == run_id).all()
            return {row.kind: row for row in rows}

    def blob(self, artifact: Artifact) -> bytes:
        data = self.store.get(str(artifact.location))
        raw = data.encode() if isinstance(data, str) else bytes(data)
        assert hashlib.sha256(raw).hexdigest() == artifact.sha256
        return raw

    def row(self, model: Any, key: str) -> Any:
        with self.sessions() as session:
            return session.get(model, key)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WorkerHarness:
    return WorkerHarness(tmp_path, monkeypatch)


# --------------------------------------------------------------------------- worker (INTEROP-25, -28, -31)


def test_task_declares_the_default_queue_and_no_retries() -> None:
    """The push rides the default pool (the only one with HTTPS egress) and never retries into a fake success."""
    assert worker.integration_push.name == "redsim.integration_push"
    assert worker.integration_push.queue == "default" and worker.integration_push.max_retries == 0
    assert worker.push_artifact_kind("integrations/foundry/scorecard.json") == "ml.integration.payload"
    assert worker.push_artifact_kind("integrations/foundry/receipt.json") == "ml.integration.receipt"


def test_worker_pushes_the_scorecard_and_audits_without_the_token(harness: WorkerHarness) -> None:
    with FakeFoundryServer() as server:
        harness.configure(server.base_url)
        push_run_id, job_id = harness.admit()
        result = harness.run_job(job_id)
        assert result.successful(), result.result
        outcome = result.result
        assert outcome["status"] == "succeeded" and outcome["campaign_run_id"] == RUN
        assert outcome["target_ref"] == DEFAULT_DATASET_RID and outcome["http_statuses"] == [200, 200, 200, 204]

        # The fake saw exactly one transaction: open, two uploads, commit, no abort; the bearer token on each.
        assert [r["step"] for r in server.requests] == ["create", "upload", "upload", "commit"]
        assert all(r["auth_ok"] for r in server.requests) and server.aborted == []
        assert server.committed == [server.transaction_rid]
        assert all(r["dataset_rid"] == DEFAULT_DATASET_RID for r in server.requests)
        paths = [r["file_path"] for r in server.uploads]
        assert paths == [f"redsim/scorecards/{RUN}/scorecard.json", f"redsim/scorecards/{RUN}/rows.jsonl"]
        pushed = server.uploaded_json("scorecard.json")
        assert validate_push_payload(pushed) == [] and pushed["run_id"] == RUN
        assert pushed["scorecard"]["mri"] == 42 and pushed["scorecard"]["grade"] == "D"
        assert pushed["scorecard"]["grade_statement"] == GRADE_STATEMENT
        assert all(row["n"] == 200 and row["n_correct_clean"] == 172 for row in pushed["rows"])
        assert all(set(row["subscores"]) == set(foundry_mod.SUBSCORE_KEYS) for row in pushed["rows"])
        body_text = server.uploads[0]["body"].decode()
        assert DEFAULT_TOKEN not in body_text and not URL_RE.search(body_text) and "pk_" not in body_text
        rows_lines = [json.loads(line) for line in server.uploads[1]["body"].decode().splitlines()]
        assert len(rows_lines) == 6 and all(line["grade_statement"] == GRADE_STATEMENT for line in rows_lines)

    # Rows: job and run succeeded; artifacts carry the payload that left, byte for byte, and the receipt.
    assert harness.row(Job, job_id).status == "succeeded" and harness.row(Run, push_run_id).status == "succeeded"
    artifacts = harness.artifacts(push_run_id)
    assert {"ml.integration.payload", "ml.integration.rows", "ml.integration.receipt"} <= set(artifacts)
    assert harness.blob(artifacts["ml.integration.payload"]) == server.uploads[0]["body"]
    receipt = json.loads(harness.blob(artifacts["ml.integration.receipt"]))
    assert receipt["outcome"] == "pushed" and receipt["n_files"] == 2 and receipt["host"] == "127.0.0.1"
    assert receipt["payload_sha256"] == hashlib.sha256(server.uploads[0]["body"]).hexdigest()
    _assert_secret_free(receipt)
    assert harness.row(Run, RUN).status == "succeeded"          # the campaign run is untouched

    # Audit: the spec 27.4 vocabulary in order on the push run's chain, digests and statuses, never the token.
    events = harness.events(f"run:{push_run_id}")
    assert [e["action"] for e in events] == [ADMISSION_ACTION, EXECUTE_ACTION, "job.complete"]
    assert all(e["success"] for e in events)
    execute = events[1]["detail"]
    assert execute["outcome"] == "pushed" and execute["host"] == "127.0.0.1"
    assert execute["dataset_rid"] == DEFAULT_DATASET_RID and execute["transaction_rid"] == server.transaction_rid
    assert execute["payload_sha256"] == hashlib.sha256(server.uploads[0]["body"]).hexdigest()
    assert execute["rows_sha256"] == hashlib.sha256(server.uploads[1]["body"]).hexdigest()
    assert execute["record_sha256"] == harness.record_sha256 and execute["http_statuses"] == [200, 200, 200, 204]
    assert execute["n_files"] == 2 and execute["campaign_run_id"] == RUN
    assert events[0]["target"] == "127.0.0.1" and events[0]["allowlist_check"] == "pass"
    assert events[0]["actor"] == "user:alice" and events[1]["actor"] == "worker:integration.push"
    assert events[2]["detail"]["status"] == "succeeded" and events[2]["detail"]["n_artifacts"] == 3
    _assert_secret_free(events)
    assert not any(k for e in events for k in e["detail"] if "token" in k.lower() and e["detail"][k] not in
                   (None, "<REDACTED>"))
    assert verify_chain(events).verified
    assert len(events) == 3, "nothing was retried or duplicated"


def test_worker_records_a_foundry_failure_honestly_and_does_not_retry(harness: WorkerHarness) -> None:
    with FakeFoundryServer(fail_at="commit", fail_status=503) as server:
        harness.configure(server.base_url)
        push_run_id, job_id = harness.admit()
        result = harness.run_job(job_id)
        assert result.failed()
        exc = result.result
        assert isinstance(exc, worker.IntegrationPushRefused) and exc.code == "foundry_push_failed"
        assert "commit_transaction" in exc.reason and "503" in exc.reason
        # One attempt per step: open, two uploads, the failing commit, then the abort. No retry loop.
        assert [r["step"] for r in server.requests] == ["create", "upload", "upload", "commit", "abort"]
        assert server.committed == [] and server.aborted == [server.transaction_rid]

    job = harness.row(Job, job_id)
    assert job.status == "failed" and "foundry_push_failed" in str(job.error)
    assert harness.row(Run, push_run_id).status == "failed"
    artifacts = harness.artifacts(push_run_id)
    assert "ml.integration.payload" in artifacts and "ml.integration.receipt" not in artifacts
    events = harness.events(f"run:{push_run_id}")
    assert [(e["action"], e["success"]) for e in events] == [
        (ADMISSION_ACTION, True), (EXECUTE_ACTION, False), ("job.complete", False),
    ]
    execute = events[1]["detail"]
    assert execute["outcome"] == "failed" and execute["reason"] == "foundry_push_failed"
    assert execute["step"] == "commit_transaction" and execute["http_status"] == 503
    assert execute["transaction_aborted"] is True and execute["payload_sha256"]
    assert events[2]["detail"]["error_class"] == "foundry_push_failed"
    _assert_secret_free(events)
    assert verify_chain(events).verified


def test_worker_fails_closed_when_foundry_is_unset_or_the_record_is_a_fixture(harness: WorkerHarness) -> None:
    with FakeFoundryServer() as server:
        harness.configure(server.base_url)
        push_run_id, job_id = harness.admit()
        # The worker's environment lost the URL between admission and pickup: no request, an honest failure.
        harness.monkeypatch.delenv(FOUNDRY_URL_ENV)
        result = harness.run_job(job_id)
        assert result.failed() and result.result.code == "integration_disabled"
        assert server.requests == []
        events = harness.events(f"run:{push_run_id}")
        assert [(e["action"], e["success"]) for e in events] == [
            (ADMISSION_ACTION, True), (EXECUTE_ACTION, False), ("job.complete", False),
        ]
        assert events[1]["detail"]["reason"] == "integration_disabled"
        assert harness.row(Job, job_id).status == "failed"

        # A record that flags itself as a fixture is refused by the worker even after admission (D3).
        harness.configure(server.base_url)
        fixture = _fixture_record()
        fixture["run_id"] = RUN
        with harness.get_session() as session:
            old = session.get(Artifact, "art-record-live")
            assert old is not None
            session.delete(old)
            session.flush()
            _store_record(session, harness.store, run_id=RUN, record=fixture, artifact_id="art-record-fixture")
        push_run_id, job_id = harness.admit()
        result = harness.run_job(job_id)
        assert result.failed() and result.result.code == "fixture_not_exportable"
        assert server.requests == []
        assert harness.events(f"run:{push_run_id}")[1]["detail"]["reason"] == "fixture_not_exportable"
