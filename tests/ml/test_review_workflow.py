"""Phase B review workflow (plan 12 wave B2, review-workflow track).

REVIEW_REPORTS-02 (confirm), -03 (reopen), -04 (resolve gates), -05 (analyst
drafts, submit, request_changes, revisions), -06 (compare-and-set), -07 (list
filter and additive keys), -09 (retest links), -11 (audit rows) and -12
(independence by identity). Offline: a file-backed sqlite harness with the
``ml_campaigns`` table created by hand (the migration owns it), an in-memory blob
store keyed by artifact location, a recording audit writer and FastAPI dependency
overrides for the caller. The baseline campaign is the frozen
``run_record.json`` fixture; the verify records are derived from it.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient
from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text, create_engine
from sqlalchemy.orm import sessionmaker

from redsim.api.app import create_app
from redsim.api.auth import CurrentUser, get_current_user
from redsim.api.settings import APISettings
from redsim.audit.chain import InMemoryAuditWriter
from redsim.db.models import Artifact, Base, Finding, Organization, Project, Run, Target
from redsim.ml.schema import CampaignRecord, FindingReview, FindingVerify, MLFindingDetail
from redsim.services import finding_review as fr
from redsim.services.ml_findings import project_campaign_findings
from redsim.storage.blobs import BlobRef
from tests.conftest import patch_jsonb_for_sqlite

pytestmark = pytest.mark.integration

FIXTURE = Path(__file__).parent / "fixtures" / "run_record.json"
PROJECT = "project-1"
OTHER_PROJECT = "project-2"
BASELINE = "run-fixture-0001"
VERIFY_OK = "run-verify-ok"
VERIFY_DRIFT = "run-verify-drift"
PLAIN = "run-plain"
CREATOR = "user:creator"
REQUESTER = "user:requester"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _campaign_table(engine: Any) -> Table:
    table = Table(
        "ml_campaigns", MetaData(),
        Column("run_id", String, primary_key=True),
        Column("project_id", String, nullable=False),
        Column("org_id", String),
        Column("target_id", String, nullable=False),
        Column("kind", String, nullable=False),
        Column("modality", String, nullable=False),
        Column("config", JSON, nullable=False),
        Column("settings_hash", String),
        Column("provenance", JSON),
        Column("score", JSON),
        Column("limitations", JSON, nullable=False),
        Column("baseline_run_id", String),
        Column("parent_run_id", String),
        Column("reviewer_notes", Text),
        Column("created_at", DateTime),
        Column("completed_at", DateTime),
    )
    table.create(engine)
    return table


class MemoryBlobStore:
    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}

    def put(self, key: str, content: bytes | str, *, content_type: str = "application/octet-stream") -> BlobRef:
        data = content.encode("utf-8") if isinstance(content, str) else content
        self.blobs[key] = data
        return BlobRef(sha256=_sha(data), location=key, size_bytes=len(data), content_type=content_type)

    def get(self, key: str) -> bytes:
        if key not in self.blobs:
            raise FileNotFoundError(key)
        return self.blobs[key]


class UserClient:
    def __init__(self, client: TestClient, holder: dict[str, CurrentUser], user: CurrentUser) -> None:
        self._client, self._holder, self.user = client, holder, user

    def _call(self, method: str, url: str, **kwargs: Any) -> Any:
        self._holder["user"] = self.user
        return getattr(self._client, method)(url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> Any:
        return self._call("get", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> Any:
        return self._call("patch", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self._call("post", url, **kwargs)


class RecordingAuditWriter(InMemoryAuditWriter):
    def __init__(self) -> None:
        super().__init__()
        self.on_append: Any = None

    def append(self, **event: Any) -> Any:
        if self.on_append is not None:
            self.on_append(event)
        return super().append(**event)

    def last(self, action: str) -> Any:
        return next(e for e in reversed(self.events) if e.action == action)

    def rows(self, action: str) -> list[Any]:
        return [e for e in self.events if e.action == action]


def _user(sub: str, role: str, project: str = PROJECT, *, system: bool = False) -> CurrentUser:
    return CurrentUser(sub=sub, email=f"{sub}@example.test", project_memberships={project: role}, is_system=system)


def _records(base: dict[str, Any]) -> dict[str, dict[str, Any]]:
    defense = {"id": "feature_squeezing", "art_class": "art.defences.preprocessor.FeatureSqueezing",
               "params": {"bit_depth": 4}}

    def verify(run_id: str) -> dict[str, Any]:
        rec = copy.deepcopy(base)
        rec.update({"run_id": run_id, "kind": "verify", "baseline_run_id": BASELINE})
        rec["provenance"]["baseline_run_id"] = BASELINE
        rec["config"]["defense"] = defense
        return rec

    ok = verify(VERIFY_OK)
    drift = verify(VERIFY_DRIFT)
    drift["settings_hash"] = "d" * 64
    drift["provenance"]["settings_hash"] = "d" * 64
    drift["score"]["settings_hash"] = "d" * 64
    return {BASELINE: base, VERIFY_OK: ok, VERIFY_DRIFT: drift}


@pytest.fixture
def review_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    patch_jsonb_for_sqlite()
    engine = create_engine(f"sqlite:///{tmp_path / 'review.db'}")
    Base.metadata.create_all(engine)
    campaigns = _campaign_table(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    @contextmanager
    def get_session() -> Any:
        with sessions.begin() as session:
            yield session

    store = MemoryBlobStore()
    base = json.loads(FIXTURE.read_text())
    records = {run_id: CampaignRecord.model_validate(rec) for run_id, rec in _records(base).items()}
    with get_session() as session:
        session.add(Organization(id="org-1", name="Org", slug="org"))
        session.flush()
        session.add_all([Project(id=PROJECT, org_id="org-1", name="P1", slug="p1"),
                         Project(id=OTHER_PROJECT, org_id="org-1", name="P2", slug="p2")])
        session.flush()
        target_id = records[BASELINE].config.target_id
        session.add(Target(id=target_id, project_id=PROJECT, kind="ml_model_artifact", value="bundled:tiny",
                           verified=True, detail={"modality": "image", "status": "available"}))
        session.flush()
        for run_id, record in records.items():
            raw = record.model_dump_json().encode()
            location = f"memory://{PROJECT}/{run_id}/run_record.json/{_sha(raw)}"
            store.blobs[location] = raw
            created_by = REQUESTER if record.kind == "verify" else CREATOR
            session.add(Run(id=run_id, project_id=PROJECT, target_id=record.config.target_id, mode="api",
                            scanner="ml.verify" if record.kind == "verify" else "ml.campaign",
                            status="succeeded", created_by=created_by, stage_table={}))
            session.flush()
            session.add(Artifact(id=f"artifact-{run_id}-record", run_id=run_id, project_id=PROJECT,
                                 kind="ml.run_record", sha256=_sha(raw), location=location,
                                 content_type="application/json", size_bytes=len(raw)))
            session.execute(campaigns.insert().values(
                run_id=run_id, project_id=PROJECT, target_id=record.config.target_id, kind=record.kind,
                modality="image", config=record.config.model_dump(mode="json"),
                settings_hash=record.settings_hash,
                provenance=record.provenance.model_dump(mode="json") if record.provenance else None,
                score=record.score.model_dump(mode="json") if record.score else None,
                limitations=list(record.limitations), baseline_run_id=record.baseline_run_id,
            ))
        session.add(Run(id=PLAIN, project_id=PROJECT, mode="api", status="succeeded", stage_table={},
                        created_by=CREATOR))

    writer = RecordingAuditWriter()
    monkeypatch.setattr("redsim.db.session.get_session", get_session)
    monkeypatch.setattr("redsim.storage.blobs.open_blob_store", lambda *_a, **_k: store)
    monkeypatch.setattr("redsim.audit.chain.resolve_writer", lambda _cfg: writer)
    monkeypatch.setattr("redsim.api.v1.ml_findings.resolve_writer", lambda _cfg: writer)

    import redsim.api.middleware.rate_limit as rl

    rl._BUCKETS.clear()   # the in-memory token buckets are process-global; this file makes many writes
    app = create_app(APISettings(env="dev", auth_mode="dev", cors_origins=["http://localhost:3000"],
                                 rate_limit_per_user_per_min=10_000, rate_limit_per_project_per_min=10_000))
    holder: dict[str, CurrentUser] = {"user": _user("viewer", "viewer")}
    app.dependency_overrides[get_current_user] = lambda: holder["user"]
    client = TestClient(app)

    def as_user(user: CurrentUser) -> UserClient:
        return UserClient(client, holder, user)

    yield {"client": client, "as_user": as_user, "sessions": sessions, "get_session": get_session,
           "campaigns": campaigns, "records": records, "store": store, "writer": writer}
    rl._BUCKETS.clear()


def _project(api: dict[str, Any]) -> dict[str, str]:
    with api["get_session"]() as session:
        ids = project_campaign_findings(session, api["records"][BASELINE])
        return {session.get(Finding, fid).schema_blob["ml"]["attack_id"]: fid for fid in ids}


def _finding(api: dict[str, Any], finding_id: str) -> Finding:
    with api["sessions"]() as session:
        return session.get(Finding, finding_id)


def _review(api: dict[str, Any], finding_id: str) -> FindingReview:
    return MLFindingDetail.model_validate(_finding(api, finding_id).schema_blob["ml"]).review


def _stamp_verify(api: dict[str, Any], finding_id: str, *, run_id: str, outcome: str, settings_hash: str | None,
                  with_delta: bool = True) -> None:
    """What the verify worker writes: the retest link, ``fixed`` / ``poc_passed`` on a verified outcome."""
    record = api["records"][run_id]
    delta = {"baseline_run_id": BASELINE, "mri_before": 42, "mri_after": 55, "delta": 13,
             "delta_subscores": {"S_acc": 10.0, "S_asr": 20.0, "S_eps": 5.0, "S_conf": 0.0, "S_expl": 1.0},
             "delta_acc_clean": {"before": {"n": 200, "n_correct": 172, "accuracy": 0.86},
                                 "after": {"n": 200, "n_correct": 170, "accuracy": 0.85}, "delta": -0.01},
             "delta_families": []}
    link = FindingVerify(run_id=run_id, defense=record.config.defense, outcome=outcome,  # type: ignore[arg-type]
                         delta=delta if with_delta else None,  # type: ignore[arg-type]
                         settings_hash=settings_hash, baseline_run_id=BASELINE)
    with api["get_session"]() as session:
        finding = session.get(Finding, finding_id)
        detail = MLFindingDetail.model_validate(finding.schema_blob["ml"])
        detail.verify = link
        detail.retests = [*detail.retests, link]
        blob = dict(finding.schema_blob)
        blob["ml"] = detail.model_dump(mode="json")
        status = {"verified": "fixed", "still_vulnerable": "failed", "inconclusive": "open"}[outcome]
        state = {"verified": "poc_passed", "still_vulnerable": "poc_failed", "inconclusive": "inconclusive"}[outcome]
        blob["status"] = status
        finding.schema_blob, finding.status, finding.validation_state = blob, status, state
        finding.validated_at = datetime.now(UTC)


# ---------------------------------------------------------------------------
# The transition table as data
# ---------------------------------------------------------------------------


def test_transition_table_shape() -> None:
    assert set(fr.TRANSITIONS) == set(fr.DECISIONS) == {"submit", "confirm", "request_changes", "dismiss",
                                                        "reopen", "resolve"}
    # Confirm, submit, request_changes and resolve never invent a Finding.status.
    for decision in ("submit", "confirm", "request_changes", "resolve"):
        assert fr.TRANSITIONS[decision].to_status is None
    assert fr.TRANSITIONS["dismiss"].to_status == "false_positive"
    assert fr.TRANSITIONS["dismiss"].from_statuses == frozenset({"open", "failed"})
    assert fr.TRANSITIONS["reopen"].to_status == "open"
    assert fr.TRANSITIONS["reopen"].from_statuses == frozenset({"false_positive"})
    assert fr.TRANSITIONS["resolve"].from_review_states == frozenset({"confirmed"})
    assert fr.TRANSITIONS["resolve"].from_statuses == frozenset({"fixed"})
    assert fr.TRANSITIONS["submit"].action == "finding.author" and fr.TRANSITIONS["submit"].author_only
    assert all(t.action == "finding.review" for d, t in fr.TRANSITIONS.items() if d != "submit")
    assert fr.REVIEW_STATES == {"unreviewed", "dismissed", "draft", "in_review", "confirmed", "resolved"}
    assert fr.STATUS_ONLY_DECISIONS == {"dismiss", "reopen"}


def test_independence_is_identity_not_rank() -> None:
    assert fr.independence_violations(actor="user:a", reviewer_is_system=False, campaign_creator="user:a",
                                      revision_author=None) == ["campaign_creator"]
    assert fr.independence_violations(actor="user:a", reviewer_is_system=False, campaign_creator="user:b",
                                      revision_author="user:a") == ["revision_author"]
    assert fr.independence_violations(actor="user:a", reviewer_is_system=False, campaign_creator="user:b",
                                      revision_author="user:c", verify_requesters=["user:a"]) == ["verify_requester"]
    assert fr.independence_violations(actor="user:a", reviewer_is_system=True, campaign_creator="user:a",
                                      revision_author="user:a") == ["system_principal", "campaign_creator",
                                                                    "revision_author"]
    assert fr.independence_violations(actor="user:z", reviewer_is_system=False, campaign_creator="user:a",
                                      revision_author="user:b", verify_requesters=["user:c"]) == []


def test_review_state_readers_tolerate_every_blob_shape() -> None:
    assert fr.review_state_of(None) is None
    assert fr.review_state_of({"id": "strix-001"}) is None
    assert fr.review_summary({"id": "strix-001"}) is None
    llm_blob = {"llm": {"probe_id": "p", "review": {"state": "confirmed", "reviewer": "user:r"}}}
    assert fr.review_state_of(llm_blob) == "confirmed"
    assert fr.review_summary(llm_blob)["reviewer"] == "user:r"
    assert fr.review_state_of({"llm": {"probe_id": "p"}}) == "unreviewed"
    assert fr.review_state_of({"ml": {"not": "a detail"}}) is None
    assert fr.manual_finding_type() in {"adversarial_ml_manual", "adversarial_ml"}


# ---------------------------------------------------------------------------
# Confirm, dismiss, reopen: roles, independence, compare-and-set, audit, history
# ---------------------------------------------------------------------------


def test_confirm_dismiss_reopen_matrix(review_api: dict[str, Any]) -> None:
    findings = _project(review_api)
    fid = findings["fgsm"]
    writer: RecordingAuditWriter = review_api["writer"]
    status_path = f"/v1/findings/{fid}/status"
    confirm = {"decision": "confirm", "expected_status": "open", "reason": "the flipped samples are genuine"}

    # Role gate before anything: no chain row for a viewer or a scanner.
    assert review_api["as_user"](_user("reader", "viewer")).patch(status_path, json=confirm).status_code == 403
    assert review_api["as_user"](_user("runner", "scanner")).patch(status_path, json=confirm).status_code == 403
    assert review_api["as_user"](_user("fixer", "remediator")).patch(status_path, json=confirm).status_code == 403
    assert writer.rows("finding.review") == []

    # Independence by identity: the campaign creator is refused even as admin, with a refused row.
    creator = review_api["as_user"](_user("creator", "admin")).patch(status_path, json=confirm)
    assert creator.status_code == 403, creator.text
    assert creator.json()["detail"]["code"] == "reviewer_not_independent"
    assert creator.json()["detail"]["relation"] == "campaign_creator"
    refused = writer.last("finding.review")
    assert refused.success is False and refused.detail["refusal"] == "reviewer_not_independent"
    assert refused.detail["decision"] == "confirm" and refused.detail["campaign_creator"] == CREATOR
    assert refused.detail["independence_violations"] == ["campaign_creator"]
    assert _finding(review_api, fid).status == "open" and _review(review_api, fid).state == "unreviewed"

    system = review_api["as_user"](_user("worker", "admin", system=True)).patch(status_path, json=confirm)
    assert system.status_code == 403 and system.json()["detail"]["relation"] == "system_principal"
    assert writer.last("finding.review").success is False

    reviewer = review_api["as_user"](_user("reviewer", "approver"))

    # Compare-and-set (REVIEW_REPORTS-06): stale status and stale review state are 409s with the current state.
    stale = reviewer.patch(status_path, json={**confirm, "expected_status": "fixed"})
    assert stale.status_code == 409 and stale.json()["detail"]["code"] == "review_state_conflict"
    assert stale.json()["detail"]["status"] == "open" and stale.json()["detail"]["review_state"] == "unreviewed"
    assert writer.last("finding.review").detail["refusal"] == "review_state_conflict"
    stale_review = reviewer.patch(status_path, json={**confirm, "expected_review_state": "in_review"})
    assert stale_review.status_code == 409 and stale_review.json()["detail"]["code"] == "review_state_conflict"
    assert stale_review.json()["detail"]["expected_review_state"] == "in_review"
    assert reviewer.patch(status_path, json={**confirm, "expected_review_state": "bogus"}).status_code == 422

    # resolve is never reachable from an unconfirmed, unverified finding: every unmet condition is named.
    blocked = reviewer.post(f"/v1/findings/{fid}/review/resolve",
                            json={"expected_status": "open", "reason": "closing"})
    assert blocked.status_code == 409 and blocked.json()["detail"]["code"] == "resolution_blocked"
    assert blocked.json()["detail"]["unmet"] == ["validation_state_not_poc_passed", "status_not_fixed",
                                                 "review_state_not_confirmed", "no_retest_linked"]
    assert writer.last("finding.review").detail["unmet"] == blocked.json()["detail"]["unmet"]

    # Audit before the write: when the success row is appended the finding is still unreviewed.
    def _still_unreviewed(event: dict[str, Any]) -> None:
        if event["action"] == "finding.review" and event["success"]:
            assert _review(review_api, fid).state == "unreviewed"

    writer.on_append = _still_unreviewed
    ok = reviewer.patch(status_path, json={**confirm, "expected_review_state": "unreviewed"})
    writer.on_append = None
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["status"] == "open" and body["review_state"] == "confirmed"
    assert body["from_status"] == "open" and body["from_review_state"] == "unreviewed"
    assert body["review"]["reviewer"] == "user:reviewer" and body["review"]["state"] == "confirmed"
    event = writer.last("finding.review")
    assert event.success is True and event.run_id == BASELINE and event.project_id == PROJECT
    for key, value in {"decision": "confirm", "from_status": "open", "to_status": "open",
                       "from_review_state": "unreviewed", "to_review_state": "confirmed",
                       "reviewer": "user:reviewer", "campaign_creator": CREATOR, "author": None,
                       "reason": confirm["reason"], "finding_id": fid, "verify_run_id": None}.items():
        assert event.detail[key] == value, key
    # ``confirmed`` keeps Finding.status = open (spec 6.4): no invented status value.
    row = _finding(review_api, fid)
    assert row.status == "open" and row.schema_blob["status"] == "open"
    review = _review(review_api, fid)
    assert review.state == "confirmed" and len(review.history) == 1
    assert review.history[0].action == "confirm" and review.history[0].from_state == "unreviewed"
    assert review.history[0].to_state == "confirmed" and review.history[0].actor == "user:reviewer"

    # Confirming twice is a transition error, not a conflict.
    again = reviewer.post(f"/v1/findings/{fid}/review/confirm",
                          json={"expected_status": "open", "reason": "again"})
    assert again.status_code == 409 and again.json()["detail"]["code"] == "review_transition_invalid"
    assert again.json()["detail"]["allowed_from_review_states"] == ["in_review", "unreviewed"]
    assert again.json()["detail"]["review_state"] == "confirmed"
    assert writer.last("finding.review").detail["refusal"] == "review_transition_invalid"
    # request_changes needs an in_review draft.
    rc = reviewer.post(f"/v1/findings/{fid}/review/request_changes",
                       json={"expected_status": "open", "reason": "tighten"})
    assert rc.status_code == 409 and rc.json()["detail"]["code"] == "review_transition_invalid"
    assert reviewer.post(f"/v1/findings/{fid}/review/nonsense",
                         json={"expected_status": "open", "reason": "x"}).status_code == 404

    # The findings list carries review_state and filters on it (REVIEW_REPORTS-07).
    listed = reviewer.get("/v1/findings", params={"review_state": "confirmed"}).json()
    assert [f["id"] for f in listed["findings"]] == [fid] and listed["count"] == 1
    assert listed["findings"][0]["review_state"] == "confirmed"
    assert listed["findings"][0]["review"]["reviewer"] == "user:reviewer"
    assert listed["findings"][0]["review"]["n_history"] == 1
    unreviewed = reviewer.get("/v1/findings", params={"review_state": "unreviewed"}).json()
    assert [f["id"] for f in unreviewed["findings"]] == [findings["pgd"]]
    assert reviewer.get("/v1/findings", params={"review_state": "approved"}).status_code == 422
    assert reviewer.get("/v1/findings", params={"status": "open"}).json()["count"] == 2
    assert reviewer.get("/v1/findings", params={"source_tool": "redsim.ml/pgd"}).json()["count"] == 1
    detail = reviewer.get(f"/v1/findings/{fid}").json()
    assert detail["review_state"] == "confirmed" and detail["validated_at"] is None
    assert detail["review"]["state"] == "confirmed" and detail["review"]["revision"] is None
    outsider = review_api["as_user"](_user("outsider", "admin", project=OTHER_PROJECT))
    assert outsider.get(f"/v1/findings/{fid}").status_code == 403
    assert outsider.get("/v1/findings").json()["count"] == 0

    # Dismissal keeps the Phase A rules and appends to the same history.
    dismiss = {"status": "false_positive", "expected_status": "open", "reason": "fixture slice only"}
    creator_dismiss = review_api["as_user"](_user("creator", "approver")).patch(status_path, json=dismiss)
    assert creator_dismiss.status_code == 403 and "creator" in creator_dismiss.json()["detail"]
    assert writer.last("finding.review").detail["refusal"] == "forbidden"
    assert reviewer.patch(status_path, json={**dismiss, "decision": "confirm"}).status_code == 422
    assert reviewer.patch(status_path, json={"expected_status": "open", "reason": "no decision"}).status_code == 422
    dismissed = reviewer.patch(status_path, json=dismiss)
    assert dismissed.status_code == 200 and dismissed.json()["status"] == "false_positive"
    assert dismissed.json()["review_state"] == "dismissed" and dismissed.json()["decision"] == "dismiss"
    review = _review(review_api, fid)
    assert review.state == "dismissed" and [h.action for h in review.history] == ["confirm", "dismiss"]
    assert writer.last("finding.review").detail["to_status"] == "false_positive"
    assert writer.last("finding.review").detail["from_review_state"] == "confirmed"
    terminal = reviewer.patch(status_path, json={**dismiss, "expected_status": "false_positive"})
    assert terminal.status_code == 409 and terminal.json()["detail"]["code"] == "run_terminal"
    assert terminal.json()["detail"]["allowed_from"] == ["failed", "open"]

    # Reopen (REVIEW_REPORTS-03): false_positive -> open, review back to unreviewed, history kept.
    reopen = {"status": "open", "expected_status": "false_positive", "reason": "new evidence in the gallery"}
    creator_reopen = review_api["as_user"](_user("creator", "approver")).patch(status_path, json=reopen)
    assert creator_reopen.status_code == 403
    assert creator_reopen.json()["detail"]["code"] == "reviewer_not_independent"
    reopened = reviewer.patch(status_path, json=reopen)
    assert reopened.status_code == 200, reopened.text
    assert reopened.json()["status"] == "open" and reopened.json()["review_state"] == "unreviewed"
    assert reopened.json()["from_status"] == "false_positive"
    row = _finding(review_api, fid)
    assert row.status == "open" and row.schema_blob["status"] == "open"
    review = _review(review_api, fid)
    assert review.state == "unreviewed" and review.reviewer == "user:reviewer"
    assert [h.action for h in review.history] == ["confirm", "dismiss", "reopen"]
    assert review.history[1].to_state == "dismissed"     # the dismissal stays on record
    event = writer.last("finding.review")
    assert event.detail["decision"] == "reopen" and event.detail["from_status"] == "false_positive"
    assert event.detail["to_status"] == "open" and event.detail["to_review_state"] == "unreviewed"
    # Reopening an open finding is a transition error.
    not_dismissed = reviewer.post(f"/v1/findings/{fid}/review/reopen",
                                  json={"expected_status": "open", "reason": "x"})
    assert not_dismissed.status_code == 409 and not_dismissed.json()["detail"]["code"] == "review_transition_invalid"
    assert not_dismissed.json()["detail"]["allowed_from"] == ["false_positive"]

    # The body-decision form (spec 17.4 shape) drives the same table.
    body_form = reviewer.post(f"/v1/findings/{fid}/review",
                              json={"decision": "confirm", "expected_status": "open", "reason": "confirmed again"})
    assert body_form.status_code == 200 and body_form.json()["review_state"] == "confirmed"
    assert [h.action for h in _review(review_api, fid).history] == ["confirm", "dismiss", "reopen", "confirm"]

    # Every successful row on the chain precedes its write and every refusal is a success=False row.
    rows = writer.rows("finding.review")
    assert [r.success for r in rows].count(True) == 4
    assert all(r.run_id == BASELINE and r.project_id == PROJECT for r in rows)
    assert all("refusal" in r.detail and "message" in r.detail for r in rows if not r.success)
    assert reviewer.post("/v1/findings/nope/review/confirm",
                         json={"expected_status": "open", "reason": "x"}).status_code == 404


def test_dismiss_from_failed_and_confirm_from_fixed(review_api: dict[str, Any]) -> None:
    findings = _project(review_api)
    reviewer = review_api["as_user"](_user("reviewer", "approver"))
    pgd = findings["pgd"]
    _stamp_verify(review_api, pgd, run_id=VERIFY_OK, outcome="still_vulnerable", settings_hash=None)
    assert _finding(review_api, pgd).status == "failed"
    confirmed = reviewer.post(f"/v1/findings/{pgd}/review/confirm",
                              json={"expected_status": "failed", "reason": "still flips after squeezing"})
    assert confirmed.status_code == 200 and confirmed.json()["status"] == "failed"
    dismissed = reviewer.patch(f"/v1/findings/{pgd}/status",
                               json={"status": "false_positive", "expected_status": "failed", "reason": "noise"})
    assert dismissed.status_code == 200 and dismissed.json()["status"] == "false_positive"
    assert [h.action for h in _review(review_api, pgd).history] == ["confirm", "dismiss"]

    fgsm = findings["fgsm"]
    _stamp_verify(review_api, fgsm, run_id=VERIFY_OK, outcome="verified", settings_hash=None)
    assert _finding(review_api, fgsm).status == "fixed"
    # ``fixed`` may be confirmed (spec 6.4) but never dismissed.
    refused = reviewer.patch(f"/v1/findings/{fgsm}/status",
                             json={"status": "false_positive", "expected_status": "fixed", "reason": "no"})
    assert refused.status_code == 409 and refused.json()["detail"]["code"] == "run_terminal"
    ok = reviewer.post(f"/v1/findings/{fgsm}/review/confirm", json={"expected_status": "fixed", "reason": "ok"})
    assert ok.status_code == 200 and ok.json()["status"] == "fixed" and ok.json()["review_state"] == "confirmed"


# ---------------------------------------------------------------------------
# Resolve (REVIEW_REPORTS-04) and retest links (REVIEW_REPORTS-09)
# ---------------------------------------------------------------------------


def test_resolve_gates_and_retest_links(review_api: dict[str, Any]) -> None:
    findings = _project(review_api)
    fid = findings["fgsm"]
    writer: RecordingAuditWriter = review_api["writer"]
    reviewer = review_api["as_user"](_user("reviewer", "approver"))
    path = f"/v1/findings/{fid}/review/resolve"

    assert reviewer.post(f"/v1/findings/{fid}/review/confirm",
                         json={"expected_status": "open", "reason": "genuine"}).status_code == 200

    # A retest whose settings differ from the baseline is linked but not comparable.
    _stamp_verify(review_api, fid, run_id=VERIFY_DRIFT, outcome="verified", settings_hash="d" * 64)
    row = _finding(review_api, fid)
    assert row.status == "fixed" and row.validation_state == "poc_passed"
    drift = reviewer.post(path, json={"expected_status": "fixed", "reason": "resolved"})
    assert drift.status_code == 409 and drift.json()["detail"]["code"] == "resolution_blocked"
    assert drift.json()["detail"]["unmet"] == ["settings_hash_mismatch"]
    assert drift.json()["detail"]["verify_run_id"] == VERIFY_DRIFT
    refused = writer.last("finding.review")
    assert refused.success is False and refused.detail["unmet"] == ["settings_hash_mismatch"]
    assert refused.detail["verify_run_id"] == VERIFY_DRIFT and refused.detail["verify_requesters"] == [REQUESTER]
    assert _review(review_api, fid).state == "confirmed"

    retests = reviewer.get(f"/v1/findings/{fid}/retests").json()
    assert retests["count"] == 1 and retests["baseline_run_id"] == BASELINE
    assert retests["baseline_settings_hash"] == review_api["records"][BASELINE].settings_hash
    link = retests["retests"][0]
    assert link["run_id"] == VERIFY_DRIFT and link["compatible"] is False
    assert link["mismatched"] == ["settings_hash"] and link["delta_mri"] is None and link["delta"] is None
    assert link["outcome"] == "verified" and link["requested_by"] == REQUESTER and link["run_status"] == "succeeded"
    assert link["defense"]["id"] == "feature_squeezing"

    # A comparable retest: same settings_hash as the baseline campaign.
    _stamp_verify(review_api, fid, run_id=VERIFY_OK, outcome="verified",
                  settings_hash=review_api["records"][BASELINE].settings_hash)
    retests = reviewer.get(f"/v1/findings/{fid}/retests").json()
    assert retests["count"] == 2 and retests["retests"][1]["compatible"] is True
    assert retests["retests"][1]["delta_mri"] == 13 and retests["retests"][1]["mismatched"] == []
    assert review_api["as_user"](_user("reader", "viewer")).get(f"/v1/findings/{fid}/retests").status_code == 200
    assert review_api["as_user"](_user("outsider", "admin", project=OTHER_PROJECT)).get(
        f"/v1/findings/{fid}/retests").status_code == 403

    # Independence for resolve: the retest requester and the campaign creator are refused (403), admin or not.
    requester = review_api["as_user"](_user("requester", "admin")).post(
        path, json={"expected_status": "fixed", "reason": "resolved"})
    assert requester.status_code == 403 and requester.json()["detail"]["relation"] == "verify_requester"
    assert writer.last("finding.review").detail["independence_violations"] == ["verify_requester"]
    creator = review_api["as_user"](_user("creator", "admin")).post(
        path, json={"expected_status": "fixed", "reason": "resolved"})
    assert creator.status_code == 403 and creator.json()["detail"]["relation"] == "campaign_creator"
    assert _review(review_api, fid).state == "confirmed"

    # Stale expectation on resolve is a conflict.
    stale = reviewer.post(path, json={"expected_status": "open", "reason": "resolved"})
    assert stale.status_code == 409 and stale.json()["detail"]["code"] == "review_state_conflict"

    def _still_confirmed(event: dict[str, Any]) -> None:
        if event["action"] == "finding.review" and event["success"]:
            assert _review(review_api, fid).state == "confirmed"

    writer.on_append = _still_confirmed
    ok = reviewer.post(path, json={"expected_status": "fixed", "expected_review_state": "confirmed",
                                   "reason": "measured delta at equal settings"})
    writer.on_append = None
    assert ok.status_code == 200, ok.text
    assert ok.json()["review_state"] == "resolved" and ok.json()["status"] == "fixed"
    assert ok.json()["verify_run_id"] == VERIFY_OK
    row = _finding(review_api, fid)
    assert row.status == "fixed" and row.validation_state == "poc_passed"      # status stays the worker's
    review = _review(review_api, fid)
    assert review.state == "resolved" and review.history[-1].verify_run_id == VERIFY_OK
    assert [h.action for h in review.history] == ["confirm", "resolve"]
    event = writer.last("finding.review")
    assert event.success is True and event.detail["decision"] == "resolve"
    assert event.detail["verify_run_id"] == VERIFY_OK and event.detail["to_review_state"] == "resolved"
    assert event.detail["from_status"] == "fixed" and event.detail["to_status"] == "fixed"
    listed = reviewer.get("/v1/findings", params={"review_state": "resolved"}).json()
    assert [f["id"] for f in listed["findings"]] == [fid]

    # Resolved is terminal for the table: no second resolve, no confirm, no dismiss.
    again = reviewer.post(path, json={"expected_status": "fixed", "reason": "again"})
    assert again.status_code == 409 and again.json()["detail"]["code"] == "resolution_blocked"
    assert again.json()["detail"]["unmet"] == ["review_state_not_confirmed"]
    confirm = reviewer.post(f"/v1/findings/{fid}/review/confirm", json={"expected_status": "fixed", "reason": "x"})
    assert confirm.status_code == 409 and confirm.json()["detail"]["code"] == "review_transition_invalid"


def test_resolve_needs_a_verified_retest(review_api: dict[str, Any]) -> None:
    findings = _project(review_api)
    fid = findings["pgd"]
    reviewer = review_api["as_user"](_user("reviewer", "approver"))
    assert reviewer.post(f"/v1/findings/{fid}/review/confirm",
                         json={"expected_status": "open", "reason": "genuine"}).status_code == 200
    # An inconclusive retest leaves open / inconclusive: three unmet conditions, no delta in the listing.
    _stamp_verify(review_api, fid, run_id=VERIFY_OK, outcome="inconclusive", with_delta=False,
                  settings_hash=review_api["records"][BASELINE].settings_hash)
    blocked = reviewer.post(f"/v1/findings/{fid}/review/resolve", json={"expected_status": "open", "reason": "r"})
    assert blocked.status_code == 409
    assert blocked.json()["detail"]["unmet"] == ["validation_state_not_poc_passed", "status_not_fixed",
                                                 "retest_outcome_not_verified"]
    link = reviewer.get(f"/v1/findings/{fid}/retests").json()["retests"][0]
    assert link["compatible"] is True and link["delta_mri"] is None and link["outcome"] == "inconclusive"


# ---------------------------------------------------------------------------
# Analyst-authored drafts (REVIEW_REPORTS-05) with submit and request_changes
# ---------------------------------------------------------------------------


def test_analyst_draft_lifecycle(review_api: dict[str, Any]) -> None:
    writer: RecordingAuditWriter = review_api["writer"]
    analyst = review_api["as_user"](_user("analyst", "remediator"))
    reviewer = review_api["as_user"](_user("reviewer", "approver"))
    draft = {
        "run_id": BASELINE, "attack_id": "fgsm", "title": "FGSM flips low-contrast vehicles", "severity": "medium",
        "observation": "The flipped samples cluster on low-contrast inputs.",
        "interpretation": "Contrast normalisation may be the weak point.",
        "candidate": "Evaluate feature squeezing at bit depth 4.",
        "evidence_ids": ["m.evasion.fgsm.eps0.03", "o.000", "m.clean"],
    }

    # Gate FINDING_AUTHOR (remediator): viewer and scanner refused before any row.
    assert review_api["as_user"](_user("reader", "viewer")).post("/v1/findings", json=draft).status_code == 403
    assert review_api["as_user"](_user("runner", "scanner")).post("/v1/findings", json=draft).status_code == 403
    assert writer.rows("finding.author") == []
    assert analyst.post("/v1/findings", json={**draft, "run_id": "missing"}).status_code == 404
    plain = analyst.post("/v1/findings", json={**draft, "run_id": PLAIN})
    assert plain.status_code == 404 and writer.last("finding.author").success is False

    # Evidence ids must exist in the digest-checked run record; the refusal is on the chain.
    unknown = analyst.post("/v1/findings", json={**draft, "evidence_ids": ["m.evasion.fgsm.eps0.03", "m.nope"]})
    assert unknown.status_code == 422 and unknown.json()["detail"]["code"] == "params_out_of_range"
    assert unknown.json()["detail"]["field"] == "evidence_ids" and unknown.json()["detail"]["reasons"] == ["m.nope"]
    refused = writer.last("finding.author")
    assert refused.success is False and refused.detail["refusal"] == "params_out_of_range"
    assert refused.detail["op"] == "create" and refused.detail["author"] == "user:analyst"
    wrong_attack = analyst.post("/v1/findings", json={**draft, "attack_id": "hopskipjump"})
    assert wrong_attack.status_code == 422 and wrong_attack.json()["detail"]["field"] == "attack_id"
    assert analyst.post("/v1/findings", json={**draft, "evidence_ids": []}).status_code == 422
    system = review_api["as_user"](_user("worker", "admin", system=True)).post("/v1/findings", json=draft)
    assert system.status_code == 403
    # A tampered record is never cited.
    store = review_api["store"]
    location = next(k for k in store.blobs if f"/{BASELINE}/run_record.json/" in k)
    original = store.blobs[location]
    store.blobs[location] = b"tampered"
    tampered = analyst.post("/v1/findings", json=draft)
    assert tampered.status_code == 409 and tampered.json()["detail"]["reasons"] == ["artifact_digest_mismatch"]
    store.blobs[location] = original
    with review_api["get_session"]() as session:
        assert session.query(Finding).count() == 0

    def _no_row_yet(event: dict[str, Any]) -> None:
        if event["action"] == "finding.author" and event["success"]:
            with review_api["sessions"]() as session:
                assert session.query(Finding).count() == 0

    writer.on_append = _no_row_yet
    created = analyst.post("/v1/findings", json=draft)
    writer.on_append = None
    assert created.status_code == 201, created.text
    body = created.json()
    fid = body["id"]
    assert body["review_state"] == "draft" and body["revision"] == 1 and body["status"] == "open"
    assert body["finding_type"] == fr.manual_finding_type() and body["severity"] == "medium"
    blob = body["schema_blob"]
    assert blob["source_tool"] == "manual" and blob["source_run_id"] == BASELINE and blob["confidence"] == "low"
    assert blob["title"] == draft["title"] and blob["status"] == "open"
    assert blob["description"].startswith("Analyst-authored draft (revision 1, author user:analyst)")
    assert "[m.evasion.fgsm.eps0.03]" in blob["description"] and "not derived from measurements" in blob["description"]
    assert blob["remediation_steps"] == "CANDIDATE (not evaluated): Evaluate feature squeezing at bit depth 4."
    assert blob["artifact_path"] == f"artifact-{BASELINE}-record"
    assert json.loads(blob["evidence"]) == {"interpretation": [], "measurements": ["m.clean", "m.evasion.fgsm.eps0.03"],
                                            "observations": ["o.000"]}
    detail = MLFindingDetail.model_validate(blob["ml"])
    assert detail.attack_id == "fgsm" and detail.attack_name == "FGSM" and detail.norm == "linf"
    assert {m.id for m in detail.measurements} == {"m.clean", "m.evasion.fgsm.eps0.03"}
    assert [o.id for o in detail.observations] == ["o.000"]
    assert detail.review.state == "draft" and detail.review.notes and "not derived" in detail.review.notes
    assert len(detail.review.revisions) == 1
    rev = detail.review.revisions[0]
    assert rev.author == "user:analyst" and rev.submitted_at is None and rev.sha256 is None
    assert rev.evidence_ids == draft["evidence_ids"] and rev.observation == draft["observation"]
    assert detail.limitations[-1].startswith("Analyst-authored draft")
    row = _finding(review_api, fid)
    assert row.source_tool == "manual" and row.validation_state == "unvalidated" and row.severity == "medium"
    assert row.scanner_finding_id.startswith("manual.fgsm.") and row.dedup_key.startswith(f"manual:{BASELINE}:fgsm:")
    event = writer.last("finding.author")
    assert event.success is True and event.run_id == BASELINE and event.project_id == PROJECT
    assert event.detail["op"] == "create" and event.detail["author"] == "user:analyst"
    assert event.detail["evidence_ids"] == draft["evidence_ids"] and event.detail["n_evidence"] == 3
    assert event.detail["revision"] == 1 and event.detail["scanner_finding_id"] == row.scanner_finding_id
    assert event.detail["title_sha256"] == _sha(draft["title"].encode())
    assert event.detail["revision_sha256"] == fr.revision_digest(
        observation=draft["observation"], interpretation=draft["interpretation"], candidate=draft["candidate"],
        evidence_ids=draft["evidence_ids"])
    # The audit detail carries ids and digests, never the analyst's text.
    assert "low-contrast" not in json.dumps(event.detail) and draft["title"] not in json.dumps(event.detail)

    listed = reviewer.get("/v1/findings", params={"review_state": "draft"}).json()
    assert [f["id"] for f in listed["findings"]] == [fid] and listed["findings"][0]["review"]["revision"] == 1
    assert reviewer.get("/v1/findings", params={"source_tool": "manual"}).json()["count"] == 1

    # A draft cannot be confirmed before it is submitted; a viewer cannot submit at all.
    early = reviewer.post(f"/v1/findings/{fid}/review/confirm", json={"expected_status": "open", "reason": "x"})
    assert early.status_code == 409 and early.json()["detail"]["code"] == "review_transition_invalid"
    assert early.json()["detail"]["review_state"] == "draft"
    submit = {"expected_status": "open", "reason": "ready for review"}
    assert review_api["as_user"](_user("reader", "viewer")).post(
        f"/v1/findings/{fid}/review/submit", json=submit).status_code == 403
    other = review_api["as_user"](_user("other", "remediator")).post(f"/v1/findings/{fid}/review/submit", json=submit)
    assert other.status_code == 403 and "author" in other.json()["detail"]
    assert writer.last("finding.author").success is False
    assert writer.last("finding.author").detail["refusal"] == "forbidden"
    submitted = analyst.post(f"/v1/findings/{fid}/review/submit", json=submit)
    assert submitted.status_code == 200, submitted.text
    assert submitted.json()["review_state"] == "in_review" and submitted.json()["status"] == "open"
    review = _review(review_api, fid)
    assert review.state == "in_review" and review.reviewer is None
    frozen = review.revisions[0]
    assert frozen.submitted_at is not None
    assert frozen.sha256 == event.detail["revision_sha256"]
    assert [h.action for h in review.history] == ["submit"] and review.history[0].revision == 1
    assert review.history[0].actor == "user:analyst" and review.history[0].from_state == "draft"
    event = writer.last("finding.author")
    assert event.success is True and event.detail["decision"] == "submit" and event.detail["author"] == "user:analyst"
    assert event.detail["from_review_state"] == "draft" and event.detail["to_review_state"] == "in_review"
    # Submitting twice, or revising a submitted revision, is refused.
    twice = analyst.post(f"/v1/findings/{fid}/review/submit", json=submit)
    assert twice.status_code == 409 and twice.json()["detail"]["code"] == "review_transition_invalid"
    locked = analyst.patch(f"/v1/findings/{fid}/draft", json={"observation": "edited after submit"})
    assert locked.status_code == 409 and locked.json()["detail"]["code"] == "review_transition_invalid"
    assert _review(review_api, fid).revisions[0].observation == draft["observation"]

    # The author cannot review their own revision, whatever their role (spec 7.7 Phase B bullet).
    self_review = review_api["as_user"](_user("analyst", "admin")).post(
        f"/v1/findings/{fid}/review/confirm", json={"expected_status": "open", "reason": "looks right"})
    assert self_review.status_code == 403 and self_review.json()["detail"]["relation"] == "revision_author"
    assert writer.last("finding.review").detail["author"] == "user:analyst"
    # Request changes: back to draft with a new editable revision carrying the texts.
    changes = reviewer.post(f"/v1/findings/{fid}/review/request_changes",
                            json={"expected_status": "open", "expected_review_state": "in_review",
                                  "reason": "cite the control row too"})
    assert changes.status_code == 200, changes.text
    assert changes.json()["review_state"] == "draft" and changes.json()["revision"] == 2
    review = _review(review_api, fid)
    assert review.state == "draft" and len(review.revisions) == 2
    assert review.revisions[0].sha256 == frozen.sha256                 # the judged revision is immutable
    assert review.revisions[1].author == "user:analyst" and review.revisions[1].submitted_at is None
    assert review.revisions[1].observation == draft["observation"]
    assert [h.action for h in review.history] == ["submit", "request_changes"]
    assert review.history[-1].revision == 1 and review.history[-1].reason == "cite the control row too"
    event = writer.last("finding.review")
    assert event.detail["decision"] == "request_changes" and event.detail["revision"] == 1
    assert event.detail["to_review_state"] == "draft"

    # Revise (author only, draft only): a third revision with new evidence and text.
    revision = {"observation": "The flipped samples cluster on low-contrast inputs; the noise control does not.",
                "evidence_ids": ["m.evasion.fgsm.eps0.03", "m.control.noise.eps0.03", "o.000"]}
    stranger = review_api["as_user"](_user("other", "remediator")).patch(f"/v1/findings/{fid}/draft", json=revision)
    assert stranger.status_code == 403 and writer.last("finding.author").success is False
    bad = analyst.patch(f"/v1/findings/{fid}/draft", json={"evidence_ids": ["m.nope"]})
    assert bad.status_code == 422 and bad.json()["detail"]["reasons"] == ["m.nope"]
    revised = analyst.patch(f"/v1/findings/{fid}/draft", json=revision)
    assert revised.status_code == 200, revised.text
    assert revised.json()["revision"] == 3 and revised.json()["review_state"] == "draft"
    row = _finding(review_api, fid)
    detail = MLFindingDetail.model_validate(row.schema_blob["ml"])
    assert len(detail.review.revisions) == 3 and detail.review.revisions[2].evidence_ids == revision["evidence_ids"]
    assert detail.review.revisions[2].interpretation == draft["interpretation"]    # carried over
    assert {m.id for m in detail.measurements} == {"m.evasion.fgsm.eps0.03", "m.control.noise.eps0.03"}
    assert row.schema_blob["description"].startswith("Analyst-authored draft (revision 3")
    assert "[m.control.noise.eps0.03]" in row.schema_blob["description"]
    event = writer.last("finding.author")
    assert event.success is True and event.detail["op"] == "revise" and event.detail["new_revision"] == 3
    assert "low-contrast" not in json.dumps(event.detail)

    # Submit the revision, confirm as the independent reviewer: Finding.status stays open throughout.
    assert analyst.post(f"/v1/findings/{fid}/review/submit", json=submit).status_code == 200
    review = _review(review_api, fid)
    assert review.revisions[2].sha256 is not None and review.revisions[1].sha256 is None
    confirmed = reviewer.post(f"/v1/findings/{fid}/review/confirm",
                              json={"expected_status": "open", "expected_review_state": "in_review",
                                    "reason": "evidence cited and read"})
    assert confirmed.status_code == 200 and confirmed.json()["review_state"] == "confirmed"
    assert confirmed.json()["status"] == "open" and confirmed.json()["revision"] == 3
    review = _review(review_api, fid)
    assert [h.action for h in review.history] == ["submit", "request_changes", "submit", "confirm"]
    assert review.history[-1].revision == 3 and review.reviewer == "user:reviewer"
    assert _finding(review_api, fid).status == "open"
    assert writer.last("finding.review").detail["revision"] == 3

    # The verify route treats the draft as an ML finding but drafts have no measured threshold crossing:
    # resolve stays blocked until the worker writes poc_passed and fixed.
    blocked = reviewer.post(f"/v1/findings/{fid}/review/resolve", json={"expected_status": "open", "reason": "x"})
    assert blocked.status_code == 409 and "no_retest_linked" in blocked.json()["detail"]["unmet"]


# ---------------------------------------------------------------------------
# Findings without a review block: status-level decisions only
# ---------------------------------------------------------------------------


def test_status_only_decisions_for_findings_without_review_block(review_api: dict[str, Any]) -> None:
    fid = "plain-finding"
    with review_api["get_session"]() as session:
        session.add(Finding(id=fid, scanner_finding_id="strix-001", run_id=PLAIN, project_id=PROJECT,
                            schema_blob={"id": "strix-001", "status": "open"}, status="open", severity="high",
                            source_tool="strix", validation_state="unvalidated"))
    reviewer = review_api["as_user"](_user("reviewer", "approver"))
    writer: RecordingAuditWriter = review_api["writer"]
    assert reviewer.get(f"/v1/findings/{fid}").json()["review_state"] is None
    assert reviewer.get("/v1/findings", params={"review_state": "unreviewed"}).json()["count"] == 0
    assert reviewer.get("/v1/findings").json()["count"] == 1

    confirm = reviewer.post(f"/v1/findings/{fid}/review/confirm", json={"expected_status": "open", "reason": "x"})
    assert confirm.status_code == 409 and confirm.json()["detail"]["code"] == "review_transition_invalid"
    assert writer.last("finding.review").success is False
    dismissed = reviewer.patch(f"/v1/findings/{fid}/status",
                               json={"status": "false_positive", "expected_status": "open", "reason": "dup"})
    assert dismissed.status_code == 200 and dismissed.json()["status"] == "false_positive"
    assert dismissed.json()["review"] is None and dismissed.json()["review_state"] is None
    row = _finding(review_api, fid)
    assert row.status == "false_positive" and row.schema_blob["status"] == "false_positive"
    assert "ml" not in row.schema_blob and "llm" not in row.schema_blob
    reopened = reviewer.patch(f"/v1/findings/{fid}/status",
                              json={"status": "open", "expected_status": "false_positive", "reason": "not a dup"})
    assert reopened.status_code == 200 and _finding(review_api, fid).status == "open"
    assert writer.last("finding.review").detail["decision"] == "reopen"
    assert reviewer.get(f"/v1/findings/{fid}/retests").json() == {
        "finding_id": fid, "baseline_run_id": PLAIN, "baseline_settings_hash": None, "validation_state": "unvalidated",
        "status": "open", "review_state": None, "retests": [], "count": 0}


def test_llm_findings_review_block_is_honoured(review_api: dict[str, Any]) -> None:
    """An LLM probe finding keeps its FindingReview at ``schema_blob.llm.review``; the table applies."""
    fid = "llm-finding"
    with review_api["get_session"]() as session:
        session.add(Finding(id=fid, scanner_finding_id="llm.dan.mitigation", run_id=BASELINE, project_id=PROJECT,
                            schema_blob={"id": "llm.dan.mitigation", "status": "open",
                                         "llm": {"probe_id": "dan", "hit_rate": 1.0, "review": {"state": "unreviewed"}}},
                            status="open", severity="high", source_tool="redsim.ml/llm_probe",
                            validation_state="unvalidated"))
    reviewer = review_api["as_user"](_user("reviewer", "approver"))
    assert reviewer.get(f"/v1/findings/{fid}").json()["review_state"] == "unreviewed"
    confirmed = reviewer.post(f"/v1/findings/{fid}/review/confirm",
                              json={"expected_status": "open", "reason": "the hits are real refusals"})
    assert confirmed.status_code == 200 and confirmed.json()["review_state"] == "confirmed"
    row = _finding(review_api, fid)
    assert row.status == "open" and row.schema_blob["llm"]["probe_id"] == "dan"
    review = FindingReview.model_validate(row.schema_blob["llm"]["review"])
    assert review.state == "confirmed" and [h.action for h in review.history] == ["confirm"]
    # No retest can ever be linked to an LLM finding, so resolve stays blocked and no MRI enters it.
    blocked = reviewer.post(f"/v1/findings/{fid}/review/resolve", json={"expected_status": "open", "reason": "x"})
    assert blocked.status_code == 409 and "no_retest_linked" in blocked.json()["detail"]["unmet"]
    assert reviewer.get("/v1/findings", params={"review_state": "confirmed"}).json()["count"] == 1
