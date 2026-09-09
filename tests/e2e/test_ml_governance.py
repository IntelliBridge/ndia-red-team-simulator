"""Governance end-to-end tests: RBAC, row-level security, the audit trail, honest capabilities.

Spec sections 7 (roles and the independent-approval rule), 21 (security and
trust), 26.4 (boundaries) and 26.5 (audit and governance), on the shared
harness of ``tests/e2e/conftest.py`` / ``tests/e2e/harness.py``. Every test
drives the production path it names and asserts on what that path left behind:

1. ``test_rbac_negatives``: every mutating ML route refuses the roles spec 7.3
   denies with ``403`` (the viewer everywhere, the scanner where remediator or
   approver is required, the campaign creator on a dismissal, the other
   organisation's admin and a member of nothing), a gate refusal writes no
   audit row and no ``Run``, and the lowest allowed role succeeds on the same
   route.
2. ``test_audit_verify_all_and_tamper``: ``redsim audit verify --all`` (the real
   CLI, a subprocess) is clean after a completed campaign; the run chain carries
   the spec 10.5 vocabulary in emission order behind the admission row; the
   rows carry no gateway key, no dataset credential and no model bytes; one
   mutated event breaks the verify naming the chain and the sequence number;
   restoring the event verifies again.
3. ``test_capabilities_and_unsupported_paths``: ``GET /v1/ml/capabilities``
   never carries the Pythia key or base URL (mock on and off), the endpoint
   connector and ``report.pdf`` are ``501 not_implemented`` with a ``phase``,
   and the catalog routes answer ``503 ml_catalog_unavailable`` instead of an
   empty ``200`` when a registry cannot be imported.
4. ``test_rls_hides_other_orgs_scores`` (``integration`` + ``e2e``): against the
   Postgres named by ``REDSIM_E2E_POSTGRES_URL``, migrated inside the test with
   the platform's own runner (``alembic upgrade head``, idempotent), two
   organisations with a campaign row each: a session scoped to the other
   organisation (the tenant GUC set the way ``tests/test_tenant_rls.py`` sets
   it, on a non-superuser role so the policies bind) reads nothing from
   ``ml_campaigns`` / ``findings`` / ``artifacts`` / ``runs``, and the real API
   over that database answers ``404`` to the other organisation and ``200`` to
   the owner. Skips with a reason when the URL is unset or the database is
   unreachable.

Run::

    REDSIM_E2E=1 pytest -q -p no:cacheprovider -m e2e tests/e2e/test_ml_governance.py
    REDSIM_E2E=1 REDSIM_E2E_POSTGRES_URL=postgresql://redsim:redsim@localhost:5433/redsim \\
        pytest -q -p no:cacheprovider -m e2e tests/e2e/test_ml_governance.py

The campaigns are tabular (``url_trees``: PGD by surrogate transfer plus
HopSkipJump with the benign control), because the harness image CNN is
degenerate (4 of 12 clean-correct, ASR 0.0 at every budget). Neither harness
model can produce a worker-projected finding: the URL evaluation split is 12
rows of which the ensemble gets 9 right, below ``MIN_CLEAN_CORRECT_FOR_FINDING``
(10, spec 12.6). The finding routes therefore get a *gate subject*: one
``Finding`` row per campaign projected with the product's own
``finding_inputs`` / ``build_finding_detail`` from the real measured rows,
labelled as seeded below the denominator floor. It is never a result.

The harness fixtures are not edited here; every extra helper lives in this file.
Heavy imports happen inside the tests, after the session fixtures have checked
the extras, so collection stays green without them.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest

from tests.e2e import harness as h

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi.testclient import TestClient

    from tests.e2e.harness import E2EApp, E2EOrg, PythiaToggle

pytestmark = pytest.mark.e2e

def campaign_job_vocabulary(attack_ids: list[str]) -> list[str]:
    """The spec 10.5 rows one whole-campaign ``attack.run`` job emits, in order, behind the admission row."""
    return ["model.load", *(f"attack.execute.{attack_id}" for attack_id in attack_ids), "explain.execute",
            "campaign.score", "harden.execute", "report.render", "job.complete"]

#: A dataset credential planted in the worker's environment for the campaign; it must never reach a row.
KAGGLE_SENTINEL = f"kaggle-e2e-sentinel-{uuid4().hex}"

#: The non-superuser, non-owner role the RLS lane drops to (same name as ``tests/test_tenant_rls.py``).
RLS_ROLE = "redsim_rls_test"

#: Environment the migration subprocess inherits (no ``REDSIM_*``, no credentials beyond the URL it is given).
_MIGRATE_SAFE_ENV_KEYS = (
    "PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE", "TERM",
    "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "SYSTEMROOT",
)

_ALEMBIC_INI = h.REPO_ROOT / "alembic.ini"
_MIGRATIONS_DIR = h.REPO_ROOT / "redsim" / "db" / "migrations"


# ---------------------------------------------------------------------------
# Helpers (read-only views over the harness database, small assertion aids)
# ---------------------------------------------------------------------------


def _governance_config(**overrides: Any) -> dict[str, Any]:
    """The harness tabular campaign (PGD by surrogate + HopSkipJump + control) with a low finding threshold.

    ``finding_asr_threshold`` is a campaign configuration value (spec 5.6). The
    low threshold lets an attack cross it on the tiny URL ensemble so the seeded
    gate subject (:func:`_seed_gate_finding`) can be projected from real rows.
    Nothing measured on the harness assets is a demo result.
    """
    return h.tabular_campaign(finding_asr_threshold=0.05, explain_k=1, **overrides)


def _total_audit_events(e2e_app: E2EApp) -> int:
    return sum(len(e2e_app.read_chain(chain_id)) for chain_id in e2e_app.chain_ids())


def _count_runs(e2e_app: E2EApp) -> int:
    from sqlalchemy import func, select

    from redsim.db.models import Run

    with e2e_app.session() as sess:
        return int(sess.execute(select(func.count()).select_from(Run)).scalar() or 0)


def _events(e2e_app: E2EApp, chain_id: str, action: str) -> list[dict[str, Any]]:
    return [ev for ev in e2e_app.read_chain(chain_id) if ev["action"] == action]


def _detail_code(response: Any) -> str | None:
    try:
        detail = response.json().get("detail")
    except ValueError:
        return None
    return str(detail.get("code")) if isinstance(detail, dict) else None


def _expect_forbidden(responses: dict[str, Any]) -> None:
    """Every response is a ``403``; the failure message lists each role and route that was not."""
    wrong = {
        label: (response.status_code, response.text[:160])
        for label, response in responses.items()
        if response.status_code != 403
    }
    assert not wrong, f"spec 7.3 denies these callers; the routes answered:\n{json.dumps(wrong, indent=2)}"


def _seed_gate_finding(e2e_app: E2EApp, run: h.CampaignRun) -> str:
    """One ``Finding`` row on a completed campaign, projected from its real measurements, as a gate subject.

    The worker projects a finding only when an attack crosses
    ``finding_asr_threshold`` **and** ``n_clean_correct >= MIN_CLEAN_CORRECT_FOR_FINDING``
    (spec 12.6). On the harness URL split (12 rows, 9 clean-correct) the floor
    is never met, so no campaign here carries a worker finding. When the
    completed run already carries one (a larger split in some future harness)
    that finding is used and nothing is seeded. Otherwise the attack that did
    cross the threshold is projected with the product's own ``finding_inputs``
    and ``build_finding_detail`` (every number measured, none invented), the
    row says in its title that it sits below the denominator floor and comes
    from this file, and it is used only as the subject of the finding-route
    gates. It never reaches a report.
    """
    from redsim.db.models import Finding
    from redsim.ml.schema import CampaignRecord
    from redsim.ml.scoring import MIN_CLEAN_CORRECT_FOR_FINDING, finding_inputs
    from redsim.services.ml_findings import build_finding_detail

    for finding in run.findings:
        if finding.get("status") == "open":
            return str(finding["id"])
    assert run.campaign is not None
    record = CampaignRecord.model_validate(
        {key: value for key, value in run.campaign.items() if key in CampaignRecord.model_fields}
    )
    crossing = [
        (attack_id, inputs) for attack_id in record.config.attack_ids
        for inputs in (finding_inputs(record.config, record.measurements, attack_id),)
        if inputs.crosses_threshold
    ]
    if not crossing:
        pytest.fail(
            f"run {run.run_id}: no attack crossed finding_asr_threshold={record.config.finding_asr_threshold} on "
            "the harness assets, so there is nothing to project as a gate subject. measurements="
            f"{[(m.family, m.attack_id, m.attack_success_rate) for m in record.measurements]!r}"
        )
    attack_id, inputs = crossing[0]
    assert not inputs.denominator_ok, (
        f"{attack_id} crossed the threshold with n_clean_correct={inputs.n_clean_correct} >= "
        f"{MIN_CLEAN_CORRECT_FOR_FINDING}, yet the worker projected no finding for run {run.run_id}"
    )
    detail = build_finding_detail(record, attack_id, inputs)
    severity = inputs.severity or "low"
    title = (
        f"e2e governance gate subject: {attack_id} crossed asr >= {inputs.threshold:g} "
        f"(first success eps={inputs.first_success_eps:g}) but n_clean_correct={inputs.n_clean_correct} is below "
        f"the floor of {MIN_CLEAN_CORRECT_FOR_FINDING}; projected by tests/e2e/test_ml_governance.py, not a product finding"
    )
    blob = {
        "id": f"e2e-gate.{attack_id}", "title": title, "severity": severity, "finding_type": "adversarial_ml",
        "description": title, "source_tool": "tests/e2e/test_ml_governance.py", "source_run_id": run.run_id,
        "status": "open", "confidence": inputs.confidence, "ml": detail.model_dump(mode="json"),
    }
    with e2e_app.session() as sess:
        row = Finding(
            id=str(uuid4()), scanner_finding_id=f"e2e-gate.{attack_id}", run_id=run.run_id,
            project_id=str(run.campaign["project_id"]), schema_blob=blob, status="open", severity=severity,
            source_tool="tests/e2e/test_ml_governance.py", validation_state="unvalidated",
        )
        sess.add(row)
        sess.flush()
        return str(row.id)


def _strings(value: Any) -> Iterator[str]:
    """Every string leaf of a JSON-like value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _seed_queued_run(e2e_app: E2EApp, *, project_id: str, target_id: str, actor: str) -> str:
    """A ``queued`` campaign Run with one ``queued`` ``attack.run`` Job.

    The harness worker is eager, so no API-launched run is ever observed queued;
    a run that is still waiting for a worker is the state ``POST /v1/runs/{id}/cancel``
    exists for (spec 10.7). Seeded directly, no audit row, no campaign record.
    """
    from redsim.db.models import Job, Run

    run_id = f"run-e2e-gov-{uuid4().hex[:12]}"
    job_id = f"job-e2e-gov-{uuid4().hex[:12]}"
    with e2e_app.session() as sess:
        sess.add(Run(id=run_id, project_id=project_id, target_id=target_id, mode="api", status="queued",
                     scanner="ml.campaign", created_by=actor, stage_table={"stage": None, "jobs": {}}))
        sess.flush()
        sess.add(Job(id=job_id, run_id=run_id, project_id=project_id, type="attack.run", status="queued",
                     created_by=actor, detail={"seeded_by": "tests/e2e/test_ml_governance.py"}))
        sess.flush()
    return run_id


def _registered_ids(client: TestClient, *, project_id: str, bundled_id: str) -> list[str]:
    """Per-project ``Target`` ids of ``bundled_id`` registered in ``project_id`` (as the caller sees it)."""
    response = client.get("/v1/models", params={"project": project_id})
    assert response.status_code == 200, response.text
    return [str(row["id"]) for row in response.json()["models"]
            if row.get("registered") and row.get("bundled_id") == bundled_id]


def _untamper_audit_event(e2e_app: E2EApp, chain_id: str, seq: int) -> None:
    """Undo the harness tamper (it adds ``detail.tampered``) so the chain hashes as it was written.

    ``canonical_json`` sorts keys, so removing the added key restores the hashed
    bytes exactly. Possible on sqlite only: on Postgres the append-only trigger
    of migration 0004 refuses the UPDATE, which is the property under test there.
    """
    from sqlalchemy import select

    from redsim.db.models import AuditEvent

    with e2e_app.session() as sess:
        row = sess.execute(
            select(AuditEvent).where(AuditEvent.chain_id == chain_id, AuditEvent.seq == seq)
        ).scalar_one()
        detail = dict(row.detail or {})
        detail.pop("tampered", None)
        row.detail = detail
        sess.flush()


# ---------------------------------------------------------------------------
# Two completed campaigns, launched by different roles
# ---------------------------------------------------------------------------


@dataclass
class Campaigns:
    """The campaigns the governance tests share (module-scoped; both succeeded)."""

    #: Launched by the ``scanner`` (the lowest role ``attack.run`` admits) with ``llm_narrative`` under
    #: the mocked gateway and a dataset-credential sentinel in the environment.
    scanner: h.CampaignRun
    #: Launched by the ``admin``: the campaign creator for the independence rule of spec 7.7.
    admin: h.CampaignRun
    #: One gate-subject finding per campaign (see :func:`_seed_gate_finding`).
    scanner_finding: str
    admin_finding: str


@pytest.fixture(scope="module")
def campaigns(e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], pythia: PythiaToggle) -> Campaigns:
    model_id = e2e_bundled[h.TABULAR_MODEL_ID]
    patch = pytest.MonkeyPatch()
    # A dataset credential the worker parent could see; the chain must never carry it.
    patch.setenv("KAGGLE_API_TOKEN", KAGGLE_SENTINEL)
    try:
        with pythia:
            scanner_run = h.run_campaign_via_api(
                e2e_org.client("scanner"), model_id, _governance_config(llm_narrative=True),
            )
        admin_run = h.run_campaign_via_api(e2e_org.client("admin"), model_id, _governance_config())
    finally:
        patch.undo()
    for who, run in (("scanner", scanner_run), ("admin", admin_run)):
        assert run.status == "succeeded", f"{who}'s run {run.run_id}: {run.run.get('stage_table')}"
        assert run.campaign is not None, run.campaign_error
        assert run.campaign["status"] == "succeeded"
    return Campaigns(scanner=scanner_run, admin=admin_run,
                     scanner_finding=_seed_gate_finding(e2e_app, scanner_run),
                     admin_finding=_seed_gate_finding(e2e_app, admin_run))


# ---------------------------------------------------------------------------
# 1. RBAC negatives on every mutating ML route
# ---------------------------------------------------------------------------


def test_rbac_negatives(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], campaigns: Campaigns,
) -> None:
    from redsim.api.errors import NOT_FOUND, RUN_TERMINAL, SCORE_UNAVAILABLE

    model_id = e2e_bundled[h.IMAGE_MODEL_ID]
    tabular_id = e2e_bundled[h.TABULAR_MODEL_ID]
    viewer, scanner, remediator = e2e_org.client("viewer"), e2e_org.client("scanner"), e2e_org.client("remediator")
    approver, admin = e2e_org.client("approver"), e2e_org.client("admin")
    outsider, stranger = e2e_org.client(h.OUTSIDER), e2e_org.client(h.STRANGER)
    scanner_run, admin_run = campaigns.scanner, campaigns.admin
    scanner_finding, admin_finding = campaigns.scanner_finding, campaigns.admin_finding

    # -- phase 0: subjects for the delete and cancel gates ---------------------------------------
    # The other organisation's admin registers a bundled model into its own project (model.register,
    # allowed at remediator and above), after removing any registration a sibling test left there.
    for stale in _registered_ids(outsider, project_id=e2e_org.other_project_id, bundled_id=h.TABULAR_MODEL_ID):
        assert outsider.delete(f"/v1/models/{stale}").status_code == 200
    registered = outsider.post("/v1/models", json={
        "source": "bundled", "bundled_id": h.TABULAR_MODEL_ID, "project_id": e2e_org.other_project_id,
    })
    assert registered.status_code == 201, registered.text
    other_model_id = str(registered.json()["id"])
    assert registered.json()["project_id"] == e2e_org.other_project_id and other_model_id != tabular_id
    queued_run_id = _seed_queued_run(e2e_app, project_id=e2e_org.project_id, target_id=model_id,
                                     actor=e2e_org.actor("scanner"))
    events_before, runs_before = _total_audit_events(e2e_app), _count_runs(e2e_app)

    # -- phase 1: every denied caller is a 403 and nothing is written -----------------------------
    register_body = {"source": "bundled", "bundled_id": h.TABULAR_MODEL_ID, "project_id": e2e_org.project_id}
    review_body = {"status": "false_positive", "expected_status": "open", "reason": "e2e governance check"}
    notes_body = {"reviewer_notes": "e2e governance check"}
    denied: dict[str, Any] = {
        # model.register: remediator and above (spec 7.4)
        "viewer POST /v1/models": viewer.post("/v1/models", json=register_body),
        "scanner POST /v1/models": scanner.post("/v1/models", json=register_body),
        "stranger POST /v1/models": stranger.post("/v1/models", json=register_body),
        "outsider POST /v1/models (other org)": outsider.post("/v1/models", json=register_body),
        # attack.run: scanner and above
        "viewer POST /models/{id}/attacks": viewer.post(f"/v1/models/{model_id}/attacks", json=_governance_config()),
        "stranger POST /models/{id}/attacks": stranger.post(f"/v1/models/{model_id}/attacks",
                                                            json=_governance_config()),
        "outsider POST /models/{id}/attacks": outsider.post(f"/v1/models/{model_id}/attacks",
                                                            json=_governance_config()),
        # target.manage: admin only (spec 7.3 "Delete a model target")
        "viewer DELETE /models/{id}": viewer.delete(f"/v1/models/{tabular_id}"),
        "scanner DELETE /models/{id}": scanner.delete(f"/v1/models/{tabular_id}"),
        "remediator DELETE /models/{id}": remediator.delete(f"/v1/models/{tabular_id}"),
        "approver DELETE /models/{id}": approver.delete(f"/v1/models/{tabular_id}"),
        "stranger DELETE /models/{id}": stranger.delete(f"/v1/models/{tabular_id}"),
        "outsider DELETE /models/{id} (other org)": outsider.delete(f"/v1/models/{tabular_id}"),
        "admin DELETE /models/{id} of the other org": admin.delete(f"/v1/models/{other_model_id}"),
        # explain.run: scanner and above
        "viewer POST /findings/{id}/explain": viewer.post(f"/v1/findings/{scanner_finding}/explain", json={}),
        "stranger POST /findings/{id}/explain": stranger.post(f"/v1/findings/{scanner_finding}/explain", json={}),
        "outsider POST /findings/{id}/explain": outsider.post(f"/v1/findings/{scanner_finding}/explain", json={}),
        # harden.recommend: remediator and above
        "viewer POST /findings/{id}/harden": viewer.post(f"/v1/findings/{scanner_finding}/harden",
                                                         json={"llm_narrative": False}),
        "scanner POST /findings/{id}/harden": scanner.post(f"/v1/findings/{scanner_finding}/harden",
                                                           json={"llm_narrative": False}),
        # verify.replay: remediator and above
        "viewer POST /findings/{id}/verify": viewer.post(f"/v1/findings/{scanner_finding}/verify", json={}),
        "scanner POST /findings/{id}/verify": scanner.post(f"/v1/findings/{scanner_finding}/verify", json={}),
        "outsider POST /findings/{id}/verify": outsider.post(f"/v1/findings/{scanner_finding}/verify", json={}),
        # finding.review: approver and above, plus the independence rule (below)
        "viewer PATCH /findings/{id}/status": viewer.patch(f"/v1/findings/{admin_finding}/status", json=review_body),
        "scanner PATCH /findings/{id}/status": scanner.patch(f"/v1/findings/{admin_finding}/status",
                                                             json=review_body),
        "remediator PATCH /findings/{id}/status": remediator.patch(f"/v1/findings/{admin_finding}/status",
                                                                   json=review_body),
        "stranger PATCH /findings/{id}/status": stranger.patch(f"/v1/findings/{admin_finding}/status",
                                                               json=review_body),
        "outsider PATCH /findings/{id}/status": outsider.patch(f"/v1/findings/{admin_finding}/status",
                                                               json=review_body),
        # finding.annotate: remediator and above
        "viewer PATCH /runs/{id}/reviewer-notes": viewer.patch(f"/v1/runs/{scanner_run.run_id}/reviewer-notes",
                                                               json=notes_body),
        "scanner PATCH /runs/{id}/reviewer-notes": scanner.patch(f"/v1/runs/{scanner_run.run_id}/reviewer-notes",
                                                                 json=notes_body),
        "stranger PATCH /runs/{id}/reviewer-notes": stranger.patch(f"/v1/runs/{scanner_run.run_id}/reviewer-notes",
                                                                   json=notes_body),
        "outsider PATCH /runs/{id}/reviewer-notes": outsider.patch(f"/v1/runs/{scanner_run.run_id}/reviewer-notes",
                                                                   json=notes_body),
        # run.cancel: remediator and above
        "viewer POST /runs/{id}/cancel": viewer.post(f"/v1/runs/{queued_run_id}/cancel"),
        "scanner POST /runs/{id}/cancel": scanner.post(f"/v1/runs/{queued_run_id}/cancel"),
        "stranger POST /runs/{id}/cancel": stranger.post(f"/v1/runs/{queued_run_id}/cancel"),
        "outsider POST /runs/{id}/cancel": outsider.post(f"/v1/runs/{queued_run_id}/cancel"),
        # report.export: scanner and above (the viewer export gap of spec 7.3 is closed)
        "viewer GET /runs/{id}/report.md": viewer.get(f"/v1/runs/{scanner_run.run_id}/report.md"),
        "stranger GET /runs/{id}/report.md": stranger.get(f"/v1/runs/{scanner_run.run_id}/report.md"),
        "outsider GET /runs/{id}/report.md": outsider.get(f"/v1/runs/{scanner_run.run_id}/report.md"),
        # audit.verify: admin only (spec 7.3 "Browse audit chain")
        "viewer GET /audit/verify?run=": viewer.get("/v1/audit/verify", params={"run": scanner_run.run_id}),
        "scanner GET /audit/verify?run=": scanner.get("/v1/audit/verify", params={"run": scanner_run.run_id}),
        "approver GET /audit/verify?run=": approver.get("/v1/audit/verify", params={"run": scanner_run.run_id}),
    }
    _expect_forbidden(denied)
    for label, response in denied.items():
        # A 403 is a plain string detail (spec 17.3 ``forbidden``), never a typed ML refusal and never
        # a leak of the resource: it does not carry a run, finding or model id of the other project.
        assert isinstance(response.json()["detail"], str), label
    # Role gates sit in front of the admission services: no audit row and no Run was written.
    assert _total_audit_events(e2e_app) == events_before, "a role refusal must not append to any chain (spec 7.8)"
    assert _count_runs(e2e_app) == runs_before
    # The queued run and the shared models are untouched by the refused deletes and cancels.
    assert admin.get(f"/v1/runs/{queued_run_id}").json()["status"] == "queued"
    assert viewer.get(f"/v1/models/{tabular_id}").status_code == 200
    assert outsider.get(f"/v1/models/{other_model_id}").status_code == 200

    # -- phase 2: the allowed role succeeds on the same routes ------------------------------------
    # attack.run (scanner): the module campaign was launched by the scanner and completed.
    assert scanner_run.launch["run_id"] == scanner_run.run_id and scanner_run.launch["job_ids"]
    assert scanner_run.status == "succeeded"
    admission = _events(e2e_app, f"run:{scanner_run.run_id}", "attack.run")
    assert admission and admission[0]["actor"] == e2e_org.actor("scanner") and admission[0]["success"] is True

    # target.manage (admin of the owning project): the other org's admin deletes what it registered.
    deleted = outsider.delete(f"/v1/models/{other_model_id}")
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["deleted"] == other_model_id and deleted.json()["status"] == "deleted"
    # ``?project=`` is passed because the deleted-row fallback of ``get_model`` otherwise checks membership
    # on the literal project ``default`` and answers 403 (redsim/api/v1/models.py, ``get_model``).
    gone = outsider.get(f"/v1/models/{other_model_id}", params={"project": e2e_org.other_project_id})
    assert gone.status_code == 404, gone.text
    assert isinstance(gone.json()["detail"], str), f"{NOT_FOUND} keeps the retained string detail (spec 17.3)"
    manage = _events(e2e_app, f"project:{e2e_org.other_project_id}", "target.manage")
    assert manage and manage[-1]["detail"].get("target_id") == other_model_id
    assert manage[-1]["actor"] == e2e_org.actor(h.OUTSIDER)

    # run.cancel (remediator): the queued run is cancelled; a terminal run is a typed 409, not a 403.
    cancelled = remediator.post(f"/v1/runs/{queued_run_id}/cancel")
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json() == {"run_id": queued_run_id, "status": "cancelled", "jobs_cancelled": 1}
    assert admin.get(f"/v1/runs/{queued_run_id}").json()["status"] == "cancelled"
    cancel_rows = _events(e2e_app, f"run:{queued_run_id}", "run.cancel")
    assert cancel_rows and cancel_rows[-1]["success"] is True and cancel_rows[-1]["actor"] == e2e_org.actor("remediator")
    terminal = remediator.post(f"/v1/runs/{admin_run.run_id}/cancel")
    assert terminal.status_code == 409, terminal.text
    assert _detail_code(terminal) == RUN_TERMINAL and terminal.json()["detail"]["status"] == "succeeded"
    refused_cancel = _events(e2e_app, f"run:{admin_run.run_id}", "run.cancel")
    assert refused_cancel and refused_cancel[-1]["success"] is False
    assert refused_cancel[-1]["detail"]["reason"] == RUN_TERMINAL

    # report.export (scanner): the rendered markdown report of the scanner's own campaign.
    report = scanner.get(f"/v1/runs/{scanner_run.run_id}/report.md")
    assert report.status_code == 200, report.text[:200]
    assert report.headers["content-type"].startswith("text/markdown")
    assert report.headers.get("x-content-type-options") == "nosniff"
    assert report.headers.get("etag"), "the report is served with its digest as the ETag"
    assert len(report.content) > 0

    # audit.verify (admin): the campaign chain verifies through the API as well as the CLI.
    verified = admin.get("/v1/audit/verify", params={"run": scanner_run.run_id})
    assert verified.status_code == 200, verified.text
    assert verified.json().get("verified") is True, verified.json()

    # finding.annotate (remediator): reviewer notes land on the campaign; the row carries the digest only.
    noted = remediator.patch(f"/v1/runs/{scanner_run.run_id}/reviewer-notes", json=notes_body)
    assert noted.status_code == 200, noted.text
    campaign = scanner.get(f"/v1/runs/{scanner_run.run_id}/campaign")
    assert campaign.status_code == 200 and campaign.json()["reviewer_notes"] == notes_body["reviewer_notes"]
    annotate = _events(e2e_app, f"run:{scanner_run.run_id}", "finding.annotate")
    assert annotate and annotate[-1]["actor"] == e2e_org.actor("remediator")
    encoded = notes_body["reviewer_notes"].encode("utf-8")
    assert annotate[-1]["detail"]["sha256"] == hashlib.sha256(encoded).hexdigest()
    assert annotate[-1]["detail"]["length"] == len(notes_body["reviewer_notes"])
    assert notes_body["reviewer_notes"] not in json.dumps(annotate[-1]["detail"]), "the note text never hits the chain"

    # explain.run (scanner) and harden.recommend (remediator): follow-on campaigns are admitted (202)
    # and run to a terminal state in the eager worker; each writes its own run chain.
    explained = scanner.post(f"/v1/findings/{scanner_finding}/explain", json={"explain_k": 1})
    assert explained.status_code == 202, explained.text
    explain_run = h.wait_for_run(scanner, explained.json()["run_id"])
    assert explain_run["status"] in h.TERMINAL_RUN_STATUSES and explain_run["scanner"] == "ml.explain"
    explain_admission = _events(e2e_app, f"run:{explained.json()['run_id']}", "explain.run")
    assert explain_admission and explain_admission[0]["actor"] == e2e_org.actor("scanner")
    assert explain_admission[0]["detail"]["finding_id"] == scanner_finding
    hardened = remediator.post(f"/v1/findings/{scanner_finding}/harden", json={"llm_narrative": False})
    assert hardened.status_code == 202, hardened.text
    harden_run = h.wait_for_run(remediator, hardened.json()["run_id"])
    assert harden_run["status"] in h.TERMINAL_RUN_STATUSES and harden_run["scanner"] == "ml.harden"
    harden_admission = _events(e2e_app, f"run:{hardened.json()['run_id']}", "harden.recommend")
    assert harden_admission and harden_admission[0]["actor"] == e2e_org.actor("remediator")

    # verify.replay (remediator): admitted when the baseline carries a score record; when the baseline
    # has none the honest answer is a typed 409 score_unavailable, never a 403 and never a number.
    assert scanner_run.campaign is not None
    baseline_score = scanner_run.campaign.get("score")
    verify = remediator.post(f"/v1/findings/{scanner_finding}/verify", json={})
    if baseline_score is None:
        assert verify.status_code == 409, verify.text
        assert _detail_code(verify) == SCORE_UNAVAILABLE
    else:
        assert verify.status_code == 202, verify.text
        verify_run = h.wait_for_run(remediator, verify.json()["run_id"])
        assert verify_run["status"] in h.TERMINAL_RUN_STATUSES and verify_run["scanner"] == "ml.verify"
        verify_admission = _events(e2e_app, f"run:{verify.json()['run_id']}", "verify.replay")
        assert verify_admission and verify_admission[0]["actor"] == e2e_org.actor("remediator")
        if baseline_score.get("completeness") == "partial":
            assert baseline_score["mri"] is None and baseline_score["missing"], baseline_score
        else:
            assert isinstance(baseline_score["mri"], int) and 0 <= baseline_score["mri"] <= 100

    # finding.review (approver) with the independence rule of spec 7.7: the creator is refused whatever
    # its rank (the admin launched this campaign), an independent approver dismisses.
    creator = admin.patch(f"/v1/findings/{admin_finding}/status", json=review_body)
    assert creator.status_code == 403, creator.text
    assert "creator" in str(creator.json()["detail"]).lower()
    refused_review = [ev for ev in _events(e2e_app, f"run:{admin_run.run_id}", "finding.review") if not ev["success"]]
    assert refused_review, "a refused dismissal is still a success=False row on the run chain (spec 5.11)"
    assert refused_review[-1]["actor"] == e2e_org.actor("admin")
    assert refused_review[-1]["detail"]["campaign_creator"] == e2e_org.actor("admin")
    assert refused_review[-1]["detail"]["refusal"] == "forbidden"
    still_open = approver.get(f"/v1/findings/{admin_finding}")
    assert still_open.status_code == 200 and still_open.json()["status"] == "open"

    dismissed = approver.patch(f"/v1/findings/{admin_finding}/status", json=review_body)
    assert dismissed.status_code == 200, dismissed.text
    assert dismissed.json()["status"] == "false_positive" and dismissed.json()["from_status"] == "open"
    assert dismissed.json()["review"]["reviewer"] == e2e_org.actor("approver")
    after = approver.get(f"/v1/findings/{admin_finding}")
    assert after.status_code == 200 and after.json()["status"] == "false_positive"
    review_rows = [ev for ev in _events(e2e_app, f"run:{admin_run.run_id}", "finding.review") if ev["success"]]
    assert review_rows and review_rows[-1]["actor"] == e2e_org.actor("approver")
    detail = review_rows[-1]["detail"]
    assert detail["from_status"] == "open" and detail["to_status"] == "false_positive"
    assert detail["reviewer"] == e2e_org.actor("approver") and detail["campaign_creator"] == e2e_org.actor("admin")
    assert detail["reason"] == review_body["reason"]
    # The dismissal is terminal for user-owned transitions (spec 6.4): a second dismissal is a stale 409.
    again = approver.patch(f"/v1/findings/{admin_finding}/status", json=review_body)
    assert again.status_code == 409 and _detail_code(again) == RUN_TERMINAL


# ---------------------------------------------------------------------------
# 2. The audit trail: verify --all, the 10.5 vocabulary, no secrets, a tamper
# ---------------------------------------------------------------------------


def test_audit_verify_all_and_tamper(
    e2e_app: E2EApp,
    e2e_org: E2EOrg,
    campaigns: Campaigns,
    audit_verify_all: Callable[[], tuple[int, str]],
    tamper_audit_event: Callable[..., tuple[str, int]],
) -> None:
    from redsim.audit.chain import verify_chain

    run = campaigns.scanner
    chain_id = f"run:{run.run_id}"

    def broken_chains(output: str) -> dict[str, str]:
        """``chain_id -> line`` for every chain the CLI reports as broken."""
        found: dict[str, str] = {}
        for line in output.splitlines():
            match = re.search(r"chain '([^']+)'", line)
            if "broken at seq=" in line and match:
                found[match.group(1)] = line
        return found

    def verified_chains(output: str) -> set[str]:
        return {match.group(1) for line in output.splitlines() if "events verified" in line
                for match in [re.search(r"chain '([^']+)'", line)] if match}

    # A sibling test in the same session may have tampered with its own chain and left it (the harness
    # smoke test does). The CLI must then name exactly those chains and nothing else; on a clean tier the
    # set is empty and the exit code is 0. This module's own campaign chain verifies in either case.
    pre_broken = {cid for cid in e2e_app.chain_ids() if not verify_chain(e2e_app.read_chain(cid)).verified}
    assert chain_id not in pre_broken

    # -- clean: every chain this module wrote verifies through the real CLI ------------------------
    code, output = audit_verify_all()
    assert set(broken_chains(output)) == pre_broken, output
    assert (code == 0) == (not pre_broken), f"exit {code} with pre-existing broken chains {sorted(pre_broken)}:\n{output}"
    assert chain_id in verified_chains(output), output
    assert set(verified_chains(output)) | pre_broken == set(e2e_app.chain_ids()), "every chain is reported once"

    # -- the run chain: admission first, then the job's rows in the spec 10.5 order ----------------
    events = e2e_app.read_chain(chain_id)
    names = [str(ev["action"]) for ev in events]
    assert names[0] == "attack.run", names
    assert events[0]["seq"] == 1 and events[0]["actor"] == e2e_org.actor("scanner")
    assert run.campaign is not None
    assert events[0]["detail"]["target_id"] == run.campaign["config"]["target_id"]
    first_complete = names.index("job.complete")
    job_segment = names[1:first_complete + 1]
    assert run.campaign is not None
    expected = campaign_job_vocabulary(list(run.campaign["config"]["attack_ids"]))
    assert job_segment == expected, (
        f"the attack.run job must emit exactly the spec 10.5 rows in order behind the admission row; "
        f"chain carries {names}"
    )
    for ev in events[1:first_complete + 1]:
        assert ev["seq"] > events[0]["seq"], "the admission row precedes every job row"
        assert ev["actor"] == "worker:attack.run", ev
        assert ev["detail"]["requested_by"] == e2e_org.actor("scanner"), ev
        assert ev["success"] is True, f"{ev['action']} was refused or failed: {ev['detail']}"
    # Rows a later admission appended (reviewer notes, a refused cancel) are human admissions, never job rows.
    for ev in events[first_complete + 1:]:
        assert str(ev["actor"]).startswith("user:"), ev
    assert events[first_complete]["detail"]["status"] == "succeeded"
    assert events[first_complete]["detail"]["n_findings"] == len(run.findings)
    # The explain row counts what the record holds (ids and digests, never arrays or images).
    explain = events[names.index("explain.execute")]["detail"]
    assert explain["n_observations"] == len(run.campaign["observations"])
    assert explain["explain_k"] == run.campaign["config"]["explain_k"]

    # -- the harden row records the redacted gateway view, the score row the honest score -----------
    harden = events[names.index("harden.execute")]["detail"]
    assert harden["llm_requested"] is True and harden["llm_used"] is True and harden["narrative_source"] == "llm"
    assert harden["llm"]["gateway"] == "pythia" and "api_key" not in harden["llm"]
    assert set(harden["llm"]) == {"gateway", "base_url", "model", "persona"}, "PythiaSettings.redacted() only"
    assert harden["prompt_sha256"] and harden["completion_sha256"], "digests, never the prompt or completion text"
    score = events[names.index("campaign.score")]["detail"]
    assert run.campaign is not None
    if run.campaign["score"] is None or run.campaign["score"]["completeness"] == "partial":
        assert score["mri"] is None and score["completeness"] == "partial" and score["missing"], score
    else:
        assert score["mri"] == run.campaign["score"]["mri"] and score["completeness"] == "complete"

    # -- no secret, no credential, no model bytes on any chain -------------------------------------
    everything = [ev for cid in e2e_app.chain_ids() for ev in e2e_app.read_chain(cid)]
    dump = json.dumps(everything, default=str)
    assert h.MOCK_PYTHIA_API_KEY not in dump, "the gateway key reached an audit row"
    assert "Bearer pk_" not in dump and "pk_e2e" not in dump
    assert KAGGLE_SENTINEL not in dump, "a dataset credential reached an audit row"
    for ev in everything:
        # Variable *names* may appear in a skip reason ("not configured (PYTHIA_API_KEY ...)"); values never.
        assert len(json.dumps(ev["detail"], default=str)) < 16 * 1024, f"detail of {ev['action']} is not ids/digests/counts"
        for leaf in _strings(ev["detail"]):
            assert len(leaf) <= 1024, f"{ev['action']} carries a payload-sized string ({len(leaf)} chars)"
            assert not leaf.startswith(("PK\x03\x04", "\x89PNG", "\x80")), f"{ev['action']} carries raw bytes"

    # -- one mutated event: the CLI names the chain and the sequence number ------------------------
    tampered_chain, seq = tamper_audit_event(chain_id=chain_id)
    assert tampered_chain == chain_id and seq > 1
    broken = verify_chain(e2e_app.read_chain(chain_id))
    assert broken.verified is False and broken.broken_at == seq
    code, output = audit_verify_all()
    assert code != 0, output
    broken = broken_chains(output)
    assert set(broken) == pre_broken | {chain_id}, output
    assert f"broken at seq={seq}" in broken[chain_id], broken[chain_id]
    assert chain_id not in verified_chains(output)

    # -- the byte-identical row verifies again, so sibling tests see the tier as it was ---------------
    _untamper_audit_event(e2e_app, chain_id, seq)
    assert verify_chain(e2e_app.read_chain(chain_id)).verified is True
    code, output = audit_verify_all()
    assert set(broken_chains(output)) == pre_broken, output
    assert (code == 0) == (not pre_broken), output
    assert chain_id in verified_chains(output)


# ---------------------------------------------------------------------------
# 3. Capabilities never leak; unsupported paths are typed refusals
# ---------------------------------------------------------------------------


def test_capabilities_and_unsupported_paths(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], campaigns: Campaigns,
    pythia: PythiaToggle, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redsim.api.errors import NOT_IMPLEMENTED
    from redsim.api.v1.ml_capabilities import ML_CATALOG_UNAVAILABLE, UPLOAD_FORMATS

    viewer, scanner, remediator, admin = (e2e_org.client(role) for role in ("viewer", "scanner", "remediator", "admin"))
    project_chain = f"project:{e2e_org.project_id}"

    def assert_secret_free(response: Any) -> dict[str, Any]:
        assert response.status_code == 200, response.text
        text = response.text
        assert h.MOCK_PYTHIA_API_KEY not in text and "pk_e2e" not in text, "the Pythia key is never served"
        assert h.MOCK_PYTHIA_BASE_URL not in text and "pythia.e2e.invalid" not in text, "the base URL is never served"
        for key, value in os.environ.items():
            if key in {"PYTHIA_API_KEY", "PYTHIA_BASE_URL"} and value:
                assert value not in text
        body: dict[str, Any] = response.json()
        return body

    # -- gateway configured (mock on): configured=True, model named, key and URL absent ---------------
    with pythia:
        body = assert_secret_free(viewer.get("/v1/ml/capabilities"))
    assert body["llm_narrative"] == {
        "configured": True, "gateway": "pythia", "model": h.MOCK_PYTHIA_MODEL, "persona_set": False,
    }
    assert body["pickle_accepted"] is False and body["sandbox_enabled"] is True
    assert list(body["upload_formats"]) == list(UPLOAD_FORMATS)
    assert "small_cnn" in body["architectures"]
    for modality in ("image", "tabular"):
        assert body["modalities"][modality] == {"status": "available", "phase": "A"}
    for modality in ("llm", "text", "detection"):
        row = body["modalities"][modality]
        assert row["status"] == "not_implemented" and row["phase"] == "B" and row["reason"], row
    assert body["endpoint_connector"]["status"] == "not_implemented"
    assert body["endpoint_connector"]["phase"] == "B" and body["endpoint_connector"]["reason"]
    assert {row["id"] for row in body["bundled_models"]} == set(h.BUNDLED_IDS), "fixtures are never listed"
    assert body["defenses"], "the defense roster comes from the registry, never an empty list"

    # -- gateway not configured (mock off): configured=False with the reason, still nothing secret ---
    body = assert_secret_free(viewer.get("/v1/ml/capabilities"))
    assert body["llm_narrative"]["configured"] is False and body["llm_narrative"]["model"] is None
    assert body["llm_narrative"]["reason"]

    # -- endpoint targets: 501 not_implemented with a reason and a phase, refusal on the chain ---------
    endpoint_body = {"source": "endpoint", "project_id": e2e_org.project_id, "name": "e2e-endpoint",
                     "url": "https://endpoint.e2e.invalid/predict"}
    refused_before = len([ev for ev in e2e_app.read_chain(project_chain)
                          if ev["action"] == "model.register" and not ev["success"]])
    endpoint = admin.post("/v1/models", json=endpoint_body)
    assert endpoint.status_code == 501, endpoint.text
    detail = endpoint.json()["detail"]
    assert detail["code"] == NOT_IMPLEMENTED and detail["phase"] == "B" and detail["message"]
    refused = [ev for ev in e2e_app.read_chain(project_chain) if ev["action"] == "model.register" and not ev["success"]]
    assert len(refused) == refused_before + 1
    assert refused[-1]["detail"]["reason"] == NOT_IMPLEMENTED and refused[-1]["detail"]["source"] == "endpoint"
    assert refused[-1]["detail"]["phase"] == "B" and refused[-1]["actor"] == e2e_org.actor("admin")
    # Spec 17.2 gates endpoint registration at TARGET_MANAGE (admin). The route answers the remediator
    # with the same 501 (the MODEL_REGISTER gate passes before the source is read); either way nothing
    # is registered and the viewer is refused before the source is looked at.
    remediator_endpoint = remediator.post("/v1/models", json=endpoint_body)
    assert remediator_endpoint.status_code in (403, 501), remediator_endpoint.text
    assert viewer.post("/v1/models", json=endpoint_body).status_code == 403
    listing = admin.get("/v1/models", params={"project": e2e_org.project_id}).json()["models"]
    assert not [row for row in listing if row.get("name") == "e2e-endpoint"], "no endpoint target was created"

    # -- report.pdf: 501 with the phase, behind the same gate as the other formats ----------------------
    run_id = campaigns.scanner.run_id
    pdf = scanner.get(f"/v1/runs/{run_id}/report.pdf")
    assert pdf.status_code == 501, pdf.text
    assert pdf.json()["detail"]["code"] == NOT_IMPLEMENTED and pdf.json()["detail"]["phase"] == "B"
    assert pdf.json()["detail"]["field"] == "ext"
    assert viewer.get(f"/v1/runs/{run_id}/report.pdf").status_code == 403, "the export gate precedes the format"

    # -- an attack id outside the registry is a typed refusal (422 unknown_attack, or 501 for a named
    #    Phase B attack), audited as a refused admission, never a launched campaign -------------------
    runs_before = _count_runs(e2e_app)
    refused_attacks_before = len([ev for ev in e2e_app.read_chain(project_chain)
                                  if ev["action"] == "attack.run" and not ev["success"]])
    phase_b = scanner.post(f"/v1/models/{e2e_bundled[h.TABULAR_MODEL_ID]}/attacks",
                           json=_governance_config(attack_ids=["pgd", "e2e_unknown_attack"], attack_params={}))
    assert phase_b.status_code in (422, 501), phase_b.text
    assert _detail_code(phase_b) in {"unknown_attack", NOT_IMPLEMENTED}, phase_b.text
    assert _count_runs(e2e_app) == runs_before
    refused_attacks = [ev for ev in e2e_app.read_chain(project_chain) if ev["action"] == "attack.run" and not ev["success"]]
    assert len(refused_attacks) == refused_attacks_before + 1, "a refused admission is a success=False row"
    assert refused_attacks[-1]["actor"] == e2e_org.actor("scanner")

    # -- catalog routes with an unimportable registry: 503 ml_catalog_unavailable, never an empty 200 --
    def assert_unavailable(response: Any, what: str) -> None:
        assert response.status_code == 503, f"{what}: {response.status_code} {response.text[:200]}"
        detail = response.json()["detail"]
        assert detail["code"] == ML_CATALOG_UNAVAILABLE and detail["reason"], detail

    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, "redsim.ml.attacks", None)
        assert_unavailable(viewer.get("/v1/attacks"), "GET /v1/attacks")
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, "redsim.ml.defenses", None)
        assert_unavailable(viewer.get("/v1/defenses"), "GET /v1/defenses")
        assert_unavailable(viewer.get("/v1/ml/capabilities"), "GET /v1/ml/capabilities (defenses)")
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, "redsim.ml.targets", None)
        assert_unavailable(viewer.get("/v1/models", params={"project": e2e_org.project_id}), "GET /v1/models")
        assert_unavailable(viewer.get("/v1/ml/capabilities"), "GET /v1/ml/capabilities (targets)")
        # Registering through an unavailable registry is the same 503, not a silent 201 (or a 409).
        assert_unavailable(remediator.post("/v1/models", json={
            "source": "bundled", "bundled_id": h.TABULAR_MODEL_ID, "project_id": e2e_org.project_id,
        }), "POST /v1/models (bundled)")

    # -- and with the registries importable again the same routes list the real catalog ---------------
    attacks = viewer.get("/v1/attacks")
    assert attacks.status_code == 200 and {row["id"] for row in attacks.json()["attacks"]} >= {
        "fgsm", "pgd", "hopskipjump", "noise_control"}
    defenses = viewer.get("/v1/defenses")
    assert defenses.status_code == 200 and defenses.json()["count"] >= 3
    models = viewer.get("/v1/models", params={"project": e2e_org.project_id})
    assert models.status_code == 200 and models.json()["count"] >= 2
    assert_secret_free(viewer.get("/v1/ml/capabilities"))


# ---------------------------------------------------------------------------
# 4. Postgres row-level security across organisations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PostgresLane:
    """The migrated Postgres of the RLS lane."""

    url: str              # driver-qualified SQLAlchemy URL (never printed with its password)
    head: str             # the alembic head revision the database is at
    migrated_here: bool   # True when this test session ran the upgrade (the database was not at head)

    @property
    def display(self) -> str:
        from sqlalchemy.engine import make_url

        return make_url(self.url).render_as_string(hide_password=True)


def _driver_qualified(raw: str) -> str:
    """``postgresql://`` names SQLAlchemy's psycopg2 default; use the driver this interpreter has.

    The platform's own URLs are ``postgresql+psycopg://`` (``.env.example``,
    ``alembic.ini``, compose, CI). A bare scheme is completed the same way when
    only psycopg 3 is installed, so the harness's ``check_postgres_migrated``
    and the migration subprocess can connect.
    """
    import importlib.util

    from sqlalchemy.engine import make_url

    url = make_url(raw)
    if url.drivername in {"postgresql", "postgres"}:
        if importlib.util.find_spec("psycopg2") is not None:
            driver = "postgresql+psycopg2"
        elif importlib.util.find_spec("psycopg") is not None:
            driver = "postgresql+psycopg"
        else:
            pytest.skip(f"{h.POSTGRES_URL_ENV} is set but neither psycopg nor psycopg2 is installed")
        url = url.set(drivername=driver)
    return url.render_as_string(hide_password=False)


def _probe_postgres(url: str) -> str | None:
    """``None`` when the database answers ``SELECT 1``; otherwise the reason it did not."""
    from sqlalchemy import create_engine, text

    engine = create_engine(url, future=True, connect_args={"connect_timeout": 3})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - the reason becomes the skip message
        return f"{type(exc).__name__}: {str(exc).splitlines()[0][:160]}"
    finally:
        engine.dispose()
    return None


def _alembic_config() -> Any:
    from alembic.config import Config

    config = Config(str(_ALEMBIC_INI))
    config.set_main_option("script_location", str(_MIGRATIONS_DIR))
    return config


def _alembic_head() -> str:
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(_alembic_config()).get_current_head()
    assert head, "the migration tree has no single head"
    return str(head)


def _alembic_version(url: str) -> str | None:
    from sqlalchemy import create_engine, inspect, text

    engine = create_engine(url, future=True)
    try:
        with engine.connect() as conn:
            if not inspect(conn).has_table("alembic_version"):
                return None
            row = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
            return str(row) if row else None
    finally:
        engine.dispose()


def _alembic_upgrade_head(url: str) -> str:
    """``alembic upgrade head`` exactly as the api container and CI run it, as a subprocess.

    ``redsim/db/migrations/env.py`` reads ``REDSIM_DB_URL`` (or ``REDSIM_DB_OWNER_URL``);
    the subprocess gets only that URL plus the interpreter basics, never this
    process's harness variables. Idempotent: at head the command is a no-op.
    """
    from sqlalchemy.engine import make_url

    env = {key: os.environ[key] for key in _MIGRATE_SAFE_ENV_KEYS if key in os.environ}
    env.update({"REDSIM_DB_URL": url, "PYTHONPATH": str(h.REPO_ROOT), "PYTHONUNBUFFERED": "1"})
    completed = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(_ALEMBIC_INI), "upgrade", "head"],
        cwd=str(h.REPO_ROOT), env=env, capture_output=True, text=True, timeout=300, check=False,
    )
    password = make_url(url).password or ""
    output = (completed.stdout + "\n" + completed.stderr).strip()
    if password:
        output = output.replace(password, "***")
    assert completed.returncode == 0, f"alembic upgrade head failed (exit {completed.returncode}):\n{output[-2000:]}"
    return output


@pytest.fixture(scope="module")
def rls_postgres(request: pytest.FixtureRequest) -> Iterator[PostgresLane]:
    """The RLS-lane Postgres, migrated by the platform's runner inside the test session.

    Skips with a reason when ``REDSIM_E2E_POSTGRES_URL`` is unset, names a
    database that does not answer, or no PostgreSQL driver is installed. Runs
    ``alembic upgrade head`` twice (the second run proves idempotency), checks
    the stored revision against the migration tree's head, then hands the
    driver-qualified URL to the harness ``postgres_url`` fixture so its own
    migrated-database check runs on the same database.
    """
    raw = h.postgres_url_from_env()
    if raw is None:
        pytest.skip(f"Postgres lane is off: set {h.POSTGRES_URL_ENV} (tests/e2e/README.md)")
    pytest.importorskip("sqlalchemy")
    pytest.importorskip("alembic")
    url = _driver_qualified(raw)
    reason = _probe_postgres(url)
    if reason is not None:
        pytest.skip(f"{h.POSTGRES_URL_ENV} is set but the database is unreachable: {reason}")
    head = _alembic_head()
    before = _alembic_version(url)
    _alembic_upgrade_head(url)
    assert _alembic_version(url) == head, "alembic upgrade head did not leave the database at the tree's head"
    _alembic_upgrade_head(url)          # idempotent: a second run changes nothing
    assert _alembic_version(url) == head
    patch = pytest.MonkeyPatch()
    patch.setenv(h.POSTGRES_URL_ENV, url)
    try:
        harness_url = request.getfixturevalue("postgres_url")
        assert harness_url == url, "the harness fixture must see the migrated database"
        yield PostgresLane(url=url, head=head, migrated_here=before != head)
    finally:
        patch.undo()


def _ensure_rls_role(owner_engine: Any) -> None:
    """A NOLOGIN, non-superuser, non-owner role with DML on every table (mirrors ``tests/test_tenant_rls.py``)."""
    from sqlalchemy import text

    with owner_engine.begin() as conn:
        conn.execute(text(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles "
            f"WHERE rolname = '{RLS_ROLE}') THEN "
            f"CREATE ROLE {RLS_ROLE} NOLOGIN; END IF; END $$;"))
        conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {RLS_ROLE}"))
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {RLS_ROLE}"))
        conn.execute(text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {RLS_ROLE}"))


def _restricted_engine(url: str) -> Any:
    """An engine whose every connection has dropped to :data:`RLS_ROLE`, so the policies bind.

    The container's ``redsim`` user is a superuser and a superuser bypasses RLS
    even under ``FORCE``; production connects as the restricted ``redsim_app``
    role. ``SET ROLE`` runs with autocommit so the pool's rollback-on-return
    cannot undo it.
    """
    from sqlalchemy import create_engine, event

    engine = create_engine(url, future=True, pool_pre_ping=True)

    @event.listens_for(engine, "connect")
    def _drop_to_restricted_role(dbapi_connection: Any, _record: Any) -> None:
        previous = dbapi_connection.autocommit
        dbapi_connection.autocommit = True
        try:
            with dbapi_connection.cursor() as cursor:
                cursor.execute(f"SET ROLE {RLS_ROLE}")
        finally:
            dbapi_connection.autocommit = previous

    return engine


@contextlib.contextmanager
def _scoped_session(sess_mod: Any, org_ids: list[str]) -> Iterator[Any]:
    """A production ``get_session`` scoped to ``org_ids``: the tenant GUC as ``tests/test_tenant_rls.py`` sets it."""
    from sqlalchemy import text

    token = sess_mod.set_current_tenants(org_ids)
    try:
        with sess_mod.get_session() as sess:
            assert sess.execute(text("SELECT current_user")).scalar() == RLS_ROLE
            assert sess.execute(text("SHOW is_superuser")).scalar() == "off"
            yield sess
    finally:
        sess_mod.reset_current_tenants(token)


@dataclass(frozen=True)
class _Tenant:
    org: str
    project: str
    target: str
    run: str
    finding: str
    artifact: str


def _seed_tenant(sess: Any, tenant: _Tenant, *, bundled_id: str) -> None:
    """One organisation with one project, one registered target, one completed run, one finding, one artifact
    and one ``ml_campaigns`` row, inserted as the system path (empty GUC) without ``org_id``.

    The campaign row carries ``score: null`` and says why: no campaign was run
    against this database, so there is no MRI to store. What the test proves is
    that the row (the score record) is invisible to the other organisation.
    """
    from sqlalchemy import text

    from redsim.db.models import Artifact, Finding, Organization, Project, Run, Target

    sess.add(Organization(id=tenant.org, name=tenant.org, slug=tenant.org))
    sess.flush()
    sess.add(Project(id=tenant.project, org_id=tenant.org, name=tenant.project, slug=tenant.project))
    sess.flush()
    sess.add(Target(id=tenant.target, project_id=tenant.project, kind="ml_model_artifact",
                    value=f"bundled:{bundled_id}", verified=True,
                    detail={"bundled_id": bundled_id, "source": "bundled", "status": "available",
                            "modality": "image", "name": bundled_id}))
    sess.flush()
    sess.add(Run(id=tenant.run, project_id=tenant.project, target_id=tenant.target, created_by="user:e2e-rls-seed",
                 mode="api", status="succeeded", scanner="ml.campaign", stage_table={"stage": "report", "jobs": {}}))
    sess.flush()
    sess.add(Finding(id=tenant.finding, scanner_finding_id=f"e2e-rls-{tenant.run}", run_id=tenant.run,
                     project_id=tenant.project, status="open", severity="medium", source_tool="ml-campaign",
                     validation_state="unvalidated",
                     schema_blob={"id": tenant.finding, "finding_type": "adversarial_ml",
                                  "title": "e2e RLS seed (no measurement)"}))
    payload = b"{}"
    sess.add(Artifact(id=tenant.artifact, run_id=tenant.run, project_id=tenant.project, kind="ml.score",
                      sha256=hashlib.sha256(payload).hexdigest(), location=f"e2e-rls/{tenant.run}/score.json",
                      content_type="application/json", size_bytes=len(payload)))
    sess.flush()
    sess.execute(text(
        "INSERT INTO ml_campaigns (run_id, project_id, target_id, kind, modality, config, score, limitations) "
        "VALUES (:run_id, :project_id, :target_id, 'attack', 'image', CAST(:config AS jsonb), NULL, "
        "CAST(:limitations AS jsonb))"
    ), {
        "run_id": tenant.run, "project_id": tenant.project, "target_id": tenant.target,
        "config": json.dumps({"target_id": tenant.target, "modality": "image", "attack_ids": ["fgsm"]}),
        "limitations": json.dumps(["e2e RLS seed: no campaign ran against this database; score is null"]),
    })


def _cleanup_tenants(owner_engine: Any, tenants: list[_Tenant]) -> None:
    from sqlalchemy import text

    runs = [t.run for t in tenants]
    with owner_engine.begin() as conn:
        for statement, key, values in (
            ("DELETE FROM ml_campaigns WHERE run_id = ANY(:v)", "v", runs),
            ("DELETE FROM artifacts WHERE run_id = ANY(:v)", "v", runs),
            ("DELETE FROM findings WHERE run_id = ANY(:v)", "v", runs),
            ("DELETE FROM jobs WHERE run_id = ANY(:v)", "v", runs),
            ("DELETE FROM runs WHERE id = ANY(:v)", "v", runs),
            ("DELETE FROM targets WHERE id = ANY(:v)", "v", [t.target for t in tenants]),
            ("DELETE FROM projects WHERE id = ANY(:v)", "v", [t.project for t in tenants]),
            ("DELETE FROM organizations WHERE id = ANY(:v)", "v", [t.org for t in tenants]),
        ):
            conn.execute(text(statement), {key: values})


@pytest.mark.integration
def test_rls_hides_other_orgs_scores(e2e_app: E2EApp, rls_postgres: PostgresLane) -> None:
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from redsim.api.auth import CurrentUser
    from redsim.db import session as sess_mod
    from redsim.db.models import Artifact, Finding, Run

    lane = rls_postgres
    suffix = uuid4().hex[:8]
    tenant_a = _Tenant(org=f"org-e2e-rls-a-{suffix}", project=f"proj-e2e-rls-a-{suffix}",
                       target=f"vehicles_cnn-rls-a{suffix}", run=f"run-e2e-rls-a-{suffix}",
                       finding=str(uuid4()), artifact=f"art-e2e-rls-a-{suffix}")
    tenant_b = _Tenant(org=f"org-e2e-rls-b-{suffix}", project=f"proj-e2e-rls-b-{suffix}",
                       target=f"vehicles_cnn-rls-b{suffix}", run=f"run-e2e-rls-b-{suffix}",
                       finding=str(uuid4()), artifact=f"art-e2e-rls-b-{suffix}")

    # The container's superuser provisions the restricted role and cleans up; nothing else runs as it.
    owner = create_engine(lane.url, future=True)
    _ensure_rls_role(owner)
    restricted = _restricted_engine(lane.url)
    saved_engine, saved_session = sess_mod._ENGINE, sess_mod.Session
    added_users: list[str] = []
    try:
        # The production session module now points at Postgres (as the restricted role); the harness
        # app's routes and the tenant middleware read through it exactly as they would in a deployment.
        sess_mod._ENGINE = restricted
        sess_mod.Session = sessionmaker(restricted, expire_on_commit=False, future=True)

        # -- seed both tenants as the system path (empty GUC): the BEFORE INSERT triggers backfill org_id --
        with sess_mod.get_session() as sess:
            assert sess.execute(text("SELECT current_user")).scalar() == RLS_ROLE
            _seed_tenant(sess, tenant_a, bundled_id=h.IMAGE_MODEL_ID)
            _seed_tenant(sess, tenant_b, bundled_id=h.IMAGE_MODEL_ID)
        with sess_mod.get_session() as sess:
            for table, column, tenant in (
                ("runs", "id", tenant_a), ("findings", "id", tenant_a), ("artifacts", "id", tenant_a),
                ("ml_campaigns", "run_id", tenant_a), ("ml_campaigns", "run_id", tenant_b),
            ):
                key = getattr(tenant, {"id": "run" if table == "runs" else table[:-1], "run_id": "run"}[column])
                org = sess.execute(text(f"SELECT org_id FROM {table} WHERE {column} = :k"), {"k": key}).scalar_one()
                assert org == tenant.org, f"{table}.org_id was not backfilled from the project: {org!r}"
            for table in ("ml_campaigns", "findings", "artifacts", "runs"):
                forced = sess.execute(text(
                    "SELECT relforcerowsecurity FROM pg_class WHERE relname = :t"), {"t": table}).scalar_one()
                assert forced is True, f"{table} is not under FORCE ROW LEVEL SECURITY"
            assert sess.execute(text(
                "SELECT count(*) FROM pg_policies WHERE tablename = 'ml_campaigns' "
                "AND policyname = 'redsim_tenant_isolation'")).scalar_one() == 1

        # -- SQL level: a session scoped to B reads nothing of A's, and the reverse -------------------
        for mine, theirs in ((tenant_b, tenant_a), (tenant_a, tenant_b)):
            with _scoped_session(sess_mod, [mine.org]) as sess:
                assert sess.execute(text("SELECT run_id, score FROM ml_campaigns WHERE run_id = :r"),
                                    {"r": theirs.run}).all() == []
                assert sess.get(Run, theirs.run) is None
                assert sess.get(Finding, theirs.finding) is None
                assert sess.get(Artifact, theirs.artifact) is None
                visible = sess.execute(text(
                    "SELECT run_id FROM ml_campaigns WHERE run_id IN (:a, :b) ORDER BY run_id"),
                    {"a": tenant_a.run, "b": tenant_b.run}).scalars().all()
                assert visible == [mine.run], f"scoped to {mine.org}, ml_campaigns lists {visible}"
                own = sess.execute(text("SELECT run_id, score, limitations FROM ml_campaigns WHERE run_id = :r"),
                                   {"r": mine.run}).mappings().one()
                assert own["score"] is None, "the seeded row carries no MRI; only the row's visibility is under test"
                assert sess.get(Finding, mine.finding) is not None and sess.get(Artifact, mine.artifact) is not None
        # Scoped to both organisations, both rows are visible: the predicate is a list, not a single org.
        with _scoped_session(sess_mod, [tenant_a.org, tenant_b.org]) as sess:
            both = sess.execute(text("SELECT run_id FROM ml_campaigns WHERE run_id IN (:a, :b) ORDER BY run_id"),
                                {"a": tenant_a.run, "b": tenant_b.run}).scalars().all()
            assert both == sorted([tenant_a.run, tenant_b.run])
        # The same scoped read as the superuser bypasses the policy: the reason production must not connect
        # as one (redsim.db.session warns about it) and the reason this test drops to the restricted role.
        token = sess_mod.set_current_tenants([tenant_b.org])
        try:
            with owner.connect() as conn:
                conn.execute(text("SELECT set_config('app.current_tenants', :v, true)"), {"v": tenant_b.org})
                leaked = conn.execute(text("SELECT run_id FROM ml_campaigns WHERE run_id = :r"),
                                      {"r": tenant_a.run}).scalars().all()
                assert leaked == [tenant_a.run], "a superuser session is expected to bypass RLS (Postgres semantics)"
        finally:
            sess_mod.reset_current_tenants(token)

        # -- API level over the same database: 404 for the other organisation, 200 for the owner ------
        users: dict[str, Any] = {}
        for label, tenant in (("a", tenant_a), ("b", tenant_b)):
            email = f"pg-{label}-{suffix}@{h.IDENTITY_DOMAIN}"
            user = CurrentUser(sub=f"dev:{email}", email=email, display_name=f"E2E RLS {label}",
                               project_memberships={tenant.project: "admin"}, is_system=False)
            e2e_app.add_user(user)
            added_users.append(email)
            users[label] = e2e_app.client_for(user)
        client_a, client_b = users["a"], users["b"]

        cross_org_reads = (
            f"/v1/runs/{tenant_a.run}",
            f"/v1/runs/{tenant_a.run}/campaign",
            f"/v1/runs/{tenant_a.run}/artifacts",
            f"/v1/runs/{tenant_a.run}/report.json",
            f"/v1/findings/{tenant_a.finding}",
            f"/v1/artifacts/{tenant_a.artifact}",
        )
        for path in cross_org_reads:
            response = client_b.get(path)
            assert response.status_code == 404, f"{path} answered {response.status_code} to the other org: {response.text[:200]}"
            for secret in (tenant_a.org, tenant_a.project, tenant_a.target):
                assert secret not in response.text, f"{path} reveals {secret} to the other organisation"
        other_model = client_b.get(f"/v1/models/{tenant_a.target}", params={"project": tenant_b.project})
        assert other_model.status_code == 404, other_model.text
        cross_list = client_b.get("/v1/findings", params={"project": tenant_a.project})
        assert cross_list.status_code == 200 and cross_list.json()["count"] == 0
        unfiltered = client_b.get("/v1/findings")
        assert unfiltered.status_code == 200
        assert tenant_a.finding not in {row["id"] for row in unfiltered.json()["findings"]}

        own_run = client_a.get(f"/v1/runs/{tenant_a.run}")
        assert own_run.status_code == 200 and own_run.json()["project_id"] == tenant_a.project
        own_finding = client_a.get(f"/v1/findings/{tenant_a.finding}")
        assert own_finding.status_code == 200 and own_finding.json()["run_id"] == tenant_a.run
        own_artifacts = client_a.get(f"/v1/runs/{tenant_a.run}/artifacts")
        assert own_artifacts.status_code == 200
        assert [row["id"] for row in own_artifacts.json()["artifacts"]] == [tenant_a.artifact]
        own_campaign = client_a.get(f"/v1/runs/{tenant_a.run}/campaign")
        # The seeded row has no immutable ml.run_record artifact, so the evidence route says so (404) rather
        # than reconstructing a record from projections: an honest state for a campaign that never ran.
        assert own_campaign.status_code == 404 and _detail_code(own_campaign) == "campaign_not_found"
    finally:
        sess_mod._ENGINE, sess_mod.Session = saved_engine, saved_session
        for email in added_users:
            e2e_app.users.pop(email, None)
        restricted.dispose()
        _cleanup_tenants(owner, [tenant_a, tenant_b])
        owner.dispose()

    # The harness sqlite database is back in place for the rest of the tier.
    assert e2e_app.chain_ids(), "the sqlite harness engine was restored"
