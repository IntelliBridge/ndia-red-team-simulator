"""Platform integrations (spec 27.3): the roster and the ``integration.push`` admission boundary.

Plan 12 wave B3, ``atlas-foundry`` track (register INTEROP-24, -27, -28, -29).
The track owns no ``redsim/services`` file, so the admission boundary lives at
package level here; the route module stays thin and the worker task lives in
``redsim.workers.tasks.integration_push``.

* :func:`roster` is the ``GET /v1/integrations`` body: which pushes this
  deployment has configured, by status string and boolean only. Foundry is off
  unless ``REDSIM_INTEGRATION_FOUNDRY_URL`` is set (``redsim.integrations.foundry``).
  Lattice is listed as ``not_implemented`` with the D3 reason: it stays text
  only (spec 27.3), so no setting, route, task or client exists for it.
* :func:`create_foundry_push` admits ``POST /v1/runs/{run_id}/integrations/foundry``
  behind the ``integration.push`` gate (admin, checked by the route): the run
  must be a terminal campaign with an ``ml.run_record`` (never a probe run, D9;
  never a fixture target, D3), Foundry must be configured, the bearer
  ``AuthProfile`` named in the body must belong to the project, and one push
  per (run, integration) may be in flight. Then, in order: the
  ``integration.push`` audit row on the follow-up run's chain, the follow-up
  ``Run`` (``scanner="ml.integration_push"``) and its ``Job``
  (``type="integration.push"``, detail without a credential), the enqueue on
  the ``default`` queue (the only pool with outbound HTTPS egress). Every
  refusal after lookup is a ``success=False`` ``integration.push`` row on the
  campaign run's chain before the :class:`~redsim.api.errors.ApiError`.

Nothing here imports an ML library or a Celery task at module import time.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, NoReturn, TypedDict
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from redsim.api.errors import (
    AUTH_PROFILE_KIND_UNSUPPORTED,
    AUTH_PROFILE_REQUIRED,
    CAMPAIGN_NOT_TERMINAL,
    ENDPOINT_NOT_ALLOWLISTED,
    FIXTURE_NOT_EXPORTABLE,
    INTEGRATION_DISABLED,
    JOB_IN_FLIGHT,
    LLM_TARGET_REQUIRED,
    NOT_FOUND,
    PARAMS_OUT_OF_RANGE,
    QUEUE_UNAVAILABLE,
    SCORE_UNAVAILABLE,
    ApiError,
)
from redsim.integrations.foundry import (
    FOUNDRY_URL_ENV,
    INTEGRATION,
    FoundryMisconfigured,
    FoundrySettings,
    foundry_status,
    scrub_detail,
    validate_target_ref,
)

if TYPE_CHECKING:
    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vocabulary (spec 27.4; register INTEROP-24, -28)
# ---------------------------------------------------------------------------

#: Integrations with code on this tree. Lattice is deliberately absent (text only, spec 27.3).
INTEGRATIONS: tuple[str, ...] = (INTEGRATION,)
#: ``Run.scanner`` of the follow-up run a push job lives on (spec 6.2 roll-up rule: a Job never sits on a
#: terminal campaign run).
PUSH_SCANNER = "ml.integration_push"
#: ``Job.type`` and the admission audit action (the ``Action.INTEGRATION_PUSH`` value).
PUSH_JOB_TYPE = "integration.push"
ADMISSION_ACTION = "integration.push"
#: The worker's completion action (spec 27.4 row 5.11).
EXECUTE_ACTION = "integration.push.execute"
#: Celery task name; the task declares ``queue="default"`` itself.
PUSH_TASK_NAME = "redsim.integration_push"
PUSH_QUEUE = "default"
#: ``stage_table.kind`` of a push run.
PUSH_RUN_KIND = "integration_push"
#: The auth-profile kind a Foundry token must have (``Authorization: Bearer``).
PUSH_AUTH_KIND = "bearer"
#: What a push may carry today. The adversarial dataset push (spec 27.3, "when exported") waits for the
#: interop-contribute export and is not claimed here.
PUSH_PAYLOADS: tuple[str, ...] = ("scorecard",)
_TERMINAL = frozenset({"succeeded", "failed", "cancelled"})

#: Why the Lattice push has no code (spec 27.3 "Conflict to resolve first"; register INTEROP-27).
LATTICE_REASON = (
    "Anduril Lattice is an operating-picture platform. The D3 bound and constitution Principle II state "
    "'no mission-system connections', so under the decisions of 2026-09-08 this integration cannot be enabled. "
    "It stays text only (spec 27.3): no setting, route, task or client exists, and none is written until an "
    "explicit product-owner decision and a constitution amendment proposal say otherwise."
)
LATTICE_STATUS: dict[str, Any] = {
    "integration": "lattice",
    "status": "not_implemented",
    "phase": "B",
    "reason": LATTICE_REASON,
    "decision": "D3 (no mission-system connections); owner decision INTEROP-27 / TESTS_DOCS-41",
    "payload_if_ever": ("beside the number and grade: the five subscores with denominators, the eps grid points, "
                        "settings_hash, computed_at, the grade sentence and a link to the full scorecard "
                        "(spec 27.3, D9(ii), D9(iii))"),
}


class IntegrationPushJobDetail(TypedDict):
    """Shape of ``Job.detail`` for ``integration.push`` jobs (spec 27.4 row 5.9): ids only, never a credential.

    ``run_id`` is the campaign run whose scorecard is pushed (the spec's
    ``IntegrationPushJobDetail.run_id``); the job itself lives on a follow-up run.
    """

    run_id: str
    integration: str
    target_ref: str
    payload: str
    auth_profile_id: str
    host: str
    record_sha256: str
    campaign_kind: str
    requested_by: str


class FoundryPushRequest(BaseModel):
    """Body of ``POST /v1/runs/{run_id}/integrations/foundry``.

    ``auth_profile_id`` names the bearer profile holding the Foundry token (no
    standing credential, spec 27 rule 3). ``target_ref`` is the Foundry dataset
    rid to write into; when absent the deployment default
    ``REDSIM_INTEGRATION_FOUNDRY_DATASET_RID`` applies.
    """

    model_config = ConfigDict(extra="forbid")

    auth_profile_id: str = Field(min_length=1, max_length=64)
    target_ref: str | None = Field(default=None, max_length=256)
    payload: Literal["scorecard"] = "scorecard"


@dataclass(frozen=True)
class IntegrationPushHandle:
    """The 17.3 ``JobHandle`` of a push admission."""

    run_id: str
    job_ids: list[str]
    campaign_run_id: str
    integration: str
    target_ref: str

    def to_response(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "job_ids": list(self.job_ids),
            "status_url": f"/v1/runs/{self.run_id}",
            "integration": self.integration,
            "campaign_run_id": self.campaign_run_id,
            "target_ref": self.target_ref,
            "kind": PUSH_RUN_KIND,
        }


# ---------------------------------------------------------------------------
# The roster (``GET /v1/integrations``; register INTEROP-29)
# ---------------------------------------------------------------------------


def roster(environ: Mapping[str, str] | None = None, *, allowlist: list[str] | None = None) -> dict[str, Any]:
    """Which integrations this deployment has configured: status strings and booleans, never a value."""
    env = os.environ if environ is None else environ
    return {
        "integrations": {
            INTEGRATION: foundry_status(env, allowlist=list(allowlist or [])),
            "lattice": dict(LATTICE_STATUS),
        },
        "push_route": "POST /v1/runs/{run_id}/integrations/foundry",
        "gate": "integration.push (admin)",
        "statement": ("Every push is opt-in and off by default, a REST call from the default worker pool, never an "
                      "LLM call, and holds no standing credential (spec 27 rules 1 to 3). A scorecard leaves only "
                      "with its subscores, denominators, eps grid, settings_hash and the grade sentence (D9)."),
    }


def foundry_settings_or_none(environ: Mapping[str, str] | None, allowlist: list[str]) -> FoundrySettings | None:
    """``FoundrySettings.from_env`` with the misconfiguration folded into ``None`` for callers that only ask
    "is it usable"; the roster and the admission report the rule themselves."""
    try:
        return FoundrySettings.from_env(environ, allowlist=allowlist)
    except FoundryMisconfigured:
        return None


# ---------------------------------------------------------------------------
# Admission (``POST /v1/runs/{run_id}/integrations/foundry``; register INTEROP-24)
# ---------------------------------------------------------------------------


def _refuse(audit_writer: AuditWriter, *, actor: str, project_id: str | None, run_id: str | None,
            exc: ApiError, **context: Any) -> NoReturn:
    """The ``success=False`` admission row (campaign run chain), then the refusal (spec 5.11, 9.5)."""
    detail: dict[str, Any] = {"actor": actor, "refused": True, "code": exc.code, "http_status": exc.status,
                              "reason": str(exc)}
    for key, value in context.items():
        if value is not None:
            detail[key] = value
    audit_writer.append(
        action=ADMISSION_ACTION, actor=actor, target=None, allowlist_check="n/a", override=False,
        success=False, detail=scrub_detail(detail), run_id=run_id, project_id=project_id,
    )
    raise exc


def _detail_flags_fixture(detail: Any) -> bool:
    if not isinstance(detail, Mapping):
        return False
    if detail.get("fixture_only") or detail.get("fixture"):
        return True
    manifest = detail.get("manifest")
    return bool(isinstance(manifest, Mapping) and (manifest.get("fixture_only") or manifest.get("fixture")))


def is_fixture_campaign(target_detail: Any, campaign_config: Any) -> bool:
    """D3 / spec 14.7: a CI-fixture target's runs are never exported or pushed."""
    if _detail_flags_fixture(target_detail):
        return True
    if isinstance(campaign_config, Mapping):
        snapshot = campaign_config.get("target_snapshot")
        if _detail_flags_fixture(snapshot):
            return True
    return False


def _in_flight_push(session: Any, *, project_id: str, campaign_run_id: str) -> Any | None:
    from sqlalchemy import select

    from redsim.db.models import Job

    rows = session.execute(
        select(Job).where(Job.project_id == project_id, Job.type == PUSH_JOB_TYPE,
                          Job.status.in_(("queued", "running")))
    ).scalars().all()
    for job in rows:
        detail = job.detail or {}
        if detail.get("run_id") == campaign_run_id and detail.get("integration") == INTEGRATION:
            return job
    return None


def _newest_record(session: Any, run_id: str) -> Any | None:
    from sqlalchemy import select

    from redsim.db.models import Artifact

    return session.execute(
        select(Artifact).where(Artifact.run_id == run_id, Artifact.kind == "ml.run_record")
        .order_by(Artifact.created_at.desc(), Artifact.id.desc())
    ).scalars().first()


def _enqueue(job_id: str) -> str | None:
    """``integration_push.apply_async`` on the default queue; the Celery task id when the broker returned one."""
    from redsim.workers.tasks.integration_push import integration_push

    queued = integration_push.apply_async(args=[job_id], queue=PUSH_QUEUE)
    task_id = getattr(queued, "id", None)
    return str(task_id) if task_id is not None else None


def _delete_admission_rows(run_id: str, job_id: str) -> None:
    from redsim.db.models import Job, Run
    from redsim.db.session import get_session

    with get_session() as sess:
        job = sess.get(Job, job_id)
        if job is not None:
            sess.delete(job)
        run = sess.get(Run, run_id)
        if run is not None:
            sess.delete(run)


def create_foundry_push(
    *,
    run_id: str,
    body: FoundryPushRequest,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
    enqueue: bool = True,
    environ: Mapping[str, str] | None = None,
) -> IntegrationPushHandle:
    """Admission boundary for the Foundry push (register INTEROP-24; spec 6.7 invariant 4).

    Refusals, each a ``success=False`` ``integration.push`` row on the campaign
    run's chain: ``not_found`` (no run, no campaign record, a profile outside the
    project), ``llm_target_required`` (a probe run: k/n scorecards never enter a
    push, D9), ``integration_disabled`` (``501``: Foundry unset or misconfigured,
    with the rule), ``campaign_not_terminal``, ``score_unavailable`` (no
    ``ml.run_record``), ``fixture_not_exportable`` (D3), ``params_out_of_range``
    (``target_ref`` malformed or absent everywhere), ``auth_profile_required`` /
    ``auth_profile_kind_unsupported``, ``job_in_flight``. Then the admission row
    (host as the audit target so the allowlist verdict is on the row), the
    follow-up ``Run`` and ``Job``, the enqueue (``503 queue_unavailable`` with the
    rows removed when the broker refuses).
    """
    from redsim.db.models import AuthProfile, Job, Run, Target
    from redsim.db.session import get_session
    from redsim.safety import AuthorizationError, authorize
    from redsim.services.reports import ml_campaign_row

    allowlist = list(getattr(config, "target_allowlist", None) or [])
    # ``target_ref`` enters the context only once it validated as a Foundry rid: a malformed value (a URL, say)
    # never reaches an audit row (spec 21.8).
    context: dict[str, Any] = {"integration": INTEGRATION, "campaign_run_id": run_id, "payload": body.payload,
                               "target_ref": None, "target_ref_requested": body.target_ref is not None,
                               "auth_profile_id": body.auth_profile_id}

    with get_session() as sess:
        run = sess.get(Run, run_id)
        if run is None:
            raise ApiError(NOT_FOUND, "run not found")
        project_id = str(run.project_id)

        def refuse(exc: ApiError, **more: Any) -> NoReturn:
            _refuse(audit_writer, actor=actor, project_id=project_id, run_id=run_id, exc=exc, **context, **more)

        try:
            from redsim.services.ml_llm import LLM_SCANNER
        except ImportError:  # pragma: no cover - the llm-api module is on this tree
            LLM_SCANNER = "ml.llm_probe"
        if run.scanner == LLM_SCANNER:
            refuse(ApiError(LLM_TARGET_REQUIRED, "an LLM probe run carries a k/n scorecard, never an MRI (D9); "
                            "nothing is pushed to Foundry for it", run_id=run_id, scanner=str(run.scanner)))
        campaign = ml_campaign_row(sess, run_id)
        if campaign is None:
            refuse(ApiError(NOT_FOUND, "campaign record not found: only a campaign or verify run has a scorecard "
                            "to push"))
        try:
            settings = FoundrySettings.from_env(environ, allowlist=allowlist)
        except FoundryMisconfigured as exc:
            refuse(ApiError(INTEGRATION_DISABLED, f"the Foundry integration is misconfigured: {exc.reason}",
                            phase="B", integration=INTEGRATION, rule=exc.rule, reason="misconfigured"))
        if settings is None:
            refuse(ApiError(INTEGRATION_DISABLED, f"the Foundry integration is not enabled in this deployment "
                            f"({FOUNDRY_URL_ENV} is unset; spec 27 rule 1)", phase="B", integration=INTEGRATION,
                            reason="disabled"))
        context["host"] = settings.host
        if run.status not in _TERMINAL:
            refuse(ApiError(CAMPAIGN_NOT_TERMINAL, f"the campaign is {run.status!r}; a scorecard is pushed only "
                            "from a terminal run", status=str(run.status)), run_status=str(run.status))
        record = _newest_record(sess, run_id)
        if record is None:
            refuse(ApiError(SCORE_UNAVAILABLE, "the run has no ml.run_record artifact; there is no scorecard to "
                            "push", status=str(run.status), reasons=["no_run_record"]))
        record_sha256 = str(record.sha256)
        context["record_sha256"] = record_sha256
        target = sess.get(Target, run.target_id) if run.target_id else None
        if is_fixture_campaign(getattr(target, "detail", None), campaign.get("config")):
            refuse(ApiError(FIXTURE_NOT_EXPORTABLE, "runs on a CI fixture target are never pushed (D3, spec 14.7)",
                            target_id=str(run.target_id) if run.target_id else None))
        try:
            requested_ref = validate_target_ref(body.target_ref)
        except ValueError as exc:
            refuse(ApiError(PARAMS_OUT_OF_RANGE, str(exc), field="target_ref"), target_ref_problem="malformed")
        target_ref = requested_ref or settings.dataset_rid
        if target_ref is None:
            refuse(ApiError(PARAMS_OUT_OF_RANGE, "no Foundry dataset to write into: name target_ref in the body or "
                            "set REDSIM_INTEGRATION_FOUNDRY_DATASET_RID on the worker", field="target_ref",
                            reason="target_ref_required"))
        context["target_ref"] = target_ref
        profile_id = body.auth_profile_id.strip()
        if not profile_id:
            refuse(ApiError(AUTH_PROFILE_REQUIRED, "auth_profile_id is required: the Foundry token lives in a "
                            "bearer AuthProfile, never in the request or the environment", field="auth_profile_id"))
        profile = sess.get(AuthProfile, profile_id)
        if profile is None or str(profile.project_id) != project_id:
            refuse(ApiError(NOT_FOUND, f"auth profile {profile_id!r} is not in this project", field="auth_profile_id"))
        if str(profile.kind) != PUSH_AUTH_KIND:
            refuse(ApiError(AUTH_PROFILE_KIND_UNSUPPORTED, f"auth profile kind {profile.kind!r} cannot carry a "
                            f"Foundry token; the REST API takes Authorization: Bearer (kind {PUSH_AUTH_KIND!r})",
                            field="auth_profile_id", kind=str(profile.kind), allowed=[PUSH_AUTH_KIND]))
        in_flight = _in_flight_push(sess, project_id=project_id, campaign_run_id=run_id)
        if in_flight is not None:
            refuse(ApiError(JOB_IN_FLIGHT, "a Foundry push for this run is already queued or running",
                            run_id=in_flight.run_id, job_id=in_flight.id), push_run_id=in_flight.run_id)

        push_run_id = f"run-{uuid4().hex[:12]}"
        job_id = f"job-{uuid4().hex[:12]}"
        job_detail: IntegrationPushJobDetail = {
            "run_id": run_id,
            "integration": INTEGRATION,
            "target_ref": target_ref,
            "payload": body.payload,
            "auth_profile_id": profile_id,
            "host": settings.host,
            "record_sha256": record_sha256,
            "campaign_kind": str(campaign.get("kind") or "attack"),
            "requested_by": actor,
        }
        # Spec 6.7 invariant 4 / 27.4: the chained event precedes the rows and the enqueue. The Foundry host
        # is the audit target so the allowlist verdict is on the row (spec 5.11); detail is ids and digests.
        try:
            authorize(
                ADMISSION_ACTION, settings.host, allowlist=allowlist, actor=actor, writer=audit_writer,
                project_id=project_id, run_id=push_run_id,
                detail=scrub_detail({
                    **context, "run_id": push_run_id, "job_id": job_id, "target_id": run.target_id,
                    "campaign_kind": job_detail["campaign_kind"], **settings.redacted(),
                }),
            )
        except AuthorizationError as exc:
            raise ApiError(ENDPOINT_NOT_ALLOWLISTED, str(exc), host=settings.host) from exc
        sess.add(Run(
            id=push_run_id, project_id=project_id, target_id=run.target_id, mode="api", status="queued",
            scanner=PUSH_SCANNER, created_by=actor,
            stage_table={"stage": None, "stages_done": [], "jobs": {}, "kind": PUSH_RUN_KIND,
                         "parent_run_id": run_id, "integration": INTEGRATION},
        ))
        sess.flush()
        sess.add(Job(id=job_id, run_id=push_run_id, project_id=project_id, type=PUSH_JOB_TYPE, status="queued",
                     created_by=actor, detail=dict(job_detail)))
        sess.flush()

    if enqueue:
        try:
            task_id = _enqueue(job_id)
        except Exception as exc:  # noqa: BLE001 - the broker refused: the admission is undone, never half-done
            logger.warning("enqueue failed for integration.push job %s; admission rows removed", job_id,
                           exc_info=True)
            _delete_admission_rows(push_run_id, job_id)
            raise ApiError(QUEUE_UNAVAILABLE, "the job queue refused the push; nothing was admitted",
                           reason=type(exc).__name__) from exc
        if task_id is not None:
            with get_session() as sess:
                job = sess.get(Job, job_id)
                if job is not None:
                    job.celery_task_id = task_id
    return IntegrationPushHandle(run_id=push_run_id, job_ids=[job_id], campaign_run_id=run_id,
                                 integration=INTEGRATION, target_ref=target_ref)


__all__ = [
    "ADMISSION_ACTION",
    "EXECUTE_ACTION",
    "INTEGRATIONS",
    "LATTICE_REASON",
    "LATTICE_STATUS",
    "PUSH_AUTH_KIND",
    "PUSH_JOB_TYPE",
    "PUSH_PAYLOADS",
    "PUSH_QUEUE",
    "PUSH_RUN_KIND",
    "PUSH_SCANNER",
    "PUSH_TASK_NAME",
    "FoundryPushRequest",
    "IntegrationPushHandle",
    "IntegrationPushJobDetail",
    "create_foundry_push",
    "foundry_settings_or_none",
    "is_fixture_campaign",
    "roster",
]
