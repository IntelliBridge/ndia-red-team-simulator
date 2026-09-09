"""Celery task ``redsim.integration_push``: one Foundry scorecard push (spec 27.3; register INTEROP-24, -25).

Plan 12 wave B3, ``atlas-foundry`` track. The task declares ``queue="default"``
because that pool is the only one with outbound HTTPS egress (spec 10.8, 27
rule 2); nothing here loads model bytes, so the credential-free ``scans`` pool
is not involved. In order, every step a durable row or a typed failure and
never a fake result:

1. **Configuration**: ``FoundrySettings.from_env`` on the worker. Unset or
   misconfigured Foundry fails the job (``integration_disabled`` /
   ``integration_misconfigured``); the admission checked the same, the worker
   re-checks because the environment is the worker's.
2. **The record**: the campaign's newest ``ml.run_record`` artifact, digest
   checked against both the stored row and the digest the admission recorded
   (``record_changed`` otherwise), validated through the frozen
   ``CampaignRecord``. A fixture target's run is refused here too (D3).
3. **The payload**: ``build_scorecard_payload`` then ``assert_push_payload``
   (the D9 / D3 guard). The bytes that are about to leave are stored first as
   the ``ml.integration.payload`` artifact so the evidence of what left is on
   the run before any request is made.
4. **The credential**: the bearer token is decrypted from the named
   ``AuthProfile`` at this point only, handed to the client and dropped with
   it. It reaches no row, no artifact, no log.
5. **The push**: ``FoundryClient.push_files`` (open transaction, upload the
   payload and its rows, commit). A 4xx / 5xx or a transport error at any step
   is ``foundry_push_failed`` with the step and status on the
   ``integration.push.execute`` ``success=False`` row; nothing is retried
   (``max_retries=0``).
6. **The receipt**: ``ml.integration.receipt`` artifact, the
   ``integration.push.execute`` row (host, dataset rid, transaction rid, the
   payload and rows digests, statuses, outcome; never a token, never a URL)
   and ``job.complete``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NoReturn

from redsim.workers.celery_app import app
from redsim.workers.tasks.ml_campaign import (
    DatabaseArtifactSink,
    _AuditEmitter,
    _publish_stage,
    artifact_kind,
)

if TYPE_CHECKING:
    from celery import Task
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

TASK_NAME = "redsim.integration_push"
QUEUE = "default"
#: Run-relative artifact names the task writes and their kinds (additive to the spec 5.8 table).
PUSH_ARTIFACT_KINDS: dict[str, str] = {
    "integrations/foundry/scorecard.json": "ml.integration.payload",
    "integrations/foundry/rows.jsonl": "ml.integration.rows",
    "integrations/foundry/receipt.json": "ml.integration.receipt",
}
STAGES: tuple[str, ...] = ("configure", "load_record", "build_payload", "push", "receipt")


def _now() -> datetime:
    return datetime.now(UTC)


class IntegrationPushRefused(RuntimeError):
    """A typed push failure: the job fails with ``code`` and nothing is faked.

    ``code`` is what ``Job.error`` and the ``job.complete`` row carry
    (``integration_disabled``, ``integration_misconfigured``, ``record_unavailable``,
    ``record_changed``, ``record_invalid``, ``fixture_not_exportable``,
    ``payload_refused``, ``auth_profile_missing``, ``auth_profile_unreadable``,
    ``auth_profile_kind_unsupported``, ``target_ref_missing``, ``foundry_push_failed``).
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message)
        self.code = code
        self.reason = message

    def __str__(self) -> str:
        return f"{self.code}: {self.reason}"


def push_artifact_kind(name: str) -> str:
    return PUSH_ARTIFACT_KINDS.get(name) or artifact_kind(name)


class IntegrationArtifactSink(DatabaseArtifactSink):
    """The campaign sink with the integration artifact kinds on top of the spec 5.8 table."""

    @staticmethod
    def _kind(name: str) -> str:
        return push_artifact_kind(name)


class _Stages:
    """``Run.stage_table`` in the spec 6.5 shape for the five push stages; every transition is published."""

    def __init__(self, session: Session, *, run_id: str, job_id: str, job_type: str) -> None:
        self.session, self.run_id, self.job_id, self.job_type = session, run_id, job_id, job_type
        self.done: list[str] = []
        self._cursor = _now().isoformat()

    def _run(self) -> Any:
        from redsim.db.models import Run

        run = self.session.get(Run, self.run_id)
        return None if run is None or run.status in {"succeeded", "failed", "cancelled"} else run

    def _store(self, stage: str, status: str, *, error: str | None = None, completeness: str | None = None) -> None:
        run = self._run()
        now = _now().isoformat()
        if run is not None:
            table = dict(run.stage_table or {})
            stages = dict(table.get("stages") or {})
            previous = stages.get(stage) if isinstance(stages.get(stage), dict) else {}
            stages[stage] = {"status": status, "started_at": (previous or {}).get("started_at") or self._cursor,
                             "finished_at": now, "job_id": self.job_id}
            jobs = dict(table.get("jobs") or {})
            jobs[self.job_id] = {**dict(jobs.get(self.job_id) or {}), "type": self.job_type,
                                 "status": "running" if status == "succeeded" else status, "stage": stage}
            table.update({"stage": stage, "stages_done": list(self.done), "stages": stages, "jobs": jobs,
                          "kind": "integration_push"})
            if completeness is not None:
                table["completeness"] = completeness
            if error is not None:
                table["error"] = error
            run.stage_table = table
            self.session.commit()
        self._cursor = now
        _publish_stage(self.run_id, self.job_id, stage, status)

    def completed(self, stage: str) -> None:
        if stage not in self.done:
            self.done.append(stage)
        self._store(stage, "succeeded")

    def failed(self, stage: str, error: str) -> None:
        self._store(stage, "failed", error=error, completeness="partial")

    def finish(self) -> None:
        run = self._run()
        if run is None:
            return
        table = dict(run.stage_table or {})
        stages = dict(table.get("stages") or {})
        for name in STAGES:
            stages.setdefault(name, {"status": "skipped", "started_at": None, "finished_at": _now().isoformat(),
                                     "job_id": self.job_id})
        table.update({"stages": stages, "stages_done": list(self.done), "completeness": "complete"})
        run.stage_table = table
        self.session.commit()


def _fixture_flagged(record: Any) -> bool:
    """D3: the record's target metadata, config snapshot or model manifest says this is a fixture."""
    target_meta = dict(record.target.metadata or {})
    snapshot = dict(record.config.target_snapshot or {})
    manifest = dict(record.provenance.model_manifest or {}) if record.provenance is not None else {}
    return any(bool(block.get("fixture") or block.get("fixture_only")) for block in (target_meta, snapshot, manifest))


@app.task(name=TASK_NAME, bind=True, max_retries=0, queue=QUEUE)
def integration_push(self: Task, job_id: str) -> dict[str, Any]:
    """One Foundry scorecard push: configure, load the record, build and guard the payload, push, receipt."""
    from redsim.config import load_config
    from redsim.db.models import Job
    from redsim.integrations import EXECUTE_ACTION, INTEGRATION, PUSH_AUTH_KIND
    from redsim.integrations.foundry import (
        FoundryClient,
        FoundryMisconfigured,
        FoundryPushFailed,
        FoundrySettings,
        PayloadRefused,
        assert_push_payload,
        build_scorecard_payload,
        scorecard_files,
        scrub_detail,
        sha256_hex,
        validate_target_ref,
    )
    from redsim.ml.schema import CampaignRecord
    from redsim.services.auth_profiles import resolve_auth_for_scan
    from redsim.services.reports import load_run_record
    from redsim.workers.bootstrap import task_context

    with task_context(job_id, task=self, commit_running=True) as ctx:
        if ctx.skip:
            return {"job_id": job_id, "skipped": True}
        audit_writer = ctx.audit_writer
        assert audit_writer is not None
        job = ctx.session.get(Job, job_id)
        if job is None:
            raise RuntimeError(f"job {job_id} disappeared")
        detail: Mapping[str, Any] = dict(job.detail or {})
        config = load_config()
        allowlist = list(getattr(config, "target_allowlist", None) or [])
        emitter = _AuditEmitter(
            writer=audit_writer, allowlist=allowlist, job_id=job_id, job_type=str(job.type), run_id=ctx.run_id,
            project_id=ctx.project_id, requested_by=job.created_by,
        )
        sink = IntegrationArtifactSink(ctx.session, ctx.blob_store, run_id=ctx.run_id, project_id=ctx.project_id)
        stages = _Stages(ctx.session, run_id=ctx.run_id, job_id=job_id, job_type=str(job.type))
        campaign_run_id = str(detail.get("run_id") or "")
        integration = str(detail.get("integration") or "")
        base_detail: dict[str, Any] = {"integration": integration or None, "campaign_run_id": campaign_run_id or None,
                                       "target_ref": detail.get("target_ref"), "payload": detail.get("payload"),
                                       "record_sha256": detail.get("record_sha256")}
        started = _now()

        def complete(status: str, *, success: bool, error_class: str | None = None,
                     extra: Mapping[str, Any] | None = None) -> None:
            emitter.emit("job.complete", scrub_detail({
                "status": status, "n_artifacts": len(sink.ids), "stages_done": list(stages.done),
                "duration_s": round((_now() - started).total_seconds(), 3), "error_class": error_class,
                **base_detail, **dict(extra or {}),
            }), success=success)

        def fail(code: str, message: str, *, stage: str, execute: Mapping[str, Any] | None = None) -> NoReturn:
            emitter.emit(EXECUTE_ACTION, scrub_detail({
                **base_detail, "outcome": "failed", "reason": code, **dict(execute or {}),
            }), success=False)
            stages.failed(stage, f"{code}: {message}")
            complete("failed", success=False, error_class=code)
            ctx.session.commit()
            raise IntegrationPushRefused(code, message[:500])

        # 1. Configuration: the worker's own environment decides; nothing is assumed from the admission.
        if integration != INTEGRATION:
            fail("integration_unknown", f"no client for integration {integration!r}", stage="configure")
        try:
            settings = FoundrySettings.from_env(allowlist=allowlist)
        except FoundryMisconfigured as exc:
            fail("integration_misconfigured", exc.reason, stage="configure", execute={"rule": exc.rule})
        if settings is None:
            fail("integration_disabled", "REDSIM_INTEGRATION_FOUNDRY_URL is unset on this worker; the integration "
                 "is off by default (spec 27 rule 1)", stage="configure")
        base_detail["host"] = settings.host
        try:
            target_ref = validate_target_ref(detail.get("target_ref")) or settings.dataset_rid
        except ValueError as exc:
            fail("target_ref_missing", str(exc), stage="configure")
        if target_ref is None:
            fail("target_ref_missing", "no Foundry dataset rid in the job detail or the worker environment",
                 stage="configure")
        base_detail["target_ref"] = target_ref
        stages.completed("configure")

        # 2. The record, digest checked twice (the artifact row and the admission-time digest).
        if not campaign_run_id:
            fail("record_unavailable", "the job names no campaign run", stage="load_record")
        try:
            payload_dict, record_sha256 = load_run_record(ctx.session, ctx.blob_store, campaign_run_id)
        except LookupError as exc:
            fail("record_unavailable", str(exc), stage="load_record")
        except ValueError as exc:
            fail("record_changed", str(exc), stage="load_record")
        admitted_sha = str(detail.get("record_sha256") or "")
        if admitted_sha and admitted_sha != record_sha256:
            fail("record_changed", "the ml.run_record digest differs from the one recorded at admission",
                 stage="load_record", execute={"record_sha256_now": record_sha256})
        base_detail["record_sha256"] = record_sha256
        try:
            record = CampaignRecord.model_validate(payload_dict)
        except Exception as exc:  # noqa: BLE001 - pydantic ValidationError and friends: the record is the authority
            fail("record_invalid", f"the run record does not validate as a CampaignRecord ({type(exc).__name__})",
                 stage="load_record")
        if _fixture_flagged(record):
            fail("fixture_not_exportable", "runs on a CI fixture target are never pushed (D3, spec 14.7)",
                 stage="load_record")
        stages.completed("load_record")

        # 3. The payload and its guard; the bytes that are about to leave are evidence on the run first.
        payload = build_scorecard_payload(record, generated_at=_now())
        try:
            assert_push_payload(payload)
        except PayloadRefused as exc:
            fail("payload_refused", "; ".join(exc.problems)[:500], stage="build_payload",
                 execute={"problems": exc.problems[:20], "n_problems": len(exc.problems)})
        files = scorecard_files(payload)
        digests: dict[str, str] = {}
        for path, data, content_type in files:
            name = "integrations/foundry/" + path.rsplit("/", 1)[-1]
            sink.put(name, data, content_type)
            digests[path.rsplit("/", 1)[-1]] = sha256_hex(data)
        payload_sha256 = digests["scorecard.json"]
        rows_sha256 = digests["rows.jsonl"]
        base_detail.update({"payload_sha256": payload_sha256, "rows_sha256": rows_sha256,
                            "n_rows": len(payload.get("rows") or []),
                            "payload_artifact_id": sink.ids.get("integrations/foundry/scorecard.json")})
        stages.completed("build_payload")

        # 4. The credential, decrypted now and only now.
        auth_profile_id = str(detail.get("auth_profile_id") or "")
        try:
            auth = resolve_auth_for_scan(ctx.session, auth_profile_id)
        except LookupError:
            fail("auth_profile_missing", f"auth profile {auth_profile_id!r} no longer exists", stage="push")
        except Exception as exc:  # noqa: BLE001 - AuthProfilesKeyError and friends: never an anonymous push
            fail("auth_profile_unreadable", f"the Foundry token could not be decrypted ({type(exc).__name__})",
                 stage="push")
        if str(auth.get("kind")) != PUSH_AUTH_KIND:
            fail("auth_profile_kind_unsupported", f"auth profile kind {auth.get('kind')!r} is not "
                 f"{PUSH_AUTH_KIND!r}", stage="push")
        token = str(auth.get("secret") or "")
        del auth
        if not token:
            fail("auth_profile_unreadable", "the auth profile holds an empty secret", stage="push")

        # 5. The push: one transaction, two files, commit. No retry into a fake success.
        try:
            with FoundryClient(settings, token) as client:
                receipt = client.push_files(target_ref, files)
        except FoundryPushFailed as exc:
            fail("foundry_push_failed", str(exc), stage="push", execute=exc.outcome())
        finally:
            token = ""
            del token
        stages.completed("push")

        # 6. The receipt, the execute row and job.complete.
        receipt_dict = receipt.as_dict()
        receipt_bytes = (json.dumps({**receipt_dict, "payload_sha256": payload_sha256, "rows_sha256": rows_sha256,
                                     "record_sha256": record_sha256, "campaign_run_id": campaign_run_id},
                                    sort_keys=True, indent=2) + "\n").encode("utf-8")
        sink.put("integrations/foundry/receipt.json", receipt_bytes, "application/json")
        execute_detail = scrub_detail({
            **base_detail, **receipt_dict, "receipt_artifact_id": sink.ids.get("integrations/foundry/receipt.json"),
        })
        emitter.emit(EXECUTE_ACTION, execute_detail, success=True)
        stages.completed("receipt")
        stages.finish()
        complete("succeeded", success=True, extra={"transaction_rid": receipt.transaction_rid,
                                                    "n_files": len(receipt.files)})
        logger.info("integration.push completed run=%s job=%s host=%s files=%d", ctx.run_id, job_id,
                    settings.host, len(receipt.files))
        return {
            "run_id": ctx.run_id, "job_id": job_id, "status": "succeeded", "integration": INTEGRATION,
            "campaign_run_id": campaign_run_id, "target_ref": target_ref, "transaction_rid": receipt.transaction_rid,
            "payload_sha256": payload_sha256, "rows_sha256": rows_sha256, "http_statuses": list(receipt.statuses),
            "stages_done": list(stages.done),
        }


__all__ = [
    "PUSH_ARTIFACT_KINDS",
    "QUEUE",
    "STAGES",
    "TASK_NAME",
    "IntegrationArtifactSink",
    "IntegrationPushRefused",
    "integration_push",
    "push_artifact_kind",
]
