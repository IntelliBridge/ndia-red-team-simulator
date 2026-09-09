"""Batch admission, roll-up and cancel for adversarial-ML campaigns (register BULK-03..09, -15).

Plan 12 wave B3, ``bulk-service-routes``. A batch is N single-run admissions
under one id, never a new kind of run: every member goes through the same
boundary the single routes use (:func:`redsim.services.ml_campaigns.create_attack_campaign`
for a ``campaign`` batch, :func:`redsim.services.ml_campaigns.create_verify_campaign`
for a ``verify`` batch), so each member writes its own ``attack.run`` /
``verify.replay`` admission row before its ``Run`` / ``Job`` / ``ml_campaigns``
rows exist and refuses with the same spec 17.3 codes. The batch adds, in this
order: a write-free pre-check of what the batch can see without admitting
anything (member cap, target resolution, one modality per batch), one
``batch.create`` audit row on the project chain, the ``ml_batches`` row, then
the members. Per-member refusals are collected (the member's own
``success=False`` row already names the code) and survive on the batch row;
when no member was admitted the batch answers ``422 batch_member_refused`` with
``members: [{target_id, code, message}]``.

``batch_id`` is stamped onto ``ml_campaigns.batch_id``, ``Run.stage_table`` and
``Job.detail`` right after each member's admission (``create_attack_campaign``
has no ``batch_id`` keyword on this tree; the stamp is a follow-up update in
the service's own transaction, noted in the wave report).

The modality rule (BULK-04, D9): a batch is one modality. Targets spanning
several are refused ``422 batch_modality_mismatch`` with ``groups:
{modality: [target ids]}`` so the client resubmits per modality; nothing here
ever aggregates an MRI across members (the roll-up carries statuses and links
into each member's scorecard, never a number).

Capacity (BULK-09, -20..22): before each member the service calls
``redsim.services.ml_capacity.admit_or_defer(session, project, kind)`` when
that module exists (the ``bulk-upload-capacity-cli`` track); a deferral admits
the member with ``enqueue=False`` and ``Job.detail.deferred = true`` so the
capacity dispatcher picks it up, and a refusal (a spent daily budget) is a
collected member refusal. Without the module every member is admitted and
enqueued at once. ``max_parallel`` on the request is a client-side bound on top
of that: members beyond it are admitted deferred.

Bulk verify (BULK-15; owner decision BULK-16): ONE defended verify run per
(baseline run, defense, params) whose ``Job.detail.finding_ids`` lists every
selected finding of the baseline run, admitted through ``create_verify_campaign``
on the first selected finding (which flips to ``fixing`` and owns
``Job.detail.finding_id``), with one ``verify.replay`` row per additional finding
naming the shared run. Projecting the shared record onto each finding is the
worker's (``_project_verify`` loops ``finding_ids``); until that lands the batch
view reports per finding whether its ``ml.verify`` block names the shared run
(``projected``), so nothing is claimed that was not written.

Status roll-up (BULK-06): ``queued`` (every member queued), ``running`` (any
member running, or a mix of queued and terminal), ``succeeded`` (every member
succeeded and none refused), ``failed`` (every admitted member failed, or
nothing was admitted), ``cancelled`` (every member cancelled) and ``partial``
(any other terminal mix, including succeeded members beside refused ones). The
``ml_batches.status`` column holds the roll-up as last written by admission or
cancel; the view recomputes it from the member runs on every read.

Nothing here imports an ML library.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NoReturn
from uuid import uuid4

from redsim.api.errors import (
    BATCH_MEMBER_REFUSED,
    BATCH_MODALITY_MISMATCH,
    BATCH_TOO_LARGE,
    NOT_FOUND,
    PARAMS_OUT_OF_RANGE,
    QUEUE_UNAVAILABLE,
    RUN_TERMINAL,
    ApiError,
)
from redsim.safety import authorize
from redsim.services.ml_campaigns import (
    _campaign_table,
    _refuse,
    create_attack_campaign,
    create_verify_campaign,
)
from redsim.services.runs import TERMINAL_RUN_STATUSES, TerminalRunError, cancel_run

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig

logger = logging.getLogger(__name__)

#: ``ml_batches.kind`` values this service writes (``upload`` is the bulk-upload track's).
BATCH_KIND_CAMPAIGN = "campaign"
BATCH_KIND_VERIFY = "verify"
BATCH_KINDS: frozenset[str] = frozenset({BATCH_KIND_CAMPAIGN, BATCH_KIND_VERIFY})
#: Roll-up vocabulary (BULK-06).
BATCH_STATUSES: tuple[str, ...] = ("queued", "running", "succeeded", "partial", "failed", "cancelled")
#: Member cap (BULK-03); ``REDSIM_ML_BATCH_MAX_MEMBERS`` raises or lowers it per deployment.
DEFAULT_BATCH_MAX_MEMBERS = 20
BATCH_MAX_MEMBERS_ENV = "REDSIM_ML_BATCH_MAX_MEMBERS"
#: Target kinds a campaign batch may name (spec 5.2), the same set the single admission accepts.
_ML_KINDS = frozenset({"ml_model_artifact", "ml_model_endpoint"})
#: Campaign body keys a batch request must not carry (the batch supplies the target; reruns are single-run).
_BATCH_FORBIDDEN_CAMPAIGN_KEYS = frozenset({"target_id", "parent_run_id"})
#: Finding statuses a bulk verify selects by default (spec 6.4: open or failed findings are re-measured).
_VERIFY_SELECTABLE_STATUSES = frozenset({"open", "failed"})
_VERIFY_SKIP_REASONS: dict[str, str] = {
    "fixing": "a verify is already in flight for this finding",
    "false_positive": "dismissed as a false positive",
    "dismissed": "dismissed",
    "fixed": "already fixed; pass include_fixed to re-measure",
}


def batch_max_members() -> int:
    """The member cap in force (``REDSIM_ML_BATCH_MAX_MEMBERS``, default :data:`DEFAULT_BATCH_MAX_MEMBERS`)."""
    raw = os.environ.get(BATCH_MAX_MEMBERS_ENV)
    if raw is None or not raw.strip():
        return DEFAULT_BATCH_MAX_MEMBERS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_BATCH_MAX_MEMBERS
    return value if value >= 1 else DEFAULT_BATCH_MAX_MEMBERS


def new_batch_id() -> str:
    return f"batch-{uuid4().hex[:12]}"


def batch_status_url(batch_id: str) -> str:
    return f"/v1/campaigns/batch/{batch_id}"


def _now() -> datetime:
    return datetime.now(UTC)


def _as_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _iso(value: Any) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else None


def _envelope_fields(exc: ApiError) -> dict[str, Any]:
    """The refusal's 17.3 envelope fields beside ``code`` / ``message`` (ids, groups, caps, counts)."""
    return {k: v for k, v in exc.detail.items() if k not in {"code", "message"}}


# ---------------------------------------------------------------------------
# Handles
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BatchMember:
    """One admitted member: the run and its jobs, plus the id the member was admitted for."""

    run_id: str
    job_ids: list[str]
    target_id: str | None = None
    defense: dict[str, Any] | None = None
    deferred: bool = False
    primary_finding_id: str | None = None

    def to_response(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "run_id": self.run_id, "job_ids": list(self.job_ids), "status_url": f"/v1/runs/{self.run_id}",
            "deferred": self.deferred,
        }
        if self.target_id is not None:
            out["target_id"] = self.target_id
        if self.defense is not None:
            out["defense"] = dict(self.defense)
        if self.primary_finding_id is not None:
            out["primary_finding_id"] = self.primary_finding_id
        return out


@dataclass(frozen=True)
class BatchHandle:
    """The admission result of a batch (the 202 body); live status comes from :func:`batch_view`."""

    batch_id: str
    kind: str
    project_id: str
    modality: str | None
    status: str
    members: list[BatchMember]
    refused: list[dict[str, Any]] = field(default_factory=list)
    config_hash: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_response(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "batch_id": self.batch_id,
            "kind": self.kind,
            "project_id": self.project_id,
            "modality": self.modality,
            "status": self.status,
            "status_url": batch_status_url(self.batch_id),
            "members": [m.to_response() for m in self.members],
            "run_ids": [m.run_id for m in self.members],
            "refused": [dict(r) for r in self.refused],
            "n_members": len(self.members),
            "n_refused": len(self.refused),
            "config_hash": self.config_hash,
        }
        body.update(self.extra)
        return body


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _load_batch(session: Session, batch_id: str) -> Any:
    from redsim.db.models import MlBatch

    row = session.get(MlBatch, batch_id)
    if row is None:
        raise LookupError(f"batch not found: {batch_id}")
    return row


def batch_project_id(batch_id: str) -> str:
    """The project a batch belongs to (``LookupError`` for an unknown batch); the routes gate on it."""
    from redsim.db.session import get_session

    with get_session() as sess:
        return str(_load_batch(sess, batch_id).project_id)


def _stamp_batch_on_member(sess: Session, *, batch_id: str, run_id: str, job_ids: Sequence[str],
                           deferred: bool, extra_job_detail: Mapping[str, Any] | None = None,
                           extra_stage: Mapping[str, Any] | None = None) -> None:
    """Write ``batch_id`` onto the member's campaign row, ``Run.stage_table`` and ``Job.detail``."""
    from redsim.db.models import Job, Run

    table = _campaign_table(sess)
    sess.execute(table.update().where(table.c.run_id == run_id).values(batch_id=batch_id))
    run = sess.get(Run, run_id)
    if run is not None:
        stage_table = dict(run.stage_table or {})
        stage_table["batch_id"] = batch_id
        if deferred:
            stage_table["deferred"] = True
        stage_table.update(dict(extra_stage or {}))
        run.stage_table = stage_table
    for job_id in job_ids:
        job = sess.get(Job, job_id)
        if job is None:
            continue
        detail = dict(job.detail or {})
        detail["batch_id"] = batch_id
        if deferred:
            detail["deferred"] = True
        detail.update(dict(extra_job_detail or {}))
        job.detail = detail


def _capacity_module() -> Any | None:
    """``redsim.services.ml_capacity`` when the ``bulk-upload-capacity-cli`` track's module is on the tree."""
    try:
        from redsim.services import ml_capacity
    except ImportError:
        return None
    except Exception:  # noqa: BLE001 - a sibling module that fails to import never blocks an admission
        logger.warning("redsim.services.ml_capacity failed to import; admitting without deferral", exc_info=True)
        return None
    return ml_capacity


def _capacity_decision(project_id: str, kind: str, *, actor: str, audit_writer: AuditWriter, **context: Any,
                       ) -> tuple[bool, ApiError | None, Any | None]:
    """``(deferred, refusal, decision)`` from ``ml_capacity.admit_or_defer`` when the module exists.

    Absent module: admitted, never deferred, ``decision`` ``None``. A typed refusal (a spent daily
    budget, ``429``; the capacity service writes its own ``success=False`` row when handed the writer)
    is returned so the caller collects it as a member refusal; any other failure of the capacity check
    is logged and the member is admitted (capacity is a bound, not an evidence rule). ``context`` (ids
    and counts only) travels onto the refusal row.
    """
    ml_capacity = _capacity_module()
    admit = getattr(ml_capacity, "admit_or_defer", None) if ml_capacity is not None else None
    if not callable(admit):
        return False, None, None
    from redsim.db.models import Project
    from redsim.db.session import get_session

    try:
        with get_session() as sess:
            project = sess.get(Project, project_id)
            result = admit(sess, project if project is not None else project_id, kind, actor=actor,
                           audit_writer=audit_writer, **context)
    except ApiError as exc:
        return False, exc, None
    except Exception:  # noqa: BLE001 - a capacity check that cannot run never blocks an admission
        logger.warning("capacity check failed for project %s; admitting without deferral", project_id,
                       exc_info=True)
        return False, None, None
    if isinstance(result, Mapping):
        return bool(result.get("deferred", False)), None, None
    if isinstance(result, (str, bool)):
        return result == "deferred", None, None
    return bool(getattr(result, "deferred", False)), None, result


def _mark_deferred(sess: Session, *, run_id: str, job_id: str, decision: Any | None) -> None:
    """The capacity service's deferral stamp (``Job.detail.deferred`` plus its counts) when it can write one."""
    ml_capacity = _capacity_module()
    mark = getattr(ml_capacity, "mark_deferred", None) if ml_capacity is not None else None
    if decision is None or not callable(mark):
        return
    try:
        mark(sess, run_id=run_id, job_id=job_id, decision=decision)
    except Exception:  # noqa: BLE001 - the batch's own deferred stamp below still marks the member
        logger.warning("mark_deferred failed for job %s", job_id, exc_info=True)


def rollup_status(member_statuses: Sequence[str], *, n_refused: int = 0) -> str:
    """The batch roll-up from its member run statuses (module docstring; BULK-06)."""
    statuses = list(member_statuses)
    if not statuses:
        return "failed" if n_refused else "queued"
    if all(s == "queued" for s in statuses):
        return "queued"
    if not all(s in TERMINAL_RUN_STATUSES for s in statuses):
        return "running"
    if all(s == "cancelled" for s in statuses):
        return "cancelled"
    if all(s == "succeeded" for s in statuses):
        return "succeeded" if n_refused == 0 else "partial"
    if all(s == "failed" for s in statuses):
        return "failed"
    return "partial"


# ---------------------------------------------------------------------------
# Campaign batches (BULK-03..05, -09)
# ---------------------------------------------------------------------------


def _target_modality(target: Any) -> str | None:
    detail = _as_mapping(getattr(target, "detail", None))
    manifest = _as_mapping(detail.get("manifest"))
    value = detail.get("modality") or manifest.get("modality")
    return str(value) if isinstance(value, str) and value else None


def _resolve_batch_targets(sess: Session, project_id: str, target_ids: Sequence[str]) -> list[tuple[Any, str | None]]:
    """The targets of the batch in request order; ``not_found`` names the ids the project cannot see."""
    from redsim.db.models import Target

    resolved: list[tuple[Any, str | None]] = []
    missing: list[str] = []
    for target_id in target_ids:
        target = sess.get(Target, target_id)
        if target is None or target.project_id != project_id or target.kind not in _ML_KINDS:
            missing.append(target_id)
            continue
        resolved.append((target, _target_modality(target)))
    if missing:
        raise ApiError(NOT_FOUND, "model not found", target_ids=missing)
    return resolved


def _validate_target_ids(target_ids: Any) -> list[str]:
    if not isinstance(target_ids, list) or not target_ids or not all(isinstance(t, str) and t for t in target_ids):
        raise ApiError(PARAMS_OUT_OF_RANGE, "target_ids must be a non-empty list of model ids", field="target_ids")
    if len(set(target_ids)) != len(target_ids):
        raise ApiError(PARAMS_OUT_OF_RANGE, "target_ids must not repeat a model", field="target_ids")
    return list(target_ids)


def _check_member_cap(n_members: int, max_members: int, *, what: str) -> None:
    if n_members > max_members:
        raise ApiError(
            BATCH_TOO_LARGE,
            f"a batch admits at most {max_members} {what} ({BATCH_MAX_MEMBERS_ENV}); {n_members} requested",
            field="target_ids" if what == "models" else "defenses", cap=max_members, requested=n_members,
        )


def _validate_max_parallel(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ApiError(PARAMS_OUT_OF_RANGE, "max_parallel must be a positive integer", field="max_parallel")
    return value


def create_campaign_batch(
    *,
    project_id: str,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
    target_ids: Sequence[str],
    campaign: Mapping[str, Any],
    max_parallel: int | None = None,
    idempotency_key: str | None = None,
    max_members: int | None = None,
) -> BatchHandle:
    """One campaign configuration across N models of one modality (BULK-03..05).

    Order: write-free pre-checks (``params_out_of_range`` on the ids or a body carrying
    ``target_id`` / ``parent_run_id``, ``batch_too_large``, ``not_found`` for a model
    the project cannot see, ``batch_modality_mismatch`` with ``groups``), each refusal
    written as a ``batch.create`` ``success=False`` row; then the ``batch.create`` row;
    then the ``ml_batches`` row; then one ``create_attack_campaign`` per member (its own
    ``attack.run`` row before its rows), collecting refusals. ``422
    batch_member_refused`` with ``members`` when nothing was admitted.
    """
    from redsim.db.models import MlBatch
    from redsim.db.session import get_session

    batch_id = new_batch_id()
    cap = max_members if max_members is not None else batch_max_members()
    body = _as_mapping(campaign)
    audit_context: dict[str, Any] = {"batch_id": batch_id, "kind": BATCH_KIND_CAMPAIGN}

    def refuse(exc: ApiError, **more: Any) -> NoReturn:
        _refuse(audit_writer, action="batch.create", actor=actor, project_id=project_id, exc=exc,
                **{**audit_context, **_envelope_fields(exc), **more})

    # -- write-free pre-checks ----------------------------------------------------------
    try:
        ids = _validate_target_ids(list(target_ids))
        audit_context["target_ids"] = ids
        audit_context["n_members"] = len(ids)
        forbidden = sorted(k for k in body if k in _BATCH_FORBIDDEN_CAMPAIGN_KEYS)
        if forbidden:
            raise ApiError(
                PARAMS_OUT_OF_RANGE,
                f"the batch supplies each member's target; remove {forbidden} from campaign "
                "(a rerun is a single-run admission)",
                field=f"campaign.{forbidden[0]}", reasons=[f"unexpected field {k}" for k in forbidden],
            )
        parallel = _validate_max_parallel(max_parallel)
        _check_member_cap(len(ids), cap, what="models")
        with get_session() as sess:
            resolved = _resolve_batch_targets(sess, project_id, ids)
            from redsim.services.llm_capacity import cap_batch_parallel
            parallel = cap_batch_parallel(parallel, (target for target, _ in resolved))
        groups: dict[str, list[str]] = {}
        for target, modality in resolved:
            groups.setdefault(modality or "unknown", []).append(str(target.id))
        if len(groups) != 1:
            raise ApiError(
                BATCH_MODALITY_MISMATCH,
                f"a batch is one modality; the selected models span {sorted(groups)}: resubmit one batch per "
                "modality (the MRI is never aggregated across modalities)",
                field="target_ids", groups=groups,
            )
        (modality,) = groups
        if isinstance(body.get("attack_ids"), list):
            audit_context["attack_ids"] = [a for a in body["attack_ids"] if isinstance(a, str)]
    except ApiError as exc:
        refuse(exc)

    config_hash = _canonical_sha256(body)
    key_digest = hashlib.sha256(idempotency_key.encode()).hexdigest() if idempotency_key else None

    # -- batch.create row first, then the batch row ---------------------------------------
    authorize(
        "batch.create", None, allowlist=config.target_allowlist, actor=actor, writer=audit_writer,
        project_id=project_id, run_id=None,
        detail={
            "actor": actor, "batch_id": batch_id, "kind": BATCH_KIND_CAMPAIGN, "target_ids": ids,
            "n_members": len(ids), "modality": modality, "config_hash": config_hash,
            "attack_ids": audit_context.get("attack_ids"), "max_parallel": parallel, "max_members": cap,
            "idempotency_key_sha256": key_digest,
        },
    )
    with get_session() as sess:
        sess.add(MlBatch(
            id=batch_id, project_id=project_id, kind=BATCH_KIND_CAMPAIGN, status="queued", created_by=actor,
            idempotency_key=key_digest,
            config={
                "target_ids": ids, "modality": modality, "campaign": dict(body), "config_hash": config_hash,
                "max_parallel": parallel, "members": [], "refused": [],
            },
        ))

    # -- members, one single-run admission each -------------------------------------------
    members: list[BatchMember] = []
    refused: list[dict[str, Any]] = []
    queue_down = False
    for index, target_id in enumerate(ids):
        if queue_down:
            refused.append({"target_id": target_id, "code": QUEUE_UNAVAILABLE,
                            "message": "not attempted: the job queue is unavailable", "attempted": False})
            continue
        deferred, capacity_refusal, decision = _capacity_decision(
            project_id, "attack.run", actor=actor, audit_writer=audit_writer, batch_id=batch_id,
            target_id=target_id)
        if capacity_refusal is not None:
            refused.append({"target_id": target_id, "code": capacity_refusal.code,
                            "message": str(capacity_refusal), "attempted": True,
                            **_envelope_fields(capacity_refusal)})
            continue
        if parallel is not None and len(members) >= parallel:
            deferred = True
        try:
            handle = create_attack_campaign(
                campaign={**body, "target_id": target_id}, project_id=project_id, actor=actor, config=config,
                audit_writer=audit_writer, enqueue=not deferred,
            )
        except ApiError as exc:
            refused.append({"target_id": target_id, "code": exc.code, "message": str(exc), "attempted": True,
                            **_envelope_fields(exc)})
            if exc.code == QUEUE_UNAVAILABLE:
                queue_down = True
            continue
        with get_session() as sess:
            if deferred:
                _mark_deferred(sess, run_id=handle.run_id, job_id=handle.job_ids[0], decision=decision)
            _stamp_batch_on_member(sess, batch_id=batch_id, run_id=handle.run_id, job_ids=handle.job_ids,
                                   deferred=deferred, extra_job_detail={"batch_member_index": index})
        members.append(BatchMember(run_id=handle.run_id, job_ids=list(handle.job_ids), target_id=target_id,
                                   deferred=deferred))

    status = rollup_status(["queued"] * len(members), n_refused=len(refused))
    with get_session() as sess:
        row = _load_batch(sess, batch_id)
        row.status = status
        row.config = {
            **dict(row.config or {}),
            "members": [m.to_response() for m in members],
            "refused": refused,
        }
    if not members:
        refuse(ApiError(BATCH_MEMBER_REFUSED,
                        "every batch member failed admission; nothing was enqueued (see members)",
                        members=refused, batch_id=batch_id),
               refused_codes=sorted({str(r["code"]) for r in refused}))
    return BatchHandle(batch_id=batch_id, kind=BATCH_KIND_CAMPAIGN, project_id=project_id, modality=modality,
                       status=status, members=members, refused=refused, config_hash=config_hash)


# ---------------------------------------------------------------------------
# Verify batches (BULK-15; owner decision BULK-16)
# ---------------------------------------------------------------------------


def _normalise_defenses(body: Mapping[str, Any]) -> list[dict[str, Any]]:
    """``[{defense, params}]`` from ``defenses`` or the single ``defense`` / ``params`` shorthand, deduplicated."""
    raw = body.get("defenses")
    entries: list[Any]
    if raw is None:
        entries = [{"defense": body.get("defense"), "params": body.get("params") or {}}]
    elif isinstance(raw, list) and raw:
        entries = list(raw)
    else:
        raise ApiError(PARAMS_OUT_OF_RANGE, "defenses must be a non-empty list of {defense, params}",
                       field="defenses")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        if isinstance(entry, str):
            entry = {"defense": entry, "params": {}}
        if not isinstance(entry, Mapping):
            raise ApiError(PARAMS_OUT_OF_RANGE, "each defenses entry is {defense, params}", field="defenses")
        defense = entry.get("defense", entry.get("id"))
        params = entry.get("params") or {}
        if defense is not None and not isinstance(defense, str):
            raise ApiError(PARAMS_OUT_OF_RANGE, "defense must be a catalog defense id", field="defense")
        if not isinstance(params, Mapping):
            raise ApiError(PARAMS_OUT_OF_RANGE, "params must be an object", field="params")
        key = _canonical_sha256({"defense": defense, "params": dict(params)})
        if key in seen:
            continue
        seen.add(key)
        out.append({"defense": defense, "params": dict(params)})
    return out


def _select_findings(sess: Session, *, run_id: str, anchor_id: str, requested: Any, include_fixed: bool,
                     ) -> tuple[list[str], list[dict[str, Any]]]:
    """``(selected finding ids, skipped [{finding_id, status, reason}])`` for the run's ML findings."""
    from sqlalchemy import select

    from redsim.db.models import Finding

    rows = list(sess.execute(
        select(Finding).where(Finding.run_id == run_id).order_by(Finding.created_at.asc(), Finding.id.asc())
    ).scalars().all())
    ml_rows = {row.id: row for row in rows
               if isinstance(row.schema_blob, dict) and isinstance(row.schema_blob.get("ml"), dict)
               and row.schema_blob.get("ml")}
    if requested is not None:
        if (not isinstance(requested, list) or not requested
                or not all(isinstance(f, str) and f for f in requested)):
            raise ApiError(PARAMS_OUT_OF_RANGE, "finding_ids must be a non-empty list of finding ids",
                           field="finding_ids")
        outside = sorted(f for f in requested if f not in ml_rows)
        if outside:
            raise ApiError(PARAMS_OUT_OF_RANGE,
                           f"finding_ids names findings that are not ML findings of run {run_id}: {outside}",
                           field="finding_ids", reasons=outside)
        candidates = [anchor_id] + [f for f in requested if f != anchor_id]
    else:
        candidates = [anchor_id] + [fid for fid in ml_rows if fid != anchor_id]
    selectable = set(_VERIFY_SELECTABLE_STATUSES) | ({"fixed"} if include_fixed else set())
    selected: list[str] = []
    skipped: list[dict[str, Any]] = []
    for fid in candidates:
        row = ml_rows.get(fid)
        if row is None:
            skipped.append({"finding_id": fid, "status": None, "reason": "not an ML finding of this run"})
            continue
        if row.status in selectable:
            selected.append(fid)
        else:
            skipped.append({"finding_id": fid, "status": row.status,
                            "reason": _VERIFY_SKIP_REASONS.get(str(row.status), f"status {row.status}")})
    return selected, skipped


def create_verify_batch(
    *,
    finding_id: str,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
    body: Mapping[str, Any] | None = None,
    idempotency_key: str | None = None,
    max_members: int | None = None,
) -> BatchHandle:
    """Bulk verify per the owner decision BULK-16 (module docstring).

    ``finding_id`` anchors the baseline run; the body may carry ``finding_ids`` (a subset of
    that run's ML findings, the anchor always included), ``include_fixed``, and either
    ``defense`` / ``params`` or ``defenses: [{defense, params}]``. One member per distinct
    (defense, params); each member is ``create_verify_campaign`` on the first selected finding
    with ``Job.detail.finding_ids`` listing every selected one. Refusals of the single route
    (``unknown_defense``, ``defense_modality_mismatch``, ``job_in_flight``, ...) are collected
    per member; ``422 batch_member_refused`` when no member was admitted.
    """
    from redsim.db.models import Finding, MlBatch, Run
    from redsim.db.session import get_session

    batch_id = new_batch_id()
    cap = max_members if max_members is not None else batch_max_members()
    request = _as_mapping(body)
    project_id: str | None = None
    audit_context: dict[str, Any] = {"batch_id": batch_id, "kind": BATCH_KIND_VERIFY, "finding_id": finding_id}

    def refuse(exc: ApiError, **more: Any) -> NoReturn:
        _refuse(audit_writer, action="batch.create", actor=actor, project_id=project_id, exc=exc,
                **{**audit_context, **_envelope_fields(exc), **more})

    try:
        with get_session() as sess:
            anchor = sess.get(Finding, finding_id)
            if anchor is None:
                raise ApiError(NOT_FOUND, "finding not found")
            project_id = str(anchor.project_id)
            baseline_id = str(anchor.run_id)
            baseline = sess.get(Run, baseline_id)
            if baseline is None:
                raise ApiError(NOT_FOUND, "baseline campaign not found")
            audit_context["baseline_run_id"] = baseline_id
            include_fixed = bool(request.get("include_fixed", False))
            selected, skipped = _select_findings(sess, run_id=baseline_id, anchor_id=finding_id,
                                                 requested=request.get("finding_ids"), include_fixed=include_fixed)
            target_id = str(baseline.target_id) if baseline.target_id is not None else None
            modality = None
            table = _campaign_table(sess)
            campaign_row = sess.execute(table.select().where(table.c.run_id == baseline_id)).mappings().one_or_none()
            if campaign_row is not None:
                modality = str(campaign_row["modality"]) if campaign_row["modality"] else None
        audit_context["finding_ids"] = selected
        audit_context["skipped"] = [s["finding_id"] for s in skipped]
        if not selected:
            raise ApiError(
                PARAMS_OUT_OF_RANGE,
                "no finding of the baseline run is verifiable: every candidate is in flight, dismissed or fixed "
                "(pass include_fixed to re-measure fixed findings)",
                field="finding_ids", skipped=skipped,
            )
        defenses = _normalise_defenses(request)
        _check_member_cap(len(defenses), cap, what="defenses")
        parallel = _validate_max_parallel(request.get("max_parallel"))
    except ApiError as exc:
        refuse(exc)

    defense_ids = [d["defense"] for d in defenses]
    config_hash = _canonical_sha256({"defenses": defenses, "finding_ids": selected})
    key_digest = hashlib.sha256(idempotency_key.encode()).hexdigest() if idempotency_key else None
    # Each member is admitted on one selected finding (the single route's ``finding_id``, which flips
    # to ``fixing`` and may carry one verify in flight); several defenses in one request take the
    # first selected finding that no earlier member of this batch already owns.
    primary = selected[0]
    busy_primaries: set[str] = set()

    authorize(
        "batch.create", None, allowlist=config.target_allowlist, actor=actor, writer=audit_writer,
        project_id=project_id, run_id=None,
        detail={
            "actor": actor, "batch_id": batch_id, "kind": BATCH_KIND_VERIFY, "baseline_run_id": baseline_id,
            "target_id": target_id, "finding_ids": selected, "n_findings": len(selected),
            "primary_finding_id": primary, "skipped": skipped, "defense_ids": defense_ids,
            "n_members": len(defenses), "config_hash": config_hash, "max_parallel": parallel, "max_members": cap,
            "idempotency_key_sha256": key_digest,
        },
    )
    with get_session() as sess:
        sess.add(MlBatch(
            id=batch_id, project_id=project_id, kind=BATCH_KIND_VERIFY, status="queued", created_by=actor,
            idempotency_key=key_digest,
            config={
                "baseline_run_id": baseline_id, "target_id": target_id, "modality": modality,
                "finding_ids": selected, "primary_finding_id": primary, "skipped": skipped,
                "defenses": defenses, "config_hash": config_hash, "max_parallel": parallel,
                "members": [], "refused": [],
            },
        ))

    members: list[BatchMember] = []
    refused: list[dict[str, Any]] = []
    queue_down = False
    for index, entry in enumerate(defenses):
        label = {"defense": entry["defense"], "params": entry["params"]}
        if queue_down:
            refused.append({**label, "code": QUEUE_UNAVAILABLE,
                            "message": "not attempted: the job queue is unavailable", "attempted": False})
            continue
        deferred, capacity_refusal, decision = _capacity_decision(
            project_id, "verify.replay", actor=actor, audit_writer=audit_writer, batch_id=batch_id,
            baseline_run_id=baseline_id, defense_id=entry["defense"])
        if capacity_refusal is not None:
            refused.append({**label, "code": capacity_refusal.code, "message": str(capacity_refusal),
                            "attempted": True, **_envelope_fields(capacity_refusal)})
            continue
        if parallel is not None and len(members) >= parallel:
            deferred = True
        member_primary = next((fid for fid in selected if fid not in busy_primaries), primary)
        try:
            handle = create_verify_campaign(
                finding_id=member_primary, defense_id=entry["defense"], params=entry["params"], actor=actor,
                config=config, audit_writer=audit_writer, enqueue=not deferred,
            )
        except ApiError as exc:
            refused.append({**label, "code": exc.code, "message": str(exc), "attempted": True,
                            "primary_finding_id": member_primary, **_envelope_fields(exc)})
            if exc.code == QUEUE_UNAVAILABLE:
                queue_down = True
            continue
        busy_primaries.add(member_primary)
        # One verify.replay row per additional finding bound to the shared run (spec 5.11 per finding),
        # written before Job.detail.finding_ids binds them.
        frozen_defense: dict[str, Any] | None = None
        with get_session() as sess:
            from redsim.db.models import Job

            job = sess.get(Job, handle.job_ids[0]) if handle.job_ids else None
            if job is not None:
                frozen_defense = _as_mapping(_as_mapping(job.detail).get("campaign_config")).get("defense")
        for other in selected:
            if other == member_primary:
                continue
            authorize(
                "verify.replay", None, allowlist=config.target_allowlist, actor=actor, writer=audit_writer,
                project_id=project_id, run_id=handle.run_id,
                detail={
                    "actor": actor, "finding_id": other, "baseline_run_id": baseline_id, "batch_id": batch_id,
                    "shared_run_id": handle.run_id, "primary_finding_id": member_primary,
                    "defense": frozen_defense or label, "projection": "shared defended run (BULK-16)",
                },
            )
        with get_session() as sess:
            if deferred:
                _mark_deferred(sess, run_id=handle.run_id, job_id=handle.job_ids[0], decision=decision)
            _stamp_batch_on_member(
                sess, batch_id=batch_id, run_id=handle.run_id, job_ids=handle.job_ids, deferred=deferred,
                extra_job_detail={"finding_ids": list(selected), "batch_member_index": index},
                extra_stage={"finding_ids": list(selected)},
            )
        members.append(BatchMember(run_id=handle.run_id, job_ids=list(handle.job_ids),
                                   defense=frozen_defense or label, deferred=deferred,
                                   primary_finding_id=member_primary))

    status = rollup_status(["queued"] * len(members), n_refused=len(refused))
    with get_session() as sess:
        row = _load_batch(sess, batch_id)
        row.status = status
        row.config = {**dict(row.config or {}), "members": [m.to_response() for m in members], "refused": refused}
    if not members:
        refuse(ApiError(BATCH_MEMBER_REFUSED,
                        "every verify member failed admission; nothing was enqueued (see members)",
                        members=refused, batch_id=batch_id),
               refused_codes=sorted({str(r["code"]) for r in refused}))
    assert project_id is not None
    return BatchHandle(
        batch_id=batch_id, kind=BATCH_KIND_VERIFY, project_id=project_id, modality=modality, status=status,
        members=members, refused=refused, config_hash=config_hash,
        extra={"baseline_run_id": baseline_id, "finding_ids": selected, "primary_finding_id": primary,
               "skipped": skipped},
    )


def create_batch(*, kind: str, project_id: str | None = None, actor: str, config: RedsimConfig,
                 audit_writer: AuditWriter, campaign: Mapping[str, Any] | None = None,
                 target_ids: Sequence[str] | None = None, finding_id: str | None = None,
                 body: Mapping[str, Any] | None = None, max_parallel: int | None = None,
                 idempotency_key: str | None = None) -> BatchHandle:
    """Dispatch on ``kind``: :func:`create_campaign_batch` or :func:`create_verify_batch`."""
    if kind == BATCH_KIND_CAMPAIGN:
        if project_id is None:
            raise ApiError(PARAMS_OUT_OF_RANGE, "project_id is required", field="project_id")
        return create_campaign_batch(project_id=project_id, actor=actor, config=config, audit_writer=audit_writer,
                                     target_ids=list(target_ids or []), campaign=campaign or {},
                                     max_parallel=max_parallel, idempotency_key=idempotency_key)
    if kind == BATCH_KIND_VERIFY:
        if not finding_id:
            raise ApiError(PARAMS_OUT_OF_RANGE, "finding_id is required for a verify batch", field="finding_id")
        return create_verify_batch(finding_id=finding_id, actor=actor, config=config, audit_writer=audit_writer,
                                   body=body, idempotency_key=idempotency_key)
    raise ApiError(PARAMS_OUT_OF_RANGE, f"unknown batch kind {kind!r}; known: {sorted(BATCH_KINDS)}", field="kind")


# ---------------------------------------------------------------------------
# Reads (BULK-06)
# ---------------------------------------------------------------------------


def batch_member_rows(session: Session, batch_id: str) -> list[dict[str, Any]]:
    """The members of a batch, oldest first: per-run status, stage, score link and lineage, never an MRI."""
    from sqlalchemy import select

    from redsim.db.models import Finding, Job, Run

    table = _campaign_table(session)
    campaign_rows = list(session.execute(
        table.select().where(table.c.batch_id == batch_id).order_by(table.c.run_id.asc())
    ).mappings().all())
    members: list[dict[str, Any]] = []
    order: dict[str, tuple[int, str, str]] = {}
    for row in campaign_rows:
        run_id = str(row["run_id"])
        run = session.get(Run, run_id)
        jobs = list(session.execute(select(Job).where(Job.run_id == run_id).order_by(Job.created_at.asc())).scalars())
        job_detail = _as_mapping(jobs[0].detail) if jobs else {}
        stage_table = _as_mapping(getattr(run, "stage_table", None))
        status = str(run.status) if run is not None else "unknown"
        scored = row["score"] is not None
        if scored:
            score_status = "scored"
        elif status in {"queued", "running"}:
            score_status = "pending"
        else:
            score_status = "unavailable"
        config_json = _as_mapping(row["config"])
        raw_index = job_detail.get("batch_member_index")
        member_index = raw_index if isinstance(raw_index, int) and not isinstance(raw_index, bool) else None
        created_at = getattr(run, "created_at", None)
        order[run_id] = (member_index if member_index is not None else 1 << 30,
                         created_at.isoformat() if isinstance(created_at, datetime) else "", run_id)
        member: dict[str, Any] = {
            "run_id": run_id,
            "member_index": member_index,
            "target_id": str(row["target_id"]),
            "kind": str(row["kind"]),
            "modality": row["modality"],
            "status": status,
            "stage": stage_table.get("stage"),
            "stages_done": list(stage_table.get("stages_done") or []),
            "job_ids": [job.id for job in jobs],
            "job_statuses": {job.id: job.status for job in jobs},
            "deferred": bool(job_detail.get("deferred", False)),
            "attack_ids": list(config_json.get("attack_ids") or []),
            "settings_hash": row["settings_hash"],
            "baseline_run_id": row["baseline_run_id"],
            "score_status": score_status,
            "scorecard_url": f"/v1/runs/{run_id}/campaign" if scored else None,
            "status_url": f"/v1/runs/{run_id}",
            "created_at": _iso(getattr(run, "created_at", None)),
            "completed_at": _iso(getattr(run, "completed_at", None)),
        }
        if str(row["kind"]) == "verify":
            member["defense"] = config_json.get("defense")
            finding_ids = [str(f) for f in (job_detail.get("finding_ids") or [])]
            if not finding_ids and job_detail.get("finding_id"):
                finding_ids = [str(job_detail["finding_id"])]
            findings: list[dict[str, Any]] = []
            for fid in finding_ids:
                finding = session.get(Finding, fid)
                blob = _as_mapping(getattr(finding, "schema_blob", None))
                verify_block = _as_mapping(_as_mapping(blob.get("ml")).get("verify"))
                findings.append({
                    "finding_id": fid,
                    "status": getattr(finding, "status", None),
                    "projected": verify_block.get("run_id") == run_id,
                    "outcome": verify_block.get("outcome") if verify_block.get("run_id") == run_id else None,
                })
            member["finding_ids"] = finding_ids
            member["findings"] = findings
        members.append(member)
    # Admission order first (the index the batch stamped on the Job), then the run's creation time, then id:
    # the migration-owned ``ml_campaigns.created_at`` is server-defaulted and the sqlite mirrors leave it null.
    members.sort(key=lambda m: order[str(m["run_id"])])
    return members


def batch_view(session: Session, batch_id: str) -> dict[str, Any]:
    """The roll-up of one batch (``LookupError`` for an unknown id): row fields, members, counts, state."""
    row = _load_batch(session, batch_id)
    config_json = _as_mapping(row.config)
    members = batch_member_rows(session, batch_id)
    refused = list(config_json.get("refused") or [])
    statuses = [str(m["status"]) for m in members]
    counts = {name: statuses.count(name) for name in ("queued", "running", "succeeded", "failed", "cancelled")}
    counts["refused"] = len(refused)
    status = rollup_status(statuses, n_refused=len(refused))
    if row.cancelled_at is not None and status == "queued" and not members:
        status = "cancelled"
    terminal = all(s in TERMINAL_RUN_STATUSES for s in statuses)
    requested: dict[str, Any] = {}
    for key in ("target_ids", "finding_ids", "primary_finding_id", "baseline_run_id", "defenses", "skipped",
                "max_parallel"):
        if key in config_json:
            requested[key] = config_json[key]
    return {
        "batch_id": str(row.id),
        "kind": str(row.kind),
        "project_id": str(row.project_id),
        "modality": config_json.get("modality"),
        "status": status,
        "state": "terminal" if terminal else "active",
        "status_url": batch_status_url(str(row.id)),
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
        "cancel_requested_at": _iso(row.cancelled_at),
        "config_hash": config_json.get("config_hash"),
        "requested": requested,
        "members": members,
        "counts": counts,
        "n_members": len(members),
        "refused": refused,
        "statement": ("Each member links into its own scorecard; the batch carries statuses and counts only, "
                      "never an aggregate score (spec 15.7, 15.8)."),
    }


def list_batches(session: Session, *, project_ids: Sequence[str] | None, limit: int = 50) -> list[dict[str, Any]]:
    """Batch summaries newest first, scoped to ``project_ids`` (``None`` = unrestricted, system principals)."""
    from sqlalchemy import select

    from redsim.db.models import MlBatch

    stmt = select(MlBatch).order_by(MlBatch.created_at.desc(), MlBatch.id.desc()).limit(limit)
    if project_ids is not None:
        if not project_ids:
            return []
        stmt = stmt.where(MlBatch.project_id.in_(list(project_ids)))
    out: list[dict[str, Any]] = []
    for row in session.execute(stmt).scalars():
        config_json = _as_mapping(row.config)
        members = batch_member_rows(session, str(row.id))
        statuses = [str(m["status"]) for m in members]
        refused = list(config_json.get("refused") or [])
        out.append({
            "batch_id": str(row.id), "kind": str(row.kind), "project_id": str(row.project_id),
            "modality": config_json.get("modality"),
            "status": rollup_status(statuses, n_refused=len(refused)),
            "n_members": len(members), "n_refused": len(refused),
            "run_ids": [m["run_id"] for m in members],
            "created_by": row.created_by, "created_at": _iso(row.created_at),
            "cancel_requested_at": _iso(row.cancelled_at),
            "status_url": batch_status_url(str(row.id)),
        })
    return out


# ---------------------------------------------------------------------------
# Cancel (BULK-08)
# ---------------------------------------------------------------------------


def cancel_batch(*, batch_id: str, actor: str, config: RedsimConfig, audit_writer: AuditWriter) -> dict[str, Any]:
    """Cancel every queued or running member (``batch.cancel`` row first, then ``cancel_run`` per member).

    ``LookupError`` for an unknown batch; ``ApiError(run_terminal)`` (with a ``success=False``
    ``batch.cancel`` row) when every member is already terminal. A member that completes between
    the batch row and its own ``run.cancel`` row is reported under ``already_terminal`` (spec 10.7
    race). ``ml_batches.cancelled_at`` is stamped and the stored roll-up becomes ``cancelled``.
    """
    from redsim.db.models import Run
    from redsim.db.session import get_session

    with get_session() as sess:
        row = _load_batch(sess, batch_id)
        project_id = str(row.project_id)
        members = batch_member_rows(sess, batch_id)
    live = [m for m in members if str(m["status"]) not in TERMINAL_RUN_STATUSES]
    already = [{"run_id": m["run_id"], "status": m["status"]} for m in members
               if str(m["status"]) in TERMINAL_RUN_STATUSES]
    if not live:
        _refuse(audit_writer, action="batch.cancel", actor=actor, project_id=project_id,
                exc=ApiError(RUN_TERMINAL, "every member of the batch is already terminal", batch_id=batch_id,
                             members=already),
                batch_id=batch_id, member_run_ids=[m["run_id"] for m in members])

    authorize(
        "batch.cancel", None, allowlist=config.target_allowlist, actor=actor, writer=audit_writer,
        project_id=project_id, run_id=None,
        detail={
            "actor": actor, "batch_id": batch_id, "n_members": len(members),
            "member_run_ids": [m["run_id"] for m in members], "cancelling": [m["run_id"] for m in live],
            "already_terminal": [m["run_id"] for m in already],
        },
    )
    cancelled: list[str] = []
    jobs_cancelled = 0
    for member in live:
        run_id = str(member["run_id"])
        try:
            outcome = cancel_run(run_id=run_id, actor=actor, config=config, audit_writer=audit_writer)
        except TerminalRunError as exc:
            already.append({"run_id": run_id, "status": exc.run_status})
            continue
        except LookupError:
            already.append({"run_id": run_id, "status": "missing"})
            continue
        cancelled.append(run_id)
        jobs_cancelled += outcome.jobs_cancelled
    with get_session() as sess:
        row = _load_batch(sess, batch_id)
        row.cancelled_at = _now()
        statuses: list[str] = []
        for member in members:
            run = sess.get(Run, member["run_id"])
            if run is not None:
                statuses.append(str(run.status))
        row.status = rollup_status(statuses, n_refused=len(_as_mapping(row.config).get("refused") or []))
        stored = row.status
    return {"batch_id": batch_id, "status": stored, "cancelled": cancelled, "already_terminal": already,
            "jobs_cancelled": jobs_cancelled}


__all__ = [
    "BATCH_KINDS",
    "BATCH_KIND_CAMPAIGN",
    "BATCH_KIND_VERIFY",
    "BATCH_MAX_MEMBERS_ENV",
    "BATCH_STATUSES",
    "DEFAULT_BATCH_MAX_MEMBERS",
    "BatchHandle",
    "BatchMember",
    "batch_max_members",
    "batch_member_rows",
    "batch_project_id",
    "batch_status_url",
    "batch_view",
    "cancel_batch",
    "create_batch",
    "create_campaign_batch",
    "create_verify_batch",
    "list_batches",
    "new_batch_id",
    "rollup_status",
]
