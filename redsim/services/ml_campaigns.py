"""Admission and persistence helpers for adversarial-ML campaigns.

Every refusal is a typed :class:`redsim.api.errors.ApiError` carrying a spec
section 17.3 code, so the routes convert it into the ``{"detail": {"code",
"message", ...}}`` envelope without parsing prose. The admission order is fixed
(spec 10.5): the ``attack.run`` / ``verify.replay`` audit row is written through
:func:`redsim.safety.authorize` **before** any ``Run`` / ``Job`` / ``ml_campaigns``
row exists and before ``task.delay``; a refused admission writes a
``success=False`` row with the code and the ids it refused, never the request
body, model bytes or secrets. When the broker refuses the enqueue the rows that
were just written are removed again and the caller receives ``503
queue_unavailable`` (spec 17.2), with a second ``success=False`` row recording
the roll-back.

Defaults the admission fills when a request omits them (spec 12.3, register
G-ATK6): ``norm="linf"``, the ε grid for the norm (``DEFAULT_EPS_GRID_LINF`` /
``DEFAULT_EPS_GRID_L2``), the reference budget (``DEFAULT_REFERENCE_EPS`` for
L-inf, the middle L2 member otherwise) and the evaluation dataset the model
manifest declares. A grid with more than ``DEFAULT_MAX_EPS_GRID_MEMBERS``
members is refused unless the caller raises the bound explicitly (spec 12.8).

Reruns (register G-API-RERUN, spec 10.6): ``parent_run_id`` names a terminal
``failed`` / ``cancelled`` attack campaign on the same model; its configuration
is copied, every admission check runs again, the lineage is stored in
``ml_campaigns.parent_run_id`` and the original rows are never touched.

``attack_params`` in the frozen config holds the caller's overrides only, each
validated through the adapter's ``resolve_params``. The grid-owned keys
(:data:`_GRID_OWNED_PARAMS`) are stripped before validation: the runner
(``redsim.ml.campaign._attack_params``) derives ``eps`` from ``eps_grid`` and
``norm_l2`` from ``norm`` and refuses a config that sets either, so freezing a
resolved default there made every API-launched campaign fail in the sandbox
child. Attack applicability is read from the registry capability tags
(``modality:<domain>``), the same declaration the runner honours, so an attack
that lists several modalities (PGD by surrogate transfer on tabular targets,
spec 12.9) is admitted while a true mismatch stays ``attack_modality_mismatch``.

Two more checks the runner (``redsim.ml.campaign._resolve_attacks``) performs
are mirrored here so a campaign the sandbox child would refuse is never
admitted, never enqueued and never becomes a failed ``Run``: ``attack_ids`` may
name evasion adapters only (the benign ``noise_control`` runs automatically at
every grid member when ``include_control`` is true, spec 12.4, and is not an
attack), and a campaign with ``norm="l2"`` may name only adapters that declare a
``norm_l2`` parameter (FGSM is L-inf only, spec 12.2). Both are
``422 params_out_of_range`` with the field that has to change.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NoReturn
from uuid import uuid4

from redsim.api.errors import (
    ATTACK_MODALITY_MISMATCH,
    ATTACK_REQUIRES_GRADIENTS,
    CAMPAIGN_NOT_TERMINAL,
    DATASET_INCOMPATIBLE,
    DEFENSE_MODALITY_MISMATCH,
    EPS_GRID_INVALID,
    JOB_IN_FLIGHT,
    MODEL_LOAD_REFUSED,
    NOT_FOUND,
    NOT_IMPLEMENTED,
    PARAMS_OUT_OF_RANGE,
    QUEUE_UNAVAILABLE,
    REFERENCE_EPS_NOT_IN_GRID,
    SCORE_UNAVAILABLE,
    UNKNOWN_ATTACK,
    UNKNOWN_DEFENSE,
    ApiError,
)
from redsim.ml.schema import CampaignConfig, CandidateRecommendation
from redsim.ml.scoring import (
    DEFAULT_MAX_EPS_GRID_MEMBERS,
    default_eps_grid,
    default_reference_eps,
)
from redsim.safety import authorize

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from redsim.audit.chain import AuditWriter
    from redsim.config import RedsimConfig

logger = logging.getLogger(__name__)

#: Target kinds a campaign may name (spec 5.2).
_ML_KINDS = frozenset({"ml_model_artifact", "ml_model_endpoint"})
#: Phase A modalities; anything else is a named Phase B route (spec 17.3 ``not_implemented``).
_PHASE_A_MODALITIES = frozenset({"image", "tabular"})
_NORMS = frozenset({"linf", "l2"})
#: Run statuses a rerun may start from (spec 10.6: retry is a new linked run of a failed/cancelled one).
_RERUN_PARENT_STATUSES = frozenset({"failed", "cancelled"})
_TERMINAL_RUN_STATUSES = frozenset({"succeeded", "failed", "cancelled"})
#: Config keys the server owns; a request or a copied parent config never sets them.
_SERVER_OWNED_CONFIG_KEYS = frozenset({"target_snapshot", "attacks", "defense", "scoring"})
#: Attack parameters the campaign runner derives from the grid and the norm, never from
#: ``attack_params`` (``redsim.ml.campaign._attack_params`` refuses them). The same set as
#: ``redsim.ml.campaign_adapter._GRID_OWNED_PARAMS`` on the offline path; kept as a literal here
#: because that name is module-private.
_GRID_OWNED_PARAMS = frozenset({"eps", "norm_l2"})
#: Spec 16.5 default for ``POST /v1/findings/{id}/verify`` when the body names no defense: feature
#: squeezing is the one Phase A preprocessor that applies to both image and tabular targets.
DEFAULT_VERIFY_DEFENSE_ID = "feature_squeezing"
#: The one attack family ``attack_ids`` may name (spec 12.2 catalog). ``control`` adapters run
#: automatically (``redsim.ml.campaign.CONTROL_ATTACK_ID``) and the runner refuses them in the set.
_ATTACK_FAMILY = "evasion"
#: The adapter parameter that switches an attack to the L2 norm; an adapter without it is L-inf only
#: and the runner refuses it under ``norm="l2"`` (``redsim.ml.campaign._resolve_attacks``).
_L2_PARAM = "norm_l2"


@dataclass(frozen=True)
class CampaignJobHandle:
    """A handle that remains compatible when campaign admission grows jobs."""

    run_id: str
    job_ids: list[str]

    def to_response(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "job_ids": list(self.job_ids),
            "status_url": f"/v1/runs/{self.run_id}",
        }


def _campaign_table(session: Session) -> Any:
    """Reflect the migration-owned table without requiring an ORM model."""
    from sqlalchemy import MetaData, Table

    return Table("ml_campaigns", MetaData(), autoload_with=session.get_bind())


def _refuse(
    audit_writer: AuditWriter,
    *,
    action: str,
    actor: str,
    project_id: str | None,
    exc: ApiError,
    **context: Any,
) -> NoReturn:
    """Write the ``success=False`` admission row for a refusal, then raise it.

    ``context`` carries ids and digests only (target, attack ids, finding, run
    ids); the request body never reaches the chain. The row sits on the project
    chain (``run_id=None``) because no run exists for a refused admission.
    """
    detail: dict[str, Any] = {
        "actor": actor, "refused": True, "code": exc.code, "http_status": exc.status,
        "reason": str(exc),
    }
    for key, value in context.items():
        if value is not None:
            detail[key] = value
    audit_writer.append(
        action=action, actor=actor, target=None, allowlist_check="n/a", override=False,
        success=False, detail=detail, run_id=None, project_id=project_id,
    )
    raise exc


def _as_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _target_manifest(detail: Mapping[str, Any]) -> dict[str, Any]:
    manifest = detail.get("manifest")
    return dict(manifest) if isinstance(manifest, Mapping) else {}


def _validate_eps_grid(raw: Any, *, max_members: int) -> list[float]:
    """Spec 12.3 grid rules: non-empty, numeric, each in (0, 1], strictly ascending, bounded size."""
    reasons: list[str] = []
    if not isinstance(raw, (list, tuple)):
        raise ApiError(EPS_GRID_INVALID, "eps_grid must be a list of budgets", field="eps_grid",
                       reasons=["not a list"])
    if not raw:
        reasons.append("empty")
    values: list[float] = []
    for item in raw:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            reasons.append(f"non-numeric member {item!r}")
            continue
        values.append(float(item))
    if any(not (0.0 < v <= 1.0) for v in values):
        reasons.append("members must lie in (0, 1]")
    if any(b <= a for a, b in zip(values, values[1:], strict=False)):
        reasons.append("members must be strictly ascending")
    if len(values) > max_members:
        reasons.append(f"{len(values)} members exceed the maximum of {max_members}")
    if reasons:
        raise ApiError(EPS_GRID_INVALID, "eps_grid violates the grid rules: " + "; ".join(reasons),
                       field="eps_grid", reasons=reasons)
    return values


def _resolve_reference_eps(raw: Any, grid: list[float], norm: str) -> float:
    if raw is None:
        candidate = default_reference_eps(norm)
        if candidate not in grid:
            raise ApiError(
                REFERENCE_EPS_NOT_IN_GRID,
                f"reference_eps was omitted and the default {candidate} is not a member of eps_grid {grid}",
                field="reference_eps", reasons=[f"default {candidate} not in grid"],
            )
        return candidate
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ApiError(REFERENCE_EPS_NOT_IN_GRID, "reference_eps must be a number from eps_grid",
                       field="reference_eps")
    value = float(raw)
    if value not in grid:
        raise ApiError(REFERENCE_EPS_NOT_IN_GRID, f"reference_eps {value} is not a member of eps_grid {grid}",
                       field="reference_eps")
    return value


def _validation_error(exc: Exception) -> ApiError:
    """Map a pydantic ``ValidationError`` on ``CampaignConfig`` to the 17.3 code for its field."""
    errors = getattr(exc, "errors", None)
    rows: list[dict[str, Any]] = list(errors()) if callable(errors) else []
    reasons = [str(row.get("msg", "")) for row in rows] or [str(exc)]
    first = rows[0] if rows else {}
    loc = [str(part) for part in first.get("loc", ())]
    field = ".".join(loc) if loc else None
    message = reasons[0]
    if loc[:1] == ["eps_grid"] or ("eps_grid" in message and "reference_eps" not in message):
        return ApiError(EPS_GRID_INVALID, message, field="eps_grid", reasons=reasons)
    if "reference_eps" in message:
        return ApiError(REFERENCE_EPS_NOT_IN_GRID, message, field="reference_eps", reasons=reasons)
    if "attack_params names attacks outside attack_ids" in message:
        return ApiError(PARAMS_OUT_OF_RANGE, message, field="attack_params", reasons=reasons)
    fields: dict[str, Any] = {"reasons": reasons}
    if field:
        fields["field"] = field
    return ApiError(PARAMS_OUT_OF_RANGE, f"campaign configuration is invalid: {message}", **fields)


def _delete_campaign_rows(run_id: str, job_ids: list[str]) -> None:
    """Remove the admission rows of ``run_id`` (campaign row, jobs, run) after a failed enqueue."""
    from redsim.db.models import Job, Run
    from redsim.db.session import get_session

    with get_session() as sess:
        table = _campaign_table(sess)
        sess.execute(table.delete().where(table.c.run_id == run_id))
        for job_id in job_ids:
            job = sess.get(Job, job_id)
            if job is not None:
                sess.delete(job)
        run = sess.get(Run, run_id)
        if run is not None:
            sess.delete(run)


def _enqueue_campaign(job_id: str) -> str | None:
    """``ml_campaign_run.delay(job_id)``; the Celery task id when the broker returned one."""
    from redsim.workers.tasks.ml_campaign import ml_campaign_run

    queued = ml_campaign_run.delay(job_id)
    task_id = getattr(queued, "id", None)
    return str(task_id) if task_id is not None else None


def _stamp_task_id(job_id: str, task_id: str | None) -> None:
    if task_id is None:
        return
    from redsim.db.models import Job
    from redsim.db.session import get_session

    with get_session() as sess:
        job = sess.get(Job, job_id)
        if job is not None:
            job.celery_task_id = task_id


# ---------------------------------------------------------------------------
# attack.run admission
# ---------------------------------------------------------------------------


def _rerun_base_config(
    sess: Session, *, parent_run_id: Any, project_id: str, target_id: str, requested: Mapping[str, Any],
) -> dict[str, Any]:
    """The parent campaign's configuration for a rerun, after the spec 10.6 lineage checks."""
    from redsim.db.models import Run

    if not isinstance(parent_run_id, str) or not parent_run_id:
        raise ApiError(PARAMS_OUT_OF_RANGE, "parent_run_id must be a run id", field="parent_run_id")
    extra = sorted(k for k in requested if k not in {"target_id", "modality", "parent_run_id"})
    if extra:
        raise ApiError(
            PARAMS_OUT_OF_RANGE,
            "a rerun copies the parent campaign configuration; pass parent_run_id alone "
            f"(unexpected: {extra})",
            field="parent_run_id", reasons=[f"unexpected field {k}" for k in extra],
        )
    parent = sess.get(Run, parent_run_id)
    if parent is None or parent.project_id != project_id:
        raise ApiError(NOT_FOUND, f"parent run not found: {parent_run_id}")
    if parent.target_id != target_id:
        raise ApiError(
            PARAMS_OUT_OF_RANGE,
            f"parent run {parent_run_id} targets model {parent.target_id!r}, not {target_id!r}",
            field="parent_run_id",
        )
    if parent.status not in _TERMINAL_RUN_STATUSES:
        raise ApiError(CAMPAIGN_NOT_TERMINAL,
                       f"parent run {parent_run_id} is {parent.status}; a rerun needs a terminal campaign",
                       status=parent.status)
    if parent.status not in _RERUN_PARENT_STATUSES:
        raise ApiError(
            PARAMS_OUT_OF_RANGE,
            f"parent run {parent_run_id} {parent.status}; a rerun applies to failed or cancelled "
            "campaigns only (start a new campaign to measure again)",
            field="parent_run_id", status=parent.status,
        )
    table = _campaign_table(sess)
    row = sess.execute(table.select().where(table.c.run_id == parent_run_id)).mappings().one_or_none()
    if row is None:
        raise ApiError(NOT_FOUND, f"parent campaign record not found: {parent_run_id}")
    if row["kind"] != "attack":
        raise ApiError(PARAMS_OUT_OF_RANGE,
                       f"parent run {parent_run_id} is a {row['kind']} campaign; only attack campaigns rerun",
                       field="parent_run_id")
    base = _as_mapping(row["config"])
    scoring = base.get("scoring")
    copied = {k: v for k, v in base.items() if k not in _SERVER_OWNED_CONFIG_KEYS}
    if isinstance(scoring, Mapping):
        copied["scoring"] = dict(scoring)   # the parent's frozen scoring block travels with the rerun
    return copied


def create_attack_campaign(
    *,
    campaign: CampaignConfig | Mapping[str, Any],
    project_id: str,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
    enqueue: bool = True,
    run_id: str | None = None,
    parent_run_id: str | None = None,
    max_eps_grid_members: int = DEFAULT_MAX_EPS_GRID_MEMBERS,
) -> CampaignJobHandle:
    """Audit first, then atomically admit one whole-campaign ``attack.run`` job.

    Raises :class:`ApiError` with the spec 17.3 code for every refusal (each
    refusal also writes a ``success=False`` ``attack.run`` audit row):
    ``not_found``, ``not_implemented`` (endpoint targets, Phase B modalities or
    attacks), ``model_load_refused`` (status not ``available``, with ``status``
    and ``refusal_reason``), ``unknown_attack``, ``attack_modality_mismatch``,
    ``attack_requires_gradients``, ``eps_grid_invalid``,
    ``reference_eps_not_in_grid``, ``params_out_of_range`` (also for a
    non-evasion adapter such as ``noise_control`` in ``attack_ids``, and for an
    L-inf-only attack under ``norm="l2"``), ``dataset_incompatible``,
    ``campaign_not_terminal`` (rerun of a live parent) and ``queue_unavailable``
    (enqueue failed; rows rolled back).

    ``attack_params`` is frozen as the caller's overrides per attack (values as
    the adapter resolves them), never the adapter defaults, and never the
    grid-owned ``eps`` / ``norm_l2`` the runner supplies itself. A rerun copies
    the parent's ``attack_params`` through the same rule, so a parent frozen
    with those keys by an earlier build reruns cleanly.
    """
    from redsim.db.models import Job, Run, Target
    from redsim.db.session import get_session

    requested: dict[str, Any] = (
        campaign.model_dump(mode="json") if isinstance(campaign, CampaignConfig) else _as_mapping(campaign)
    )
    if parent_run_id is None and requested.get("parent_run_id") is not None:
        parent_run_id = requested.get("parent_run_id")
    requested.pop("parent_run_id", None)
    target_id = requested.get("target_id")
    audit_context: dict[str, Any] = {"target_id": target_id, "parent_run_id": parent_run_id}

    def refuse(exc: ApiError, **more: Any) -> NoReturn:
        _refuse(audit_writer, action="attack.run", actor=actor, project_id=project_id, exc=exc,
                **{**audit_context, **more})

    if not isinstance(target_id, str) or not target_id:
        refuse(ApiError(NOT_FOUND, "model not found"))

    try:
        with get_session() as sess:
            target = sess.get(Target, target_id)
            if target is None or target.project_id != project_id or target.kind not in _ML_KINDS:
                raise ApiError(NOT_FOUND, "model not found")
            if target.kind == "ml_model_endpoint":
                raise ApiError(NOT_IMPLEMENTED, "black-box endpoint campaigns are not implemented",
                               phase="B", reason="endpoint connector is a Phase B route (spec 17.4)")
            detail = _as_mapping(getattr(target, "detail", None))
            manifest = _target_manifest(detail)
            target_status = detail.get("status") if detail.get("status") is not None else manifest.get("status")
            if target_status != "available":
                shown = str(target_status) if target_status is not None else "unknown"
                refusal_reason = (detail.get("refusal_reason") or manifest.get("refusal_reason")
                                  or ("no validation status recorded for this model"
                                      if target_status is None else f"model status is {shown}"))
                raise ApiError(
                    MODEL_LOAD_REFUSED, f"model is not available for campaigns (status {shown})",
                    status=shown, refusal_reason=str(refusal_reason),
                )
            target_modality = detail.get("modality") or manifest.get("modality")
            model_sha256 = detail.get("sha256") or manifest.get("sha256")
            gradients = detail.get("gradients", manifest.get("gradients"))
            manifest_dataset = detail.get("dataset_id") or manifest.get("dataset_id")
            manifest_revision = detail.get("dataset_revision") or manifest.get("dataset_revision")
            target_snapshot = {
                "id": target.id, "kind": target.kind, "value": str(target.value), "detail": detail,
            }
            base: dict[str, Any] = {}
            if parent_run_id is not None:
                base = _rerun_base_config(sess, parent_run_id=parent_run_id, project_id=project_id,
                                          target_id=target_id, requested=requested)
    except ApiError as exc:
        refuse(exc)

    # -- assemble the configuration: parent copy (rerun) or request, server-owned keys stripped ------
    snapshot: dict[str, Any] = dict(base)
    snapshot.update({k: v for k, v in requested.items() if k not in _SERVER_OWNED_CONFIG_KEYS})
    snapshot["target_id"] = target_id
    try:
        modality = snapshot.get("modality") or target_modality
        if target_modality and modality != target_modality:
            raise ApiError(ATTACK_MODALITY_MISMATCH,
                           f"campaign modality {modality!r} differs from the model modality {target_modality!r}",
                           field="modality")
        if modality not in _PHASE_A_MODALITIES:
            raise ApiError(NOT_IMPLEMENTED, f"{modality!r} campaigns are not implemented; Phase A evaluates "
                           f"{sorted(_PHASE_A_MODALITIES)} classifiers", phase="B", field="modality")
        snapshot["modality"] = modality
        norm = snapshot.get("norm") or "linf"
        if norm not in _NORMS:
            raise ApiError(PARAMS_OUT_OF_RANGE, f"norm must be one of {sorted(_NORMS)}, got {norm!r}",
                           field="norm")
        snapshot["norm"] = norm
        grid_raw = snapshot.get("eps_grid")
        eps_grid = (default_eps_grid(norm) if grid_raw is None
                    else _validate_eps_grid(grid_raw, max_members=max_eps_grid_members))
        snapshot["eps_grid"] = eps_grid
        snapshot["reference_eps"] = _resolve_reference_eps(snapshot.get("reference_eps"), eps_grid, norm)
        dataset_id = snapshot.get("dataset_id")
        if dataset_id is None:
            if not manifest_dataset:
                raise ApiError(DATASET_INCOMPATIBLE,
                               "the request names no dataset_id and the model manifest declares no "
                               "evaluation dataset", field="dataset_id")
            snapshot["dataset_id"] = manifest_dataset
        elif manifest_dataset and dataset_id != manifest_dataset:
            raise ApiError(DATASET_INCOMPATIBLE,
                           f"dataset {dataset_id!r} is not the dataset the model manifest binds "
                           f"({manifest_dataset!r})", field="dataset_id")
        if snapshot.get("dataset_revision") is None and manifest_revision:
            snapshot["dataset_revision"] = manifest_revision
        attack_ids = snapshot.get("attack_ids")
        if not isinstance(attack_ids, list) or not attack_ids or not all(isinstance(a, str) for a in attack_ids):
            raise ApiError(PARAMS_OUT_OF_RANGE, "attack_ids must be a non-empty list of attack ids",
                           field="attack_ids")
        audit_context["attack_ids"] = list(attack_ids)
        audit_context["dataset_id"] = snapshot.get("dataset_id")
        attack_params = _as_mapping(snapshot.get("attack_params"))
        unknown_param_owners = sorted(set(attack_params) - set(attack_ids))
        if unknown_param_owners:
            raise ApiError(PARAMS_OUT_OF_RANGE,
                           f"attack_params names attacks outside attack_ids: {unknown_param_owners}",
                           field="attack_params")

        from redsim.ml.attacks import ATTACKS, attack_capabilities, get_attack

        attack_infos = []
        frozen_params: dict[str, dict[str, float | int | bool]] = {}
        for attack_id in attack_ids:
            try:
                adapter = get_attack(attack_id)
            except KeyError as exc:
                raise ApiError(UNKNOWN_ATTACK, f"unknown attack {attack_id!r}", field="attack_ids") from exc
            info = adapter.info()
            if info.status != "available":
                raise ApiError(NOT_IMPLEMENTED, f"attack {attack_id!r} is not implemented"
                               + (f": {info.reason}" if info.reason else ""),
                               phase="B", field="attack_ids")
            # The runner refuses a non-evasion adapter in the attack set (``_resolve_attacks``); the benign
            # control is not an attack and runs automatically at every eps when ``include_control`` is true.
            if info.family != _ATTACK_FAMILY:
                raise ApiError(
                    PARAMS_OUT_OF_RANGE,
                    f"attack_ids names {attack_id!r}, a {info.family} adapter, not an attack: the benign "
                    f"noise control runs automatically at every eps of the grid (include_control, spec 12.4) "
                    f"and is never part of the attack set",
                    field="attack_ids", reasons=[f"{attack_id} is family {info.family}, not {_ATTACK_FAMILY}"],
                )
            # The runner refuses an L-inf-only adapter under the L2 norm; the norm is a campaign-wide choice, so
            # the field that has to change is ``norm`` (or the attack set). The alternatives are listed.
            if norm == "l2" and not any(spec.name == _L2_PARAM for spec in info.params_schema):
                l2_capable = sorted(
                    a.id for a in ATTACKS
                    if a.info().family == _ATTACK_FAMILY
                    and any(spec.name == _L2_PARAM for spec in a.info().params_schema)
                )
                raise ApiError(
                    PARAMS_OUT_OF_RANGE,
                    f"attack {attack_id!r} supports the L-inf norm only and the campaign norm is 'l2'; "
                    f"attacks that take norm_l2: {l2_capable}",
                    field="norm", reasons=[f"{attack_id} declares no {_L2_PARAM} parameter"],
                )
            # Applicability comes from the registry capability tags (``modality:<domain>`` for every
            # domain the adapter declares), the same declaration ``redsim.ml.campaign._resolve_attacks``
            # honours; ``AttackInfo.domain`` is the primary domain only and would refuse PGD by surrogate
            # transfer on a tabular model (spec 12.9).
            try:
                capabilities = attack_capabilities(adapter)
            except ValueError as exc:
                raise ApiError(UNKNOWN_ATTACK,
                               f"attack {attack_id!r} is registered with an invalid capability declaration: "
                               f"{exc}", field="attack_ids") from exc
            if f"modality:{modality}" not in capabilities:
                supported = sorted(tag.removeprefix("modality:") for tag in capabilities
                                   if tag.startswith("modality:"))
                raise ApiError(ATTACK_MODALITY_MISMATCH,
                               f"attack {attack_id!r} applies to {supported} targets, not {modality!r}",
                               field="attack_ids")
            # A white-box attack on a model without loss gradients is admitted when the adapter declares
            # ``surrogate_transfer`` and the target declares a surrogate: the runner
            # (``redsim.ml.campaign._surrogate_for_white_box``) then runs it on the surrogate and notes the
            # transfer on every row (spec 12.9).
            surrogate_declared = bool(detail.get("surrogate") or manifest.get("surrogate"))
            by_surrogate = "surrogate_transfer" in capabilities and surrogate_declared
            if info.requires_gradients and gradients is False and not by_surrogate:
                raise ApiError(ATTACK_REQUIRES_GRADIENTS,
                               f"attack {attack_id!r} needs loss gradients the model does not expose "
                               "(manifest gradients: false)", field="attack_ids")
            # The runner supplies ``eps`` (from the grid) and ``norm_l2`` (from ``norm``) at run time and
            # refuses a config that sets them, so they are stripped before validation rather than refused:
            # a copied parent config frozen by an earlier build still carries them. The remaining caller
            # keys are validated (defaults filled, bounds checked) and only those keys are frozen, with
            # the adapter's coerced values. Consequence for ``settings_hash`` (spec 5.6): adapter defaults
            # are no longer part of the hashed config, so spelling a default out (``batch_size: 64``)
            # hashes differently from omitting it, and a later change to an adapter default is not pinned
            # by the hash; the effective values are recorded by the run's provenance instead.
            given = {k: v for k, v in _as_mapping(attack_params.get(attack_id)).items()
                     if k not in _GRID_OWNED_PARAMS}
            try:
                resolved = adapter.resolve_params(given)
            except ValueError as exc:
                raise ApiError(PARAMS_OUT_OF_RANGE, f"invalid parameters for {attack_id!r}: {exc}",
                               field=f"attack_params.{attack_id}") from exc
            declared = {spec.name for spec in info.params_schema}
            frozen_params[attack_id] = {k: resolved[k] for k in given if k in declared and k in resolved}
            attack_infos.append(info)
        snapshot["attack_params"] = frozen_params
        snapshot["attacks"] = [info.model_dump(mode="json") for info in attack_infos]
        snapshot["target_snapshot"] = target_snapshot
        snapshot.pop("defense", None)
        try:
            frozen = CampaignConfig.model_validate(snapshot)
        except ValueError as exc:   # pydantic.ValidationError subclasses ValueError
            raise _validation_error(exc) from exc
    except ApiError as exc:
        refuse(exc)

    from redsim.ml.scoring import settings_hash

    run_id = run_id or f"run-{uuid4().hex[:12]}"
    job_id = f"job-{uuid4().hex[:12]}"
    frozen_json = frozen.model_dump(mode="json")
    frozen_settings_hash = settings_hash(frozen, model_sha256)
    audited_config = frozen.model_dump(mode="json", exclude={"target_snapshot", "attacks"})

    # This must precede all Run/Job/campaign rows (spec 10.5). ML campaigns target a
    # registered model rather than an active network location, hence target=None.
    authorize(
        "attack.run", None, allowlist=config.target_allowlist,
        actor=actor, writer=audit_writer, project_id=project_id, run_id=run_id,
        detail={
            "actor": actor, "target_id": frozen.target_id,
            "attack_ids": list(frozen.attack_ids),
            "norm": frozen.norm, "eps_grid": list(frozen.eps_grid), "reference_eps": frozen.reference_eps,
            "n_samples": frozen.n_samples, "seed": frozen.seed,
            "dataset_id": frozen.dataset_id, "dataset_revision": frozen.dataset_revision,
            "model_sha256": model_sha256, "settings_hash": frozen_settings_hash,
            "rerun": parent_run_id is not None, "parent_run_id": parent_run_id,
            "config": audited_config,
        },
    )

    stage_table: dict[str, Any] = {"stage": None, "stages_done": [], "jobs": {}}
    job_detail: dict[str, Any] = {"campaign_config": frozen_json}
    if parent_run_id is not None:
        stage_table["parent_run_id"] = parent_run_id
        job_detail["parent_run_id"] = parent_run_id
    with get_session() as sess:
        target = sess.get(Target, frozen.target_id)
        if target is None or target.project_id != project_id:
            raise ApiError(NOT_FOUND, "model not found")
        sess.add(Run(
            id=run_id, project_id=project_id, target_id=frozen.target_id,
            mode="api", status="queued", scanner="ml.campaign",
            created_by=actor, stage_table=stage_table,
        ))
        sess.flush()
        sess.add(Job(
            id=job_id, run_id=run_id, project_id=project_id,
            type="attack.run", status="queued", created_by=actor,
            # Full immutable input, not a pointer to mutable target/config state.
            detail=job_detail,
        ))
        sess.flush()
        table = _campaign_table(sess)
        sess.execute(table.insert().values(
            run_id=run_id, project_id=project_id, target_id=frozen.target_id,
            kind="attack", modality=frozen.modality, config=frozen_json,
            parent_run_id=parent_run_id, settings_hash=frozen_settings_hash,
            limitations=[],
        ))

    if enqueue:
        try:
            task_id = _enqueue_campaign(job_id)
        except Exception as exc:  # noqa: BLE001 - any broker failure is the same refusal
            logger.warning("enqueue failed for ML campaign job %s; rolling the admission back", job_id,
                           exc_info=True)
            _delete_campaign_rows(run_id, [job_id])
            refuse(ApiError(QUEUE_UNAVAILABLE, "job queue is unavailable; the campaign was not admitted",
                            reason=type(exc).__name__),
                   rolled_back_run_id=run_id, rolled_back_job_ids=[job_id])
        _stamp_task_id(job_id, task_id)
    return CampaignJobHandle(run_id=run_id, job_ids=[job_id])


def recommendation_defense_ids(recommendation: CandidateRecommendation) -> set[str]:
    """The catalog defense ids a candidate recommendation names.

    Rule-generated candidates (``redsim.ml.recommend.rules``) cite a defense as
    a ``defense:<id>`` reference next to ``<ART class> (Phase A verify loop)``
    and the motivating paper, so the ids are read back through
    ``rules.defense_configs`` rather than by matching the bare class string.
    Hand-authored evidence (the frozen ``run_record.json`` fixture shape) names
    the bare ART class instead, which resolves to the catalog id that owns it.
    """
    from redsim.ml.defenses import DEFENSES
    from redsim.ml.recommend.rules import defense_configs

    cited = {cfg.id for cfg in defense_configs(recommendation)}
    cited |= {
        str(spec["id"]) for spec in DEFENSES
        if spec["art_class"] in recommendation.references
    }
    return cited


def persist_campaign_record(session: Session, run_id: str, record: Any) -> None:
    """Project a completed CampaignRecord onto the queryable campaign row."""
    from sqlalchemy import update

    table = _campaign_table(session)
    session.execute(
        update(table).where(table.c.run_id == run_id).values(
            settings_hash=record.settings_hash,
            provenance=(record.provenance.model_dump(mode="json")
                        if record.provenance is not None else None),
            score=(record.score.model_dump(mode="json") if record.score is not None else None),
            limitations=list(record.limitations),
            completed_at=record.completed_at,
        )
    )


# ---------------------------------------------------------------------------
# verify.replay admission
# ---------------------------------------------------------------------------


def _resolve_verify_defense(
    defense_id: str | None, recommendation: CandidateRecommendation | None,
) -> str:
    """The defense a verify request applies (spec 16.5 default; the recommendation's own when it names one).

    * ``defense_id`` given: it must be a catalog defense; when a recommendation is named it must be
      one the recommendation cites (``params_out_of_range`` on ``defense`` otherwise).
    * omitted with a recommendation: the sole runnable defense the recommendation cites; several
      cited defenses need an explicit choice; a Phase B apply step (adversarial training) is
      ``not_implemented``; a recommendation naming no defense cannot be verified.
    * omitted without a recommendation: :data:`DEFAULT_VERIFY_DEFENSE_ID`.
    """
    from redsim.ml.defenses import DEFENSES
    from redsim.ml.recommend.rules import DEFENSE_IDS

    catalog = {str(spec["id"]) for spec in DEFENSES}
    phase_b = set(DEFENSE_IDS) - catalog
    cited = recommendation_defense_ids(recommendation) if recommendation is not None else set()
    if defense_id is None:
        if recommendation is None:
            return DEFAULT_VERIFY_DEFENSE_ID
        runnable = sorted(cited & catalog)
        if len(runnable) == 1:
            return runnable[0]
        if runnable:
            raise ApiError(PARAMS_OUT_OF_RANGE,
                           f"recommendation {recommendation.id!r} names several defenses {runnable}; "
                           "pass defense to choose one", field="defense", reasons=runnable)
        if cited & phase_b:
            raise ApiError(NOT_IMPLEMENTED,
                           f"recommendation {recommendation.id!r} names {sorted(cited & phase_b)}: a Phase B "
                           "apply step the Phase A verify loop cannot run", phase="B", field="defense")
        raise ApiError(PARAMS_OUT_OF_RANGE,
                       f"recommendation {recommendation.id!r} names no defense the verify loop can apply",
                       field="defense", reasons=sorted(cited))
    if defense_id in phase_b:
        raise ApiError(NOT_IMPLEMENTED, f"defense {defense_id!r} is a Phase B apply step, not a Phase A "
                       "preprocessing defense", phase="B", field="defense")
    if defense_id not in catalog:
        raise ApiError(UNKNOWN_DEFENSE, f"unknown defense {defense_id!r}; known: {sorted(catalog)}",
                       field="defense")
    if recommendation is not None and defense_id not in cited:
        named = sorted(cited)
        raise ApiError(
            PARAMS_OUT_OF_RANGE,
            f"recommendation {recommendation.id!r} names {named if named else 'no defense'}, not {defense_id!r}",
            field="defense", reasons=named,
        )
    return defense_id


def create_verify_campaign(
    *,
    finding_id: str,
    defense_id: str | None = None,
    params: Mapping[str, Any] | None = None,
    recommendation_id: str | None = None,
    actor: str,
    config: RedsimConfig,
    audit_writer: AuditWriter,
    enqueue: bool = True,
) -> CampaignJobHandle:
    """Audit and admit a defense evaluation as a separate ML campaign (spec 16.5, 17.2).

    ``recommendation_id`` is optional: when given, the defense must be one the
    recommendation names (through the ``defense:<id>`` references of
    ``redsim.ml.recommend.rules`` or the bare ART class). ``defense_id`` is
    optional too; see :func:`_resolve_verify_defense` for the default. Refusals
    are :class:`ApiError` with ``not_found``, ``campaign_not_terminal``,
    ``score_unavailable`` (baseline without a usable score record),
    ``job_in_flight``, ``unknown_defense``, ``defense_modality_mismatch``,
    ``params_out_of_range``, ``not_implemented`` or ``queue_unavailable``; each
    writes a ``success=False`` ``verify.replay`` audit row.
    """
    from sqlalchemy import select

    from redsim.db.models import Artifact, Finding, Job, Run
    from redsim.db.session import get_session
    from redsim.ml.defenses import get_defense, resolve_defense_params
    from redsim.ml.schema import CampaignRecord, MLFindingDetail
    from redsim.storage.blobs import open_blob_store

    project_id: str | None = None
    audit_context: dict[str, Any] = {"finding_id": finding_id, "recommendation_id": recommendation_id,
                                     "defense_id": defense_id}

    def refuse(exc: ApiError, **more: Any) -> NoReturn:
        _refuse(audit_writer, action="verify.replay", actor=actor, project_id=project_id, exc=exc,
                **{**audit_context, **more})

    try:
        with get_session() as sess:
            finding = sess.get(Finding, finding_id)
            if finding is None:
                raise ApiError(NOT_FOUND, "finding not found")
            project_id = finding.project_id
            previous_status = finding.status
            schema_blob = dict(finding.schema_blob or {})
            ml_blob = schema_blob.get("ml")
            if not isinstance(ml_blob, dict) or not ml_blob:
                raise ApiError(NOT_FOUND, "finding carries no ML campaign evidence to verify")
            ml_detail = MLFindingDetail.model_validate(ml_blob)
            recommendation: CandidateRecommendation | None = None
            if recommendation_id is not None:
                recommendation = next((r for r in ml_detail.recommendations if r.id == recommendation_id), None)
                if recommendation is None:
                    raise ApiError(PARAMS_OUT_OF_RANGE,
                                   f"recommendation {recommendation_id!r} does not belong to this finding",
                                   field="recommendation_id")
            baseline = sess.get(Run, finding.run_id)
            if baseline is None:
                raise ApiError(NOT_FOUND, "baseline campaign not found")
            if baseline.status not in _TERMINAL_RUN_STATUSES:
                raise ApiError(CAMPAIGN_NOT_TERMINAL, "the baseline campaign has not reached a terminal status",
                               status=baseline.status)
            if baseline.status != "succeeded":
                raise ApiError(SCORE_UNAVAILABLE,
                               f"the baseline campaign {baseline.status}; it carries no score to measure against",
                               status=baseline.status)
            active = sess.execute(select(Job).where(
                Job.project_id == finding.project_id,
                Job.type == "verify.replay",
                Job.status.in_(["queued", "running"]),
            )).scalars()
            if any((job.detail or {}).get("finding_id") == finding_id for job in active):
                raise ApiError(JOB_IN_FLIGHT, "a verify.replay job is already queued or running for this finding")
            table = _campaign_table(sess)
            baseline_campaign = sess.execute(
                table.select().where(table.c.run_id == baseline.id)
            ).mappings().one_or_none()
            if baseline_campaign is None:
                raise ApiError(NOT_FOUND, "baseline campaign record not found")
            baseline_artifact = sess.execute(select(Artifact).where(
                Artifact.run_id == baseline.id,
                Artifact.kind == "ml.run_record",
            )).scalar_one_or_none()
            if baseline_artifact is None:
                raise ApiError(NOT_FOUND, "baseline campaign record not found")
            baseline_location = str(baseline_artifact.location)
            baseline_sha256 = str(baseline_artifact.sha256)
            baseline_id = baseline.id
        audit_context["baseline_run_id"] = baseline_id

        baseline_bytes = open_blob_store().get(baseline_location)
        if isinstance(baseline_bytes, str):
            baseline_bytes = baseline_bytes.encode("utf-8")
        if hashlib.sha256(baseline_bytes).hexdigest() != baseline_sha256:
            raise ApiError(SCORE_UNAVAILABLE, "baseline evidence digest mismatch: the recorded ml.run_record "
                           "does not match its sha256", reasons=["artifact_digest_mismatch"])
        baseline_record = CampaignRecord.model_validate_json(baseline_bytes)
        if baseline_record.run_id != baseline_id or baseline_record.score is None:
            raise ApiError(SCORE_UNAVAILABLE, "baseline evidence is incomplete: no score record to measure "
                           "a delta against", reasons=["baseline_score_missing"])
        snapshot = baseline_record.config.model_dump(mode="json")
        resolved_defense_id = _resolve_verify_defense(defense_id, recommendation)
        audit_context["defense_id"] = resolved_defense_id
        spec = get_defense(resolved_defense_id)
        modality = str(snapshot.get("modality") or "")
        if modality not in spec["domains"]:
            raise ApiError(DEFENSE_MODALITY_MISMATCH,
                           f"defense {resolved_defense_id!r} applies to {list(spec['domains'])} targets, "
                           f"not {modality!r}", field="defense")
        try:
            resolved_params = resolve_defense_params(resolved_defense_id, dict(params or {}))
        except ValueError as exc:
            raise ApiError(PARAMS_OUT_OF_RANGE, f"invalid parameters for {resolved_defense_id!r}: {exc}",
                           field="params") from exc
        snapshot["defense"] = {
            "id": resolved_defense_id, "art_class": spec["art_class"], "params": resolved_params,
        }
        try:
            frozen = CampaignConfig.model_validate(snapshot)
        except ValueError as exc:
            raise _validation_error(exc) from exc
    except ApiError as exc:
        refuse(exc)

    frozen_json = frozen.model_dump(mode="json")
    run_id = f"run-{uuid4().hex[:12]}"
    job_id = f"job-{uuid4().hex[:12]}"
    target_id = frozen.target_id

    authorize(
        "verify.replay",
        None,
        allowlist=config.target_allowlist,
        actor=actor,
        writer=audit_writer,
        project_id=project_id,
        run_id=run_id,
        detail={
            "actor": actor,
            "finding_id": finding_id,
            "recommendation_id": recommendation_id,
            "baseline_run_id": baseline_id,
            "model_sha256": (
                baseline_record.provenance.model_sha256
                if baseline_record.provenance is not None else None
            ),
            "settings_hash": baseline_record.settings_hash,
            "defense": frozen_json["defense"],
        },
    )
    with get_session() as sess:
        finding = sess.get(Finding, finding_id)
        if finding is None:
            raise ApiError(NOT_FOUND, "finding not found")
        finding.status = "fixing"
        sess.add(Run(
            id=run_id,
            project_id=project_id,
            target_id=target_id,
            mode="api",
            status="queued",
            scanner="ml.verify",
            created_by=actor,
            stage_table={
                "stage": None,
                "stages_done": [],
                "baseline_run_id": baseline_id,
                "jobs": {},
            },
        ))
        sess.flush()
        sess.add(Job(
            id=job_id,
            run_id=run_id,
            project_id=project_id,
            type="verify.replay",
            status="queued",
            created_by=actor,
            detail={
                "finding_id": finding_id,
                "recommendation_id": recommendation_id,
                "baseline_run_id": baseline_id,
                "campaign_config": frozen_json,
            },
        ))
        sess.flush()
        table = _campaign_table(sess)
        sess.execute(table.insert().values(
            run_id=run_id,
            project_id=project_id,
            target_id=target_id,
            kind="verify",
            modality=frozen.modality,
            baseline_run_id=baseline_id,
            settings_hash=baseline_record.settings_hash,
            config=frozen_json,
            limitations=[],
        ))
    if enqueue:
        try:
            task_id = _enqueue_campaign(job_id)
        except Exception as exc:  # noqa: BLE001 - any broker failure is the same refusal
            logger.warning("enqueue failed for ML verify job %s; rolling the admission back", job_id,
                           exc_info=True)
            _delete_campaign_rows(run_id, [job_id])
            with get_session() as sess:
                finding = sess.get(Finding, finding_id)
                if finding is not None and finding.status == "fixing":
                    finding.status = previous_status
            refuse(ApiError(QUEUE_UNAVAILABLE, "job queue is unavailable; the verification was not admitted",
                            reason=type(exc).__name__),
                   rolled_back_run_id=run_id, rolled_back_job_ids=[job_id])
        _stamp_task_id(job_id, task_id)
    return CampaignJobHandle(run_id=run_id, job_ids=[job_id])


__all__ = [
    "DEFAULT_MAX_EPS_GRID_MEMBERS", "DEFAULT_VERIFY_DEFENSE_ID",
    "CampaignJobHandle", "create_attack_campaign", "create_verify_campaign",
    "persist_campaign_record", "recommendation_defense_ids",
]
