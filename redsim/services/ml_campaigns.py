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

Modalities (plan 12 wave B2, register MODALITIES-06..08): :data:`SUPPORTED_MODALITIES`
is the one table of what a campaign may evaluate (``image``, ``tabular``, ``text``,
``detection``) with, per modality, the budgets it can be measured under, the
default budget grid and reference for each, the label the axis carries, the
``n_samples`` default and cap and whether a black-box endpoint may serve it. The
"norm" of a text campaign is the ``edit`` budget (share of words substituted) and
of a detection campaign the ``patch_area`` budget (share of the image area); a
norm that does not belong to the modality is ``422 params_out_of_range`` on
``norm`` and a grid that breaks the grid rules is ``422 eps_grid_invalid``, in
both cases with the reason. ``llm`` is not a campaign modality
(:data:`NOT_IMPLEMENTED_MODALITIES`): probe runs have their own route and never
enter an MRI. A detection campaign is admitted with ``n_samples`` capped at
:data:`DETECTION_N_SAMPLES_CAP` (CPU budget, spec 12.8) and its explain stage
records ``ExplainerUnavailable``; the cap is the admission's, the schema range
is unchanged.

Defaults the admission fills when a request omits them (spec 12.3, register
G-ATK6, MODALITIES-08): the modality's default norm, the ε grid and reference
budget for that norm (``DEFAULT_EPS_GRID_LINF`` / ``DEFAULT_EPS_GRID_L2`` from
``redsim.ml.scoring``, :data:`DEFAULT_EDIT_GRID`, :data:`DEFAULT_PATCH_AREA_GRID`)
and the evaluation dataset the model manifest declares. A grid with more than
``DEFAULT_MAX_EPS_GRID_MEMBERS`` members is refused unless the caller raises the
bound explicitly (spec 12.8).

Attack norms (ATTACKS_HARDEN-03): an attack may name only the norms it declares
(``redsim.ml.attacks.attack_supports_norm``); a campaign whose norm the adapter
does not support is ``422 params_out_of_range`` on ``norm`` naming the adapter's
norms and the attacks that do take the campaign norm on that modality. The caller's
overrides are validated with the adapter's per-modality cost defaults in place
(``apply_domain_defaults``, HopSkipJump on images); only the caller's keys are
frozen, the adapter records the effective values on every row.

Endpoint targets (ENDPOINT-08, -14, register endpoint-admission): a
``ml_model_endpoint`` target is admitted only when its detail carries the
``EndpointSpec`` binding the registration route wrote; it exposes no gradients by
contract, so a white-box attack is ``422 attack_requires_gradients`` (no surrogate
transfer either: the remote model has no build-time surrogate); ``explain_k`` is
capped through ``EXPLAIN_QUERY_CAPS``; the worst-case query budget (clean and
control rows, the attacks' bounds from their resolved parameters, the explainer
bound at the caps) is compared with the per-job row cap and recorded in the frozen
config's provenance slot (``target_snapshot["endpoint"]``) so the worker can hand
the same limits to the broker; the target snapshot never carries a URL or a
credential.

Scoring (REVIEW_REPORTS-29): the ``scoring`` block is server-owned. Admission reads
``projects.ml_scoring`` (the per-project override written by the settings route),
validates it through ``ScoringConfig`` without renormalising and freezes it onto
the campaign; a request that sends ``scoring`` is ``422 params_out_of_range``. A
rerun keeps its parent's frozen block and a verify run keeps its baseline's, so
lineage pairs stay comparable. The 202 response and the ``attack.run`` audit detail
disclose ``scoring_source`` (``project`` / ``default`` / ``parent``),
``scoring_weights`` and ``non_default_weights``.

Reruns (register G-API-RERUN, spec 10.6): ``parent_run_id`` names a terminal
``failed`` / ``cancelled`` attack campaign on the same model; its configuration
is copied, every admission check runs again, the lineage is stored in
``ml_campaigns.parent_run_id`` and the original rows are never touched.

``attack_params`` in the frozen config holds the caller's overrides only, each
validated through the adapter's ``resolve_params``. The grid-owned keys (:data:`_GRID_OWNED_PARAMS`) are stripped
before validation: the runner (``redsim.ml.campaign._attack_params``) derives
``eps`` from ``eps_grid`` and ``norm_l2`` from ``norm`` and refuses a config that
sets either. Attack applicability is read from the registry capability tags
(``modality:<domain>``), the same declaration the runner honours, so an attack
that lists several modalities (PGD by surrogate transfer on tabular targets,
spec 12.9) is admitted while a true mismatch stays ``attack_modality_mismatch``.

Two more checks the runner (``redsim.ml.campaign._resolve_attacks``) performs
are mirrored here so a campaign the sandbox child would refuse is never
admitted, never enqueued and never becomes a failed ``Run``: ``attack_ids`` may
name evasion adapters only (the benign control runs automatically at every grid
member when ``include_control`` is true, spec 12.4, and is not an attack), and
an attack may only run under a norm it supports. Both are ``422
params_out_of_range`` with the field that has to change.

Verify runs (spec 16.5): a training defense (``kind: training`` in the catalog,
ATTACKS_HARDEN-12) is admitted for the modalities its row declares on a model
that exposes gradients (the proxy for a torch module the trainer can fine-tune);
on a tabular tree ensemble it is ``422 defense_modality_mismatch`` with the
register ATTACKS_HARDEN-20 reason, and on a model without gradients ``422
params_out_of_range`` with the trainer's reason. Nothing is faked: the
``defense_apply`` stage runs in the verify child and records the defense as
unavailable, with the score withheld, when it cannot train.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NoReturn
from uuid import uuid4

from redsim.api import errors as _errors
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
from redsim.ml.schema import CampaignConfig, CandidateRecommendation, MRIWeights, ScoringConfig
from redsim.ml.scoring import (
    DEFAULT_EPS_GRID_L2,
    DEFAULT_EPS_GRID_LINF,
    DEFAULT_MAX_EPS_GRID_MEMBERS,
    DEFAULT_REFERENCE_EPS,
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
_ENDPOINT_KIND = "ml_model_endpoint"
#: Run statuses a rerun may start from (spec 10.6: retry is a new linked run of a failed/cancelled one).
_RERUN_PARENT_STATUSES = frozenset({"failed", "cancelled"})
_TERMINAL_RUN_STATUSES = frozenset({"succeeded", "failed", "cancelled"})
#: Config keys the server owns; a request or a copied parent config never sets them. ``scoring`` is
#: refused when a request sends it (REVIEW_REPORTS-29); the others are dropped silently as before.
_SERVER_OWNED_CONFIG_KEYS = frozenset({"target_snapshot", "attacks", "defense", "scoring"})
_CLIENT_REFUSED_CONFIG_KEYS = frozenset({"scoring"})
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
#: The adapter parameter that switches a takes-eps attack to the L2 norm; an adapter without it and
#: without an explicit ``norms`` declaration is L-inf only (``redsim.ml.attacks.attack_norms``).
_L2_PARAM = "norm_l2"
#: The 17.3 code for an endpoint campaign whose worst-case query estimate exceeds the per-job cap
#: (spec 17.3 addendum, wave B2). Falls back to ``params_out_of_range`` on a tree without the code.
_QUERY_BUDGET_EXCEEDED: str = getattr(_errors, "QUERY_BUDGET_EXCEEDED", PARAMS_OUT_OF_RANGE)
#: Keys a frozen endpoint target snapshot never carries (D3: no URL string, no credential leaves).
_ENDPOINT_SECRET_KEYS = frozenset({
    "url", "auth", "auth_header", "authorization", "secret", "token", "password", "api_key", "headers",
    "allowlist", "credential", "credentials",
})

# ---------------------------------------------------------------------------
# Modalities (MODALITIES-06..08)
# ---------------------------------------------------------------------------

#: Spec 12.3 edit-budget grid for text campaigns (share of words substituted per input) and its reference.
#: The same values as ``redsim.ml.attacks.word_substitution.DEFAULT_EDIT_GRID`` / ``DEFAULT_EDIT_REFERENCE``
#: (asserted equal in tests/ml/test_admission_phase_b.py so the two cannot drift).
DEFAULT_EDIT_GRID: tuple[float, ...] = (0.1, 0.2, 0.3)
DEFAULT_EDIT_REFERENCE = 0.2
#: Spec 12.3 patch-area grid for detection campaigns (patch area as a share of the image area) and its
#: reference; equal to ``redsim.ml.attacks.dpatch.DEFAULT_PATCH_AREA_GRID`` / ``DEFAULT_REFERENCE_PATCH_AREA``.
DEFAULT_PATCH_AREA_GRID: tuple[float, ...] = (0.01, 0.03, 0.05)
DEFAULT_PATCH_AREA_REFERENCE = 0.03
#: Detection ``n_samples``: the admission default (images; every row's own ``n`` counts boxes) and the CPU cap
#: (spec 12.8; DPatch at 320 px runs minutes per image on a laptop). The schema range is unchanged.
DETECTION_N_SAMPLES_DEFAULT = 50
DETECTION_N_SAMPLES_CAP = 200

#: What the budget axis of each norm measures (MODALITIES-43: reports label the axis from the literal).
BUDGET_LABELS: dict[str, str] = {
    "linf": "L-inf perturbation (fraction of the [0, 1] input range)",
    "l2": "L2 perturbation radius",
    "edit": "edit budget (share of words substituted)",
    "patch_area": "patch area (share of the image area)",
}


@dataclass(frozen=True)
class ModalitySpec:
    """One row of :data:`SUPPORTED_MODALITIES`: what a campaign on this modality may be measured under."""

    modality: str
    norms: tuple[str, ...]                          # budgets a campaign on this modality may name
    default_norm: str                               # filled when the request omits ``norm``
    eps_grids: Mapping[str, tuple[float, ...]]      # default grid per norm (spec 12.3)
    reference_eps: Mapping[str, float]              # default reference per norm; a member of the grid
    default_n_samples: int | None = None            # filled when the request omits ``n_samples``
    max_n_samples: int | None = None                # admission cap (``422 params_out_of_range``)
    endpoint: bool = False                          # a black-box endpoint target may serve this modality
    mri: bool = True                                # False: the campaign carries a scorecard, never an MRI

    def default_eps_grid(self, norm: str) -> list[float]:
        """The spec 12.3 default grid for ``norm`` on this modality as a fresh ascending list."""
        try:
            return list(self.eps_grids[norm])
        except KeyError as exc:
            raise ValueError(f"no default grid for norm {norm!r} on {self.modality} campaigns; "
                             f"norms: {list(self.norms)}") from exc

    def default_reference_eps(self, norm: str) -> float:
        try:
            return float(self.reference_eps[norm])
        except KeyError as exc:
            raise ValueError(f"no default reference budget for norm {norm!r} on {self.modality} campaigns; "
                             f"norms: {list(self.norms)}") from exc


_CLASSIFIER_GRIDS: dict[str, tuple[float, ...]] = {"linf": DEFAULT_EPS_GRID_LINF, "l2": DEFAULT_EPS_GRID_L2}
_CLASSIFIER_REFERENCES: dict[str, float] = {"linf": DEFAULT_REFERENCE_EPS, "l2": default_reference_eps("l2")}

#: The campaign modalities (MODALITIES-06). Availability of a *target* is still the target row's own
#: status: a bundled text or detection model whose assets are not built stays ``not_implemented`` /
#: ``model_load_refused`` on its row and never yields a fake run.
SUPPORTED_MODALITIES: dict[str, ModalitySpec] = {
    "image": ModalitySpec(
        modality="image", norms=("linf", "l2"), default_norm="linf",
        eps_grids=_CLASSIFIER_GRIDS, reference_eps=_CLASSIFIER_REFERENCES, endpoint=True,
    ),
    "tabular": ModalitySpec(
        modality="tabular", norms=("linf", "l2"), default_norm="linf",
        eps_grids=_CLASSIFIER_GRIDS, reference_eps=_CLASSIFIER_REFERENCES, endpoint=True,
    ),
    "text": ModalitySpec(
        modality="text", norms=("edit",), default_norm="edit",
        eps_grids={"edit": DEFAULT_EDIT_GRID}, reference_eps={"edit": DEFAULT_EDIT_REFERENCE},
    ),
    "detection": ModalitySpec(
        modality="detection", norms=("patch_area",), default_norm="patch_area",
        eps_grids={"patch_area": DEFAULT_PATCH_AREA_GRID},
        reference_eps={"patch_area": DEFAULT_PATCH_AREA_REFERENCE},
        default_n_samples=DETECTION_N_SAMPLES_DEFAULT, max_n_samples=DETECTION_N_SAMPLES_CAP, mri=False,
    ),
}

#: Modalities the catalog knows but a campaign never evaluates, with the reason the 501 carries.
NOT_IMPLEMENTED_MODALITIES: dict[str, str] = {
    "llm": ("LLM targets run garak probes through POST /v1/models/{id}/probes (spec 11); probe results are a "
            "scorecard with denominators and never enter an attack campaign or an MRI"),
}

#: Every norm some modality accepts (the union of the table; equal to ``redsim.ml.attacks.KNOWN_NORMS``).
KNOWN_NORMS: frozenset[str] = frozenset(n for spec in SUPPORTED_MODALITIES.values() for n in spec.norms)


def modality_norms(modality: str) -> frozenset[str]:
    """The budgets a campaign on ``modality`` may name (empty for an unknown modality)."""
    spec = SUPPORTED_MODALITIES.get(modality)
    return frozenset(spec.norms) if spec is not None else frozenset()


def default_eps_grid_for(modality: str, norm: str) -> list[float]:
    """The default grid for ``norm`` on ``modality`` (``ValueError`` when the pair is not in the table)."""
    spec = SUPPORTED_MODALITIES.get(modality)
    if spec is None:
        raise ValueError(f"unknown campaign modality {modality!r}; known: {sorted(SUPPORTED_MODALITIES)}")
    return spec.default_eps_grid(norm)


def default_reference_eps_for(modality: str, norm: str) -> float:
    """The default reference budget for ``norm`` on ``modality`` (``ValueError`` for an unknown pair)."""
    spec = SUPPORTED_MODALITIES.get(modality)
    if spec is None:
        raise ValueError(f"unknown campaign modality {modality!r}; known: {sorted(SUPPORTED_MODALITIES)}")
    return spec.default_reference_eps(norm)


def _norm_label(norms: list[str]) -> str:
    names = {"linf": "L-inf", "l2": "L2", "edit": "edit-budget", "patch_area": "patch-area"}
    return " / ".join(names.get(n, n) for n in norms)


def check_norm_for_modality(modality: str, norm: Any) -> ApiError | None:
    """The refusal for a ``norm`` that does not belong to ``modality`` (MODALITIES-08), or ``None``.

    ``edit`` is the text budget and ``patch_area`` the detection budget; image and tabular campaigns are
    measured in ``linf`` or ``l2``. The message names the budgets the modality takes so the field that has
    to change is clear; the code is ``params_out_of_range`` on ``norm``.
    """
    spec = SUPPORTED_MODALITIES.get(modality)
    if spec is None:
        return ApiError(PARAMS_OUT_OF_RANGE, f"unknown campaign modality {modality!r}", field="modality")
    if not isinstance(norm, str) or norm not in KNOWN_NORMS:
        return ApiError(PARAMS_OUT_OF_RANGE, f"norm must be one of {sorted(KNOWN_NORMS)}, got {norm!r}",
                        field="norm", reasons=[f"unknown norm {norm!r}"])
    if norm not in spec.norms:
        owners = sorted(m for m, s in SUPPORTED_MODALITIES.items() if norm in s.norms)
        return ApiError(
            PARAMS_OUT_OF_RANGE,
            f"norm {norm!r} is the {_norm_label([norm])} budget of {owners} campaigns; a {modality} campaign is "
            f"measured under {list(spec.norms)} ({'; '.join(BUDGET_LABELS[n] for n in spec.norms)})",
            field="norm", reasons=[f"norm {norm} does not belong to modality {modality}"],
        )
    return None


# ---------------------------------------------------------------------------
# Endpoint budgets (ENDPOINT-08, -14)
# ---------------------------------------------------------------------------

#: Worst-case predict rows per grid member for the black-box adapters, from their resolved parameters
#: (register ENDPOINT-08 formulas). An adapter may expose ``worst_case_queries(params, n)`` instead.
_QUERY_ROW_FORMULAS: dict[str, Callable[[Mapping[str, Any], int], int]] = {
    "hopskipjump": lambda p, n: n * (int(p["init_size"]) + int(p["max_iter"]) * (int(p["max_eval"]) + 1)),
    "zoo": lambda p, n: n * int(p["max_iter"]) * int(p["binary_search_steps"]) * 2 * int(p["nb_parallel"]),
}
_ENDPOINT_LIMIT_DEFAULTS: dict[str, float | int] = {
    "rps": 10.0, "batch_rows": 32, "timeout_s": 30.0, "max_rows": 500_000, "max_requests": 20_000,
}


def _endpoint_limits(modality: str, endpoint_block: Mapping[str, Any]) -> dict[str, float | int]:
    """The per-job limits an endpoint campaign runs under: environment defaults merged with the binding."""
    overrides: dict[str, Any] = dict(_as_mapping(endpoint_block.get("limits")))
    for key in ("batch_rows", "timeout_s"):
        if endpoint_block.get(key) is not None and key not in overrides:
            overrides[key] = endpoint_block[key]
    try:
        from redsim.ml.endpoint_broker import EndpointLimits
    except ImportError:   # pragma: no cover - the broker module ships with the tree
        limits = dict(_ENDPOINT_LIMIT_DEFAULTS)
        if modality == "tabular":
            limits["batch_rows"] = 256
        for key, raw in overrides.items():
            if key in limits and isinstance(raw, (int, float)) and not isinstance(raw, bool) and raw > 0:
                limits[key] = float(raw) if key in {"rps", "timeout_s"} else int(raw)
        return limits
    return dict(EndpointLimits.from_env(modality).merged(overrides).as_dict())


def _worst_case_attack_rows(adapter: Any, attack_id: str, params: Mapping[str, Any], n: int, n_eps: int,
                            ) -> int | None:
    """Upper bound on the predict rows ``attack_id`` may issue for ``n`` inputs, or ``None`` when unknown."""
    fn = getattr(adapter, "worst_case_queries", None)
    if callable(fn):
        try:
            return int(fn(dict(params), n)) * n_eps
        except Exception:  # noqa: BLE001 - an adapter bound that fails is "not estimable", never a guess
            logger.debug("worst_case_queries failed for %s", attack_id, exc_info=True)
    formula = _QUERY_ROW_FORMULAS.get(attack_id)
    if formula is None:
        return None
    try:
        return int(formula(params, n)) * n_eps
    except (KeyError, TypeError, ValueError):
        return None


def _redacted_endpoint_snapshot(detail: Mapping[str, Any], url_host: str) -> dict[str, Any]:
    """The target detail for a frozen endpoint snapshot: host only, no URL, credential or allowlist keys."""
    def scrub(block: Mapping[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in block.items() if str(k).lower() not in _ENDPOINT_SECRET_KEYS}

    out = scrub(detail)
    for key in ("manifest", "endpoint"):
        if isinstance(out.get(key), Mapping):
            out[key] = scrub(out[key])
    if isinstance(out.get("manifest"), Mapping) and isinstance(out["manifest"].get("endpoint"), Mapping):
        out["manifest"] = {**out["manifest"], "endpoint": scrub(out["manifest"]["endpoint"])}
    out["url_host"] = url_host
    return out


# ---------------------------------------------------------------------------
# Handles and shared helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CampaignJobHandle:
    """A handle that remains compatible when campaign admission grows jobs.

    The scoring keys (REVIEW_REPORTS-29/-30) are additive: ``scoring_source`` says where the frozen block
    came from (``project`` override, deployment ``default``, the rerun's ``parent`` or the verify's
    ``baseline``), ``non_default_weights`` is ``True`` when the frozen weight vector differs from
    ``MRIWeights()`` (such a campaign is comparable only with campaigns under the same vector) and
    ``scoring_weights`` is that vector. They are omitted when the handle does not carry them.
    """

    run_id: str
    job_ids: list[str]
    scoring_source: str | None = None
    non_default_weights: bool | None = None
    scoring_weights: dict[str, float] | None = None

    def to_response(self) -> dict[str, Any]:
        response: dict[str, Any] = {
            "run_id": self.run_id,
            "job_ids": list(self.job_ids),
            "status_url": f"/v1/runs/{self.run_id}",
        }
        if self.scoring_source is not None:
            response["scoring_source"] = self.scoring_source
        if self.non_default_weights is not None:
            response["non_default_weights"] = self.non_default_weights
        if self.scoring_weights is not None:
            response["scoring_weights"] = dict(self.scoring_weights)
        return response


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


def _resolve_reference_eps(raw: Any, grid: list[float], default_reference: float) -> float:
    if raw is None:
        if default_reference not in grid:
            raise ApiError(
                REFERENCE_EPS_NOT_IN_GRID,
                f"reference_eps was omitted and the default {default_reference} is not a member of eps_grid {grid}",
                field="reference_eps", reasons=[f"default {default_reference} not in grid"],
            )
        return default_reference
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
# Scoring (REVIEW_REPORTS-29)
# ---------------------------------------------------------------------------


def _resolve_scoring(
    *, parent_scoring: Any, project_scoring: Any,
) -> tuple[ScoringConfig, str]:
    """The server-owned ``scoring`` block for a new campaign and where it came from.

    A rerun keeps its parent's frozen block (``parent``); otherwise the project's ``ml_scoring`` override
    (``project``) or the deployment default (``default``). The block is validated through ``ScoringConfig``
    exactly as stored: a weight vector that does not sum to one is refused, never filled in or renormalised.
    """
    if isinstance(parent_scoring, Mapping) and parent_scoring:
        block: Any = dict(parent_scoring)
        source = "parent"
    elif isinstance(project_scoring, Mapping) and project_scoring:
        block = dict(project_scoring)
        source = "project"
    else:
        return ScoringConfig(), "default"
    try:
        return ScoringConfig.model_validate(block), source
    except ValueError as exc:   # pydantic.ValidationError subclasses ValueError
        errors = getattr(exc, "errors", None)
        rows = list(errors()) if callable(errors) else []
        reasons = [str(row.get("msg", "")) for row in rows] or [str(exc)]
        raise ApiError(
            PARAMS_OUT_OF_RANGE,
            f"the {source} scoring block is not a valid ScoringConfig (weights must sum to 1 and are never "
            f"renormalised): {reasons[0]}",
            field="scoring", reasons=reasons, scoring_source=source,
        ) from exc


def is_default_weights(scoring: ScoringConfig | Mapping[str, Any]) -> bool:
    """``True`` when the block's weight vector equals ``MRIWeights()`` (spec 15.3 badge predicate)."""
    if isinstance(scoring, ScoringConfig):
        return scoring.weights == MRIWeights()
    weights = _as_mapping(_as_mapping(scoring).get("weights"))
    if not weights:
        return True
    try:
        return MRIWeights.model_validate(weights) == MRIWeights()
    except ValueError:
        return False


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
    max_n_samples: Mapping[str, int] | None = None,
) -> CampaignJobHandle:
    """Audit first, then atomically admit one whole-campaign ``attack.run`` job.

    Raises :class:`ApiError` with the spec 17.3 code for every refusal (each
    refusal also writes a ``success=False`` ``attack.run`` audit row):
    ``not_found``, ``not_implemented`` (``llm`` targets, an endpoint target without
    its ``EndpointSpec`` binding, an endpoint on a modality the contract does not
    serve, unavailable attacks), ``model_load_refused`` (status not ``available``,
    with ``status`` and ``refusal_reason``), ``unknown_attack``,
    ``attack_modality_mismatch``, ``attack_requires_gradients`` (also every
    white-box attack on an endpoint target), ``eps_grid_invalid``,
    ``reference_eps_not_in_grid``, ``params_out_of_range`` (a norm outside the
    modality, an attack that does not support the norm, a non-evasion adapter such
    as ``noise_control`` in ``attack_ids``, ``n_samples`` above the modality cap,
    a client-sent ``scoring`` block), ``query_budget_exceeded`` (endpoint worst-case
    rows above the per-job cap), ``dataset_incompatible``,
    ``campaign_not_terminal`` (rerun of a live parent) and ``queue_unavailable``
    (enqueue failed; rows rolled back).

    ``max_n_samples`` overrides the per-modality ``n_samples`` caps of
    :data:`SUPPORTED_MODALITIES` (``{"detection": 100}``), the way
    ``max_eps_grid_members`` raises the grid bound: explicit configuration only.

    ``attack_params`` is frozen as the caller's overrides per attack (values as
    the adapter resolves them, validated with the adapter's per-modality defaults
    in place), never the adapter defaults, and never the grid-owned ``eps`` /
    ``norm_l2`` the runner supplies itself. A rerun copies the parent's
    ``attack_params`` through the same rule, so a parent frozen with those keys by
    an earlier build reruns cleanly.
    """
    from redsim.db.models import Job, Project, Run, Target
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
            detail = _as_mapping(getattr(target, "detail", None))
            manifest = _target_manifest(detail)
            is_endpoint = target.kind == _ENDPOINT_KIND
            endpoint_block = _as_mapping(detail.get("endpoint") or manifest.get("endpoint"))
            if is_endpoint and not endpoint_block.get("url_host"):
                # No EndpointSpec binding: the target was never registered through the endpoint route, so
                # there is no host, contract or auth profile the worker-parent broker could serve.
                raise ApiError(
                    NOT_IMPLEMENTED,
                    "black-box endpoint campaigns run only for endpoint targets that carry their EndpointSpec "
                    "binding (url_host, auth_profile_id, contract_version); this target has none",
                    phase="B", reason="endpoint binding missing; register through POST /v1/models source=endpoint",
                )
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
            # An endpoint exposes predictions only (EndpointSpec: gradients False by contract) and has no
            # build-time surrogate, whatever a hand-written detail says.
            gradients = False if is_endpoint else detail.get("gradients", manifest.get("gradients"))
            surrogate_declared = (not is_endpoint) and bool(detail.get("surrogate") or manifest.get("surrogate"))
            manifest_dataset = detail.get("dataset_id") or manifest.get("dataset_id")
            manifest_revision = detail.get("dataset_revision") or manifest.get("dataset_revision")
            if is_endpoint:
                url_host = str(endpoint_block["url_host"])
                target_snapshot: dict[str, Any] = {
                    "id": target.id, "kind": target.kind, "value": f"endpoint:{url_host}",
                    "detail": _redacted_endpoint_snapshot(detail, url_host),
                }
            else:
                target_snapshot = {
                    "id": target.id, "kind": target.kind, "value": str(target.value), "detail": detail,
                }
            project = sess.get(Project, project_id)
            project_scoring = getattr(project, "ml_scoring", None) if project is not None else None
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
    endpoint_provenance: dict[str, Any] | None = None
    if isinstance(snapshot.get("attack_ids"), list):
        # Ids only, on every refusal row from here on (the full check of the list comes below).
        audit_context["attack_ids"] = [a for a in snapshot["attack_ids"] if isinstance(a, str)]
    try:
        sent_server_keys = sorted(k for k in requested if k in _CLIENT_REFUSED_CONFIG_KEYS)
        if sent_server_keys:
            raise ApiError(
                PARAMS_OUT_OF_RANGE,
                "scoring is server-owned: the project's ml_scoring block (PUT /v1/projects/{slug}/settings) is "
                "frozen onto the campaign at admission and a rerun keeps its parent's; remove scoring from the "
                "request",
                field="scoring", reasons=[f"client-sent {k}" for k in sent_server_keys],
            )
        scoring_cfg, scoring_source = _resolve_scoring(parent_scoring=base.get("scoring"),
                                                       project_scoring=project_scoring)
        snapshot["scoring"] = scoring_cfg.model_dump(mode="json")
        non_default_weights = not is_default_weights(scoring_cfg)

        modality = snapshot.get("modality") or target_modality
        if target_modality and modality != target_modality:
            raise ApiError(ATTACK_MODALITY_MISMATCH,
                           f"campaign modality {modality!r} differs from the model modality {target_modality!r}",
                           field="modality")
        if modality in NOT_IMPLEMENTED_MODALITIES:
            raise ApiError(NOT_IMPLEMENTED, f"{modality!r} campaigns are not implemented: "
                           f"{NOT_IMPLEMENTED_MODALITIES[modality]}", phase="B", field="modality",
                           reason=NOT_IMPLEMENTED_MODALITIES[modality])
        spec = SUPPORTED_MODALITIES.get(modality) if isinstance(modality, str) else None
        if spec is None:
            raise ApiError(PARAMS_OUT_OF_RANGE,
                           f"unknown campaign modality {modality!r}; campaigns evaluate "
                           f"{sorted(SUPPORTED_MODALITIES)} models", field="modality")
        modality = spec.modality
        if is_endpoint and not spec.endpoint:
            raise ApiError(
                NOT_IMPLEMENTED,
                f"black-box endpoints serve {sorted(m for m, s in SUPPORTED_MODALITIES.items() if s.endpoint)} "
                f"classifiers only: the endpoint-v1 contract carries class probabilities, not {modality} outputs",
                phase="B", field="modality",
                reason=f"endpoint contract does not carry {modality} outputs",
            )
        snapshot["modality"] = modality
        norm = snapshot.get("norm") or spec.default_norm
        norm_error = check_norm_for_modality(modality, norm)
        if norm_error is not None:
            raise norm_error
        snapshot["norm"] = norm
        grid_raw = snapshot.get("eps_grid")
        eps_grid = (spec.default_eps_grid(norm) if grid_raw is None
                    else _validate_eps_grid(grid_raw, max_members=max_eps_grid_members))
        snapshot["eps_grid"] = eps_grid
        snapshot["reference_eps"] = _resolve_reference_eps(snapshot.get("reference_eps"), eps_grid,
                                                           spec.default_reference_eps(norm))
        if snapshot.get("n_samples") is None and spec.default_n_samples is not None:
            snapshot["n_samples"] = spec.default_n_samples
        n_samples_raw = snapshot.get("n_samples")
        n_cap: int | None = spec.max_n_samples
        if max_n_samples and modality in max_n_samples:
            n_cap = int(max_n_samples[modality])
        if (n_cap is not None and isinstance(n_samples_raw, int) and not isinstance(n_samples_raw, bool)
                and n_samples_raw > n_cap):
            raise ApiError(
                PARAMS_OUT_OF_RANGE,
                f"n_samples {n_samples_raw} exceeds the {modality} campaign cap of {n_cap} (spec 12.8 CPU budget; "
                f"a detection row's own n counts ground-truth boxes, not images)",
                field="n_samples", reasons=[f"{modality} n_samples cap {n_cap}"], cap=n_cap,
            )
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

        # Endpoint explain caps (ENDPOINT-14): the requested k is recorded, the capped one is frozen.
        explain_caps: Any = None
        explain_k_requested: Any = None
        if is_endpoint:
            from redsim.ml.explain.base import EXPLAIN_QUERY_CAPS

            explain_caps = EXPLAIN_QUERY_CAPS
            explain_k_requested = snapshot.get("explain_k", CampaignConfig.model_fields["explain_k"].default)
            if isinstance(explain_k_requested, int) and not isinstance(explain_k_requested, bool):
                snapshot["explain_k"] = min(explain_k_requested, explain_caps.explain_k)

        from redsim.ml.attacks import (
            ATTACKS,
            apply_domain_defaults,
            attack_capabilities,
            attack_norms,
            attack_supports_norm,
            get_attack,
        )

        attack_infos = []
        frozen_params: dict[str, dict[str, float | int | bool]] = {}
        attack_rows: dict[str, int | None] = {}
        n_for_budget = int(CampaignConfig.model_fields["n_samples"].default)
        if isinstance(n_samples_raw, int) and not isinstance(n_samples_raw, bool):
            n_for_budget = n_samples_raw
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
            # Applicability and norms come from the registry declarations (``modality:<domain>`` tags for
            # every domain the adapter declares, ``norms`` for the budgets it can be evaluated under), the
            # same declarations ``redsim.ml.campaign._resolve_attacks`` honours; ``AttackInfo.domain`` is the
            # primary domain only and would refuse PGD by surrogate transfer on a tabular model (spec 12.9).
            try:
                capabilities = attack_capabilities(adapter)
                supported_norms = sorted(attack_norms(adapter))
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
            # The runner refuses an attack under a norm it does not support (ATTACKS_HARDEN-03); the norm is a
            # campaign-wide choice, so the field that has to change is ``norm`` (or the attack set). The
            # attacks that do take this norm on this modality are listed.
            if not attack_supports_norm(adapter, norm):
                capable = sorted(
                    a.id for a in ATTACKS
                    if a.info().family == _ATTACK_FAMILY and attack_supports_norm(a, norm)
                    and f"modality:{modality}" in attack_capabilities(a)
                )
                has_l2_switch = any(p.name == _L2_PARAM for p in info.params_schema)
                reasons = ([f"{attack_id} declares no {_L2_PARAM} parameter"]
                           if norm == "l2" and not has_l2_switch
                           else [f"{attack_id} supports norms {supported_norms}, not {norm!r}"])
                raise ApiError(
                    PARAMS_OUT_OF_RANGE,
                    f"attack {attack_id!r} supports the {_norm_label(supported_norms)} norm only and the campaign "
                    f"norm is {norm!r}; attacks that take {norm!r} on {modality} targets: {capable}",
                    field="norm", reasons=reasons,
                )
            # A white-box attack on a model without loss gradients is admitted when the adapter declares
            # ``surrogate_transfer`` and the target declares a surrogate: the runner
            # (``redsim.ml.campaign._surrogate_for_white_box``) then runs it on the surrogate and notes the
            # transfer on every row (spec 12.9). An endpoint has neither gradients nor a surrogate.
            by_surrogate = "surrogate_transfer" in capabilities and surrogate_declared
            if info.requires_gradients and gradients is False and not by_surrogate:
                raise ApiError(
                    ATTACK_REQUIRES_GRADIENTS,
                    f"attack {attack_id!r} needs loss gradients the model does not expose "
                    + ("(black-box endpoint: predictions only, no surrogate)" if is_endpoint
                       else "(manifest gradients: false)"),
                    field="attack_ids",
                )
            # The runner supplies ``eps`` (from the grid) and ``norm_l2`` (from ``norm``) at run time and
            # refuses a config that sets them, so they are stripped before validation rather than refused:
            # a copied parent config frozen by an earlier build still carries them. The caller keys are
            # validated with the adapter's per-modality cost defaults in place (ATTACKS_HARDEN-04; the
            # adapter applies the same defaults at run time and records the effective values in
            # ``Measurement.params``) and only the caller's keys are frozen, with the adapter's coerced values.
            # Consequence for ``settings_hash`` (spec 5.6): adapter defaults are not part of the hashed
            # config, so spelling a default out (``batch_size: 64``) hashes differently from omitting it, and
            # a later change to an adapter default is not pinned by the hash; the effective values are
            # recorded by the run's provenance instead.
            given = {k: v for k, v in _as_mapping(attack_params.get(attack_id)).items()
                     if k not in _GRID_OWNED_PARAMS}
            try:
                resolved = adapter.resolve_params(apply_domain_defaults(adapter, modality, given))
            except ValueError as exc:
                raise ApiError(PARAMS_OUT_OF_RANGE, f"invalid parameters for {attack_id!r}: {exc}",
                               field=f"attack_params.{attack_id}") from exc
            declared = {p.name for p in info.params_schema}
            frozen_params[attack_id] = {k: resolved[k] for k in given if k in declared and k in resolved}
            attack_infos.append(info)
            if is_endpoint:
                # A takes-eps attack runs once per grid member; a minimal-norm attack runs once and is
                # thresholded against the grid (spec 12.3), so its bound is not multiplied.
                n_eps = len(eps_grid) if getattr(adapter, "takes_eps", True) else 1
                attack_rows[attack_id] = _worst_case_attack_rows(adapter, attack_id, resolved, n_for_budget, n_eps)
        snapshot["attack_params"] = frozen_params
        snapshot["attacks"] = [info.model_dump(mode="json") for info in attack_infos]

        # Endpoint query budget (ENDPOINT-08): worst case from the resolved parameters against the per-job
        # cap; recorded in the frozen snapshot's provenance slot so the worker hands the broker the same limits.
        if is_endpoint:
            from redsim.ml.explain.base import estimate_kernel_explain_rows

            limits = _endpoint_limits(modality, endpoint_block)
            include_control = bool(snapshot.get("include_control", True))
            explain_k = int(snapshot.get("explain_k", explain_caps.explain_k))
            eval_rows = n_for_budget
            control_rows = n_for_budget * len(eps_grid) if include_control else 0
            if explain_k <= 0:
                explain_rows = 0
            elif modality == "tabular":
                explain_rows = int(explain_caps.estimate_rows(explain_k, with_control=include_control))
            else:
                # PartitionExplainer over predict_proba: at most ``nsamples`` masked evaluations per explained
                # input (the KernelExplainer bound with a one-row background).
                explain_rows = int(estimate_kernel_explain_rows(
                    k=min(explain_k, explain_caps.explain_k), background_rows=1, nsamples=explain_caps.nsamples,
                    with_control=include_control))
            unbounded = sorted(aid for aid, rows in attack_rows.items() if rows is None)
            if unbounded:
                raise ApiError(
                    _QUERY_BUDGET_EXCEEDED,
                    f"attack(s) {unbounded} expose no worst-case query bound; an endpoint campaign admits only "
                    "attacks whose query cost is bounded at admission (HopSkipJump, ZOO)",
                    field="attack_ids", reasons=[f"{aid}: no query bound" for aid in unbounded],
                )
            estimated_rows = eval_rows + control_rows + sum(int(r or 0) for r in attack_rows.values()) + explain_rows
            max_rows = int(limits["max_rows"])
            endpoint_provenance = {
                "url_host": str(endpoint_block["url_host"]),
                "auth_profile_id": endpoint_block.get("auth_profile_id"),
                "contract_version": endpoint_block.get("contract_version"),
                "limits": limits,
                "explain_caps": explain_caps.as_dict(),
                "explain_k_requested": explain_k_requested,
                "query_budget": {
                    "estimated_rows": estimated_rows, "eval_rows": eval_rows, "control_rows": control_rows,
                    "attack_rows": {aid: int(r or 0) for aid, r in attack_rows.items()},
                    "explain_rows": explain_rows, "max_rows": max_rows, "max_requests": int(limits["max_requests"]),
                    "estimate_kind": ("worst-case upper bound from the resolved parameters at admission; the "
                                      "broker's measured rows and requests are recorded in provenance at run "
                                      "time and are never summed with this bound"),
                },
            }
            if estimated_rows > max_rows:
                reasons = [f"estimated {estimated_rows} rows > cap {max_rows} rows"]
                if _QUERY_BUDGET_EXCEEDED == PARAMS_OUT_OF_RANGE:
                    reasons.insert(0, "query_budget_exceeded")
                raise ApiError(
                    _QUERY_BUDGET_EXCEEDED,
                    f"the worst-case query estimate of {estimated_rows} predict rows exceeds the endpoint budget of "
                    f"{max_rows} rows per job (REDSIM_ML_ENDPOINT_MAX_ROWS); lower n_samples, the grid, explain_k "
                    "or the attacks' cost parameters",
                    field="n_samples", estimate=estimated_rows, cap=max_rows, reasons=reasons,
                )
            target_snapshot["endpoint"] = endpoint_provenance
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
    scoring_weights = frozen.scoring.weights.as_dict()

    # This must precede all Run/Job/campaign rows (spec 10.5). ML campaigns target a
    # registered model rather than an active network location, hence target=None.
    audit_detail: dict[str, Any] = {
        "actor": actor, "target_id": frozen.target_id, "target_kind": target_snapshot["kind"],
        "attack_ids": list(frozen.attack_ids),
        "modality": frozen.modality, "budget": BUDGET_LABELS.get(frozen.norm, frozen.norm),
        "norm": frozen.norm, "eps_grid": list(frozen.eps_grid), "reference_eps": frozen.reference_eps,
        "n_samples": frozen.n_samples, "seed": frozen.seed, "explain_k": frozen.explain_k,
        "dataset_id": frozen.dataset_id, "dataset_revision": frozen.dataset_revision,
        "model_sha256": model_sha256, "settings_hash": frozen_settings_hash,
        "rerun": parent_run_id is not None, "parent_run_id": parent_run_id,
        "scoring_source": scoring_source, "scoring_weights": scoring_weights,
        "non_default_weights": non_default_weights,
        "config": audited_config,
    }
    if endpoint_provenance is not None:
        budget = endpoint_provenance["query_budget"]
        audit_detail["endpoint"] = {
            "url_host": endpoint_provenance["url_host"], "auth_profile_id": endpoint_provenance["auth_profile_id"],
            "estimated_rows": budget["estimated_rows"], "max_rows": budget["max_rows"],
            "max_requests": budget["max_requests"], "explain_k_requested": endpoint_provenance["explain_k_requested"],
        }
    authorize(
        "attack.run", None, allowlist=config.target_allowlist,
        actor=actor, writer=audit_writer, project_id=project_id, run_id=run_id,
        detail=audit_detail,
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
    return CampaignJobHandle(run_id=run_id, job_ids=[job_id], scoring_source=scoring_source,
                             non_default_weights=non_default_weights, scoring_weights=scoring_weights)


def recommendation_defense_ids(recommendation: CandidateRecommendation) -> set[str]:
    """The catalog defense ids a candidate recommendation names.

    Rule-generated candidates (``redsim.ml.recommend.rules``) cite a defense as
    a ``defense:<id>`` reference next to ``<ART class> (Phase A verify loop)``
    and the motivating paper, so the ids are read back through
    ``rules.defense_configs`` rather than by matching the bare class string.
    Hand-authored evidence (the frozen ``run_record.json`` fixture shape) names
    the bare ART class instead, which resolves to the catalog id that owns it
    (preprocessing and training rows alike).
    """
    from redsim.ml import defenses as _defenses
    from redsim.ml.recommend.rules import defense_configs

    catalog_rows: tuple[dict[str, Any], ...] = getattr(_defenses, "ALL_DEFENSES", _defenses.DEFENSES)
    cited = {cfg.id for cfg in defense_configs(recommendation)}
    cited |= {
        str(spec["id"]) for spec in catalog_rows
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


def _defense_catalog() -> tuple[set[str], set[str]]:
    """``(catalog ids, training ids)`` from the defenses catalog (both kinds when the tree has them)."""
    from redsim.ml import defenses as _defenses

    rows: tuple[dict[str, Any], ...] = getattr(_defenses, "ALL_DEFENSES", _defenses.DEFENSES)
    catalog = {str(spec["id"]) for spec in rows}
    training = {str(spec["id"]) for spec in rows if spec.get("kind") == "training"}
    return catalog, training


def _resolve_verify_defense(
    defense_id: str | None, recommendation: CandidateRecommendation | None,
) -> str:
    """The defense a verify request applies (spec 16.5 default; the recommendation's own when it names one).

    * ``defense_id`` given: it must be a catalog defense; when a recommendation is named it must be
      one the recommendation cites (``params_out_of_range`` on ``defense`` otherwise).
    * omitted with a recommendation: the sole runnable defense the recommendation cites; several
      cited defenses need an explicit choice; a defense the catalog does not carry (a Phase B apply
      step on a tree without the training rows) is ``not_implemented``; a recommendation naming no
      defense cannot be verified.
    * omitted without a recommendation: :data:`DEFAULT_VERIFY_DEFENSE_ID`.

    Whether a training defense can run on *this* model (modality, gradients) is checked by the caller
    once the baseline is known (:func:`_check_training_defense`).
    """
    from redsim.ml.recommend.rules import DEFENSE_IDS

    catalog, _training = _defense_catalog()
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
                           "apply step this tree's verify loop cannot run", phase="B", field="defense")
        raise ApiError(PARAMS_OUT_OF_RANGE,
                       f"recommendation {recommendation.id!r} names no defense the verify loop can apply",
                       field="defense", reasons=sorted(cited))
    if defense_id in phase_b:
        raise ApiError(NOT_IMPLEMENTED, f"defense {defense_id!r} is a Phase B apply step this tree's verify "
                       "loop cannot run", phase="B", field="defense")
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


def _check_training_defense(defense_id: str, spec: Mapping[str, Any], *, modality: str, gradients: Any) -> None:
    """Refuse a training defense the verify child could not apply to this model (ATTACKS_HARDEN-12, -20).

    The modality must be one the catalog row declares (a tabular tree ensemble carries the register
    ATTACKS_HARDEN-20 reason) and the model must expose gradients, the admission-time proxy for a torch
    module the trainer can fine-tune (an ONNX graph without a conversion, or an endpoint, has none).
    """
    if spec.get("kind") != "training":
        return
    from redsim.ml.harden import apply as _harden

    if modality not in spec["domains"]:
        reason = (getattr(_harden, "TREE_ENSEMBLE_REASON", "tree ensembles have no gradient-based adversarial "
                                                             "training in ART")
                  if modality == "tabular"
                  else f"training defenses apply to {list(spec['domains'])} targets, not {modality!r}")
        raise ApiError(DEFENSE_MODALITY_MISMATCH,
                       f"defense {defense_id!r} applies to {list(spec['domains'])} targets, not {modality!r}: "
                       f"{reason}", field="defense", reasons=[reason])
    if gradients is False:
        reason = getattr(_harden, "NO_TORCH_MODULE_REASON", "the target exposes no torch module")
        raise ApiError(PARAMS_OUT_OF_RANGE,
                       f"defense {defense_id!r} fine-tunes a torch module and the model exposes none "
                       f"(manifest gradients: false): {reason}", field="defense",
                       reasons=["training_defense_unavailable", reason])


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
    ``job_in_flight``, ``unknown_defense``, ``defense_modality_mismatch`` (also a
    training defense on a tabular tree ensemble), ``params_out_of_range`` (also a
    training defense on a model without gradients), ``not_implemented`` or
    ``queue_unavailable``; each writes a ``success=False`` ``verify.replay`` audit
    row. The frozen ``scoring`` block is the baseline's (REVIEW_REPORTS-29), so
    the pair stays comparable whatever the project override says today.
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
        if modality not in spec["domains"] and spec.get("kind") != "training":
            raise ApiError(DEFENSE_MODALITY_MISMATCH,
                           f"defense {resolved_defense_id!r} applies to {list(spec['domains'])} targets, "
                           f"not {modality!r}", field="defense")
        snapshot_target = _as_mapping(snapshot.get("target_snapshot"))
        snapshot_detail = _as_mapping(snapshot_target.get("detail"))
        snapshot_manifest = _target_manifest(snapshot_detail)
        baseline_gradients = (False if snapshot_target.get("kind") == _ENDPOINT_KIND
                              else snapshot_detail.get("gradients", snapshot_manifest.get("gradients")))
        _check_training_defense(resolved_defense_id, spec, modality=modality, gradients=baseline_gradients)
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
    scoring_weights = frozen.scoring.weights.as_dict()
    non_default_weights = not is_default_weights(frozen.scoring)

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
            "defense_kind": spec.get("kind", "preprocessing"),
            "scoring_source": "baseline",
            "scoring_weights": scoring_weights,
            "non_default_weights": non_default_weights,
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
    # The verify handle keeps the Phase A response shape (run_id, job_ids, status_url): the frozen block is
    # the baseline's and the audit row above discloses it; the attack handle carries the scoring keys.
    return CampaignJobHandle(run_id=run_id, job_ids=[job_id])


__all__ = [
    "BUDGET_LABELS", "DEFAULT_EDIT_GRID", "DEFAULT_EDIT_REFERENCE", "DEFAULT_MAX_EPS_GRID_MEMBERS",
    "DEFAULT_PATCH_AREA_GRID", "DEFAULT_PATCH_AREA_REFERENCE", "DEFAULT_VERIFY_DEFENSE_ID",
    "DETECTION_N_SAMPLES_CAP", "DETECTION_N_SAMPLES_DEFAULT", "KNOWN_NORMS", "NOT_IMPLEMENTED_MODALITIES",
    "SUPPORTED_MODALITIES", "CampaignJobHandle", "ModalitySpec", "check_norm_for_modality",
    "create_attack_campaign", "create_verify_campaign", "default_eps_grid_for", "default_reference_eps_for",
    "is_default_weights", "modality_norms", "persist_campaign_record", "recommendation_defense_ids",
]
