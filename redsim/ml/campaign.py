"""Run one adversarial-ML campaign end to end and assemble its record.

Pure Python: no Celery, database or HTTP. The worker task calls ``run_campaign``
inside the sandboxed child and persists the returned record; tests call it on the
``TinyTarget`` double with a ``FilesystemSink``.

``run_campaign`` is the shared frame (Phase B, MODALITIES-09): it resolves the target,
the defense and the attack set, keeps the stage bookkeeping (``stages_done`` and the
live ``on_stage`` callback), owns the evidence lists, writes the curve and flip-matrix
artifacts, scores, interprets, recommends and assembles the record with its
provenance. The stages that depend on what a sample is (``sample``, ``clean_eval``,
``attack:<attack_id>``, ``control`` and the explain step) belong to the modality
runner looked up in ``redsim.ml.runners.base.MODALITY_RUNNERS``: ``image`` and
``tabular`` run ``redsim.ml.runners.classification.run_classification`` (the
pre-refactor code, behaviour unchanged), ``text`` and ``detection`` run ``run_text``
and ``run_detection`` from their own modules, and a modality whose runner module is
absent is refused as ``ModalityRunnerUnavailable`` before any stage runs.

Stage order follows ``redsim.ml.schema.STAGES`` (read at run time, never copied):
load_target -> [defense_apply, when a defense was applied and the stage exists] ->
sample -> clean_eval -> attack (written per attack as ``attack:<attack_id>``, every eps
in the grid) -> control (benign noise at every eps, the reference eps included) ->
explain (at the reference budget; optional and tolerant of a missing or failing
explainer) -> score -> interpret -> recommend -> report. The explain and recommend
modules are imported lazily; when one is absent or fails the record says so in an
``Interpretation`` and a limitation rather than pretending (spec 14.7).

Invariants enforced here (spec 14, 15): measurements, observations, interpretation
and candidate recommendations stay in separate lists; every Measurement carries
``n`` and its denominators; a control accompanies the attacks at the same eps; the
MRI is computed only when all five subscores exist and the score record is
otherwise partial with the reason in ``missing`` and ``limitations``; a modality that
declares no MRI (detection) gets a score status of ``unavailable`` with its reason;
every citation resolves to a recorded id; candidates carry no measured delta.

An attack whose adapter raises ``AttackNotApplicable`` at run time (a white-box
attack on a target without loss gradients, spec 9.5) is recorded ``not_run`` in an
``Interpretation``, a limitation and ``flip_matrix.json`` and is removed from the
in-scope attack set BEFORE scoring (spec 15.4); it has no rows, no curve and no
finding, and the score describes only the attacks that ran. On a tabular target
whose manifest declares a build-time surrogate, white-box adapters receive a view of
the target whose ``art_classifier()`` is the surrogate estimator while predictions
(and therefore every measurement) stay on the real model; the rows say so (12.9).

A verify run applies the configured defense before anything is measured. A
preprocessing defense goes through ``redsim.ml.defenses.apply_defense``; a defense
whose catalog entry has ``kind: "training"`` (adversarial fine-tuning, distillation)
goes through ``redsim.ml.harden.apply.apply_training_defense`` (ATTACKS_HARDEN-06),
imported lazily. When that module is absent the defense is recorded as unavailable
in the provenance, an ``Interpretation`` and the limitations, the attacks still run
against the undefended model so the rows are real, and the score is withheld (status
``unavailable``) so no delta can be read from a run whose defense never happened.

The returned ``CampaignRecord`` is a ``RunRecord`` plus the queryable projections
(``curve``, ``settings_hash``, ``completeness``, ``missing``, ``score_status``).
"""

from __future__ import annotations

import contextlib
import importlib
import io
import logging
import os
import platform
import socket
import sys
import uuid
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version
from typing import Any

import numpy as np

from redsim.ml import schema as _schema
from redsim.ml.artifacts import ArtifactSink
from redsim.ml.attacks import (
    ATTACKS,
    CPU_FLOAT32_NOTE,
    apply_domain_defaults,
    attack_norms,
    attack_supports_norm,
    library_versions,
)
from redsim.ml.errors import AttackNotApplicable, ExplainUnavailable, MLError, TargetUnavailable
from redsim.ml.eval import eps_tag
from redsim.ml.runners.base import (
    CONTROL_ATTACK_ID,
    CURVE_PNG_NAME,
    DEFAULT_MAX_ADV_ARTIFACT_MB,
    MODALITY_RUNNERS,
    REALIZABILITY_CAVEAT,
    SUBJECT_CENTERED_CAVEAT,
    SURROGATE_NOTE_PREFIX,
    SURROGATE_TRANSFER_LIMITATION_TEMPLATE,
    TABULAR_LIMITATION,
    CampaignFrame,
    ModalityResult,
    ModalityRunner,
    ModalityRunnerUnavailable,
    call_supported,
    json_bytes,
    manifest_get,
    pinned_offline_env,
    resolve_runner,
    sha256_indices,
    sink_work_dir,
    subject_centered,
    surrogate_for_white_box,
    uniq,
    utcnow,
)
from redsim.ml.schema import (
    AttackInfo,
    CampaignConfig,
    CampaignRecord,
    CandidateRecommendation,
    DefenseConfig,
    Interpretation,
    Measurement,
    MRIRecord,
    Observation,
    Provenance,
    RobustnessCurve,
    ScoreStatus,
    standing_limitations,
)
from redsim.ml.scoring import (
    ONE_POINT_GRID_LIMITATION,
    robustness_curves,
    score_run,
    settings_hash,
)
from redsim.ml.targets.base import Target
from redsim.ml.targets.registry import TARGETS

logger = logging.getLogger(__name__)

DEFENSE_LIMITATION = (
    "The white-box attacks in this run used ART's straight-through gradient estimate through the "
    "preprocessing defense. Adaptive attacks that account for the defense may succeed where these did "
    "not, so the measured delta MRI is an upper bound on the defense's benefit against these attacks, "
    "not a general robustness gain.")
# ATTACKS_HARDEN-06: a training-time defense (adversarial fine-tuning, distillation) applied in the verify child.
TRAINING_DEFENSE_LIMITATION = (
    "The defense in this run is a training-time hardening of the model applied inside the verify child at the "
    "declared budget; the attacks ran against the derived model with the same access as the baseline. The measured "
    "delta describes robustness to the declared attack set, eps grid and slice only, not a general robustness gain, "
    "and the derived model is a new artifact whose lineage is recorded, not a change to the registered model.")
TRAINING_DEFENSE_MODULE = "redsim.ml.harden.apply"
TRAINING_DEFENSE_HOOK = "apply_training_defense"
TRAINING_DEFENSE_KIND = "training"
#: ``code`` of the hook's typed refusal (``redsim.ml.harden.apply.TrainingDefenseUnavailable``).
TRAINING_DEFENSE_UNAVAILABLE_CODE = "training_defense_unavailable"
MRI_SCOPE_LIMITATION = (
    "The MRI summarises this campaign only (one model, one modality, the declared attack set, eps grid "
    "and reference budget); it is not comparable across campaigns with different settings and is never "
    "aggregated across modalities.")
WHITE_BOX_STANDING = "White-box gradient attacks assume full model access; black-box and physical-world attacks were not evaluated."
WHITE_BOX_WITH_BLACK_BOX = (
    "White-box gradient attacks assume full model access; the black-box attack hopskipjump was evaluated "
    "with label-only query access; physical-world attacks were not evaluated.")
# The D3 bounds statement (spec 11.1, 21.5, 26 item 9), printed with every campaign's limitations.
D3_BOUNDS_LIMITATION = (
    "Open, unclassified public data only (D3). This tool evaluates and hardens the robustness of a classifier; it "
    "never trains, optimises or deploys targeting or weapons models and connects to no mission system. Results are "
    "evidence for human review, not a readiness or certification determination.")
# Spec 10.8 / 16.1: the child records that a requested narrative is the parent's job; the worker parent
# replaces this sentence with the narrative outcome (generated, or why not) after the envelope returns.
# It names the configuration gap deliberately: Pythia is not configured inside the sandbox child.
NARRATIVE_DEFERRED_LIMITATION = (
    "An LLM narrative was requested. Pythia is not configured inside the sandbox child (it holds no "
    "PYTHIA_BASE_URL / PYTHIA_API_KEY / REDSIM_ML_LLM_MODEL); the narrative is produced by the worker parent "
    "after this record is returned, and until then recommendations carry rule text only "
    "(narrative_source='rules').")
NARRATIVE_NOT_REQUESTED_LIMITATION = "No LLM narrative was requested; recommendations carry rule text only."
SHAP_SUMMARY_TEXT_NAME = "shap_summary.txt"            # spec 13.6 / 13.7, Artifact kind ml.shap.summary_text
_SUMMARY_MODULE = "redsim.ml.explain.summary"
_THREAD_ENV_VARS = ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "REDSIM_ML_SANDBOX_THREADS")
# Robustness-curve series colours: a fixed categorical order (never cycled), validated colour-vision-safe for
# adjacent pairs; the control is neutral and the clean point is ink. Identity is also carried by the legend.
_CURVE_SERIES_COLOURS = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948")
_CURVE_CONTROL_COLOUR = "#6b6b6b"
_CURVE_INK = "#0b0b0b"

# Backwards-compatible aliases: these names were defined here before the runner split and are imported by
# other modules and tests (``_surrogate_for_white_box`` is cited by the e2e harness and the admission service).
_surrogate_for_white_box = surrogate_for_white_box
_utcnow = utcnow


def _dist_version(dist: str, module: str) -> str:
    try:
        return version(dist)
    except PackageNotFoundError:
        pass
    try:
        return str(getattr(importlib.import_module(module), "__version__", "unknown"))
    except Exception:  # noqa: BLE001 - optional dependency
        return "not installed"


def _redsim_version() -> str:
    try:
        from redsim import __version__
        return str(__version__)
    except Exception:  # noqa: BLE001
        return _dist_version("redsim-platform", "redsim")


def _thread_env() -> dict[str, str]:
    """``OMP_NUM_THREADS``, ``MKL_NUM_THREADS`` and the torch thread count, as observed (spec 14.4)."""
    env = {k: os.environ[k] for k in _THREAD_ENV_VARS if os.environ.get(k)}
    with contextlib.suppress(Exception):  # torch is optional for tabular targets
        import torch
        env["torch_threads"] = str(torch.get_num_threads())
    return env


def _defense_provenance(target: Target, config: CampaignConfig) -> dict[str, Any] | None:
    """``Provenance.defense`` for a verify run: the applied defense as the wrapper describes it (ART class,
    resolved params, what it does not defend), else the requested ``DefenseConfig`` when the wrapper does
    not describe itself. ``None`` for an attack run."""
    if config.defense is None:
        return None
    describe = getattr(target, "describe", None)
    if callable(describe):
        described = describe()
        if isinstance(described, dict):
            return dict(described)
    return config.defense.model_dump(mode="json")


# --- robustness curve rendering (spec 12.3) --------------------------------------------------------------

def render_curve_png(curves: list[RobustnessCurve], *, norm: str, reference_eps: float) -> bytes:
    """One PNG for the campaign: every in-scope attack's accuracy over the grid, the benign control at the same
    eps, and the clean point at eps=0, all on one accuracy axis with the denominator ``n`` in the title.
    Raises ``ImportError`` when matplotlib is absent; the caller records that as a limitation."""
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    fig = Figure(figsize=(6.4, 4.2), dpi=100)
    FigureCanvasAgg(fig)
    ax = fig.add_subplot(111)
    clean = curves[0].clean if curves else None
    n_txt = f"n = {clean.n} per point; clean {clean.n_correct}/{clean.n}" if clean is not None else "no clean row"
    for idx, curve in enumerate(curves):
        xs = [0.0] + [p.eps for p in curve.points if p.accuracy is not None]
        ys = ([clean.accuracy if clean is not None and clean.accuracy is not None else float("nan")]
              + [float(p.accuracy) for p in curve.points if p.accuracy is not None])
        colour = _CURVE_SERIES_COLOURS[idx % len(_CURVE_SERIES_COLOURS)]
        ax.plot(xs, ys, color=colour, linewidth=2.0, marker="o", markersize=5, label=f"{curve.attack_id} (evasion)")
    control = curves[0].control if curves else []
    if control:
        xs_c = [0.0] + [p.eps for p in control if p.accuracy is not None]
        ys_c = ([clean.accuracy if clean is not None and clean.accuracy is not None else float("nan")]
                + [float(p.accuracy) for p in control if p.accuracy is not None])
        ax.plot(xs_c, ys_c, color=_CURVE_CONTROL_COLOUR, linewidth=2.0, linestyle="--", marker="s", markersize=5,
                label="noise_control (benign control)")
    if clean is not None and clean.accuracy is not None:
        ax.plot([0.0], [clean.accuracy], color=_CURVE_INK, marker="D", markersize=6, linestyle="none",
                label=f"clean ({clean.n_correct}/{clean.n})")
    ax.axvline(float(reference_eps), color=_CURVE_INK, linewidth=0.8, linestyle=":", alpha=0.6)
    ax.text(float(reference_eps), 1.01, f"reference eps {reference_eps:g}", fontsize=7, ha="center", va="bottom",
            color=_CURVE_INK)
    ax.set_ylim(0.0, 1.05)
    ax.set_xlabel(f"eps ({norm}); 0 = clean input", fontsize=9)
    ax.set_ylabel("accuracy (n_correct / n)", fontsize=9)
    ax.set_title(f"Robustness curve, {n_txt}", fontsize=10)
    ax.grid(True, color="#d9d9d9", linewidth=0.6)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.legend(fontsize=7, loc="lower left", frameon=False)
    fig.text(0.01, -0.04, "Measured behaviour under the declared attack set, eps grid and slice; not a readiness "
             "or certification statement.", fontsize=6, color="#52514e")
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=100, bbox_inches="tight")
    return buf.getvalue()


# --- configuration -> runnable pieces -------------------------------------------------------------------

def _bundled_registry_id(config: CampaignConfig) -> str:
    """The ``redsim.ml.targets`` registry id behind a platform Target.

    Bundled models registered through ``POST /v1/models`` get a per-project ``Target.id``
    (``<bundled_id>-<8 hex>``) while ``Target.value`` stays ``bundled:<registry id>`` and
    ``detail.bundled_id`` carries the registry id; the frozen config's ``target_id`` is the
    platform id, so resolve the registry id from the snapshot first and fall back to the id.
    """
    snapshot = dict(config.target_snapshot or {})
    value = str(snapshot.get("value") or "")
    if value.startswith("bundled:") and value[len("bundled:"):]:
        return value[len("bundled:"):]
    detail = snapshot.get("detail")
    if isinstance(detail, dict) and detail.get("bundled_id"):
        return str(detail["bundled_id"])
    return config.target_id


def _check_target(target: Target, config: CampaignConfig) -> None:
    info = target.info()
    if info.status != "available":
        raise TargetUnavailable(info.reason or f"target {config.target_id!r} is {info.status}")
    if info.domain != config.modality:
        raise ValueError(f"config.modality {config.modality!r} does not match the target domain {info.domain!r}")


def _resolve_target(config: CampaignConfig) -> Target:
    """The loaded, undefended target behind ``config`` (registry lookup, status and domain checks)."""
    target = TARGETS.maybe_get(_bundled_registry_id(config))
    if target is None:
        raise TargetUnavailable(f"unknown target {config.target_id!r}")
    _check_target(target, config)
    target.load()
    return target


def _defense_kind(defense: DefenseConfig) -> str:
    """``kind`` of the defense's catalog entry (``redsim.ml.defenses.get_defense``), ``"preprocessing"`` when the
    catalog does not say (older catalogs, an injected test module) or the id is unknown to it."""
    try:
        defenses = importlib.import_module("redsim.ml.defenses")
    except ImportError:
        return "preprocessing"
    get = getattr(defenses, "get_defense", None)
    if not callable(get):
        return "preprocessing"
    try:
        entry = get(defense.id)
    except Exception:  # noqa: BLE001 - an unknown id is refused by apply_defense with its own message
        return "preprocessing"
    kind = entry.get("kind") if isinstance(entry, dict) else getattr(entry, "kind", None)
    return kind if isinstance(kind, str) and kind else "preprocessing"


def _apply_defense(target: Target, config: CampaignConfig, sink: ArtifactSink) -> tuple[Target, dict[str, Any] | None]:
    """Apply ``config.defense`` to the loaded target. Returns ``(target, unavailable)``.

    Preprocessing defenses go through ``redsim.ml.defenses.apply_defense`` and a missing module is refused
    (never an undefended campaign in a defended run's place). A ``kind: training`` defense goes through the
    ``apply_training_defense`` hook of ``redsim.ml.harden.apply``, called with the target and the
    ``DefenseConfig`` plus ``config``, ``sink`` and ``seed`` when the hook accepts them; a missing module or hook
    hands back the undefended target with an ``unavailable`` description the frame records (score withheld).
    An attack run (no defense) returns the target untouched."""
    if config.defense is None:
        return target, None
    if _defense_kind(config.defense) == TRAINING_DEFENSE_KIND:
        requested = config.defense.model_dump(mode="json")
        try:
            harden = importlib.import_module(TRAINING_DEFENSE_MODULE)
        except ImportError as exc:
            return target, {"id": config.defense.id, "kind": TRAINING_DEFENSE_KIND, "status": "unavailable",
                            "reason": f"module {TRAINING_DEFENSE_MODULE!r} not importable ({exc})",
                            "requested": requested}
        hook = getattr(harden, TRAINING_DEFENSE_HOOK, None)
        if not callable(hook):
            return target, {"id": config.defense.id, "kind": TRAINING_DEFENSE_KIND, "status": "unavailable",
                            "reason": f"{TRAINING_DEFENSE_MODULE!r} defines no callable {TRAINING_DEFENSE_HOOK!r}",
                            "requested": requested}
        try:
            defended = call_supported(hook, target, config.defense, config=config, sink=sink, seed=config.seed)
        except MLError as exc:
            if getattr(exc, "code", None) != TRAINING_DEFENSE_UNAVAILABLE_CODE:
                raise
            # The hook refused the defense for this target (no training slice, a tree ensemble): recorded as
            # unavailable with its typed reason; the run measures the undefended model and withholds the score.
            record = getattr(exc, "unavailable", None)
            dump = getattr(record, "model_dump", None)
            typed: dict[str, Any] = dict(dump(mode="json")) if callable(dump) else {}
            return target, {**typed, "id": config.defense.id, "kind": TRAINING_DEFENSE_KIND,
                            "status": "unavailable", "code": TRAINING_DEFENSE_UNAVAILABLE_CODE,
                            "reason": str(typed.get("reason") or exc), "requested": requested}
        if defended is None:
            raise MLError(f"{TRAINING_DEFENSE_MODULE}.{TRAINING_DEFENSE_HOOK} returned no target for "
                          f"{config.defense.id!r}")
        return defended, None
    try:
        defenses = importlib.import_module("redsim.ml.defenses")
    except ImportError as exc:
        raise MLError("a defense was requested but redsim.ml.defenses is not available; "
                      "refusing to run an undefended campaign in its place") from exc
    return defenses.apply_defense(target, config.defense.id, dict(config.defense.params)), None


def _resolve_attacks(config: CampaignConfig, domain: str) -> list[Any]:
    ids = uniq([i for i in config.attack_ids if i])
    if not ids:
        raise ValueError("CampaignConfig.attack_ids is empty")
    adapters = []
    for aid in ids:
        adapter = ATTACKS.maybe_get(aid)
        if adapter is None:
            raise AttackNotApplicable(f"unknown attack {aid!r}; registered: {ATTACKS.ids()}")
        info = adapter.info()
        if info.family != "evasion":
            raise AttackNotApplicable(
                f"{aid!r} is a {info.family} adapter; the benign control runs automatically and is not "
                "part of the attack set")
        if info.status != "available":
            raise AttackNotApplicable(info.reason or f"attack {aid!r} is {info.status}")
        domains = getattr(adapter, "domains", frozenset({info.domain}))
        if domain not in domains:
            raise AttackNotApplicable(f"attack {aid!r} applies to {sorted(domains)}, not {domain!r}")
        if not attack_supports_norm(adapter, config.norm):
            # Spec 12.3 / ATTACKS_HARDEN-03: an adapter is evaluated only in a norm it declares (a minimal-norm
            # attack's achieved norm is thresholded in that norm); it is never silently re-normed.
            raise AttackNotApplicable(f"attack {aid!r} supports the {norm_phrase(attack_norms(adapter))}; "
                                      f"the campaign norm is {config.norm!r}")
        adapters.append(adapter)
    return adapters


NORM_LABELS: dict[str, str] = {"linf": "L-inf", "l2": "L2", "edit": "edit", "patch_area": "patch_area"}


def norm_phrase(norms: frozenset[str] | set[str]) -> str:
    """``"L-inf norm only"`` for one norm, ``"norms L2 and L-inf"`` for several (refusal wording)."""
    labels = [NORM_LABELS.get(n, n) for n in sorted(norms)]
    if len(labels) == 1:
        return f"{labels[0]} norm only"
    return "norms " + ", ".join(labels[:-1]) + f" and {labels[-1]}"


def _attack_params(config: CampaignConfig, adapters: list[Any],
                   domain: str | None = None) -> dict[str, dict[str, Any]]:
    """``config.attack_params`` per adapter. ``eps`` comes from the grid and ``norm_l2`` from
    ``config.norm``, so a caller that sets either per attack has a configuration error. With ``domain``
    the adapter's ``domain_defaults[domain]`` (ATTACKS_HARDEN-04) fill every key the caller omitted, so the
    values in effect land in ``Measurement.params`` like any other parameter."""
    out: dict[str, dict[str, Any]] = {}
    l2 = config.norm == "l2"
    for a in adapters:
        given = dict(config.attack_params.get(a.id, {}))
        clash = sorted(k for k in ("eps", "norm_l2") if k in given)
        if clash:
            raise ValueError(f"attack_params[{a.id!r}] must not set {clash}: eps comes from eps_grid and the "
                             "norm from config.norm")
        given = apply_domain_defaults(a, domain, given)
        if any(s.name == "norm_l2" for s in a.info().params_schema):
            given["norm_l2"] = l2
        out[a.id] = given
    return out


def _stages() -> tuple[str, ...]:
    """``schema.STAGES`` as it is at run time (never copied here); ``defense_apply`` follows ``load_target``."""
    return tuple(_schema.STAGES)


# --- the run --------------------------------------------------------------------------------------------

def run_campaign(config: CampaignConfig, sink: ArtifactSink, *, explain: bool = True,
                 narrative_settings: Any | None = None, baseline_run_id: str | None = None,
                 parent_run_id: str | None = None,
                 on_stage: Callable[[str], None] | None = None,
                 target_override: Target | None = None) -> CampaignRecord:
    """Run the campaign described by ``config`` and return its record (status ``succeeded``).

    Raises ``TargetUnavailable`` / ``AttackNotApplicable`` / ``ModalityRunnerUnavailable`` / ``ValueError``
    for configuration problems before any stage runs. Explain and recommend failures never fail the run:
    they are recorded as unavailable (spec 14.7, 16.1). ``baseline_run_id`` (verify runs) and
    ``parent_run_id`` (reruns) are copied onto the provenance and the record when given.

    ``narrative_settings`` is an explicit, offline-only injection (CLI, tests): this function never
    reads ``PYTHIA_*`` from the environment. Inside the platform the sandbox child leaves it ``None``
    and the worker parent produces the Pythia narrative after the record returns (spec 10.8); a
    requested narrative is recorded here as :data:`NARRATIVE_DEFERRED_LIMITATION`.

    For the run's duration ``NLTK_DATA`` and ``TORCH_HOME`` are pinned to offline paths (the assets
    lexicon directory and an empty cache under the sink's work dir) unless the environment set them,
    so no runner can download a lexicon or a weight file (MODALITIES-10)."""
    with pinned_offline_env(sink_work_dir(sink)):
        return _run_campaign(config, sink, explain=explain, narrative_settings=narrative_settings,
                             baseline_run_id=baseline_run_id, parent_run_id=parent_run_id, on_stage=on_stage,
                             target_override=target_override)


def _run_campaign(config: CampaignConfig, sink: ArtifactSink, *, explain: bool,
                  narrative_settings: Any | None, baseline_run_id: str | None, parent_run_id: str | None,
                  on_stage: Callable[[str], None] | None, target_override: Target | None) -> CampaignRecord:
    started_at = utcnow()
    run_id = uuid.uuid4().hex
    runner: ModalityRunner = resolve_runner(config.modality)   # a missing runner module refuses before any stage

    # --- load_target -------------------------------------------------------------------------
    if target_override is not None:
        target = target_override
        _check_target(target, config)
        target.load()
    else:
        target = _resolve_target(config)
    target, defense_unavailable = _apply_defense(target, config, sink)
    info = target.info()
    domain = info.domain
    manifest = dict(target.manifest() or {})
    model_sha256 = manifest_get(manifest, "model_sha256", "weights_sha256", "sha256")
    adapters = _resolve_attacks(config, domain)
    params_by_attack = _attack_params(config, adapters, domain)
    grid = [float(e) for e in config.eps_grid]
    ref = float(config.reference_eps)
    l2 = config.norm == "l2"
    for a in adapters:  # validate bounds before running anything (spec 12.1)
        for e in grid:
            if getattr(a, "takes_eps", True):
                a.resolve_params({**params_by_attack[a.id], "eps": e})
            else:
                a.resolve_params(params_by_attack[a.id])
    shash = settings_hash(config, None if model_sha256 is None else str(model_sha256))
    dataset_name = (manifest_get(manifest, "dataset", "dataset_id", "dataset_name")
                    or info.metadata.get("dataset") or config.dataset_id)
    dataset_revision = config.dataset_revision or manifest_get(manifest, "dataset_revision", "revision")
    frame = CampaignFrame(
        config=config, sink=sink, target=target, info=info, domain=domain, manifest=manifest, adapters=adapters,
        params_by_attack=params_by_attack, grid=grid, ref=ref, l2=l2, attack_registry=ATTACKS, explain=explain,
        dataset_name=dataset_name, dataset_revision=dataset_revision,
        subject_centered=subject_centered(manifest, info.metadata), on_stage=on_stage,
        nondeterminism=[CPU_FLOAT32_NOTE], versions=library_versions(),
    )
    stage_done = frame.stage_done
    measurements = frame.measurements
    observations = frame.observations
    interpretation = frame.interpretation
    limitations = frame.limitations
    nondeterminism = frame.nondeterminism
    versions = frame.versions
    stage_done("load_target")
    if config.defense is not None and defense_unavailable is None:
        # Spec 6.5: a verify campaign records ``defense_apply`` directly after ``load_target`` (STAGES order);
        # a defense that could not be applied writes no such stage, since nothing was applied.
        stage_done("defense_apply")
    if defense_unavailable is not None:
        limitations.append(
            f"Defense {defense_unavailable['id']!r} (kind {TRAINING_DEFENSE_KIND}) was not applied: "
            f"{defense_unavailable['reason']}. The rows below measure the undefended model, the defense is "
            "recorded as unavailable in the provenance and no score is computed, so this record carries no "
            "verify result and no delta can be read from it.")

    # --- sample -> clean_eval -> attack:<id> -> control (the modality runner) ------------------
    result: ModalityResult = runner(config, target, frame=frame)
    n = int(result.n)
    in_scope = frame.close_attack_set()
    in_scope_ids = frame.in_scope_ids
    scoring_config = frame.scoring_config
    not_run = frame.not_run

    # One RobustnessCurve per attack (spec 12.3), read back from the measurement table so the curve and
    # the rows can never disagree; the control points are the same for every attack.
    curves: list[RobustnessCurve] = (robustness_curves(scoring_config, measurements)
                                     if in_scope and result.curves else [])
    for curve in curves:
        sink.put(f"curve/{curve.attack_id}.json", curve.model_dump_json(indent=2).encode("utf-8"),
                 "application/json")
    if curves:
        # The rendered form of the ml.curve artifact (spec 12.3), beside the JSON. Skipped, and said so, without
        # matplotlib; a rendering failure never fails the run and is never replaced by a placeholder image.
        try:
            png = render_curve_png(curves, norm=config.norm, reference_eps=ref)
        except ImportError:
            limitations.append(f"{CURVE_PNG_NAME} not rendered: matplotlib is not installed in this worker; the "
                               "curve JSON carries every point with its denominator.")
        except Exception as exc:  # noqa: BLE001 - rendering is not evidence
            limitations.append(f"{CURVE_PNG_NAME} not rendered ({type(exc).__name__}: {exc}); the curve JSON carries "
                               "every point with its denominator.")
        else:
            sink.put(CURVE_PNG_NAME, png, "image/png")
    sink.put("flip_matrix.json", json_bytes({"attack_ids": in_scope_ids, "eps_grid": grid, "n": n,
                                             "norm": config.norm, "not_run": not_run,
                                             "indices": [int(i) for i in np.asarray(result.indices)],
                                             "flipped": result.flip_matrix, **result.flip_matrix_extra}),
             "application/json")

    # --- explain -----------------------------------------------------------------------------
    explain_attempted = explain and config.explain_k > 0 and bool(in_scope)
    if not explain_attempted:
        why = ("explain disabled" if not explain else "explain_k = 0" if config.explain_k <= 0
               else "no in-scope attack ran")
        limitations.append(f"Explanations were not computed ({why}); S_expl has no input and the MRI is not "
                           "computed (spec 15.4). No observation was recorded.")
    else:
        if result.explain is not None:
            result.explain()
        else:
            # The modality has no explainer (detection): recorded per attack, exactly as an unavailable module is.
            why_unavailable = f"{ExplainUnavailable.__name__}: no explainer is implemented for the {domain!r} domain"
            for adapter in in_scope:
                aid = adapter.id
                interpretation.append(Interpretation(
                    id=f"i.explain.unavailable.{aid}",
                    statement=(f"Explanations are unavailable for attack {aid!r} at eps={ref:g} "
                               f"({why_unavailable}); no attribution evidence was recorded and S_expl has no "
                               "input, so the MRI is not computed."),
                    basis=[f"m.evasion.{aid}.{eps_tag(ref)}"]))
                limitations.append(f"Explain stage unavailable for {aid!r}: {why_unavailable}.")
        stage_done("explain")

    # --- score -------------------------------------------------------------------------------
    score: MRIRecord | None
    score_reason: str | None
    if in_scope and result.mri and defense_unavailable is None:
        score, score_reason = score_run(config=scoring_config, measurements=measurements, settings_hash=shash,
                                        computed_at=utcnow())
    elif not in_scope:
        score, score_reason = None, ("MRI not computed: no declared attack ran against this target (not_run: "
                                     + "; ".join(f"{k}: {v}" for k, v in not_run.items()) + "). Nothing to score.")
    elif defense_unavailable is not None:
        score, score_reason = None, (f"MRI not computed: the requested defense {defense_unavailable['id']!r} was not "
                                     f"applied ({defense_unavailable['reason']}); scoring the undefended model "
                                     "as a verify result would fake a delta.")
    else:
        score, score_reason = None, (result.score_unavailable_reason
                                     or f"MRI not computed: the {domain!r} modality declares no MRI.")
    if score_reason:
        limitations.append(score_reason)
    if len(grid) == 1:
        limitations.append(ONE_POINT_GRID_LIMITATION)
    stage_done("score")

    # --- interpret / recommend ---------------------------------------------------------------
    standing = _standing(dataset_name, grid, in_scope_ids)
    try:
        rules = importlib.import_module("redsim.ml.recommend.rules")
    except ImportError:
        rules = None
    meta_flat = _flatten_explain_meta(frame.explain_meta, domain, score_reason)
    recommendations: list[CandidateRecommendation] = []
    if rules is None:
        interpretation.append(Interpretation(
            id="i.rules.unavailable",
            statement=("Interpretation and recommendation rules are unavailable (module redsim.ml.recommend.rules "
                       "not present); no rule-based statement and no candidate recommendation was produced."),
            basis=["m.clean"]))
        limitations.append("Rule layer unavailable: no interpretation rules ran and no candidate recommendations "
                           "were produced.")
        stage_done("interpret")
        stage_done("recommend")
    else:
        # Base contracts: interpret(measurements, observations, score) and
        # recommend(measurements, observations, score, *, interpretation=...). The extra keywords
        # (thresholds, reference eps, explain meta, ...) are passed only when the rules module declares
        # them. A failing rule layer is recorded, never faked.
        try:
            produced = list(call_supported(
                rules.interpret, measurements, observations, score,
                explain_meta=meta_flat, reference_eps=ref, scoring_reason=score_reason,
                thresholds=config.scoring.interpretation,
                finding_asr_threshold=config.finding_asr_threshold) or [])
        except Exception as exc:  # noqa: BLE001 - the rule layer must never fail the campaign (14.7)
            produced = []
            interpretation.append(Interpretation(
                id="i.rules.unavailable",
                statement=(f"Interpretation rules failed ({type(exc).__name__}: {exc}); no rule-based statement "
                           "was produced."),
                basis=["m.clean"]))
            limitations.append(f"Rule layer failed during interpretation ({type(exc).__name__}); no candidate "
                               "recommendations were produced.")
            rules = None
        interpretation.extend(_drop_dangling(produced, measurements, observations, interpretation, limitations,
                                             "interpretation"))
        stage_done("interpret")
        if rules is not None and config.auto_recommend:
            try:
                produced_recs = list(call_supported(
                    rules.recommend, measurements, observations, score,
                    interpretation=interpretation, explain_meta=meta_flat, reference_eps=ref, modality=domain,
                    seed=config.seed, thresholds=config.scoring.interpretation,
                    finding_asr_threshold=config.finding_asr_threshold) or [])
            except Exception as exc:  # noqa: BLE001
                produced_recs = []
                limitations.append(f"Rule layer failed during recommendation ({type(exc).__name__}: {exc}); no "
                                   "candidate recommendations were produced.")
            recommendations = _drop_dangling(produced_recs, measurements, observations, interpretation,
                                             limitations, "recommendation")
            stage_done("recommend")
        elif rules is not None:
            limitations.append("auto_recommend=false: no candidate recommendations were generated in this run; "
                               "the harden step can create them later under the same run.")

    llm_provenance: dict[str, Any] | None = None
    if recommendations:
        # Spec 10.8 / 16.1: the Pythia writer runs in the worker parent after this child returns.
        # This process never reads PYTHIA_* / REDSIM_ML_LLM_MODEL (the sandbox strips them) and
        # only narrates when an offline caller injects ``narrative_settings`` explicitly.
        settings = narrative_settings
        if settings is None and config.llm_narrative:
            limitations.append(NARRATIVE_DEFERRED_LIMITATION)
        if settings is not None:
            try:
                summary_mod = importlib.import_module("redsim.ml.explain.summary")
                narrative_mod = importlib.import_module("redsim.ml.recommend.narrative")
                summary_text = call_supported(
                    summary_mod.text_summary, measurements, observations, score,
                    explain_meta=meta_flat, scoring_reason=score_reason, limitations=standing + limitations,
                    norm=config.norm)
                recommendations = list(narrative_mod.add_narrative(recommendations, summary_text, settings))
            except Exception as exc:  # noqa: BLE001 - narrative failure leaves rule output standing (16.1)
                limitations.append(f"LLM narrative not generated ({type(exc).__name__}: {exc}); recommendations "
                                   "carry rule text only (narrative_source='rules').")
            if any(r.narrative_source == "llm" for r in recommendations):
                nondeterminism.append("LLM narrative is nondeterministic (temperature=0.2); prompt and response "
                                      "hashes recorded")
                redacted = getattr(settings, "redacted", None)
                llm_provenance = (dict(redacted()) if callable(redacted)
                                  else {"settings": type(settings).__name__, "redacted": "unavailable"})
        elif not config.llm_narrative:
            limitations.append(NARRATIVE_NOT_REQUESTED_LIMITATION)

    # --- report ------------------------------------------------------------------------------
    finished_at = utcnow()
    limitations = standing + [D3_BOUNDS_LIMITATION] + limitations
    limitations.extend(result.trailing_limitations)
    if config.defense is not None and defense_unavailable is None:
        limitations.append(TRAINING_DEFENSE_LIMITATION if _defense_kind(config.defense) == TRAINING_DEFENSE_KIND
                           else DEFENSE_LIMITATION)
    if score is not None and score.mri is not None:
        limitations.append(MRI_SCOPE_LIMITATION)
    if "explain" in frame.stages_done:
        # The SHAP text summary is an artifact of every campaign with an explain stage (spec 13.6, ml.shap.summary_text),
        # not only the LLM writer's input. Unavailable is recorded, never a placeholder.
        try:
            summary_mod = importlib.import_module(_SUMMARY_MODULE)
            summary_text_out = call_supported(
                summary_mod.text_summary, measurements, observations, score,
                explain_meta=meta_flat, scoring_reason=score_reason, limitations=uniq(limitations),
                norm=config.norm)
            sink.put(SHAP_SUMMARY_TEXT_NAME, str(summary_text_out).encode("utf-8"), "text/plain; charset=utf-8")
        except Exception as exc:  # noqa: BLE001 - the summary is derived text, never evidence
            why_summary = (f"module {_SUMMARY_MODULE!r} not importable" if isinstance(exc, ImportError)
                           else f"{type(exc).__name__}: {exc}")
            limitations.append(f"{SHAP_SUMMARY_TEXT_NAME} not written ({why_summary}).")
    provenance = Provenance(
        redsim_version=_redsim_version(), python=platform.python_version(),
        torch=versions.get("torch", "not installed"), art=versions.get("art", "not installed"),
        shap=_dist_version("shap", "shap"), numpy=versions.get("numpy", np.__version__),
        onnxruntime=versions.get("onnxruntime"), sklearn=versions.get("scikit-learn"),
        xgboost=versions.get("xgboost"),
        model_sha256=None if model_sha256 is None else str(model_sha256),
        dataset=str(dataset_name),
        dataset_revision=None if dataset_revision is None else str(dataset_revision),
        dataset_split=config.dataset_split,
        sample_indices_sha256=sha256_indices(result.indices), settings_hash=shash,
        baseline_run_id=baseline_run_id, parent_run_id=parent_run_id,
        defense=defense_unavailable if defense_unavailable is not None else _defense_provenance(target, config),
        llm=llm_provenance, thread_env=_thread_env(),
        model_manifest={**manifest, "seed": config.seed, "n_samples": n, "library_versions": versions,
                        "python_executable": sys.executable},
        started_at=started_at, finished_at=finished_at,
        hostname=socket.gethostname(), device=str(manifest.get("device") or "cpu"),
        nondeterminism=uniq(nondeterminism),
    )
    stage_done("report")

    record = CampaignRecord(
        run_id=run_id, status="succeeded", stage="report", stages_done=frame.stages_done, created_at=started_at,
        config=config, target=info, attacks=[a.info() for a in in_scope], provenance=provenance,
        measurements=measurements, observations=observations, interpretation=interpretation,
        recommendations=recommendations, score=score, limitations=uniq(limitations),
        kind="verify" if config.defense is not None else "attack", completed_at=finished_at,
        settings_hash=shash, baseline_run_id=baseline_run_id, parent_run_id=parent_run_id, curve=curves,
        completeness=score.completeness if score is not None else "partial",
        missing=list(score.missing) if score is not None else [score_reason or "score unavailable"],
        score_status=None if score is not None else ScoreStatus(state="unavailable", reason=score_reason),
    )
    sink.put("run_record.json", record.model_dump_json(indent=2).encode("utf-8"), "application/json")
    if score is not None:
        sink.put("score.json", score.model_dump_json(indent=2).encode("utf-8"), "application/json")
    return record


# --- helpers ----------------------------------------------------------------------------------------

def _drop_dangling(items: list[Any], measurements: list[Measurement], observations: list[Observation],
                   interpretation: list[Interpretation], limitations: list[str], what: str) -> list[Any]:
    """Keep only the statements whose citations resolve to recorded ids (spec 14.1). A dropped statement
    is named in ``limitations``: it is a rule-layer defect, not evidence."""
    known = {m.id for m in measurements} | {o.id for o in observations} | {i.id for i in interpretation}
    kept: list[Any] = []
    for item in items:
        cites = list(getattr(item, "basis", None) or getattr(item, "triggered_by", None) or [])
        dangling = [c for c in cites if c not in known]
        if dangling:
            limitations.append(f"Dropped {what} {item.id!r}: it cites ids that were not recorded in this run "
                               f"({', '.join(dangling)}).")
            continue
        kept.append(item)
        known.add(item.id)
    return kept


def _flatten_explain_meta(per_attack_meta: dict[str, dict[str, Any]], domain: str,
                          scoring_reason: str | None) -> dict[str, Any]:
    """One flat dict for the rules / summary layer: ``modality``, the per-attack metas under
    ``per_attack``, and the scalar fields of the attack with the largest ``expl_shift_mean``
    (labelled ``flat_from_attack``) so a single-attack consumer reads the worst case, never an
    invented average. ``unavailable_reason`` carries the MRI-not-computed reason when there is one."""
    flat: dict[str, Any] = {"modality": domain, "per_attack": dict(per_attack_meta)}
    if scoring_reason:
        flat["unavailable_reason"] = scoring_reason
    with_shift = [(aid, m) for aid, m in per_attack_meta.items()
                  if isinstance(m, dict) and isinstance(m.get("expl_shift_mean"), (int, float))]
    if with_shift:
        aid, meta = max(with_shift, key=lambda kv: float(kv[1]["expl_shift_mean"]))
        flat.update({k: v for k, v in meta.items() if k not in ("per_attack", "modality")})
        flat["flat_from_attack"] = aid
    return flat


def _standing(dataset_name: Any, grid: list[float], attack_ids: list[str]) -> list[str]:
    """``schema.standing_limitations`` for this campaign, with the white-box sentence adjusted when
    the black-box HopSkipJump attack ran (the standing text would otherwise be false)."""
    out = standing_limitations(str(dataset_name), grid)
    if "hopskipjump" in attack_ids:
        out = [WHITE_BOX_WITH_BLACK_BOX if s == WHITE_BOX_STANDING else s for s in out]
    return out


__all__ = [
    "CONTROL_ATTACK_ID",
    "CURVE_PNG_NAME",
    "D3_BOUNDS_LIMITATION",
    "DEFAULT_MAX_ADV_ARTIFACT_MB",
    "DEFENSE_LIMITATION",
    "MODALITY_RUNNERS",
    "MRI_SCOPE_LIMITATION",
    "NARRATIVE_DEFERRED_LIMITATION",
    "NARRATIVE_NOT_REQUESTED_LIMITATION",
    "REALIZABILITY_CAVEAT",
    "SHAP_SUMMARY_TEXT_NAME",
    "SUBJECT_CENTERED_CAVEAT",
    "SURROGATE_NOTE_PREFIX",
    "SURROGATE_TRANSFER_LIMITATION_TEMPLATE",
    "TABULAR_LIMITATION",
    "TRAINING_DEFENSE_HOOK",
    "TRAINING_DEFENSE_LIMITATION",
    "TRAINING_DEFENSE_MODULE",
    "ArtifactSink",
    "AttackInfo",
    "CampaignFrame",
    "CampaignRecord",
    "MRIRecord",
    "ModalityResult",
    "ModalityRunner",
    "ModalityRunnerUnavailable",
    "render_curve_png",
    "run_campaign",
]
