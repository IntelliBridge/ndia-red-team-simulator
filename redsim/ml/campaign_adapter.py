"""The ``ml-campaign`` scanner facade and the offline campaign runner (spec 8, CLI-04, CLI-44).

Two things live here, both light to import so the API process can list the
roster without touching torch, ART, onnxruntime, SHAP or scikit-learn:

* :class:`CampaignScannerAdapter`, the built-in ``ScannerAdapter`` registered
  under ``ml-campaign`` with the capabilities ``adversarial_ml`` and
  ``explainability``. It makes the ML vertical visible to ``list_scanners()``,
  ``dispatch()``, ``redsim doctor`` and ``GET /v1/scanners``. ``health_check()``
  reports whether the ``ml`` extra is installed and whether the sandbox child
  launches (a ``--help`` probe of ``redsim.ml.sandbox_worker`` under the real
  child environment, never a model load).
* :func:`run_offline_campaign`, the offline path ``redsim ml attack`` and the
  facade's ``scan()`` share. It mirrors ``services.scans.start_scan`` and
  ``services.ml_campaigns.create_attack_campaign``: build a frozen
  ``CampaignConfig`` for a bundled target from the local asset manifest, write
  the ``attack.run`` audit row first through the platform's ``JsonlAuditWriter``
  at ``<out>/<run_id>/audit.jsonl`` (single-file chain ``run:<run_id>``), run
  the campaign in the sandbox child (``run_campaign_sandboxed``), then write the
  run record, the six-section reports and the curve under ``<out>/<run_id>/``.
  Every stage event and the terminal ``job.complete`` land in the same chain,
  so ``verify_chain`` over that file proves the trail.

Refusals happen before any file is written: ``endpoint_stub`` (and any other
target whose ``info().status`` is not ``available``) is refused with the
``not_implemented`` reason the target itself gives, and a fixture-only target
(the CIFAR-10 fixture, or any manifest entry flagged ``fixture_only``) is refused
with ``fixture_only``, because fixture data is never served as a result.

No network and no Pythia: the config keeps ``llm_narrative=False`` so every
candidate recommendation stays ``narrative_source="rules"``; the sandbox child
never receives ``PYTHIA_*`` or proxy variables.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from redsim import __version__ as _REDSIM_VERSION

if TYPE_CHECKING:
    from redsim.audit.chain import AuditWriter
    from redsim.ml.schema import CampaignConfig, CampaignRecord
    from redsim.scanners.registry import ScanOptions, ScanResult
    from redsim.state import RunStateAPI

logger = logging.getLogger(__name__)

ADAPTER_NAME = "ml-campaign"
CAPABILITY_ADVERSARIAL_ML = "adversarial_ml"
CAPABILITY_EXPLAINABILITY = "explainability"
ADAPTER_CAPABILITIES: frozenset[str] = frozenset({CAPABILITY_ADVERSARIAL_ML, CAPABILITY_EXPLAINABILITY})

# Mirrors ``redsim.ml.sandbox.MlSandboxConfig.timeout_s`` (spec 9.4) without importing numpy here.
DEFAULT_CAMPAIGN_TIMEOUT_S = 1200

# Same names ``redsim.ml.targets.bundled`` and ``redsim.ml.sandbox`` read; literals so this module
# stays free of ML imports.
ASSETS_DIR_ENV = "REDSIM_ML_ASSETS_DIR"
DEFAULT_ASSETS_DIR = "./assets"

AUDIT_FILE_NAME = "audit.jsonl"
RUN_RECORD_NAME = "run_record.json"
REPORT_NAMES: tuple[str, ...] = ("report.md", "report.json", "report.html")
CURVE_ARTIFACT = "artifacts/curve/robustness_curve.png"   # FilesystemSink path of campaign.CURVE_PNG_NAME

DEFAULT_ATTACK_IDS: tuple[str, ...] = ("fgsm", "pgd")
DEFAULT_ACTOR = "cli:anonymous"

# Refusal reason codes (spec 17.3 vocabulary where it has one; ``fixture_only`` is the spec 11.1 rule).
REASON_NOT_IMPLEMENTED = "not_implemented"
REASON_FIXTURE_ONLY = "fixture_only"
REASON_UNKNOWN_TARGET = "not_found"
REASON_UNKNOWN_ATTACK = "unknown_attack"
REASON_ATTACK_UNAVAILABLE = "attack_unavailable"
REASON_ATTACK_MODALITY = "attack_modality_mismatch"
REASON_PARAMS = "params_out_of_range"
REASON_EPS_GRID = "eps_grid_invalid"
REASON_REFERENCE_EPS = "reference_eps_not_in_grid"
REASON_RUN_DIR = "run_dir_not_empty"

# Attack parameters the campaign runner derives from the grid and the norm, never from attack_params.
_GRID_OWNED_PARAMS: frozenset[str] = frozenset({"eps", "norm_l2"})

# Stage -> audit action, the same table the Celery task uses so offline and platform chains agree.
_STAGE_ACTIONS: dict[str, str] = {
    "attack": "attack.run",
    "explain": "explain.run",
    "score": "score.compute",
    "report": "report.render",
}


class OfflineCampaignRefused(Exception):
    """The request cannot run; nothing was written. ``reason`` is a stable code, ``str()`` the message."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass(frozen=True)
class OfflineCampaignRequest:
    """What ``redsim ml attack`` asks for. Defaults follow ``CampaignConfig`` and spec 12.3."""

    target_id: str
    attack_ids: tuple[str, ...] = DEFAULT_ATTACK_IDS
    eps_grid: tuple[float, ...] | None = None          # None: the default grid for ``norm``
    reference_eps: float | None = None                 # None: the default reference, else a grid member
    n_samples: int = 200
    seed: int = 0
    explain_k: int = 8
    include_control: bool = True
    norm: str = "linf"
    actor: str = DEFAULT_ACTOR


@dataclass
class OfflineCampaignResult:
    run_id: str
    run_dir: Path
    record: CampaignRecord
    audit_path: Path
    report_paths: dict[str, Path] = field(default_factory=dict)
    curve_path: Path | None = None
    narrative_source: str = "rules"
    audit_events: int = 0

    @property
    def succeeded(self) -> bool:
        return self.record.status == "succeeded"


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


def resolve_assets_dir(explicit: str | Path | None = None) -> Path:
    """``explicit``, else ``REDSIM_ML_ASSETS_DIR``, else ``./assets``, as an absolute path."""
    if explicit is not None:
        raw = str(explicit)
    else:
        raw = os.environ.get(ASSETS_DIR_ENV, "").strip() or DEFAULT_ASSETS_DIR
    return Path(raw).expanduser().resolve()


def _pin_assets_dir(assets_dir: Path) -> None:
    """Make the sandbox parent and child resolve the same asset tree (``redsim.ml.sandbox._assets_dir``)."""
    os.environ[ASSETS_DIR_ENV] = str(assets_dir)


# ---------------------------------------------------------------------------
# Config construction (the offline half of ``create_attack_campaign``)
# ---------------------------------------------------------------------------


def _parse_grid(request: OfflineCampaignRequest) -> tuple[list[float], float]:
    from redsim.ml.scoring import default_eps_grid, default_reference_eps

    norm = request.norm
    if norm not in {"linf", "l2"}:
        raise OfflineCampaignRefused(REASON_EPS_GRID, f"norm must be linf or l2, got {norm!r}")
    grid = [float(e) for e in request.eps_grid] if request.eps_grid else default_eps_grid(norm)
    if not grid:
        raise OfflineCampaignRefused(REASON_EPS_GRID, "eps grid is empty")
    if any(not (0.0 < e <= 1.0) for e in grid):
        raise OfflineCampaignRefused(REASON_EPS_GRID, f"eps grid members must lie in (0, 1]: {grid}")
    if any(b <= a for a, b in zip(grid, grid[1:], strict=False)):
        raise OfflineCampaignRefused(REASON_EPS_GRID, f"eps grid must be strictly ascending: {grid}")
    if request.reference_eps is not None:
        reference = float(request.reference_eps)
        if reference not in grid:
            raise OfflineCampaignRefused(
                REASON_REFERENCE_EPS, f"reference eps {reference:g} is not a member of the grid {grid}")
        return grid, reference
    default_reference = default_reference_eps(norm)
    if default_reference in grid:
        return grid, default_reference
    return grid, grid[len(grid) // 2]


def build_offline_config(request: OfflineCampaignRequest) -> tuple[CampaignConfig, str | None]:
    """Resolve the bundled target and the attacks, refuse what may not run, freeze the config.

    Imports the target and attack registries (numpy) but never a model: the
    target's ``info()`` reads ``MANIFEST.json`` only. Returns the frozen config
    and the model sha256 the manifest records (``None`` when it has none).
    """
    from redsim.ml.attacks.registry import ATTACKS
    from redsim.ml.schema import CampaignConfig
    from redsim.ml.targets.registry import TARGETS

    target = TARGETS.maybe_get(request.target_id)
    if target is None:
        raise OfflineCampaignRefused(
            REASON_UNKNOWN_TARGET,
            f"unknown target {request.target_id!r}; registered: {TARGETS.ids()}")
    info = target.info()
    meta: dict[str, Any] = dict(info.metadata or {})
    if meta.get("fixture_only"):
        raise OfflineCampaignRefused(
            REASON_FIXTURE_ONLY,
            f"target {request.target_id!r} is fixture-only (CI / test data) and is never served as a result")
    if info.status != "available":
        reason = REASON_NOT_IMPLEMENTED if info.status == "not_implemented" else str(info.status)
        raise OfflineCampaignRefused(
            reason, info.reason or f"target {request.target_id!r} is {info.status}")

    modality = info.domain
    attack_ids = [a for a in dict.fromkeys(request.attack_ids) if a]
    if not attack_ids:
        raise OfflineCampaignRefused(REASON_UNKNOWN_ATTACK, "no attack ids given")
    attack_infos = []
    resolved_params: dict[str, dict[str, float | int | bool]] = {}
    for attack_id in attack_ids:
        adapter = ATTACKS.maybe_get(attack_id)
        if adapter is None:
            raise OfflineCampaignRefused(
                REASON_UNKNOWN_ATTACK, f"unknown attack {attack_id!r}; registered: {ATTACKS.ids()}")
        attack_info = adapter.info()
        if attack_info.status != "available":
            raise OfflineCampaignRefused(
                REASON_ATTACK_UNAVAILABLE,
                attack_info.reason or f"attack {attack_id!r} is {attack_info.status}")
        if attack_info.family != "evasion":
            raise OfflineCampaignRefused(
                REASON_ATTACK_UNAVAILABLE,
                f"{attack_id!r} is a {attack_info.family} adapter; the benign control runs automatically")
        domains = getattr(adapter, "domains", None) or frozenset({attack_info.domain})
        if modality not in domains:
            raise OfflineCampaignRefused(
                REASON_ATTACK_MODALITY, f"attack {attack_id!r} applies to {sorted(domains)}, not {modality!r}")
        try:
            resolved = adapter.resolve_params({})
        except ValueError as exc:
            raise OfflineCampaignRefused(REASON_PARAMS, f"invalid parameters for {attack_id!r}: {exc}") from exc
        # ``eps`` comes from the grid and ``norm_l2`` from ``config.norm`` (campaign._attack_params refuses
        # them in attack_params); the remaining resolved defaults are frozen for reproducibility.
        resolved_params[attack_id] = {k: v for k, v in resolved.items() if k not in _GRID_OWNED_PARAMS}
        attack_infos.append(attack_info)

    grid, reference = _parse_grid(request)
    model_sha256 = meta.get("sha256")
    detail: dict[str, Any] = {
        "status": "available",
        "name": info.name,
        "modality": modality,
        "source": "bundled",
        "sha256": model_sha256,
        "gradients": meta.get("gradients"),
        "manifest": meta,
    }
    try:
        config = CampaignConfig(
            target_id=request.target_id,
            modality=modality,
            attack_ids=attack_ids,
            attack_params=resolved_params,
            norm=request.norm,
            eps_grid=grid,
            reference_eps=reference,
            n_samples=request.n_samples,
            seed=request.seed,
            include_control=request.include_control,
            explain_k=request.explain_k,
            dataset_id=str(meta.get("dataset_id") or "unknown"),
            dataset_revision=meta.get("dataset_revision"),
            dataset_split=str(meta.get("dataset_split") or "test"),
            llm_narrative=False,
            target_snapshot={
                "id": request.target_id,
                "kind": "ml_model_artifact",
                "value": f"bundled:{request.target_id}",
                "detail": detail,
            },
            attacks=attack_infos,
        )
    except ValueError as exc:
        raise OfflineCampaignRefused(REASON_PARAMS, f"campaign configuration rejected: {exc}") from exc
    return config, (str(model_sha256) if model_sha256 else None)


# ---------------------------------------------------------------------------
# The offline run
# ---------------------------------------------------------------------------


def _prepare_run_dir(out_dir: Path, run_id: str) -> Path:
    run_dir = out_dir / run_id
    if run_dir.exists() and any(run_dir.iterdir()):
        raise OfflineCampaignRefused(REASON_RUN_DIR, f"run directory {run_dir} exists and is not empty")
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def run_offline_campaign(
    request: OfflineCampaignRequest,
    *,
    out_dir: str | Path,
    run_id: str | None = None,
    assets_dir: str | Path | None = None,
    allowlist: list[str] | None = None,
    log: Callable[[str], None] | None = None,
) -> OfflineCampaignResult:
    """Run one offline campaign against a bundled target; see the module docstring for the contract.

    Raises :class:`OfflineCampaignRefused` before anything is written when the
    request may not run. Raises the ``redsim.ml.errors`` class the sandbox
    reports (``SandboxTimeout``, ``SandboxKilled``, ``EnvelopeInvalid``, ...)
    after writing the ``job.complete`` row with ``success=False``; a campaign
    the child finished but marked ``failed`` comes back as a normal result with
    ``record.status == "failed"`` so the caller can print its error and exit
    non-zero.
    """
    from redsim.audit.chain import JsonlAuditWriter
    from redsim.ml.artifacts import FilesystemSink
    from redsim.ml.errors import MLError
    from redsim.ml.reporting import render_campaign_reports
    from redsim.ml.sandbox import run_campaign_sandboxed
    from redsim.ml.scoring import settings_hash
    from redsim.safety import authorize

    say = log or (lambda _msg: None)
    resolved_assets = resolve_assets_dir(assets_dir)
    _pin_assets_dir(resolved_assets)

    config, model_sha256 = build_offline_config(request)
    run_id = run_id or f"run-{uuid4().hex[:12]}"
    run_dir = _prepare_run_dir(Path(out_dir), run_id)
    audit_path = run_dir / AUDIT_FILE_NAME
    writer: AuditWriter = JsonlAuditWriter(run_dir, single_file=AUDIT_FILE_NAME)
    frozen_settings_hash = settings_hash(config, model_sha256)
    snapshot = config.model_dump(mode="json")

    # Audit first (spec 10.2 / 5.11): the attack.run row precedes every other write of this run.
    authorize(
        "attack.run", None, allowlist=list(allowlist or []), actor=request.actor,
        writer=writer, run_id=run_id,
        detail={
            "actor": request.actor, "mode": "offline", "target_id": config.target_id,
            "attack_ids": list(config.attack_ids), "dataset_id": config.dataset_id,
            "dataset_revision": config.dataset_revision, "model_sha256": model_sha256,
            "settings_hash": frozen_settings_hash, "assets_dir": str(resolved_assets),
            "llm_narrative": False, "config": snapshot,
        },
    )
    say(f"run {run_id}: {config.target_id} x {config.attack_ids} eps={config.eps_grid} "
        f"(reference {config.reference_eps:g}, n={config.n_samples}, seed={config.seed})")

    sink = FilesystemSink(run_dir)
    emitted: set[str] = set()

    def audit(action: str, *, success: bool, detail: dict[str, Any]) -> None:
        emitted.add(action)
        writer.append(
            action=action, actor=request.actor, target=None, allowlist_check="pass",
            override=False, success=success, detail={"run_id": run_id, **detail}, run_id=run_id,
        )

    def on_stage(stage: str) -> None:
        say(f"stage {stage}")
        action = _STAGE_ACTIONS.get(stage)
        if action is not None:
            audit(action, success=True, detail={"stage": stage})

    try:
        record = run_campaign_sandboxed(config, sink, on_stage=on_stage, job_id=run_id)
    except MLError as exc:
        audit("job.complete", success=False,
              detail={"status": "failed", "error": f"{type(exc).__name__}: {exc}"[:1000]})
        raise
    record = record.model_copy(update={"run_id": run_id})

    # The parent renders the platform reports; the child's ``report`` stage already audited the
    # render on a completed campaign, a partial record gets its own row before the files exist.
    if "report.render" not in emitted:
        audit("report.render", success=record.status == "succeeded",
              detail={"status": record.status, "partial": True})
    report_paths: dict[str, Path] = {}
    for name, data, _content_type in render_campaign_reports(record, generated_at=datetime.now(UTC)):
        path = run_dir / name
        path.write_bytes(data)
        report_paths[name] = path
    record_path = run_dir / RUN_RECORD_NAME
    record_path.write_text(record.model_dump_json(indent=2) + "\n", encoding="utf-8")
    report_paths[RUN_RECORD_NAME] = record_path

    curve_candidate = run_dir / CURVE_ARTIFACT
    curve_path: Path | None = curve_candidate if curve_candidate.is_file() else None

    narrative_sources = {r.narrative_source for r in record.recommendations} or {"rules"}
    audit("job.complete", success=record.status == "succeeded", detail={
        "status": record.status, "stages_done": list(record.stages_done),
        "settings_hash": record.settings_hash, "error": record.error,
        "reports": sorted(report_paths), "curve": str(curve_path.relative_to(run_dir)) if curve_path else None,
        "narrative_source": sorted(narrative_sources),
    })
    return OfflineCampaignResult(
        run_id=run_id, run_dir=run_dir, record=record, audit_path=audit_path,
        report_paths=report_paths, curve_path=curve_path,
        narrative_source=",".join(sorted(narrative_sources)),
        audit_events=_count_lines(audit_path),
    )


# ---------------------------------------------------------------------------
# Health probes (never load a model)
# ---------------------------------------------------------------------------

_ML_EXTRA_MODULES: tuple[tuple[str, str], ...] = (
    ("numpy", "numpy"),
    ("torch", "torch"),
    ("art", "adversarial-robustness-toolbox"),
    ("sklearn", "scikit-learn"),
    ("shap", "shap"),
)


def ml_extra_available() -> tuple[bool, str]:
    """Whether the ``ml`` extra is installed, by ``find_spec`` (nothing is imported here)."""
    missing = [dist for module, dist in _ML_EXTRA_MODULES if importlib.util.find_spec(module) is None]
    if missing:
        return False, "ml extra incomplete: missing " + ", ".join(missing) + ' (install ".[ml]")'
    return True, "ml extra installed: " + ", ".join(dist for _module, dist in _ML_EXTRA_MODULES)


def sandbox_child_launches(timeout_s: float = 30.0) -> tuple[bool, str]:
    """Spawn ``python -m redsim.ml.sandbox_worker --help`` under the real child env; no model is touched."""
    argv = [sys.executable, "-m", "redsim.ml.sandbox_worker", "--help"]
    try:
        from redsim.ml.sandbox import MlSandboxConfig, _assets_dir, _ml_child_env

        env = _ml_child_env(MlSandboxConfig.from_env(), assets=str(_assets_dir()), hash_seed=0)
    except Exception as exc:  # noqa: BLE001 - the probe must report, never raise
        return False, f"sandbox environment could not be built: {type(exc).__name__}: {exc}"
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"sandbox child did not launch: {type(exc).__name__}: {exc}"
    if proc.returncode != 0 or "--request" not in (proc.stdout or ""):
        tail = (proc.stderr or proc.stdout or "").strip()[-300:]
        return False, f"sandbox child exited {proc.returncode} on --help: {tail}"
    return True, "sandbox child launches (redsim.ml.sandbox_worker --help)"


class CampaignScannerAdapter:
    """Built-in ``ScannerAdapter`` facade for the adversarial-ML vertical (spec 8 table, CLI-44)."""

    name = ADAPTER_NAME
    capabilities: set[str] = set(ADAPTER_CAPABILITIES)
    default_timeout = DEFAULT_CAMPAIGN_TIMEOUT_S

    def adapter_version(self) -> str:
        return str(_REDSIM_VERSION)

    def health_detail(self) -> dict[str, Any]:
        extra_ok, extra_msg = ml_extra_available()
        child_ok, child_msg = sandbox_child_launches()
        return {
            "ml_extra": extra_ok, "ml_extra_detail": extra_msg,
            "sandbox_child": child_ok, "sandbox_child_detail": child_msg,
            "assets_dir": str(resolve_assets_dir()),
        }

    def health_check(self) -> bool:
        detail = self.health_detail()
        return bool(detail["ml_extra"]) and bool(detail["sandbox_child"])

    def scan(self, run_state: RunStateAPI, options: ScanOptions) -> ScanResult:
        """Run the offline campaign ``options.target`` names into ``run_state.run_path``.

        ``options.target`` is a bundled target id (``vehicles_cnn``); ``options.extra``
        may carry ``attacks`` (list), ``eps`` (list), ``n_samples``, ``seed``,
        ``explain_k`` and ``include_control``. ML findings are campaign records, not
        ``RedsimFinding`` rows, so ``findings`` is always empty; the record and the
        reports are on disk and the exit code and ``error`` carry the outcome.
        """
        from redsim.scanners.registry import ScanResult

        started = time.monotonic()
        version = self.adapter_version()
        extra = dict(getattr(options, "extra", None) or {})
        attacks = extra.get("attacks") or list(DEFAULT_ATTACK_IDS)
        command = f"redsim ml attack {options.target} --attacks {','.join(str(a) for a in attacks)}"
        run_path = getattr(run_state, "run_path", None)
        if run_path is None:
            return ScanResult(findings=[], adapter_name=self.name, adapter_version=version,
                              command_str=command, exit_code=-1, duration_s=time.monotonic() - started,
                              error="ml-campaign needs a run_state with a run_path")
        eps = extra.get("eps")
        request = OfflineCampaignRequest(
            target_id=str(options.target),
            attack_ids=tuple(str(a) for a in attacks),
            eps_grid=tuple(float(e) for e in eps) if eps else None,
            n_samples=int(extra.get("n_samples", 200)),
            seed=int(extra.get("seed", 0)),
            explain_k=int(extra.get("explain_k", 8)),
            include_control=bool(extra.get("include_control", True)),
        )
        try:
            result = run_offline_campaign(
                request, out_dir=Path(str(run_path)).parent, run_id=str(getattr(run_state, "run_id", None)
                                                                          or Path(str(run_path)).name),
            )
        except OfflineCampaignRefused as exc:
            return ScanResult(findings=[], adapter_name=self.name, adapter_version=version,
                              command_str=command, exit_code=1, duration_s=time.monotonic() - started,
                              error=f"{exc.reason}: {exc.message}")
        except Exception as exc:  # noqa: BLE001 - the sandbox's typed failure becomes the error envelope
            return ScanResult(findings=[], adapter_name=self.name, adapter_version=version,
                              command_str=command, exit_code=1, duration_s=time.monotonic() - started,
                              error=f"{type(exc).__name__}: {exc}")
        return ScanResult(
            findings=[], adapter_name=self.name, adapter_version=version, command_str=command,
            exit_code=0 if result.succeeded else 1, duration_s=time.monotonic() - started,
            error=None if result.succeeded else (result.record.error or f"campaign {result.record.status}"),
        )


def register_campaign_adapter() -> CampaignScannerAdapter:
    """Register the facade into the scanner registry once; return the registered instance."""
    from redsim.scanners.registry import _REGISTRY, register

    existing = _REGISTRY.get(ADAPTER_NAME)
    if isinstance(existing, CampaignScannerAdapter):
        return existing
    adapter = CampaignScannerAdapter()
    register(adapter)
    return adapter


__all__ = [
    "ADAPTER_CAPABILITIES",
    "ADAPTER_NAME",
    "ASSETS_DIR_ENV",
    "AUDIT_FILE_NAME",
    "CURVE_ARTIFACT",
    "DEFAULT_ATTACK_IDS",
    "REASON_FIXTURE_ONLY",
    "REASON_NOT_IMPLEMENTED",
    "REPORT_NAMES",
    "RUN_RECORD_NAME",
    "CampaignScannerAdapter",
    "OfflineCampaignRefused",
    "OfflineCampaignRequest",
    "OfflineCampaignResult",
    "build_offline_config",
    "ml_extra_available",
    "register_campaign_adapter",
    "resolve_assets_dir",
    "run_offline_campaign",
    "sandbox_child_launches",
]
