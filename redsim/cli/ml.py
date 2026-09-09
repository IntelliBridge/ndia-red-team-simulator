"""``redsim ml`` subcommands: build-assets, attack (offline) and seed (spec 11, 20.1, CLI-02/04).

``add_ml_subparser``, ``cmd_ml`` and ``cmd_ml_build_assets`` are the entry
points ``redsim.cli.main`` wires. P0 shipped them as a skeleton that reported
``not_implemented``; the M1 / M4 builder now sits behind the same names, so
``BUILD_ASSETS_STATUS`` reads ``implemented`` and the reason is empty.

``redsim ml attack <target_id>`` runs one offline campaign against a bundled
target from the local asset manifest (``REDSIM_ML_ASSETS_DIR`` or ``./assets``)
through ``redsim.ml.campaign_adapter.run_offline_campaign``: the same frozen
``CampaignConfig``, sandbox child and six-section renderer the worker uses, with
the hash-chained audit trail at ``<out>/<run_id>/audit.jsonl``. It makes no
network call and never talks to Pythia (``narrative_source`` stays ``rules``).
``endpoint_stub`` and fixture-only targets are refused before anything is
written, and the process exits non-zero on a refusal or a failed campaign.

``redsim ml seed`` registers the bundled, non-fixture models of the manifest
into a project through ``redsim.services.ml_models.register_bundled_model``
(the audit-first admission boundary ``POST /v1/models`` with ``source=bundled``
uses): the service verifies the bundled files against the manifest, writes the
``model.register`` audit row, copies the weights into the blob store and adds a
per-project ``Target`` (id ``<bundled_id>-<8 hex>``, value
``bundled:<bundled_id>``), which the CLI commits per model. A model the project
already holds is found first by a read-only lookup
(``redsim.services.ml_models.find_bundled_registration``) and reported as
already present: re-seeding is the expected idempotent operation, not a refused
admission, so it writes no audit row and calls the service for nothing. Every
genuine refusal (unverified assets, an unknown id) is written to the project
chain as a ``success=False`` ``model.register`` row, as the route does. When the
service is absent in this build the command says so and exits non-zero instead
of pretending.

``build-assets --fixture`` writes the committed CIFAR-10 test slice
(``tests/ml/fixtures/cifar10_test_500.npz`` and its sidecar entry) from a local
copy of the test split -- the bundled ``test.npz`` under ``--out`` or the hub
parquet in the cache -- and never downloads. On its own it builds no model;
combined with ``--dataset`` / ``--only`` it runs after those builds.

Building the parser imports nothing from the ``ml`` extra. torch,
scikit-learn and httpx load inside the handler, so the rest of the CLI never
pays for them and a test can assert the parser stays light.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redsim.cli import _console
from redsim.ml.assets import ARCH_CHOICES, ASSET_IDS, DATASET_CHOICES, LEGACY_MODEL_IDS, MODEL_IDS
from redsim.ml.campaign_adapter import ASSETS_DIR_ENV, DEFAULT_ACTOR, DEFAULT_ATTACK_IDS

if TYPE_CHECKING:
    from redsim.config import RedsimConfig

BUILD_ASSETS_STATUS = "implemented"
BUILD_ASSETS_REASON = ""

# Spec 20.3: the dataset cache shared by build-assets and the loaders. ``--cache-dir`` wins over it.
DATASET_CACHE_ENV = "REDSIM_ML_DATASET_CACHE"

# The wave-2 admission service this CLI calls (spec 8 table, G-ASSET4), looked up by name so a build
# without it gets a clear refusal: ``register_bundled_model(session, project_id, bundled_id, actor, *,
# audit_writer, config, blob_store, assets_root) -> Target``; ``ApiError(already_registered)`` for a duplicate.
SEED_SERVICE_MODULE = "redsim.services.ml_models"
SEED_SERVICE_FUNCTION = "register_bundled_model"
DB_URL_ENV = "REDSIM_DB_URL"

EXIT_REFUSED = 1
EXIT_USAGE = 2


def add_ml_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``redsim ml ...`` on the top-level subparser collection."""
    p_ml = sub.add_parser("ml", help="Adversarial-ML vertical: build the bundled datasets and models")
    ml_sub = p_ml.add_subparsers(dest="ml_action", required=True)

    legacy_ids = ", ".join(f"{old} (alias of {new})" for old, new in LEGACY_MODEL_IDS.items())
    p_build = ml_sub.add_parser(
        "build-assets",
        help="Fetch the open datasets of spec section 11, train the bundled models on CPU, write assets/MANIFEST.json",
        description=(
            "Fetch each dataset by pinned revision (HuggingFace hub via its API and resolve URLs; the Kaggle "
            "malicious-URLs file with KAGGLE_API_TOKEN read from the environment or a .env file (REDSIM_ENV_FILE), "
            "or the older KAGGLE_USERNAME / KAGGLE_KEY pair, else the committed CI sample), train the "
            f"bundled image CNN ({MODEL_IDS['image']}, {MODEL_IDS['cifar10']}) and URL classifier "
            f"({MODEL_IDS['tabular']}) with a fixed seed on CPU, and record dataset ids, revisions, splits, weight "
            "sha256s, clean metrics and library versions in <out>/MANIFEST.json. Each model entry is a "
            "redsim.ml.schema.MLModelManifest plus the build record, under the id the target registry serves "
            f"(legacy ids still accepted by --only: {legacy_ids}). --fixture writes the committed CIFAR-10 test "
            "slice tests/ml/fixtures/cifar10_test_500.npz with its sidecar MANIFEST.json entry from local files only. "
            "Network access happens only here, never in the worker or the tests."
        ),
    )
    p_build.add_argument("--dataset", choices=DATASET_CHOICES, default=None,
                         help="Which asset to build: image (vehicle CNN), tabular (URL classifier), cifar10 "
                              "(CI fixture CNN), or all (the default unless --fixture is given alone)")
    p_build.add_argument("--only", action="append", choices=sorted(ASSET_IDS), default=None, metavar="MODEL_ID",
                         help="Build only the named bundled model (repeatable; one of %(choices)s). "
                              "Overrides --dataset")
    p_build.add_argument("--epochs", type=int, default=3, help="CNN training epochs (default: 3)")
    p_build.add_argument("--out", default="assets",
                         help="Assets root; MANIFEST.json is written here (default: assets/)")
    p_build.add_argument("--cache-dir", dest="cache_dir", default=None,
                         help=f"Dataset download cache (default: ${DATASET_CACHE_ENV} when set, else <out>/cache)")
    p_build.add_argument("--seed", type=int, default=0, help="Training and split seed (default: 0)")
    p_build.add_argument("--arch", choices=ARCH_CHOICES, default="small_cnn",
                         help="Image architecture for the CNN builds: small_cnn (default) or resnet18 (torchvision "
                              "backbone adapted to the class count; ImageNet weights only from the local torch hub "
                              "cache, else random init, recorded in the manifest)")
    p_build.add_argument("--image-size", dest="image_size", type=int, default=128,
                         help="Square input resolution for the vehicle CNN (default: 128; spec 11.3.1)")
    p_build.add_argument("--image-repo", dest="image_repo", default="leibnitz-lab/military_vehicles",
                         help="HuggingFace imagefolder dataset for the image asset")
    p_build.add_argument("--image-revision", dest="image_revision", default="main",
                         help="Revision of the image dataset to resolve and pin (default: main)")
    p_build.add_argument("--cifar10-revision", dest="cifar10_revision", default="main",
                         help="Revision of uoft-cs/cifar10 to resolve and pin (default: main)")
    p_build.add_argument("--max-train", dest="max_train", type=int, default=None,
                         help="Cap the training split to a seeded stratified subset (smoke builds; recorded in the manifest)")
    p_build.add_argument("--max-eval", dest="max_eval", type=int, default=None,
                         help="Cap the evaluation split likewise (smoke builds; recorded in the manifest)")
    p_build.add_argument("--workers", type=int, default=8, help="Parallel image downloads (default: 8)")
    p_build.add_argument("--xgboost", dest="prefer_xgboost", action="store_true", default=False,
                         help="Train the URL classifier with xgboost (xgboost_json) when it is installed; the default "
                              "is scikit-learn HistGradientBoosting (sklearn_joblib), the bundled format every worker "
                              "image can load")
    p_build.add_argument("--no-xgboost", dest="prefer_xgboost", action="store_false", default=argparse.SUPPRESS,
                         help="Explicitly select the scikit-learn ensemble (the default)")
    p_build.add_argument("--fixture", action="store_true", default=False,
                         help="Write tests/ml/fixtures/cifar10_test_500.npz (50 per class, seed 0) and its sidecar "
                              "entry from a local copy of the CIFAR-10 test split; downloads nothing. Alone, builds "
                              "no model")
    p_build.add_argument("--fixture-out", dest="fixture_out", default=None,
                         help="Where --fixture writes the npz (default: tests/ml/fixtures/cifar10_test_500.npz)")
    p_build.add_argument("--fixture-sidecar", dest="fixture_sidecar", default=None,
                         help="Sidecar MANIFEST.json for --fixture (default: beside --fixture-out)")
    p_build.add_argument("--fixture-synthetic-ok", dest="fixture_allow_synthetic", action="store_true", default=False,
                         help="When no local CIFAR-10 test split exists, let --fixture write a seeded synthetic "
                              "stand-in labelled synthetic=true in the sidecar (never over a real committed draw)")

    p_attack = ml_sub.add_parser(
        "attack",
        help="Run one offline adversarial campaign against a bundled target (no network, no Pythia)",
        description=(
            "Offline CampaignConfig run against a bundled target from the local asset manifest "
            f"(${ASSETS_DIR_ENV} or ./assets): the attacks run in the credential-free sandbox child, the "
            "six-section report (report.md/json/html), run_record.json and the robustness curve are written "
            "under <out>/<run_id>/, and every audit event is appended to <out>/<run_id>/audit.jsonl through the "
            "platform's hash-chained JsonlAuditWriter (chain run:<run_id>; redsim audit verify --run <run_id> "
            "walks it). endpoint_stub answers not_implemented and fixture-only targets (cifar10_smallcnn, any "
            "manifest entry flagged fixture_only) answer fixture_only; both exit non-zero before anything is "
            "written. The narrative stays rules-only (narrative_source=rules): Pythia is never called here."
        ),
    )
    p_attack.add_argument("target_id", help="Bundled target id (vehicles_cnn, url_trees); see GET /v1/models")
    p_attack.add_argument("--attacks", default=",".join(DEFAULT_ATTACK_IDS),
                          help="Comma-separated attack ids (default: %(default)s); noise_control runs automatically")
    p_attack.add_argument("--eps", default=None,
                          help="Comma-separated eps grid, ascending, each in (0, 1] (default: the norm's spec 12.3 grid)")
    p_attack.add_argument("--reference-eps", dest="reference_eps", type=float, default=None,
                          help="Reference budget; must be a grid member (default: 0.03 for linf when in the grid)")
    p_attack.add_argument("--n-samples", dest="n_samples", type=int, default=200,
                          help="Stratified evaluation slice size, 10..1000 (default: 200)")
    p_attack.add_argument("--seed", type=int, default=0, help="Sampling and attack seed (default: 0)")
    p_attack.add_argument("--explain-k", dest="explain_k", type=int, default=8,
                          help="SHAP explanations per attack at the reference eps, 0..32; 0 skips explain (default: 8)")
    p_attack.add_argument("--no-control", dest="no_control", action="store_true", default=False,
                          help="Skip the benign noise control (the report then says so)")
    p_attack.add_argument("--norm", choices=("linf", "l2"), default="linf", help="Perturbation norm (default: linf)")
    p_attack.add_argument("--out", default=None,
                          help="Runs root; the run lands in <out>/<run_id>/ (default: the config output_dir)")
    p_attack.add_argument("--assets-dir", dest="assets_dir", default=None,
                          help=f"Bundled asset tree with MANIFEST.json (default: ${ASSETS_DIR_ENV}, else ./assets)")
    p_attack.add_argument("--actor", default=DEFAULT_ACTOR, help="Actor recorded on the audit rows (default: %(default)s)")

    p_seed = ml_sub.add_parser(
        "seed",
        help="Register the bundled, non-fixture models of the asset manifest into a project (audit-first)",
        description=(
            "Open the configured database (REDSIM_DB_URL) and call "
            f"{SEED_SERVICE_MODULE}.{SEED_SERVICE_FUNCTION}(session, project_id, bundled_id, actor, ...) for each "
            "bundled model in <assets>/MANIFEST.json that is not fixture-only: the service verifies the bundled "
            "files against the manifest, writes the model.register audit row first, puts the weights blob and "
            "creates the ml_model_artifact Target (id <bundled_id>-<8 hex>, value bundled:<bundled_id>) as "
            "available; each registration is committed before the next model. A model the project already holds "
            "is found by a read-only lookup first, reported as already present and never re-registered (no audit "
            "row: re-seeding is idempotent, not a refusal); every genuine refusal is recorded on the project chain "
            "as a success=False model.register row and makes the command exit 1 after the remaining models were "
            "tried. When the service is absent in this build the command says so and exits non-zero."
        ),
    )
    p_seed.add_argument("--project", default=None,
                        help="Project id or slug (default: the only project when exactly one exists)")
    p_seed.add_argument("--only", default=None, metavar="MODEL_IDS",
                        help="Comma-separated bundled ids to seed (default: every non-fixture model in the manifest)")
    p_seed.add_argument("--assets-dir", dest="assets_dir", default=None,
                        help=f"Bundled asset tree with MANIFEST.json (default: ${ASSETS_DIR_ENV}, else ./assets)")
    p_seed.add_argument("--actor", default=DEFAULT_ACTOR, help="Actor recorded on the audit rows (default: %(default)s)")


def cmd_ml_build_assets(args: argparse.Namespace, _config: RedsimConfig) -> None:
    """Run the asset build. Heavy imports live here so the parser stays light."""
    import httpx

    from redsim.ml.assets.build import DEFAULT_FIXTURE_PATH, BuildOptions, build_assets, summarize
    from redsim.ml.assets.datasets import DatasetUnavailable as FetchUnavailable
    from redsim.ml.datasets import DatasetUnavailable as SliceUnavailable

    cache_env = os.environ.get(DATASET_CACHE_ENV, "").strip()
    cache_dir = Path(args.cache_dir) if args.cache_dir else (Path(cache_env) if cache_env else None)
    fixture = bool(getattr(args, "fixture", False))
    explicit_selection = args.dataset is not None or bool(args.only)
    try:
        opts = BuildOptions(
            dataset=args.dataset or "all", only=tuple(args.only or ()), epochs=args.epochs, out=args.out,
            cache_dir=cache_dir, seed=args.seed, image_size=args.image_size, image_repo=args.image_repo,
            image_revision=args.image_revision, cifar10_revision=args.cifar10_revision,
            max_train=args.max_train, max_eval=args.max_eval, workers=args.workers,
            prefer_xgboost=bool(getattr(args, "prefer_xgboost", False)), arch=getattr(args, "arch", "small_cnn"),
            build_models=explicit_selection or not fixture, fixture=fixture,
            fixture_out=Path(args.fixture_out) if getattr(args, "fixture_out", None) else DEFAULT_FIXTURE_PATH,
            fixture_sidecar=Path(args.fixture_sidecar) if getattr(args, "fixture_sidecar", None) else None,
            fixture_allow_synthetic=bool(getattr(args, "fixture_allow_synthetic", False)),
        )
    except ValueError as exc:
        _console._err(str(exc))
        sys.exit(2)
    if opts.build_models:
        what = ", ".join(opts.only) if opts.only else f"{opts.dataset} asset(s)"
        _console._info(f"building {what} into {opts.out} (epochs={opts.epochs}, seed={opts.seed}, arch={opts.arch}, "
                       f"cache={opts.cache_dir})")
    if opts.fixture:
        _console._info(f"fixture: writing {opts.fixture_out} from local files only (no download)")
    try:
        manifest = build_assets(opts, log=_console._info, warn=_console._warn)
    except (FetchUnavailable, SliceUnavailable, httpx.HTTPError) as exc:
        _console._err(f"asset build failed: {exc}")
        sys.exit(1)
    if opts.build_models:
        print(summarize(manifest))


# ---------------------------------------------------------------------------
# redsim ml attack (offline campaign)
# ---------------------------------------------------------------------------


def _csv(raw: str | None) -> list[str]:
    return [part.strip() for part in (raw or "").split(",") if part.strip()]


def _csv_floats(raw: str | None, *, flag: str) -> list[float] | None:
    parts = _csv(raw)
    if not parts:
        return None
    try:
        return [float(part) for part in parts]
    except ValueError:
        _console._err(f"{flag} expects comma-separated numbers, got {raw!r}")
        sys.exit(EXIT_USAGE)


def _output_dir(args: argparse.Namespace, config: RedsimConfig | None) -> Path:
    if getattr(args, "out", None):
        return Path(args.out)
    return Path(str(getattr(config, "output_dir", None) or "redsim_output"))


def cmd_ml_attack(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Run one offline campaign. Heavy imports live in the runner, behind the refusal checks."""
    from redsim.ml.campaign_adapter import (
        OfflineCampaignRefused,
        OfflineCampaignRequest,
        resolve_assets_dir,
        run_offline_campaign,
    )
    from redsim.ml.errors import MLError
    from redsim.plugins import load_ml_attack_plugins

    attacks = _csv(getattr(args, "attacks", None)) or list(DEFAULT_ATTACK_IDS)
    eps = _csv_floats(getattr(args, "eps", None), flag="--eps")
    n_samples = int(args.n_samples)
    if not 10 <= n_samples <= 1000:
        _console._err(f"--n-samples must lie in [10, 1000] (CampaignConfig), got {n_samples}")
        sys.exit(EXIT_USAGE)
    explain_k = int(args.explain_k)
    if not 0 <= explain_k <= 32:
        _console._err(f"--explain-k must lie in [0, 32] (CampaignConfig), got {explain_k}")
        sys.exit(EXIT_USAGE)
    request = OfflineCampaignRequest(
        target_id=args.target_id, attack_ids=tuple(attacks), eps_grid=tuple(eps) if eps else None,
        reference_eps=getattr(args, "reference_eps", None), n_samples=n_samples, seed=int(args.seed),
        explain_k=explain_k, include_control=not bool(getattr(args, "no_control", False)),
        norm=str(getattr(args, "norm", "linf")), actor=str(getattr(args, "actor", None) or DEFAULT_ACTOR),
    )
    out_dir = _output_dir(args, config)
    assets_dir = resolve_assets_dir(getattr(args, "assets_dir", None))
    _console._info(f"offline campaign: target={request.target_id} attacks={list(request.attack_ids)} "
                   f"assets={assets_dir} out={out_dir}")
    _console._info("no network, no Pythia: llm_narrative=false, narrative_source stays 'rules'")
    # Opt-in third-party attack adapters (REDSIM_PLUGINS=1) join the registry before resolution.
    for row in load_ml_attack_plugins():
        _console._info(f"attack plugin {row.name}: {row.status}{(' (' + row.detail + ')') if row.detail else ''}")
    allowlist = list(getattr(config, "target_allowlist", None) or [])
    try:
        result = run_offline_campaign(request, out_dir=out_dir, assets_dir=assets_dir, allowlist=allowlist,
                                      log=_console._info)
    except OfflineCampaignRefused as exc:
        _console._err(f"refused ({exc.reason}): {exc.message}")
        sys.exit(EXIT_REFUSED)
    except MLError as exc:
        _console._err(f"campaign failed ({type(exc).__name__}): {exc}")
        sys.exit(EXIT_REFUSED)

    record = result.record
    _console._info(f"run {result.run_id}: status={record.status} stages={list(record.stages_done)}")
    if record.score is not None and record.score.mri is not None:
        _console._info(f"MRI {record.score.mri} ({record.score.grade}); subscores and the per-family table "
                       f"are in {result.report_paths.get('report.md')}")
    elif record.score is not None:
        _console._info(f"score partial: {'; '.join(record.score.missing) or 'see report'}")
    elif record.score_status is not None:
        _console._info(f"score {record.score_status.state}: {record.score_status.reason or ''}".rstrip())
    for name, path in sorted(result.report_paths.items()):
        print(f"    {name:<16} {path}")
    if result.curve_path is not None:
        print(f"    {'curve':<16} {result.curve_path}")
    print(f"    {'audit chain':<16} {result.audit_path} ({result.audit_events} events, chain run:{result.run_id})")
    _console._info(f"narrative_source={result.narrative_source} (rules only; Pythia is not called offline)")
    _console._info(f"verify the trail: redsim audit verify --run {result.run_id} "
                   f"(the offline chain lives in {result.audit_path})")
    if record.status != "succeeded":
        _console._err(f"campaign {record.status}: {record.error or 'see run_record.json'}")
        sys.exit(EXIT_REFUSED)


# ---------------------------------------------------------------------------
# redsim ml seed (register the bundled models into a project)
# ---------------------------------------------------------------------------


class SeedUnavailable(RuntimeError):
    """``redsim ml seed`` cannot proceed; the message says exactly why."""


def _seed_service() -> Any:
    """``redsim.services.ml_models.register_bundled_model``, or ``None`` when this build lacks it."""
    import importlib

    try:
        module = importlib.import_module(SEED_SERVICE_MODULE)
    except ImportError:
        return None
    fn = getattr(module, SEED_SERVICE_FUNCTION, None)
    return fn if callable(fn) else None


def _require_db_url() -> str:
    url = os.environ.get(DB_URL_ENV, "").strip()
    if not url:
        raise SeedUnavailable(f"{DB_URL_ENV} is not set; redsim ml seed writes Target rows and needs the "
                              "platform database")
    return url


@contextmanager
def _seed_session() -> Iterator[Any]:
    """The configured DB session (``REDSIM_DB_URL``).

    ``redsim.db.session.get_session`` initialises the engine from that variable
    on first use; ``resolve_writer`` has usually done so already, so the audit
    writer and the Target rows share one engine.
    """
    _require_db_url()
    from redsim.db.session import get_session

    with get_session() as sess:
        yield sess


def _seed_project_id(sess: Any, requested: str | None) -> str:
    from sqlalchemy import select

    from redsim.db.models import Project

    if requested:
        project = sess.get(Project, requested)
        if project is None:
            project = sess.execute(select(Project).where(Project.slug == requested)).scalar_one_or_none()
        if project is None:
            raise SeedUnavailable(f"project {requested!r} not found (by id or slug)")
        return str(project.id)
    projects = list(sess.execute(select(Project)).scalars().all())
    if len(projects) == 1:
        return str(projects[0].id)
    if not projects:
        raise SeedUnavailable("no project exists yet; create one (cd deploy && make seed) or pass --project")
    listing = ", ".join(f"{p.id} ({p.slug})" for p in projects)
    raise SeedUnavailable(f"several projects exist, pass --project: {listing}")


def _registry_fixture_only_ids() -> set[str]:
    """Targets the registry itself marks fixture-only (the CIFAR-10 CNN); tolerant of a missing ml extra."""
    try:
        from redsim.ml.targets.registry import list_targets

        return {info.id for info in list_targets() if (info.metadata or {}).get("fixture_only")}
    except Exception:  # noqa: BLE001 - numpy or the registry may be unavailable on a slim install
        return set()


def _seed_candidates(manifest: dict[str, Any], only: list[str]) -> tuple[list[str], list[str]]:
    """``(bundled ids to seed, skipped fixture-only ids)`` from the manifest's ``models`` mapping."""
    raw = manifest.get("models")
    entries: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict):
        entries = {str(k): dict(v) for k, v in raw.items() if isinstance(v, dict)}
    elif isinstance(raw, list):
        entries = {str(v.get("id")): dict(v) for v in raw if isinstance(v, dict) and v.get("id")}
    if not entries:
        raise SeedUnavailable("the asset manifest lists no models; run `redsim ml build-assets` first")
    fixture_ids = {mid for mid, entry in entries.items() if entry.get("fixture_only")} | _registry_fixture_only_ids()
    wanted = only or sorted(entries)
    unknown = [mid for mid in wanted if mid not in entries]
    if unknown:
        raise SeedUnavailable(f"--only names models the manifest lacks: {unknown}; available: {sorted(entries)}")
    skipped = [mid for mid in wanted if mid in fixture_ids]
    return [mid for mid in wanted if mid not in fixture_ids], skipped


def _describe_target(target: Any) -> str:
    """``(target <id>, status <detail.status>)`` for the ``Target`` row the service returns."""
    detail = getattr(target, "detail", None)
    status = detail.get("status") if isinstance(detail, dict) else None
    parts = [f"target {target.id}", f"status {status}" if status else ""]
    return " (" + ", ".join(p for p in parts if p) + ")"


def _describe_refusal(exc: Any) -> str:
    """The 17.3 fields worth showing on the console: ``target_id``, ``refusal_reason`` and ``reasons``."""
    detail = getattr(exc, "detail", None)
    if not isinstance(detail, dict):
        return ""
    parts: list[str] = []
    if detail.get("target_id"):
        parts.append(f"target {detail['target_id']}")
    if detail.get("refusal_reason"):
        parts.append(f"refusal_reason {detail['refusal_reason']}")
    reasons = detail.get("reasons")
    if isinstance(reasons, list) and reasons:
        parts.append("; ".join(str(r) for r in reasons))
    return f" ({', '.join(parts)})" if parts else ""


def cmd_ml_seed(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Register every bundled, non-fixture model of the manifest into one project.

    Per model: a read-only ``find_bundled_registration`` lookup first; a live
    registration in the project is printed as already present and nothing else
    happens (no service call, no audit row: a re-seed is idempotent, not a
    refused admission). Otherwise ``register_bundled_model`` verifies the bundled
    files against the manifest, writes the ``model.register`` audit row, copies
    the weights into the blob store and adds the ``Target`` row; the CLI then
    commits that row so a refusal further down the list leaves the models before
    it registered. A refusal (``ApiError``) is written to the project chain as a
    ``success=False`` ``model.register`` row through ``audit_refused_admission``,
    exactly as ``POST /v1/models`` does, and makes the command exit 1 after the
    remaining models were tried. ``already_registered`` from the service (a
    registration that landed between the lookup and the call) is still reported
    as already present, without a row.
    """
    fn = _seed_service()
    if fn is None:
        _console._err(f"redsim ml seed needs {SEED_SERVICE_MODULE}.{SEED_SERVICE_FUNCTION}, which this build "
                      "does not provide (the wave-2 admission service is not merged); nothing was registered")
        sys.exit(EXIT_REFUSED)
    # After the presence check: ``redsim.api.errors`` resolves the ``redsim.api`` package, whose routers import
    # the service by name, so a build without it must be refused above rather than fail here.
    from redsim.api.errors import ALREADY_REGISTERED, ApiError
    from redsim.ml.campaign_adapter import resolve_assets_dir
    from redsim.services.ml_models import (
        DatasetBindingError,
        MlCatalogUnavailable,
        audit_refused_admission,
        canonical_bundled_id,
        find_bundled_registration,
        read_asset_manifest,
    )

    assets_dir = resolve_assets_dir(getattr(args, "assets_dir", None))
    # The target registry reads the manifest through this variable; keep it in step with --assets-dir.
    os.environ[ASSETS_DIR_ENV] = str(assets_dir)
    actor = str(getattr(args, "actor", None) or DEFAULT_ACTOR)
    try:
        manifest = read_asset_manifest(assets_dir)
        bundled_ids, skipped = _seed_candidates(manifest, _csv(getattr(args, "only", None)))
    except DatasetBindingError as exc:
        _console._err(str(exc))
        sys.exit(EXIT_REFUSED)
    except SeedUnavailable as exc:
        _console._err(str(exc))
        sys.exit(EXIT_USAGE)
    for mid in skipped:
        _console._warn(f"skipping {mid}: fixture-only, never registered as a demo target")
    if not bundled_ids:
        _console._warn("nothing to seed: every selected model is fixture-only")
        return

    registered = 0
    present = 0
    failures = 0
    try:
        _require_db_url()
        # The writer first: with REDSIM_DB_URL set it initialises the engine the session below reuses.
        from redsim.audit.chain import resolve_writer
        from redsim.storage.blobs import open_blob_store

        writer = resolve_writer(config)
        blob_store = open_blob_store(config)
        with _seed_session() as sess:
            project_id = _seed_project_id(sess, getattr(args, "project", None))
            _console._info(f"seeding {bundled_ids} into project {project_id} from {assets_dir}")
            for bundled_id in bundled_ids:
                # Read-only first: a model the project already holds is the expected state on a re-seed,
                # not a refused admission, so it is reported without a service call or an audit row.
                existing = find_bundled_registration(sess, project_id, canonical_bundled_id(bundled_id))
                if existing is not None:
                    present += 1
                    _console._info(f"already present: {bundled_id}{_describe_target(existing)}")
                    continue
                try:
                    target = fn(sess, project_id, bundled_id, actor, audit_writer=writer, config=config,
                                blob_store=blob_store, assets_root=assets_dir)
                except ApiError as exc:
                    sess.rollback()
                    if exc.code == ALREADY_REGISTERED:
                        # Registered between the lookup and the call: the same idempotent outcome, no row.
                        present += 1
                        _console._info(f"already present: {bundled_id}{_describe_refusal(exc)}")
                        continue
                    audit_refused_admission(
                        writer, action="model.register", actor=actor, project_id=project_id,
                        detail={"kind": "ml_model_artifact", "source": "bundled", "bundled_id": bundled_id,
                                "reason": exc.code, **{k: v for k, v in exc.detail.items()
                                                       if k in {"reason", "refusal_reason", "status", "target_id"}}},
                    )
                    failures += 1
                    _console._err(f"{bundled_id}: refused ({exc.code}): {exc}{_describe_refusal(exc)}")
                    continue
                # The audit row and the blob are durable already; commit the Target row now so a refusal on a
                # later model never rolls this registration back.
                sess.commit()
                registered += 1
                _console._info(f"registered: {bundled_id}{_describe_target(target)}")
    except SeedUnavailable as exc:
        _console._err(str(exc))
        sys.exit(EXIT_REFUSED)
    except MlCatalogUnavailable as exc:
        _console._err(f"{exc}; nothing was registered")
        sys.exit(EXIT_REFUSED)
    _console._info(f"seed finished: {registered} registered, {present} already present, {failures} refused")
    if failures:
        sys.exit(EXIT_REFUSED)


def cmd_ml(args: argparse.Namespace, config: RedsimConfig) -> None:
    if args.ml_action == "build-assets":
        cmd_ml_build_assets(args, config)
    elif args.ml_action == "attack":
        cmd_ml_attack(args, config)
    elif args.ml_action == "seed":
        cmd_ml_seed(args, config)
    else:
        _console._err(f"Unknown ml action: {args.ml_action}")
        sys.exit(2)
