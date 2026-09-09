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
``--norm`` accepts every ``schema.Norm`` literal (``linf``, ``l2``, ``edit``,
``patch_area``); what the caller omits is filled per norm from the spec 12.3
table (:func:`resolve_attack_defaults`): the norm itself from the target's
modality in the asset manifest (``edit`` for a text target, ``patch_area`` for a
detection target, ``linf`` otherwise), then the attack set (``fgsm,pgd``,
``word_substitution`` or ``dpatch``), the budget grid and the reference budget.
The adapter validates whatever is sent; a norm it cannot run yet is its refusal.

Phase B (plan 12): ``build-assets --dataset text`` trains the SMS spam
classifier (``sms_tfidf_lr``) and ``--dataset detection`` the military-assets
detector (``assets_frcnn_mnv3``; named explicitly only, it needs the published
subset); ``--only`` accepts both ids. The image builds also write the bundled
training slice a training defense fine-tunes on, and ``--attach-train-slice``
records a slice drawn out-of-band in an existing manifest without retraining.
The vocabulary comes from ``redsim.ml.assets.manifest`` (import-light) so the
parser needs neither numpy nor the builder.

Several target ids, or ``--matrix FILE.yaml`` (register BULK-17 / -18, plan 12
wave B3), expand into a grid of cells (models x attack sets x eps grids x
seeds). Every cell is one offline run with its own ``run_id``, its own run
directory and its own hash-chained ``audit.jsonl`` (chain ``run:<run_id>``),
verified with ``verify_chain`` as soon as it closes; nothing is aggregated
across cells. The command prints a summary table (one row per cell: status,
MRI and grade where computed, run id, event count, chain verdict), writes
``<out>/matrix-<id>/summary.json`` with the same rows and exits non-zero when
any cell was refused or failed. ``--fail-fast`` stops at the first such cell.
:data:`MATRIX_SCHEMA_HELP` documents the YAML shape and is printed by
``redsim ml attack --help``.

``redsim ml seed`` registers the bundled, non-fixture models of the manifest
(image, tabular and, once built, text and detection alike: every entry that is
not fixture-only) into a project through ``redsim.services.ml_models.register_bundled_model``
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
import json
import os
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from itertools import product
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from redsim.cli import _console
from redsim.ml.assets import ARCH_CHOICES, LEGACY_MODEL_IDS
from redsim.ml.assets.manifest import (
    BUILD_ASSET_IDS,
    BUILD_DATASET_CHOICES,
    BUILD_MODEL_IDS,
    EXPLICIT_ONLY_DATASETS,
    all_build_datasets,
)
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

# ``redsim ml attack`` budget defaults per norm (spec 12.3; MODALITIES-06). Literals so building the parser
# stays import-light; tests/ml/test_cli_ml.py asserts they equal the attack modules' constants
# (``redsim.ml.scoring`` for linf and l2, ``word_substitution.DEFAULT_EDIT_GRID``,
# ``dpatch.DEFAULT_PATCH_AREA_GRID`` / ``DEFAULT_REFERENCE_PATCH_AREA``) so the two cannot drift.
NORM_CHOICES: tuple[str, ...] = ("linf", "l2", "edit", "patch_area")
#: Default attack set per norm: the Phase A pair for the pixel and feature norms, the text and detection
#: adapters for their own norms. The modality's noise control runs automatically in every case.
NORM_DEFAULT_ATTACKS: dict[str, tuple[str, ...]] = {
    "linf": DEFAULT_ATTACK_IDS, "l2": DEFAULT_ATTACK_IDS, "edit": ("word_substitution",), "patch_area": ("dpatch",),
}
NORM_DEFAULT_GRIDS: dict[str, tuple[float, ...]] = {
    "linf": (0.01, 0.03, 0.1), "l2": (0.25, 0.5, 1.0), "edit": (0.1, 0.2, 0.3), "patch_area": (0.01, 0.03, 0.05),
}
NORM_DEFAULT_REFERENCE: dict[str, float] = {"linf": 0.03, "l2": 0.5, "edit": 0.2, "patch_area": 0.03}
#: The norm a target's modality is measured under when ``--norm`` is omitted (``schema.Modality`` literals);
#: the modality comes from the asset manifest entry of the target, ``linf`` when the manifest does not name it.
MODALITY_DEFAULT_NORM: dict[str, str] = {"image": "linf", "tabular": "linf", "text": "edit", "detection": "patch_area"}

#: Top-level keys a ``--matrix`` YAML document may carry (anything else is a usage error).
MATRIX_KEYS: frozenset[str] = frozenset({
    "models", "attack_sets", "eps_grids", "seeds", "norm", "reference_eps", "n_samples", "explain_k",
    "include_control", "name", "description",
})

#: The ``--matrix`` YAML schema, printed by ``redsim ml attack --help`` (register BULK-17).
MATRIX_SCHEMA_HELP = """\
matrix YAML (--matrix FILE): cells = models x attack_sets x eps_grids x seeds, one offline run and one
hash-chained audit.jsonl per cell, a summary table and <out>/matrix-<id>/summary.json at the end.

  name: nightly-grid                    # optional label, recorded in summary.json
  models: [vehicles_cnn, url_trees]     # required: bundled target ids (fixture-only ids are refused per cell)
  attack_sets:                          # optional: each entry is one campaign's attack list (default: the
                                        #   --attacks flag, else the norm's spec 12.3 default set)
    - [fgsm, pgd]                       #   (a comma-separated string is accepted too: "fgsm,pgd")
    - [hopskipjump]
  eps_grids:                            # optional, default [null]: each entry is one ascending grid in (0, 1];
    - [0.01, 0.03]                      #   null means the --eps flag, else the norm's spec 12.3 default grid
    - null
  seeds: [0, 1]                         # optional, default [0]
  norm: linf                            # optional: linf | l2 | edit | patch_area (default: the --norm flag,
                                        #   else the target's modality norm from the asset manifest)
  reference_eps: null                   # optional: a member of every grid (default: the --reference-eps flag)
  n_samples: 200                        # optional, 10..1000 (default: the --n-samples flag)
  explain_k: 8                          # optional, 0..32 (default: the --explain-k flag)
  include_control: true                 # optional (default: the inverse of --no-control)

A cell an attack cannot run on (an image-only attack on a tabular model, an unknown id) is recorded as
refused in the table and makes the command exit 1; it never stops the other cells unless --fail-fast is set.
Nothing is averaged or ranked across cells: each run_record.json stands alone with its own chain."""


class _MlSubcommandParser(argparse.ArgumentParser):
    """``redsim ml`` subcommand parser: ``attack`` needs a target id or ``--matrix`` at parse time."""

    def parse_known_args(  # type: ignore[override]
        self, args: Sequence[str] | None = None, namespace: Any = None,
    ) -> tuple[argparse.Namespace, list[str]]:
        parsed, extras = super().parse_known_args(args, namespace)
        if hasattr(parsed, "matrix") and not getattr(parsed, "matrix", None) and not getattr(parsed, "target_id", None):
            self.error("a target id (or several) or --matrix FILE is required")
        return parsed, list(extras)


def add_ml_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``redsim ml ...`` on the top-level subparser collection."""
    p_ml = sub.add_parser("ml", help="Adversarial-ML vertical: build the bundled datasets and models")
    ml_sub = p_ml.add_subparsers(dest="ml_action", required=True, parser_class=_MlSubcommandParser)

    legacy_ids = ", ".join(f"{old} (alias of {new})" for old, new in LEGACY_MODEL_IDS.items())
    all_datasets = ", ".join(sorted(all_build_datasets()))
    explicit_only = ", ".join(EXPLICIT_ONLY_DATASETS)
    p_build = ml_sub.add_parser(
        "build-assets",
        help="Fetch the open datasets of spec section 11, train the bundled models on CPU, write assets/MANIFEST.json",
        description=(
            "Fetch each dataset by pinned revision (HuggingFace hub via its API and resolve URLs; the Kaggle "
            "malicious-URLs file with KAGGLE_API_TOKEN read from the environment or a .env file (REDSIM_ENV_FILE), "
            "or the older KAGGLE_USERNAME / KAGGLE_KEY pair, else the committed CI sample; the UCI SMS Spam "
            "Collection zip, else its committed CI sample), train the bundled image CNN "
            f"({BUILD_MODEL_IDS['image']}, {BUILD_MODEL_IDS['cifar10']}), URL classifier ({BUILD_MODEL_IDS['tabular']}), "
            f"SMS spam classifier ({BUILD_MODEL_IDS['text']}) and military-assets detector "
            f"({BUILD_MODEL_IDS['detection']}) with a fixed seed on CPU, and record dataset ids, revisions, splits, "
            "weight sha256s, clean metrics and library versions in <out>/MANIFEST.json. Each model entry is a "
            "redsim.ml.schema.MLModelManifest plus the build record, under the id the target registry serves "
            f"(legacy ids still accepted by --only: {legacy_ids}). --dataset all builds {all_datasets}; {explicit_only} "
            "is built only when named because its input, the capped subset under "
            "<assets>/cache/military_assets_subset, is published by the datasets step and not fetched here. The "
            "image builds also write bundled/<model>/train_slice.npz, the training slice a training defense "
            "fine-tunes on; --attach-train-slice records a slice drawn out-of-band (its train_slice.json sidecar) "
            "in an existing manifest without retraining. --fixture writes the committed CIFAR-10 test slice "
            "tests/ml/fixtures/cifar10_test_500.npz with its sidecar MANIFEST.json entry from local files only. "
            "Network access happens only here, never in the worker or the tests."
        ),
    )
    p_build.add_argument("--dataset", choices=BUILD_DATASET_CHOICES, default=None,
                         help="Which asset to build: image (vehicle CNN), tabular (URL classifier), cifar10 "
                              "(CI fixture CNN), text (SMS spam classifier), detection (military-assets detector; "
                              f"named only), or all ({all_datasets}; the default unless --fixture or "
                              "--attach-train-slice is given alone)")
    p_build.add_argument("--only", action="append", choices=sorted(BUILD_ASSET_IDS), default=None, metavar="MODEL_ID",
                         help="Build only the named bundled model (repeatable; one of %(choices)s). "
                              "Overrides --dataset")
    p_build.add_argument("--epochs", type=int, default=3, help="CNN / detector training epochs (default: 3)")
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
    p_build.add_argument("--no-train-slice", dest="train_slice", action="store_false", default=True,
                         help="Skip writing bundled/<model>/train_slice.npz for the image builds (the seeded "
                              "stratified training slice a training defense fine-tunes on; written by default)")
    p_build.add_argument("--train-slice-n", dest="train_slice_n", type=int, default=1536,
                         help="Rows in the training slice (default: 1536; capped at the training split's size)")
    p_build.add_argument("--attach-train-slice", dest="attach_train_slice", action="append", default=None,
                         metavar="MODEL_ID",
                         help="Record an existing bundled/<MODEL_ID>/train_slice.npz (described by its train_slice.json "
                              "sidecar, digest-checked) in <out>/MANIFEST.json for a model already built there; "
                              "repeatable, no training, no download. Alone, builds no model")
    p_build.add_argument("--detection-image-size", dest="detection_image_size", type=int, default=320,
                         help="Square input resolution for the detector build (default: 320)")
    p_build.add_argument("--detection-subset", dest="detection_subset", default=None,
                         help="Directory of the published military-assets subset (manifest.json, images/, labels/); "
                              "default: <cache-dir>/military_assets_subset, else <out>/cache/military_assets_subset")

    p_attack = ml_sub.add_parser(
        "attack",
        help="Run offline adversarial campaigns against bundled targets (no network, no Pythia); "
             "several ids or --matrix FILE.yaml run one chain per cell",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Offline CampaignConfig run against a bundled target from the local asset manifest "
            f"(${ASSETS_DIR_ENV} or ./assets): the attacks run in the credential-free sandbox child, the "
            "six-section report (report.md/json/html), run_record.json and the robustness curve are written "
            "under <out>/<run_id>/, and every audit event is appended to <out>/<run_id>/audit.jsonl through the "
            "platform's hash-chained JsonlAuditWriter (chain run:<run_id>; redsim audit verify --run <run_id> "
            "walks it). endpoint_stub answers not_implemented and fixture-only targets (cifar10_smallcnn, any "
            "manifest entry flagged fixture_only) answer fixture_only; both exit non-zero before anything is "
            "written. The narrative stays rules-only (narrative_source=rules): Pythia is never called here. "
            "Several target ids, or --matrix FILE.yaml, run one offline campaign and one verifiable audit chain "
            "per cell and print a summary table (no cross-cell aggregate)."
        ),
        epilog=MATRIX_SCHEMA_HELP,
    )
    p_attack.add_argument("target_id", nargs="?", default=None,
                          help="Bundled target id (vehicles_cnn, url_trees, and once built sms_tfidf_lr, "
                               "assets_frcnn_mnv3); see GET /v1/models. Optional with --matrix")
    p_attack.add_argument("targets", nargs="*", metavar="TARGET_ID",
                          help="Further bundled target ids: one offline run and one audit chain per target")
    p_attack.add_argument("--matrix", default=None, metavar="FILE",
                          help="YAML matrix (models x attack_sets x eps_grids x seeds); schema below. The flags "
                               "below are the defaults for keys the file omits")
    p_attack.add_argument("--fail-fast", dest="fail_fast", action="store_true", default=False,
                          help="Stop at the first refused or failed cell (default: run every cell, exit 1 at the end)")
    p_attack.add_argument("--attacks", default=None,
                          help=(f"Comma-separated attack ids (default per norm: {','.join(DEFAULT_ATTACK_IDS)} for linf "
                                f"and l2, {NORM_DEFAULT_ATTACKS['edit'][0]} for edit, "
                                f"{NORM_DEFAULT_ATTACKS['patch_area'][0]} for patch_area); the modality's noise "
                                "control runs automatically"))
    p_attack.add_argument("--eps", default=None,
                          help=("Comma-separated budget grid, ascending, each in (0, 1] (default: the norm's spec 12.3 "
                                "grid: " + "; ".join(f"{n} {','.join(f'{e:g}' for e in g)}"
                                                     for n, g in NORM_DEFAULT_GRIDS.items()) + ")"))
    p_attack.add_argument("--reference-eps", dest="reference_eps", type=float, default=None,
                          help=("Reference budget; must be a grid member (default per norm, when in the grid: "
                                + ", ".join(f"{n} {r:g}" for n, r in NORM_DEFAULT_REFERENCE.items()) + ")"))
    p_attack.add_argument("--n-samples", dest="n_samples", type=int, default=200,
                          help="Stratified evaluation slice size, 10..1000 (default: 200)")
    p_attack.add_argument("--seed", type=int, default=0, help="Sampling and attack seed (default: 0)")
    p_attack.add_argument("--explain-k", dest="explain_k", type=int, default=8,
                          help="SHAP explanations per attack at the reference eps, 0..32; 0 skips explain (default: 8)")
    p_attack.add_argument("--no-control", dest="no_control", action="store_true", default=False,
                          help="Skip the benign noise control (the report then says so)")
    p_attack.add_argument("--norm", choices=NORM_CHOICES, default=None,
                          help=("Budget norm (default: the target's modality norm from the asset manifest: linf for "
                                "an image or tabular target, edit for a text target, patch_area for a detection "
                                "target; linf when the manifest does not name the target)"))
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
            "bundled model in <assets>/MANIFEST.json that is not fixture-only (the image CNN, the URL classifier "
            f"and, once built, the text classifier {BUILD_MODEL_IDS['text']} and the detector "
            f"{BUILD_MODEL_IDS['detection']}; the registry must serve the id): the service verifies the bundled "
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
    attach = tuple(getattr(args, "attach_train_slice", None) or ())
    explicit_selection = args.dataset is not None or bool(args.only)
    detection_subset = getattr(args, "detection_subset", None)
    try:
        opts = BuildOptions(
            dataset=args.dataset or "all", only=tuple(args.only or ()), epochs=args.epochs, out=args.out,
            cache_dir=cache_dir, seed=args.seed, image_size=args.image_size, image_repo=args.image_repo,
            image_revision=args.image_revision, cifar10_revision=args.cifar10_revision,
            max_train=args.max_train, max_eval=args.max_eval, workers=args.workers,
            prefer_xgboost=bool(getattr(args, "prefer_xgboost", False)), arch=getattr(args, "arch", "small_cnn"),
            build_models=explicit_selection or not (fixture or attach), fixture=fixture,
            fixture_out=Path(args.fixture_out) if getattr(args, "fixture_out", None) else DEFAULT_FIXTURE_PATH,
            fixture_sidecar=Path(args.fixture_sidecar) if getattr(args, "fixture_sidecar", None) else None,
            fixture_allow_synthetic=bool(getattr(args, "fixture_allow_synthetic", False)),
            train_slice=bool(getattr(args, "train_slice", True)),
            train_slice_n=int(getattr(args, "train_slice_n", 1536)),
            attach_train_slice=attach,
            detection_image_size=int(getattr(args, "detection_image_size", 320)),
            detection_subset=Path(detection_subset) if detection_subset else None,
        )
    except ValueError as exc:
        _console._err(str(exc))
        sys.exit(2)
    if opts.build_models:
        what = ", ".join(opts.only) if opts.only else f"{opts.dataset} asset(s)"
        _console._info(f"building {what} into {opts.out} (epochs={opts.epochs}, seed={opts.seed}, arch={opts.arch}, "
                       f"cache={opts.cache_dir}, train_slice={'on' if opts.train_slice else 'off'})")
    if opts.attach_train_slice:
        _console._info(f"attach-train-slice: recording {', '.join(opts.attach_train_slice)} from the train_slice.json "
                       f"sidecar(s) under {opts.out}/bundled (no training, no download)")
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


@dataclass(frozen=True)
class AttackDefaults:
    """What ``redsim ml attack`` sends after the per-norm defaults filled what the caller omitted."""

    norm: str
    attack_ids: tuple[str, ...]
    eps_grid: tuple[float, ...]
    reference_eps: float | None
    filled: tuple[str, ...]        # which of norm / attacks / eps / reference_eps came from the defaults


def resolve_attack_defaults(*, modality: str | None, norm: str | None, attacks: Sequence[str] | None,
                            eps: Sequence[float] | None, reference_eps: float | None) -> AttackDefaults:
    """Fill the omitted budget settings from the norm, and the norm from the target's modality (spec 12.3).

    Explicit values always win and are passed through unchanged for the adapter to
    validate. A reference the caller omitted is the norm's default only when that
    value is a member of the grid in use; otherwise it stays ``None`` and the adapter
    applies its own rule.
    """
    filled: list[str] = []
    chosen_norm = norm
    if chosen_norm is None:
        chosen_norm = MODALITY_DEFAULT_NORM.get(modality or "", "linf")
        filled.append("norm")
    if chosen_norm not in NORM_CHOICES:
        raise ValueError(f"--norm must be one of {list(NORM_CHOICES)}, got {chosen_norm!r}")
    attack_ids = tuple(str(a) for a in attacks) if attacks else ()
    if not attack_ids:
        attack_ids = NORM_DEFAULT_ATTACKS[chosen_norm]
        filled.append("attacks")
    grid = tuple(float(e) for e in eps) if eps else ()
    if not grid:
        grid = NORM_DEFAULT_GRIDS[chosen_norm]
        filled.append("eps")
    reference = reference_eps
    if reference is None and NORM_DEFAULT_REFERENCE[chosen_norm] in grid:
        reference = NORM_DEFAULT_REFERENCE[chosen_norm]
        filled.append("reference_eps")
    return AttackDefaults(norm=chosen_norm, attack_ids=attack_ids, eps_grid=grid, reference_eps=reference,
                          filled=tuple(filled))


def _target_modality(assets_dir: Path, target_id: str) -> str | None:
    """The ``modality`` the asset manifest records for ``target_id``, or ``None`` (no manifest, unknown id).

    Read from ``<assets>/MANIFEST.json`` only (import-light, no registry, no model bytes);
    the adapter resolves and refuses the target itself afterwards.
    """
    from redsim.ml.assets.manifest import MANIFEST_NAME, load_manifest, model_entry

    try:
        entry = model_entry(load_manifest(Path(assets_dir) / MANIFEST_NAME), target_id)
    except (OSError, ValueError):
        return None
    modality = getattr(entry, "modality", None)
    return str(modality) if modality else None


def _resolved_row(defaults: AttackDefaults, modality: str | None) -> dict[str, Any]:
    """What a cell actually sent after the per-norm defaults were filled (recorded per cell, never aggregated)."""
    return {
        "modality": modality, "norm": defaults.norm, "attack_ids": list(defaults.attack_ids),
        "eps_grid": list(defaults.eps_grid), "reference_eps": defaults.reference_eps, "filled": list(defaults.filled),
    }


# ---------------------------------------------------------------------------
# Matrix expansion (pure: no ML import, no I/O beyond reading the YAML file)
# ---------------------------------------------------------------------------


class MatrixError(ValueError):
    """The matrix file or the target list cannot be expanded; ``str()`` says why (a usage error)."""


@dataclass(frozen=True)
class MatrixCell:
    """One cell of the grid: the inputs of one ``OfflineCampaignRequest`` before the per-norm defaults.

    An empty ``attack_ids``, a ``None`` ``eps_grid`` or a ``None`` ``norm`` means the spec 12.3 default
    for the norm (the norm itself from the target's modality), filled by :func:`resolve_attack_defaults`
    when the cell runs.
    """

    index: int
    target_id: str
    attack_ids: tuple[str, ...]
    eps_grid: tuple[float, ...] | None
    seed: int
    norm: str | None
    reference_eps: float | None
    n_samples: int
    explain_k: int
    include_control: bool

    @property
    def label(self) -> str:
        eps = ",".join(f"{e:g}" for e in self.eps_grid) if self.eps_grid else "default"
        return f"{self.target_id} x [{','.join(self.attack_ids) or 'default'}] eps={eps} seed={self.seed}"

    def as_dict(self) -> dict[str, Any]:
        row = asdict(self)
        row["attack_ids"] = list(self.attack_ids)
        row["eps_grid"] = list(self.eps_grid) if self.eps_grid is not None else None
        return row


@dataclass
class MatrixDefaults:
    """The per-cell values the CLI flags supply for keys a matrix file omits.

    ``None`` for ``attack_ids``, ``eps_grid`` or ``norm`` is the spec 12.3 per-norm default
    (:func:`resolve_attack_defaults`; the norm from the target's modality in the asset manifest).
    """

    attack_ids: tuple[str, ...] | None = None
    eps_grid: tuple[float, ...] | None = None
    seed: int = 0
    norm: str | None = None
    reference_eps: float | None = None
    n_samples: int = 200
    explain_k: int = 8
    include_control: bool = True


@dataclass
class CellResult:
    """What one cell produced: status, ids, digests and counts (never a payload)."""

    index: int
    cell: MatrixCell
    status: str                                  # succeeded | failed | refused | error
    run_id: str | None = None
    run_dir: str | None = None
    mri: float | None = None
    grade: str | None = None
    score_state: str | None = None
    settings_hash: str | None = None
    audit_events: int = 0
    chain_verified: bool | None = None
    chain_error: str | None = None
    reason: str | None = None
    message: str | None = None
    narrative_source: str | None = None
    stages_done: list[str] = field(default_factory=list)
    wall_time_s: float | None = None
    resolved: dict[str, Any] | None = None       # norm / attacks / grid / reference actually sent, and what was filled

    @property
    def ok(self) -> bool:
        return self.status == "succeeded"

    def as_dict(self) -> dict[str, Any]:
        row = asdict(self)
        row["cell"] = self.cell.as_dict()
        row["label"] = self.cell.label
        return row


def _as_str_list(value: Any, *, key: str) -> list[str]:
    if isinstance(value, str):
        items = _csv(value)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        items = [str(v).strip() for v in value if str(v).strip()]
    else:
        raise MatrixError(f"{key} must be a list of strings, got {type(value).__name__}")
    if not items:
        raise MatrixError(f"{key} must not be empty")
    return items


def _as_float_grid(value: Any, *, key: str) -> tuple[float, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        parts = _csv(value)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        parts = list(value)
    else:
        raise MatrixError(f"{key} must be a list of numbers or null, got {type(value).__name__}")
    try:
        grid = tuple(float(p) for p in parts)
    except (TypeError, ValueError) as exc:
        raise MatrixError(f"{key} must hold numbers: {parts!r}") from exc
    if not grid:
        raise MatrixError(f"{key} must not be an empty grid (use null for the default grid)")
    return grid


def _as_int(value: Any, *, key: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        try:
            value = int(str(value))
        except (TypeError, ValueError) as exc:
            raise MatrixError(f"{key} must be an integer, got {value!r}") from exc
    if not lo <= value <= hi:
        raise MatrixError(f"{key} must lie in [{lo}, {hi}] (CampaignConfig), got {value}")
    return int(value)


def load_matrix_file(path: str | Path) -> dict[str, Any]:
    """Read and shape-check a ``--matrix`` YAML document (top-level mapping, known keys only)."""
    import yaml

    file_path = Path(path)
    if not file_path.is_file():
        raise MatrixError(f"matrix file not found: {file_path}")
    try:
        document = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise MatrixError(f"matrix file {file_path} is not valid YAML: {exc}") from exc
    if isinstance(document, dict) and isinstance(document.get("matrix"), dict) and len(document) == 1:
        document = document["matrix"]          # a top-level ``matrix:`` wrapper is accepted
    if not isinstance(document, dict):
        raise MatrixError(f"matrix file {file_path} must hold a mapping at the top level")
    unknown = sorted(set(map(str, document)) - MATRIX_KEYS)
    if unknown:
        raise MatrixError(f"matrix file {file_path} has unknown keys {unknown}; allowed: {sorted(MATRIX_KEYS)}")
    return {str(k): v for k, v in document.items()}


def expand_matrix(document: Mapping[str, Any], defaults: MatrixDefaults | None = None) -> list[MatrixCell]:
    """``models x attack_sets x eps_grids x seeds`` in that nesting order; the file's scalars win over ``defaults``."""
    base = defaults or MatrixDefaults()
    unknown = sorted(set(map(str, document)) - MATRIX_KEYS)
    if unknown:
        raise MatrixError(f"unknown matrix keys {unknown}; allowed: {sorted(MATRIX_KEYS)}")
    if "models" not in document:
        raise MatrixError("matrix needs a non-empty 'models' list of bundled target ids")
    models = _as_str_list(document["models"], key="models")
    raw_sets = document.get("attack_sets")
    if raw_sets is None:
        attack_sets: list[tuple[str, ...]] = [tuple(base.attack_ids) if base.attack_ids else ()]
    else:
        if isinstance(raw_sets, str):
            raw_sets = [raw_sets]
        if not isinstance(raw_sets, Sequence) or not raw_sets:
            raise MatrixError("attack_sets must be a non-empty list; each entry is one campaign's attack list")
        attack_sets = [tuple(_as_str_list(entry, key=f"attack_sets[{i}]")) for i, entry in enumerate(raw_sets)]
    raw_grids = document.get("eps_grids")
    if raw_grids is None:
        eps_grids: list[tuple[float, ...] | None] = [base.eps_grid]
    else:
        if not isinstance(raw_grids, Sequence) or isinstance(raw_grids, str) or not raw_grids:
            raise MatrixError("eps_grids must be a non-empty list; each entry is one grid or null")
        eps_grids = [_as_float_grid(entry, key=f"eps_grids[{i}]") for i, entry in enumerate(raw_grids)]
    raw_seeds = document.get("seeds")
    if raw_seeds is None:
        seeds = [int(base.seed)]
    else:
        if isinstance(raw_seeds, (int, str)) and not isinstance(raw_seeds, bool):
            raw_seeds = [raw_seeds]
        if not isinstance(raw_seeds, Sequence) or not raw_seeds:
            raise MatrixError("seeds must be a non-empty list of integers")
        seeds = [_as_int(s, key=f"seeds[{i}]", lo=0, hi=2**31 - 1) for i, s in enumerate(raw_seeds)]
    norm_raw = document.get("norm", base.norm)
    norm = None if norm_raw is None else str(norm_raw)
    if norm is not None and norm not in NORM_CHOICES:
        raise MatrixError(f"norm must be one of {list(NORM_CHOICES)} (null: the target's modality norm), got {norm!r}")
    reference_raw = document.get("reference_eps", base.reference_eps)
    try:
        reference_eps = None if reference_raw is None else float(reference_raw)
    except (TypeError, ValueError) as exc:
        raise MatrixError(f"reference_eps must be a number or null, got {reference_raw!r}") from exc
    n_samples = _as_int(document.get("n_samples", base.n_samples), key="n_samples", lo=10, hi=1000)
    explain_k = _as_int(document.get("explain_k", base.explain_k), key="explain_k", lo=0, hi=32)
    include_raw = document.get("include_control", base.include_control)
    if not isinstance(include_raw, bool):
        raise MatrixError(f"include_control must be true or false, got {include_raw!r}")
    cells: list[MatrixCell] = []
    for index, (model, attacks, grid, seed) in enumerate(product(models, attack_sets, eps_grids, seeds)):
        cells.append(MatrixCell(
            index=index, target_id=model, attack_ids=attacks, eps_grid=grid, seed=seed, norm=norm,
            reference_eps=reference_eps, n_samples=n_samples, explain_k=explain_k, include_control=include_raw,
        ))
    return cells


def cells_from_targets(target_ids: Sequence[str], defaults: MatrixDefaults) -> list[MatrixCell]:
    """One cell per target id with the CLI flags as the shared settings (duplicates collapse, order kept)."""
    ids = [t for t in dict.fromkeys(str(t).strip() for t in target_ids) if t]
    if not ids:
        raise MatrixError("at least one target id (or --matrix FILE) is required")
    return [
        MatrixCell(index=i, target_id=tid, attack_ids=tuple(defaults.attack_ids or ()), eps_grid=defaults.eps_grid,
                   seed=defaults.seed, norm=defaults.norm, reference_eps=defaults.reference_eps,
                   n_samples=defaults.n_samples, explain_k=defaults.explain_k,
                   include_control=defaults.include_control)
        for i, tid in enumerate(ids)
    ]


def _fmt(value: Any, width: int) -> str:
    text = "-" if value is None else (f"{value:.3f}" if isinstance(value, float) else str(value))
    return text[:width].ljust(width)


def format_summary_table(results: Sequence[CellResult]) -> str:
    """The per-cell summary: one row per cell, no mean, no rank, no cross-cell aggregate."""
    columns = (("#", 4), ("target", 16), ("attacks", 18), ("eps", 16), ("seed", 5), ("status", 10),
               ("MRI", 7), ("grade", 6), ("run_id", 17), ("events", 7), ("chain", 9))
    header = " ".join(name.ljust(width) for name, width in columns)
    lines = [header, "-" * len(header)]
    for r in results:
        sent = r.resolved or {}
        attacks = ",".join(sent.get("attack_ids") or r.cell.attack_ids) or "default"
        grid = sent.get("eps_grid") or r.cell.eps_grid
        eps = ",".join(f"{e:g}" for e in grid) if grid else "default"
        chain = "-" if r.chain_verified is None else ("verified" if r.chain_verified else "BROKEN")
        values = (r.index, r.cell.target_id, attacks, eps, r.cell.seed, r.status,
                  r.mri, r.grade, r.run_id, r.audit_events if r.run_id else None, chain)
        lines.append(" ".join(_fmt(v, w) for v, (_n, w) in zip(values, columns, strict=True)).rstrip())
    n_ok = sum(1 for r in results if r.ok)
    lines.append(f"{len(results)} cell(s): {n_ok} succeeded, "
                 f"{sum(1 for r in results if r.status == 'refused')} refused, "
                 f"{sum(1 for r in results if r.status in {'failed', 'error'})} failed; "
                 "one run_record.json and one audit chain per cell, nothing aggregated across cells")
    return "\n".join(lines)


def _verify_cell_chain(audit_path: Path) -> tuple[bool | None, str | None, int]:
    """Walk the cell's ``audit.jsonl`` with ``verify_chain``; ``(verified, error, n_events)``."""
    from redsim.audit.chain import verify_chain

    try:
        lines = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        outcome = verify_chain(iter(lines))
    except Exception as exc:  # noqa: BLE001 - a chain that cannot be read is reported, never hidden
        return None, f"{type(exc).__name__}: {exc}", 0
    return bool(outcome.verified), (None if outcome.verified else str(getattr(outcome, "error", "broken"))), len(lines)


def run_cell(cell: MatrixCell, *, out_dir: Path, assets_dir: Path, allowlist: list[str], actor: str,
             log: Any = None) -> CellResult:
    """Run one cell through ``run_offline_campaign`` and verify its chain; never raises for a cell outcome."""
    from redsim.ml.campaign_adapter import (
        OfflineCampaignRefused,
        OfflineCampaignRequest,
        run_offline_campaign,
    )
    from redsim.ml.errors import MLError

    modality = _target_modality(assets_dir, cell.target_id)
    try:
        defaults = resolve_attack_defaults(
            modality=modality, norm=cell.norm, attacks=cell.attack_ids, eps=cell.eps_grid,
            reference_eps=cell.reference_eps,
        )
    except ValueError as exc:
        return CellResult(index=cell.index, cell=cell, status="refused", reason="invalid_norm", message=str(exc))
    resolved = _resolved_row(defaults, modality)
    request = OfflineCampaignRequest(
        target_id=cell.target_id, attack_ids=defaults.attack_ids, eps_grid=defaults.eps_grid,
        reference_eps=defaults.reference_eps, n_samples=cell.n_samples, seed=cell.seed, explain_k=cell.explain_k,
        include_control=cell.include_control, norm=defaults.norm, actor=actor,
    )
    started = datetime.now(UTC)
    try:
        outcome = run_offline_campaign(request, out_dir=out_dir, assets_dir=assets_dir, allowlist=allowlist, log=log)
    except OfflineCampaignRefused as exc:
        return CellResult(index=cell.index, cell=cell, status="refused", reason=exc.reason, message=exc.message,
                          wall_time_s=(datetime.now(UTC) - started).total_seconds(), resolved=resolved)
    except MLError as exc:
        return CellResult(index=cell.index, cell=cell, status="error", reason=type(exc).__name__, message=str(exc),
                          wall_time_s=(datetime.now(UTC) - started).total_seconds(), resolved=resolved)
    record = outcome.record
    verified, chain_error, n_events = _verify_cell_chain(outcome.audit_path)
    score = record.score
    return CellResult(
        index=cell.index, cell=cell, status=str(record.status), run_id=outcome.run_id, run_dir=str(outcome.run_dir),
        mri=(float(score.mri) if score is not None and score.mri is not None else None),
        grade=(str(score.grade) if score is not None and score.mri is not None else None),
        score_state=(record.score_status.state if record.score_status is not None else
                     ("complete" if score is not None and score.mri is not None else None)),
        settings_hash=record.settings_hash, audit_events=n_events or outcome.audit_events,
        chain_verified=verified, chain_error=chain_error, reason=None if record.status == "succeeded" else "failed",
        message=record.error, narrative_source=outcome.narrative_source, stages_done=list(record.stages_done),
        wall_time_s=(datetime.now(UTC) - started).total_seconds(), resolved=resolved,
    )


def write_summary(results: Sequence[CellResult], *, out_dir: Path, matrix_id: str, source: dict[str, Any]) -> Path:
    """``<out>/matrix-<id>/summary.json``: the cells, their outcomes and where each chain lives."""
    summary_dir = out_dir / f"matrix-{matrix_id}"
    summary_dir.mkdir(parents=True, exist_ok=True)
    path = summary_dir / "summary.json"
    document = {
        "matrix_id": matrix_id, "generated_at": datetime.now(UTC).isoformat(), "source": source,
        "n_cells": len(results), "n_succeeded": sum(1 for r in results if r.ok),
        "n_refused": sum(1 for r in results if r.status == "refused"),
        "n_failed": sum(1 for r in results if r.status in {"failed", "error"}),
        "note": "one offline run and one hash-chained audit.jsonl per cell; no value here is aggregated "
                "across cells (verify each with redsim audit verify --run-dir <run_dir>)",
        "cells": [r.as_dict() for r in results],
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _matrix_defaults(args: argparse.Namespace) -> MatrixDefaults:
    attacks = _csv(getattr(args, "attacks", None))
    eps = _csv_floats(getattr(args, "eps", None), flag="--eps")
    norm_flag = getattr(args, "norm", None)
    n_samples = int(args.n_samples)
    if not 10 <= n_samples <= 1000:
        _console._err(f"--n-samples must lie in [10, 1000] (CampaignConfig), got {n_samples}")
        sys.exit(EXIT_USAGE)
    explain_k = int(args.explain_k)
    if not 0 <= explain_k <= 32:
        _console._err(f"--explain-k must lie in [0, 32] (CampaignConfig), got {explain_k}")
        sys.exit(EXIT_USAGE)
    return MatrixDefaults(
        attack_ids=tuple(attacks) if attacks else None, eps_grid=tuple(eps) if eps else None, seed=int(args.seed),
        norm=(str(norm_flag) if norm_flag else None), reference_eps=getattr(args, "reference_eps", None),
        n_samples=n_samples, explain_k=explain_k, include_control=not bool(getattr(args, "no_control", False)),
    )


def resolve_cells(args: argparse.Namespace) -> tuple[list[MatrixCell], dict[str, Any]]:
    """The cells a ``redsim ml attack`` invocation asks for, and a description of where they came from."""
    defaults = _matrix_defaults(args)
    target_ids = [t for t in [getattr(args, "target_id", None), *(getattr(args, "targets", None) or [])] if t]
    matrix_path = getattr(args, "matrix", None)
    if matrix_path:
        document = load_matrix_file(matrix_path)
        cells = expand_matrix(document, defaults)
        if target_ids:
            # Positional ids add models to the file's list (the file's own attack sets, grids and seeds apply).
            extra = expand_matrix({**document, "models": target_ids}, defaults)
            offset = len(cells)
            cells.extend(MatrixCell(**{**asdict(c), "index": offset + i}) for i, c in enumerate(extra))
        source: dict[str, Any] = {"matrix_file": str(Path(matrix_path)), "name": document.get("name"),
                                  "extra_targets": target_ids}
        return cells, source
    return cells_from_targets(target_ids, defaults), {"targets": target_ids}


def cmd_ml_attack(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Run offline campaigns: one target as before, or several targets / a matrix with one chain per cell."""
    from redsim.ml.campaign_adapter import resolve_assets_dir
    from redsim.plugins import load_ml_attack_plugins

    try:
        cells, source = resolve_cells(args)
    except MatrixError as exc:
        _console._err(str(exc))
        sys.exit(EXIT_USAGE)
    actor = str(getattr(args, "actor", None) or DEFAULT_ACTOR)
    out_dir = _output_dir(args, config)
    assets_dir = resolve_assets_dir(getattr(args, "assets_dir", None))
    allowlist = list(getattr(config, "target_allowlist", None) or [])
    # Opt-in third-party attack adapters (REDSIM_PLUGINS=1) join the registry before resolution.
    plugin_rows = list(load_ml_attack_plugins())

    if len(cells) == 1 and not getattr(args, "matrix", None):
        _run_single(cells[0], actor=actor, out_dir=out_dir, assets_dir=assets_dir, allowlist=allowlist,
                    plugin_rows=plugin_rows)
        return

    matrix_id = uuid4().hex[:8]
    _console._info(f"offline matrix {matrix_id}: {len(cells)} cell(s) from {source} assets={assets_dir} out={out_dir}")
    _console._info("no network, no Pythia: llm_narrative=false, narrative_source stays 'rules'; one run and one "
                   "audit chain per cell")
    for row in plugin_rows:
        _console._info(f"attack plugin {row.name}: {row.status}{(' (' + row.detail + ')') if row.detail else ''}")
    results: list[CellResult] = []
    fail_fast = bool(getattr(args, "fail_fast", False))
    for cell in cells:
        _console._info(f"cell {cell.index}: {cell.label}")
        result = run_cell(cell, out_dir=out_dir, assets_dir=assets_dir, allowlist=allowlist, actor=actor,
                          log=_console._info)
        results.append(result)
        if result.ok:
            _console._info(f"cell {cell.index}: run {result.run_id} succeeded; chain "
                           f"{'verified' if result.chain_verified else 'NOT verified'} ({result.audit_events} events)")
        else:
            _console._err(f"cell {cell.index}: {result.status} ({result.reason}): {result.message or ''}".rstrip())
            if fail_fast:
                _console._warn(f"--fail-fast: stopping after cell {cell.index}; "
                               f"{len(cells) - len(results)} cell(s) not run")
                break
    print(format_summary_table(results))
    summary_path = write_summary(results, out_dir=out_dir, matrix_id=matrix_id,
                                 source={**source, "n_cells_planned": len(cells), "fail_fast": fail_fast})
    print(f"    {'summary':<16} {summary_path}")
    for result in results:
        if result.run_id:
            print(f"    {'audit chain':<16} {Path(result.run_dir or '') / 'audit.jsonl'} "
                  f"({result.audit_events} events, chain run:{result.run_id})")
    _console._info("verify a cell: redsim audit verify --run-dir <run_dir> (each chain stands alone)")
    if any(not r.ok for r in results) or len(results) < len(cells):
        sys.exit(EXIT_REFUSED)


def _run_single(cell: MatrixCell, *, actor: str, out_dir: Path, assets_dir: Path, allowlist: list[str],
                plugin_rows: list[Any]) -> None:
    """The one-target path: the wave 3 output plus the spec 12.3 per-norm defaults (wave B2)."""
    from redsim.ml.campaign_adapter import (
        OfflineCampaignRefused,
        OfflineCampaignRequest,
        run_offline_campaign,
    )
    from redsim.ml.errors import MLError

    modality = _target_modality(assets_dir, cell.target_id)
    try:
        defaults = resolve_attack_defaults(
            modality=modality, norm=cell.norm, attacks=cell.attack_ids, eps=cell.eps_grid,
            reference_eps=cell.reference_eps,
        )
    except ValueError as exc:
        _console._err(str(exc))
        sys.exit(EXIT_USAGE)
    request = OfflineCampaignRequest(
        target_id=cell.target_id, attack_ids=defaults.attack_ids, eps_grid=defaults.eps_grid,
        reference_eps=defaults.reference_eps, n_samples=cell.n_samples, seed=cell.seed, explain_k=cell.explain_k,
        include_control=cell.include_control, norm=defaults.norm, actor=actor,
    )
    _console._info(f"offline campaign: target={request.target_id} modality={modality or 'not in the manifest'} "
                   f"norm={request.norm} attacks={list(request.attack_ids)} eps={list(defaults.eps_grid)} "
                   f"reference={defaults.reference_eps if defaults.reference_eps is not None else 'adapter default'} "
                   f"(defaults filled: {', '.join(defaults.filled) or 'none'}) assets={assets_dir} out={out_dir}")
    _console._info("no network, no Pythia: llm_narrative=false, narrative_source stays 'rules'")
    for row in plugin_rows:
        _console._info(f"attack plugin {row.name}: {row.status}{(' (' + row.detail + ')') if row.detail else ''}")
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
