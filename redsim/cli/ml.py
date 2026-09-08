"""``redsim ml`` subcommands: the bundled-asset build (spec 11, 20.1 step 3).

``add_ml_subparser``, ``cmd_ml`` and ``cmd_ml_build_assets`` are the entry
points ``redsim.cli.main`` wires. P0 shipped them as a skeleton that reported
``not_implemented``; the M1 / M4 builder now sits behind the same names, so
``BUILD_ASSETS_STATUS`` reads ``implemented`` and the reason is empty.

Building the parser imports nothing from the ``ml`` extra. torch,
scikit-learn and httpx load inside the handler, so the rest of the CLI never
pays for them and a test can assert the parser stays light.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from redsim.cli import _console
from redsim.ml.assets import ASSET_IDS, DATASET_CHOICES

if TYPE_CHECKING:
    from redsim.config import RedsimConfig

BUILD_ASSETS_STATUS = "implemented"
BUILD_ASSETS_REASON = ""

# Spec 20.3: the dataset cache shared by build-assets and the loaders. ``--cache-dir`` wins over it.
DATASET_CACHE_ENV = "REDSIM_ML_DATASET_CACHE"


def add_ml_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``redsim ml ...`` on the top-level subparser collection."""
    p_ml = sub.add_parser("ml", help="Adversarial-ML vertical: build the bundled datasets and models")
    ml_sub = p_ml.add_subparsers(dest="ml_action", required=True)

    p_build = ml_sub.add_parser(
        "build-assets",
        help="Fetch the open datasets of spec section 11, train the bundled models on CPU, write assets/MANIFEST.json",
        description=(
            "Fetch each dataset by pinned revision (HuggingFace hub via its API and resolve URLs; the Kaggle "
            "malicious-URLs file with KAGGLE_API_TOKEN read from the environment or a .env file (REDSIM_ENV_FILE), "
            "or the older KAGGLE_USERNAME / KAGGLE_KEY pair, else the committed CI sample), train the "
            "bundled SmallCNN and URL classifier with a fixed seed on CPU, and record dataset ids, revisions, "
            "splits, weight sha256s, clean metrics and library versions in <out>/MANIFEST.json. Each model entry "
            "is a redsim.ml.schema.MLModelManifest plus the build record. Network access happens only here, "
            "never in the worker or the tests."
        ),
    )
    p_build.add_argument("--dataset", choices=DATASET_CHOICES, default="all",
                         help="Which asset to build: image (vehicle CNN), tabular (URL classifier), cifar10 "
                              "(CI fixture CNN), or all (default)")
    p_build.add_argument("--only", action="append", choices=sorted(ASSET_IDS), default=None, metavar="MODEL_ID",
                         help="Build only the named bundled model (repeatable; one of %(choices)s). "
                              "Overrides --dataset")
    p_build.add_argument("--epochs", type=int, default=3, help="CNN training epochs (default: 3)")
    p_build.add_argument("--out", default="assets",
                         help="Assets root; MANIFEST.json is written here (default: assets/)")
    p_build.add_argument("--cache-dir", dest="cache_dir", default=None,
                         help=f"Dataset download cache (default: ${DATASET_CACHE_ENV} when set, else <out>/cache)")
    p_build.add_argument("--seed", type=int, default=0, help="Training and split seed (default: 0)")
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
    p_build.add_argument("--no-xgboost", dest="prefer_xgboost", action="store_false",
                         help="Use scikit-learn HistGradientBoosting even when xgboost is installed")


def cmd_ml_build_assets(args: argparse.Namespace, _config: RedsimConfig) -> None:
    """Run the asset build. Heavy imports live here so the parser stays light."""
    import httpx

    from redsim.ml.assets.build import BuildOptions, build_assets, summarize
    from redsim.ml.assets.datasets import DatasetUnavailable

    cache_env = os.environ.get(DATASET_CACHE_ENV, "").strip()
    cache_dir = Path(args.cache_dir) if args.cache_dir else (Path(cache_env) if cache_env else None)
    try:
        opts = BuildOptions(
            dataset=args.dataset, only=tuple(args.only or ()), epochs=args.epochs, out=args.out,
            cache_dir=cache_dir, seed=args.seed, image_size=args.image_size, image_repo=args.image_repo,
            image_revision=args.image_revision, cifar10_revision=args.cifar10_revision,
            max_train=args.max_train, max_eval=args.max_eval, workers=args.workers,
            prefer_xgboost=args.prefer_xgboost,
        )
    except ValueError as exc:
        _console._err(str(exc))
        sys.exit(2)
    what = ", ".join(opts.only) if opts.only else f"{opts.dataset} asset(s)"
    _console._info(f"building {what} into {opts.out} (epochs={opts.epochs}, seed={opts.seed}, "
                   f"cache={opts.cache_dir})")
    try:
        manifest = build_assets(opts, log=_console._info, warn=_console._warn)
    except (DatasetUnavailable, httpx.HTTPError) as exc:
        _console._err(f"asset build failed: {exc}")
        sys.exit(1)
    print(summarize(manifest))


def cmd_ml(args: argparse.Namespace, config: RedsimConfig) -> None:
    if args.ml_action == "build-assets":
        cmd_ml_build_assets(args, config)
    else:
        _console._err(f"Unknown ml action: {args.ml_action}")
        sys.exit(2)
