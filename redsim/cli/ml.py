"""``redsim ml`` subcommands: the bundled-asset build (spec 11, 20.1 step 3).

The parser is registered from ``redsim.cli.main``; everything heavy (torch,
scikit-learn, httpx) is imported inside the handler so building the parser
and running the rest of the CLI never load the ml extra.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, Any

from redsim.cli import _console

if TYPE_CHECKING:
    from redsim.config import RedsimConfig

DATASET_CHOICES = ("image", "tabular", "cifar10", "all")


def add_ml_subparser(sub: Any) -> None:
    p_ml = sub.add_parser("ml", help="Adversarial-ML vertical: build the bundled datasets and models")
    ml_sub = p_ml.add_subparsers(dest="ml_action", required=True)

    p_build = ml_sub.add_parser(
        "build-assets",
        help="Fetch the open datasets of spec section 11, train the bundled models on CPU, write assets/MANIFEST.json",
        description=(
            "Fetch each dataset by pinned revision (HuggingFace hub via its API and resolve URLs; the Kaggle "
            "malicious-URLs file with KAGGLE_USERNAME / KAGGLE_KEY, else the committed CI sample), train the "
            "bundled SmallCNN and URL classifier with a fixed seed on CPU, and record dataset ids, revisions, "
            "splits, weight sha256s, clean metrics and library versions in <out>/MANIFEST.json. Network access "
            "happens only here, never in the worker or the tests."
        ),
    )
    p_build.add_argument("--dataset", choices=DATASET_CHOICES, default="all",
                         help="Which asset to build: image (vehicle CNN), tabular (URL classifier), cifar10 "
                              "(CI fixture CNN), or all (default)")
    p_build.add_argument("--epochs", type=int, default=3, help="CNN training epochs (default: 3)")
    p_build.add_argument("--out", default="assets", help="Assets root; MANIFEST.json is written here (default: assets/)")
    p_build.add_argument("--cache-dir", dest="cache_dir", default=None,
                         help="Dataset download cache (default: <out>/cache)")
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


def cmd_ml(args: argparse.Namespace, config: RedsimConfig) -> None:
    if args.ml_action == "build-assets":
        _cmd_build_assets(args)
    else:
        _console._err(f"Unknown ml action: {args.ml_action}")
        sys.exit(2)


def _cmd_build_assets(args: argparse.Namespace) -> None:
    import httpx

    from redsim.ml.assets.build import BuildOptions, build_assets, summarize
    from redsim.ml.assets.datasets import DatasetUnavailable

    try:
        opts = BuildOptions(
            dataset=args.dataset, epochs=args.epochs, out=args.out, cache_dir=args.cache_dir, seed=args.seed,
            image_size=args.image_size, image_repo=args.image_repo, image_revision=args.image_revision,
            cifar10_revision=args.cifar10_revision, max_train=args.max_train, max_eval=args.max_eval,
            workers=args.workers, prefer_xgboost=args.prefer_xgboost,
        )
    except ValueError as exc:
        _console._err(str(exc))
        sys.exit(2)
    _console._info(f"building {opts.dataset} asset(s) into {opts.out} (epochs={opts.epochs}, seed={opts.seed})")
    try:
        manifest = build_assets(opts, log=_console._info, warn=_console._warn)
    except (DatasetUnavailable, httpx.HTTPError) as exc:
        _console._err(f"asset build failed: {exc}")
        sys.exit(1)
    print(summarize(manifest))
