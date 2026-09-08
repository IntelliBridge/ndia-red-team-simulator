"""`redsim ml` — adversarial-ML vertical commands.

``redsim ml build-assets`` is the M0 skeleton of the asset builder that will
train and export the bundled sample models and datasets (spec sections 11
and 20). It does no work yet: it reports that the step is not implemented
and returns. Nothing is fetched, trained or written, and no manifest is
produced, so no later step can mistake this stub for a seeded catalog.
"""

from __future__ import annotations

import argparse
import sys

from redsim.cli import _console
from redsim.config import RedsimConfig

BUILD_ASSETS_STATUS = "not_implemented"
BUILD_ASSETS_REASON = (
    "redsim ml build-assets is a scaffold (milestone M0). The asset builder lands with "
    "the image target in M1 and the tabular target in M4. No models or datasets were "
    "fetched, trained or written."
)


def add_ml_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``redsim ml ...`` on the top-level subparser collection."""
    p_ml = sub.add_parser("ml", help="Adversarial-ML vertical commands")
    ml_sub = p_ml.add_subparsers(dest="ml_action", required=True)
    p_build = ml_sub.add_parser(
        "build-assets",
        help="Build the bundled sample models and datasets (skeleton, not implemented yet)",
    )
    p_build.add_argument("--out", default=None,
                         help="Asset output directory (default: REDSIM_ML_DATASET_CACHE)")
    p_build.add_argument("--only", action="append", default=None,
                         help="Build only the named asset id (repeatable)")


def cmd_ml_build_assets(args: argparse.Namespace, _config: RedsimConfig) -> None:
    """Skeleton: state that the builder is not implemented and return cleanly."""
    _console._warn(f"build-assets: {BUILD_ASSETS_STATUS}")
    _console._info(BUILD_ASSETS_REASON)
    if getattr(args, "only", None):
        _console._info(f"requested assets (not built): {', '.join(args.only)}")


def cmd_ml(args: argparse.Namespace, config: RedsimConfig) -> None:
    if args.ml_action == "build-assets":
        cmd_ml_build_assets(args, config)
    else:
        _console._err(f"Unknown ml action: {args.ml_action}")
        sys.exit(2)
