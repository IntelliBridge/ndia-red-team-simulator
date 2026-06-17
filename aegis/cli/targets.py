"""`aegis targets` — manages vulnerable-target containers (list / up / down)."""

from __future__ import annotations

import argparse
import sys

from aegis.cli import _console
from aegis.config import AegisConfig


def cmd_targets(args: argparse.Namespace, config: AegisConfig) -> None:
    """Manage vulnerable-target containers (list / up / down)."""
    from aegis.safety import authorize
    from aegis.state import RunState
    from aegis.targets import get_target_pack, list_target_packs

    action = args.targets_action
    if action == "list":
        for name in list_target_packs():
            print(name)
        return

    pack_name = args.target_pack
    if action == "up":
        state = RunState(config.output_dir) if args.run is None else RunState(config.output_dir, args.run)
        pack = get_target_pack(pack_name, run_path=state.run_path, port=args.port)
        authorize(
            "target.start", pack.runtime.url,
            allowlist=config.target_allowlist, run_path=state.run_path,
            override_authorized=getattr(args, "override_authorized", False),
            detail={"pack": pack_name, "repo": args.repo, "port": args.port},
        )
        if args.repo:
            _console._info(f"Building {pack_name} from {args.repo} and starting on {pack.runtime.url}")
            runtime = pack.up_from_repo(args.repo)
        else:
            _console._info(f"Starting {pack_name} from pinned image on {pack.runtime.url}")
            runtime = pack.up(image_tag=getattr(config, "juice_shop_image_tag", None)
                              if pack_name == "juice-shop" else None)
        ready = pack.wait_ready(timeout=args.timeout)
        _console._info(f"Container ready: {ready} ({runtime.url})")
        return

    if action == "down":
        state = RunState(config.output_dir) if args.run is None else RunState(config.output_dir, args.run)
        pack = get_target_pack(pack_name, run_path=state.run_path)
        authorize(
            "target.down", pack.runtime.url,
            allowlist=config.target_allowlist, run_path=state.run_path,
            detail={"pack": pack_name, "container_name": pack.container_name},
        )
        pack.down()
        _console._info(f"Stopped {pack.container_name}")
        return

    _console._err(f"Unknown targets action: {action}")
    sys.exit(1)
