"""`redsim doctor` — validates the Redsim development environment."""

from __future__ import annotations

import argparse
import os
import sys

from redsim.config import RedsimConfig

_CYAN = "\033[36m"
_YELLOW = "\033[33m"
_RESET = "\033[0m"

#: Env fallback for worker mode until the parser grows ``--worker-mode``
#: (``redsim/cli/main.py`` owns the ``doctor`` subparser). The worker image can
#: set it once so ``redsim doctor`` there treats the ML checks as required.
WORKER_MODE_ENV = "REDSIM_DOCTOR_WORKER_MODE"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def _report_offline_vendor(config: RedsimConfig) -> None:
    """Surface the air-gapped mirror host, if one is configured.

    When ``offline_vendor_host`` is set we print the mirror host. When unset we
    leave a single-line note pointing at the env var. The pentest submodule
    URL-rewrite helper (``redsim.vendor``) was removed with the pentest domain,
    so this no longer rewrites ``.gitmodules`` URLs — there are no vendored
    submodules to mirror in the ML red-team fork.
    """
    host = getattr(config, "offline_vendor_host", None)
    print()
    if not host:
        print(f"  {_YELLOW}~{_RESET} Offline vendor mirror: not set "
              f"(set REDSIM_OFFLINE_VENDOR_HOST for an air-gapped package mirror)")
        return

    print(f"  {_CYAN}>{_RESET} Offline vendor mirror: {host}")


def worker_mode_requested(args: argparse.Namespace) -> bool:
    """``--worker-mode`` when the parser provides it, else ``REDSIM_DOCTOR_WORKER_MODE``.

    In worker mode the adversarial-ML checks (``ml`` extra, sandbox child, asset
    manifest) are required rather than informational — the worker image is the
    only process that loads models (spec 8.4, 20.2).
    """
    if getattr(args, "worker_mode", False):
        return True
    return os.environ.get(WORKER_MODE_ENV, "").strip().lower() in _TRUE_VALUES


def cmd_doctor(args: argparse.Namespace, config: RedsimConfig) -> None:
    """Validate the Redsim development environment."""
    from redsim.doctor import run_doctor

    ok = run_doctor(
        config,
        api_mode=bool(getattr(args, "api_mode", False)),
        worker_mode=worker_mode_requested(args),
    )
    _report_offline_vendor(config)
    sys.exit(0 if ok else 1)
