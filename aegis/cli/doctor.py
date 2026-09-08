"""`aegis doctor` — validates the Aegis development environment."""

from __future__ import annotations

import argparse
import sys

from aegis.config import AegisConfig

_CYAN = "\033[36m"
_YELLOW = "\033[33m"
_RESET = "\033[0m"


def _report_offline_vendor(config: AegisConfig) -> None:
    """Surface the air-gapped mirror host, if one is configured.

    When ``offline_vendor_host`` is set we print the mirror host. When unset we
    leave a single-line note pointing at the env var. The pentest submodule
    URL-rewrite helper (``aegis.vendor``) was removed with the pentest domain,
    so this no longer rewrites ``.gitmodules`` URLs — there are no vendored
    submodules to mirror in the ML red-team fork.
    """
    host = getattr(config, "offline_vendor_host", None)
    print()
    if not host:
        print(f"  {_YELLOW}~{_RESET} Offline vendor mirror: not set "
              f"(set AEGIS_OFFLINE_VENDOR_HOST for an air-gapped package mirror)")
        return

    print(f"  {_CYAN}>{_RESET} Offline vendor mirror: {host}")



def cmd_doctor(args: argparse.Namespace, config: AegisConfig) -> None:
    """Validate the Aegis development environment."""
    from aegis.doctor import run_doctor

    ok = run_doctor(config, api_mode=getattr(args, "api_mode", False))
    _report_offline_vendor(config)
    sys.exit(0 if ok else 1)
