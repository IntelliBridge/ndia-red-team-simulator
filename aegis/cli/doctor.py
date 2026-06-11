"""`aegis doctor` — validates the Aegis development environment."""

from __future__ import annotations

import sys

_CYAN = "\033[36m"
_YELLOW = "\033[33m"
_RESET = "\033[0m"


def _report_offline_vendor(config) -> None:
    """Surface the air-gapped submodule mirror, if one is configured.

    When ``offline_vendor_host`` is set we print the mirror host plus the
    rewritten URL for each submodule so an operator can confirm the mapping
    before running ``scripts/vendor-submodules.sh``. When unset we leave a
    single-line note pointing at the env var.
    """
    from pathlib import Path

    host = getattr(config, "offline_vendor_host", None)
    print()
    if not host:
        print(f"  {_YELLOW}~{_RESET} Offline vendor mirror: not set "
              f"(set AEGIS_OFFLINE_VENDOR_HOST for air-gapped submodule fetches)")
        return

    from aegis.vendor import submodule_mirror_map

    print(f"  {_CYAN}>{_RESET} Offline vendor mirror: {host}")
    gitmodules = Path(".gitmodules")
    if not gitmodules.exists():
        print(f"    {_YELLOW}~{_RESET} no .gitmodules found in {Path.cwd()}")
        return
    mapping = submodule_mirror_map(gitmodules.read_text(), host)
    if not mapping:
        print(f"    {_YELLOW}~{_RESET} .gitmodules declares no submodule URLs")
        return
    for original, mirrored in mapping.items():
        print(f"    {original} -> {mirrored}")


def cmd_doctor(args, config) -> None:
    """Validate the Aegis development environment."""
    from aegis.doctor import run_doctor

    ok = run_doctor(config, api_mode=getattr(args, "api_mode", False))
    _report_offline_vendor(config)
    sys.exit(0 if ok else 1)
