"""`aegis doctor` — validates the Aegis development environment."""

from __future__ import annotations

import argparse
import sys

from aegis.config import AegisConfig


def cmd_doctor(args: argparse.Namespace, config: AegisConfig) -> None:
    """Validate the Aegis development environment."""
    from aegis.doctor import run_doctor

    ok = run_doctor(config, api_mode=getattr(args, "api_mode", False))
    sys.exit(0 if ok else 1)
