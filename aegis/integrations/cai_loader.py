"""Centralized loader for the CAI library.

The Phase 2 ``aegis.remediate.cai_runner`` module mutated ``sys.path`` inside
each function that needed CAI. That's duplicated and obscures the
``cai_path`` dependency. This loader does it once, in one place, returning
a small bundle the rest of the code uses.

The loader is intentionally tolerant: when CAI isn't importable (e.g. the
submodule isn't initialised, or a test environment forces it off), it
returns ``None`` rather than raising — callers decide whether that's a hard
failure or a soft fallback.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CAIBundle:
    """Pointers to the CAI primitives a service / worker needs."""
    Runner: Any
    codeagent: Any
    blueteam_agent: Any
    cai_version: str | None
    cai_path: Path


_BUNDLE: CAIBundle | None = None


def _git_sha(repo: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True, timeout=5,
        )
        return result.stdout.strip()
    except Exception:
        return None


def load_cai(config, *, force_reload: bool = False) -> CAIBundle | None:
    """Inject ``<config.cai_path>/src`` onto sys.path once and import CAI.

    Returns the bundle, or ``None`` when CAI can't be imported (caller
    decides how to fall back).
    """
    global _BUNDLE
    if _BUNDLE is not None and not force_reload:
        return _BUNDLE

    cai_path = Path(config.cai_path).resolve()
    cai_src = cai_path / "src"
    if cai_src.is_dir() and str(cai_src) not in sys.path:
        sys.path.insert(0, str(cai_src))

    try:
        from cai.agents.codeagent import codeagent  # type: ignore
        from cai.agents.blue_teamer import blueteam_agent  # type: ignore
        from cai.sdk.agents import Runner  # type: ignore
    except ImportError:
        return None

    _BUNDLE = CAIBundle(
        Runner=Runner,
        codeagent=codeagent,
        blueteam_agent=blueteam_agent,
        cai_version=_git_sha(cai_path),
        cai_path=cai_path,
    )
    return _BUNDLE
