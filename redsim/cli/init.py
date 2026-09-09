"""`redsim init` — writes a default redsim.yaml into the current directory.

The template mirrors the committed ``redsim.yaml``: the operator-facing keys
only. It never writes the legacy provider-style ``model`` default (every LLM
call goes through Pythia, configured by environment variables, D5) and never
writes a field whose default is read from the environment (``auth_profiles_key``
and friends), so a secret exported in the shell cannot end up in a config file.
"""

from __future__ import annotations

import argparse
import dataclasses
from typing import Any

import redsim.cli.main as _main
from redsim.cli import _console
from redsim.config import RedsimConfig

#: Dataclass fields the template writes, in order. Everything else is env-only,
#: a secret, or a legacy fallback that redsim.yaml no longer carries.
TEMPLATE_FIELDS: tuple[str, ...] = ("output_dir", "target_allowlist", "job_max_runtime_seconds")

_HEADER = """\
# Redsim configuration
#
# Every LLM call goes through the Pythia gateway, configured by environment
# variables only (PYTHIA_BASE_URL, PYTHIA_API_KEY, REDSIM_ML_LLM_MODEL; see
# .env.example and docs/ops/pythia.md). There is no provider key or
# provider-style default model in this file.
"""

_FOOTER = """\
# Per-task LLM model routing ({task: model id}). "ml.harden_narrative" is seeded
# from REDSIM_ML_LLM_MODEL when unmapped here; a mapping must be a Pythia
# canonical id (<vendor>/<model> or pythia/auto).
task_models: {}
"""


def _render_value(name: str, value: Any) -> list[str]:
    if isinstance(value, list):
        lines = [f"{name}:"]
        lines.extend(f"  - \"{item}\"" for item in value)
        return lines
    if isinstance(value, bool):
        return [f"{name}: {'true' if value else 'false'}"]
    if isinstance(value, str):
        return [f"{name}: \"{value}\""]
    return [f"{name}: {value}"]


def render_template(defaults: RedsimConfig | None = None) -> str:
    """The redsim.yaml text ``redsim init`` writes (exposed for tests)."""
    cfg = defaults if defaults is not None else RedsimConfig()
    by_name = {f.name: f for f in dataclasses.fields(cfg)}
    lines = [_HEADER]
    for name in TEMPLATE_FIELDS:
        if name not in by_name:  # pragma: no cover - guards against a renamed field
            continue
        lines.extend(_render_value(name, getattr(cfg, name)))
    lines.append("")
    lines.append(_FOOTER)
    return "\n".join(lines)


def cmd_init(_args: argparse.Namespace, _config: RedsimConfig) -> None:
    """Create a default redsim.yaml in the current directory."""
    target = _main.Path("redsim.yaml")
    if target.exists():
        _console._warn("redsim.yaml already exists — skipping.")
        return

    target.write_text(render_template())
    _console._info(f"Created {target.resolve()}")
