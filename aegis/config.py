"""Aegis configuration loader."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class AegisConfig:
    strix_path: str = "./project_repos/strix"
    cai_path: str = "./project_repos/cai"
    vulnfixer_path: str = "./project_repos/vulnerability-fixer"
    mcp_kali_url: str = "http://127.0.0.1:5000"
    output_dir: str = "./aegis_output"
    model: str = "gemini/gemini-2.5-flash"
    target_allowlist: list[str] = field(
        default_factory=lambda: ["127.0.0.1", "localhost", "host.docker.internal"]
    )
    target_pack: str = "juice-shop"
    default_repo: str | None = None
    enable_pr: bool = False
    juice_shop_image_tag: str = "bkimminich/juice-shop:v17.3.0"
    strix_command: str | None = None


def load_config(path: str | None = None) -> AegisConfig:
    """Load configuration from a YAML file and return an AegisConfig.

    Resolution order for the config file path:
      1. Explicit ``path`` argument
      2. ``AEGIS_CONFIG`` environment variable
      3. ``aegis.yaml`` in the current working directory
    """
    if path is None:
        path = os.environ.get("AEGIS_CONFIG", "aegis.yaml")

    config_path = Path(path)

    if not config_path.exists():
        # No config file found — return defaults.
        return AegisConfig()

    with open(config_path, "r") as f:
        raw = yaml.safe_load(f) or {}

    return AegisConfig(**{k: v for k, v in raw.items() if k in AegisConfig.__dataclass_fields__})
