"""Aegis environment validation (doctor) module — provider-aware."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from aegis.config import AegisConfig, load_config

_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_RESET = "\033[0m"


def _pass(label: str, detail: str = "") -> None:
    suffix = f" ({detail})" if detail else ""
    print(f"  {_GREEN}✓{_RESET} {label}{suffix}")


def _fail(label: str, detail: str = "") -> None:
    suffix = f" ({detail})" if detail else ""
    print(f"  {_RED}✗{_RESET} {label}{suffix}")


def _warn(label: str, detail: str = "") -> None:
    suffix = f" ({detail})" if detail else ""
    print(f"  {_YELLOW}~{_RESET} {label}{suffix}")


def _cmd_version(cmd: str) -> str | None:
    try:
        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


_PROVIDER_KEYS: dict[str, tuple[str, ...]] = {
    "gemini": ("GOOGLE_API_KEY", "GEMINI_API_KEY"),
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "azure": ("AZURE_API_KEY", "AZURE_OPENAI_API_KEY"),
}


def detect_provider(model: str) -> str:
    """Infer the LLM provider from a litellm-style model string.

    e.g. "gemini/gemini-2.5-flash" -> "gemini"
         "openai/gpt-4o" -> "openai"
         "claude-3-5-sonnet" -> "anthropic" (fallback inference)
         unknown -> "unknown"
    """
    if not model:
        return "unknown"
    head = model.split("/", 1)[0].lower()
    if head in _PROVIDER_KEYS:
        return head
    lowered = model.lower()
    if "claude" in lowered:
        return "anthropic"
    if "gpt" in lowered or "o1" in lowered or "o3" in lowered:
        return "openai"
    if "gemini" in lowered:
        return "gemini"
    return "unknown"


def run_doctor(config: AegisConfig | None = None, *, provider_override: str | None = None) -> bool:
    """Validate the Aegis development environment.

    Returns True if every *required* check passes, False otherwise.
    Provider-specific credentials are only required for the active provider.
    """
    if config is None:
        config = load_config()

    ok = True
    print("Aegis Doctor — environment check\n")

    py_ver = sys.version_info
    if py_ver >= (3, 12):
        _pass("Python version", f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}")
    else:
        _fail("Python version", f"{py_ver.major}.{py_ver.minor}.{py_ver.micro} — need 3.12+")
        ok = False

    docker_ver = _cmd_version("docker --version")
    if docker_ver:
        _pass("Docker", docker_ver)
    else:
        _fail("Docker", "not found — install Docker")
        ok = False

    strix = Path(config.strix_path)
    if strix.is_dir():
        _pass("Strix path", str(strix.resolve()))
    else:
        _fail("Strix path", f"{config.strix_path} is not a directory")
        ok = False

    cai = Path(config.cai_path)
    if cai.is_dir():
        _pass("CAI path", str(cai.resolve()))
    else:
        _fail("CAI path", f"{config.cai_path} is not a directory")
        ok = False

    provider = provider_override or detect_provider(config.model)
    keys = _PROVIDER_KEYS.get(provider)
    if keys is None:
        _warn("LLM provider", f"unknown provider for model '{config.model}' — credentials not checked")
    else:
        present = [k for k in keys if os.environ.get(k)]
        if present:
            _pass(f"{provider} API key", " or ".join(present) + " set")
        else:
            _fail(f"{provider} API key", f"set one of {', '.join(keys)} (model={config.model})")
            ok = False

    mcp_url = config.mcp_kali_url.rstrip("/") + "/health"
    try:
        with urlopen(mcp_url, timeout=5) as resp:
            _pass("MCP Kali Server", f"{mcp_url} responded {resp.status}")
    except (URLError, OSError, ValueError) as exc:
        _warn("MCP Kali Server", f"not reachable at {mcp_url} — {exc}")

    if os.environ.get("GITHUB_TOKEN"):
        _pass("GitHub token", "GITHUB_TOKEN set")
    else:
        _warn("GitHub token", "GITHUB_TOKEN not set (optional, required for --open-pr)")

    gh_ver = _cmd_version("gh --version")
    if gh_ver:
        _pass("gh CLI", gh_ver.splitlines()[0])
    else:
        _warn("gh CLI", "not found (optional, required for --open-pr)")

    print()
    if ok:
        print(f"{_GREEN}All required checks passed.{_RESET}")
    else:
        print(f"{_RED}Some required checks failed.{_RESET}")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if run_doctor() else 1)
