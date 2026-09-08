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


def _check_db(url: str) -> tuple[bool, str]:
    try:
        from sqlalchemy import create_engine, text
        engine = create_engine(url, future=True, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "SELECT 1 ok"
    except Exception as exc:  # pragma: no cover
        return False, f"{type(exc).__name__}: {exc}"


def _check_blob_backend(backend: str) -> tuple[bool, str]:
    if backend == "fs":
        from pathlib import Path
        base = Path(os.environ.get("AEGIS_BLOB_FS_PATH", "aegis_output/blobs"))
        try:
            base.mkdir(parents=True, exist_ok=True)
            return True, f"fs at {base}"
        except Exception as exc:  # pragma: no cover
            return False, f"{type(exc).__name__}: {exc}"
    if backend == "s3":
        try:
            import boto3  # noqa: F401
            return True, "boto3 importable; head-bucket probe deferred to runtime"
        except ImportError:  # pragma: no cover
            return False, "boto3 missing — install with pip install aegis-platform[api]"
    return False, f"unknown backend: {backend}"


def _check_oidc(issuer: str) -> tuple[bool, str]:
    try:
        with urlopen(issuer.rstrip("/") + "/.well-known/openid-configuration",
                     timeout=5) as resp:
            if resp.status == 200:
                return True, f"{resp.status} from issuer"
            return False, f"unexpected status {resp.status}"
    except Exception as exc:  # pragma: no cover
        return False, f"{type(exc).__name__}: {exc}"


def run_doctor(config: AegisConfig | None = None, *,
               provider_override: str | None = None,
               api_mode: bool = False) -> bool:
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

    if api_mode:
        db_url = os.environ.get("AEGIS_DB_URL")
        if db_url:
            db_ok, db_detail = _check_db(db_url)
            (_pass if db_ok else _fail)("Postgres", db_detail)
            if not db_ok:
                ok = False
        else:
            _fail("Postgres", "AEGIS_DB_URL not set (required in --api-mode)")
            ok = False

        backend = os.environ.get("AEGIS_BLOB_BACKEND", "fs")
        blob_ok, blob_detail = _check_blob_backend(backend)
        (_pass if blob_ok else _fail)("Blob backend", blob_detail)
        if not blob_ok:
            ok = False

        issuer = os.environ.get("AEGIS_OIDC_ISSUER")
        if issuer:
            oidc_ok, oidc_detail = _check_oidc(issuer)
            (_pass if oidc_ok else _warn)("OIDC issuer", oidc_detail)
        else:
            _warn("OIDC issuer", "AEGIS_OIDC_ISSUER not set (dev mode allowed only if AEGIS_ENV != prod)")

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
