"""Redsim environment validation (doctor) — Pythia-aware, provider-free (D5).

Every LLM call in redsim goes through the Pythia gateway (``redsim.llm.pythia``);
the deployment holds no model-provider key, so the doctor no longer derives a
"required API key" from ``RedsimConfig.model``. The Pythia block is purely
informational: when ``PYTHIA_BASE_URL`` / ``PYTHIA_API_KEY`` / ``REDSIM_ML_LLM_MODEL``
are present it reports *configured* (key redacted to prefix and length); when
any is absent it reports *narrative off (rules only)* and never fails the run.

Modes (``run_doctor`` keyword flags):

* default (developer laptop, offline CLI): the adversarial-ML checks — ``ml``
  extra importable, sandbox child launches, asset manifest verifies — are
  informational;
* ``worker_mode``: those three become *required* (the worker image is the only
  place models are loaded, spec 8.4 / 20.2);
* ``api_mode``: the ML checks stay informational (the API image never installs
  the ``ml`` extra) and the Postgres / blob-store / OIDC probes are added.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import subprocess
import sys
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from urllib.request import urlopen

from redsim.config import RedsimConfig, load_config

_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_RESET = "\033[0m"

#: Characters of the Pythia key that may be shown (mirrors ``redsim.llm.pythia_check``).
KEY_PREFIX_CHARS = 3

#: Python modules the ``ml`` extra must provide for a campaign to run (spec 8.4, 20.2).
ML_EXTRA_MODULES: tuple[str, ...] = ("torch", "art", "shap", "sklearn")

#: Scanner-registry name of the campaign façade (spec 8.3) and the module the adapter lives in.
ML_CAMPAIGN_SCANNER = "ml-campaign"
ML_CAMPAIGN_ADAPTER_MODULE = "redsim.ml.campaign_adapter"

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def _pass(label: str, detail: str = "") -> None:
    suffix = f" ({detail})" if detail else ""
    print(f"  {_GREEN}✓{_RESET} {label}{suffix}")


def _fail(label: str, detail: str = "") -> None:
    suffix = f" ({detail})" if detail else ""
    print(f"  {_RED}✗{_RESET} {label}{suffix}")


def _warn(label: str, detail: str = "") -> None:
    suffix = f" ({detail})" if detail else ""
    print(f"  {_YELLOW}~{_RESET} {label}{suffix}")


def _env_flag(name: str, environ: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return env.get(name, "").strip().lower() in _TRUE_VALUES


def _cmd_version(cmd: str) -> str | None:
    try:
        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


# ---------------------------------------------------------------------------
# Pythia gateway (informational, never required)
# ---------------------------------------------------------------------------


def _pythia_module() -> ModuleType | None:
    """``redsim.llm.pythia`` when importable (it needs ``httpx``, absent from the lean base install)."""
    try:
        return importlib.import_module("redsim.llm.pythia")
    except ImportError:
        return None


def redact_key(key: str) -> str:
    """Prefix and length only — the full key never reaches the terminal."""
    if not key:
        return "(unset)"
    return f"{key[:KEY_PREFIX_CHARS]}… ({len(key)} chars)"


@dataclass
class PythiaStatus:
    """What the doctor learned about the gateway settings, with the key already redacted."""

    configured: bool
    base_url: str = ""
    key_redacted: str = "(unset)"
    model: str = ""
    persona: str = ""
    env_file: str | None = None
    missing: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    llm_disabled: bool = False

    def detail(self) -> str:
        parts: list[str] = []
        if self.configured:
            parts.append(f"PYTHIA_BASE_URL={self.base_url}")
            parts.append(f"PYTHIA_API_KEY={self.key_redacted}")
            parts.append(f"model={self.model}")
            if self.persona:
                parts.append(f"persona={self.persona}")
        else:
            parts.append("not configured — narrative off (rules only)")
            if self.missing:
                parts.append(f"missing {', '.join(self.missing)}")
        if self.llm_disabled:
            parts.append("REDSIM_DISABLE_LLM set — narrative off (rules only)")
        if self.env_file:
            parts.append(f"env file {self.env_file}")
        parts.extend(self.notes)
        return "; ".join(parts)


def _resolve_pythia_env(environ: Mapping[str, str] | None = None) -> tuple[dict[str, str], str | None, str | None]:
    """``(merged env, env-file path, note)`` — layered over ``.env`` exactly as the writer does.

    ``redsim.llm.pythia`` needs ``httpx``, which the lean base install lacks; in
    that case only the process environment is consulted and the note says so.
    """
    env = os.environ if environ is None else environ
    pythia = _pythia_module()
    if pythia is None:
        return dict(env), None, "(.env file not read: redsim.llm.pythia needs httpx)"
    merged: dict[str, str] = dict(pythia.resolve_env(env))
    path = pythia.env_file_path(env)
    return merged, (str(path) if path is not None else None), None


def _resolve_pythia_model(env: Mapping[str, str]) -> tuple[str, str | None]:
    """``(model, variable it was read from)``; honours the deprecated aliases like the writer does."""
    pythia = _pythia_module()
    if pythia is None:
        value = env.get("REDSIM_ML_LLM_MODEL", "").strip()
        if value:
            return value, "REDSIM_ML_LLM_MODEL"
        for alias in ("AEGIS_ML_LLM_MODEL", "REDSIM_LLM_MODEL"):
            value = env.get(alias, "").strip()
            if value:
                return value, alias
        return "", None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        model, variable = pythia.resolve_model(env)
    return str(model), (str(variable) if variable else None)


def pythia_status(environ: Mapping[str, str] | None = None) -> PythiaStatus:
    """Inspect the Pythia settings without ever exposing the key."""
    merged, env_file, note = _resolve_pythia_env(environ)
    base = merged.get("PYTHIA_BASE_URL", "").strip()
    key = merged.get("PYTHIA_API_KEY", "").strip()
    model, model_var = _resolve_pythia_model(merged)
    persona = merged.get("PYTHIA_PERSONA", "").strip()
    missing = [name for name, value in (("PYTHIA_BASE_URL", base), ("PYTHIA_API_KEY", key),
                                         ("REDSIM_ML_LLM_MODEL", model)) if not value]
    status = PythiaStatus(
        configured=not missing,
        base_url=base,
        key_redacted=redact_key(key),
        model=model,
        persona=persona,
        env_file=env_file,
        missing=missing,
        llm_disabled=_env_flag("REDSIM_DISABLE_LLM", merged),
    )
    if note:
        status.notes.append(note)
    if model and model_var and model_var != "REDSIM_ML_LLM_MODEL":
        status.notes.append(f"model read from deprecated {model_var} — rename it to REDSIM_ML_LLM_MODEL")
    return status


def _report_pythia() -> None:
    """Informational: is the hardening narrative on? Never flips the overall result."""
    try:
        status = pythia_status()
    except Exception as exc:  # noqa: BLE001 - defensive: a doctor probe must not crash the doctor
        _warn("Pythia gateway", f"could not read settings — {type(exc).__name__}: {exc}")
        return
    label = "Pythia gateway"
    if status.configured and not status.llm_disabled:
        _pass(label, f"configured; {status.detail()}")
    else:
        _warn(label, status.detail())


# ---------------------------------------------------------------------------
# Adversarial-ML environment (required in worker mode, informational otherwise)
# ---------------------------------------------------------------------------


def _check_ml_extra() -> tuple[bool, str]:
    """Import the ``ml`` extra's load-bearing modules; never touches a model."""
    present: list[str] = []
    missing: list[str] = []
    for name in ML_EXTRA_MODULES:
        try:
            module = importlib.import_module(name)
        except Exception:  # noqa: BLE001 - a broken wheel is "missing" for the operator's purposes
            missing.append(name)
            continue
        version = getattr(module, "__version__", None)
        present.append(f"{name} {version}" if version else name)
    if missing:
        return False, (f"missing {', '.join(missing)} — install with pip install -e \".[ml]\" "
                       f"(worker image only; the API image never carries it)")
    return True, ", ".join(present)


def _check_sandbox_launch(timeout_s: float = 30.0) -> tuple[bool, str]:
    """Launch the ML sandbox child the way the worker does, with ``--help`` as its only work.

    Same interpreter, same allowlisted environment (``_ml_child_env``: no
    ``REDSIM_*`` secret, no Pythia key, no proxy), same rlimits and process
    group. The child parses its arguments and exits; no request file exists, so
    no model bytes are ever read.
    """
    try:
        from redsim.ml.sandbox import MlSandboxConfig, _assets_dir, _ml_child_env
        from redsim.scanners.sandbox import _rlimit_preexec
    except Exception as exc:  # noqa: BLE001 - report an unimportable sandbox module, do not crash
        return False, f"redsim.ml.sandbox unavailable — {type(exc).__name__}: {exc}"
    cfg = MlSandboxConfig.from_env()
    env = _ml_child_env(cfg, assets=str(_assets_dir()), hash_seed=0)
    argv = [sys.executable, "-m", "redsim.ml.sandbox_worker", "--help"]
    try:
        proc = subprocess.run(  # noqa: PLW1510 - check=False is explicit below
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
            preexec_fn=_rlimit_preexec(cfg.rlimits()),  # noqa: PLW1509 - required for POSIX rlimits
            start_new_session=True,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"child did not exit within {timeout_s:.0f}s"
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip().splitlines()
        reason = tail[-1][:200] if tail else "no stderr"
        return False, f"child exited {proc.returncode}: {reason}"
    return True, (f"python -m redsim.ml.sandbox_worker --help exit 0 under rlimits "
                  f"(wall {cfg.timeout_s}s, cpu {cfg.cpu_seconds}s, mem {cfg.memory_mb}MB, "
                  f"threads {cfg.threads}); no model loaded")


def _assets_root() -> Path:
    """``REDSIM_ML_ASSETS_DIR`` or ``./assets`` — the same pair the sandbox and the loaders read."""
    try:
        from redsim.ml.sandbox import ASSETS_DIR_ENV, DEFAULT_ASSETS_DIR
    except Exception:  # noqa: BLE001 - fall back to the documented literals
        ASSETS_DIR_ENV, DEFAULT_ASSETS_DIR = "REDSIM_ML_ASSETS_DIR", "./assets"  # noqa: N806
    raw = os.environ.get(ASSETS_DIR_ENV, "").strip() or DEFAULT_ASSETS_DIR
    return Path(raw).expanduser()


def _check_assets_manifest() -> tuple[bool | None, str]:
    """``(None, …)`` when no manifest exists; otherwise whether every bundled model verifies.

    Uses ``redsim.ml.assets.manifest`` (pydantic only, no torch) and
    ``verify_model_assets`` per model: weight / surrogate digests, the entry's
    ``manifest_sha256``, and the evaluation split the model is bound to.
    """
    root = _assets_root()
    path = root / "MANIFEST.json"
    if not path.is_file():
        return None, f"{path} not found — run `redsim ml build-assets`; bundled targets report unavailable until then"
    try:
        from redsim.ml.assets.manifest import load_manifest, verify_model_assets
        manifest = load_manifest(path)
    except Exception as exc:  # noqa: BLE001 - a malformed manifest is a finding, not a crash
        return False, f"{path} unreadable — {type(exc).__name__}: {exc}"
    problems: list[str] = []
    for model_id in sorted(manifest.models):
        result = verify_model_assets(manifest, root, model_id)
        problems.extend(result.model)
        problems.extend(result.dataset)
    if problems:
        more = f" (+{len(problems) - 1} more)" if len(problems) > 1 else ""
        return False, f"{len(problems)} problem(s) in {path}: {problems[0]}{more}"
    ids = ", ".join(sorted(manifest.models)) or "no models"
    return True, f"{path}: {len(manifest.models)} bundled model(s) verified — {ids}"


def _report_ml_environment(*, required: bool) -> bool:
    """Run the three ML checks; return False only when ``required`` and one failed."""
    ok = True
    tier = "required" if required else "informational"
    fail = _fail if required else _warn

    ml_ok, ml_detail = _check_ml_extra()
    if ml_ok:
        _pass("ML extra (torch/art/shap/sklearn)", ml_detail)
    else:
        fail("ML extra (torch/art/shap/sklearn)", f"{ml_detail} [{tier}]")
        ok = ok and not required

    sb_ok, sb_detail = _check_sandbox_launch()
    if sb_ok:
        _pass("ML sandbox child", sb_detail)
    else:
        fail("ML sandbox child", f"{sb_detail} [{tier}]")
        ok = ok and not required

    as_ok, as_detail = _check_assets_manifest()
    if as_ok:
        _pass("ML assets manifest", as_detail)
    elif as_ok is None:
        fail("ML assets manifest", f"{as_detail} [{tier}]")
        ok = ok and not required
    else:
        # A manifest that is present but does not verify is wrong in every mode.
        _fail("ML assets manifest", as_detail)
        ok = False
    return ok


# ---------------------------------------------------------------------------
# api-mode probes
# ---------------------------------------------------------------------------


def _check_db(url: str) -> tuple[bool, str]:
    try:
        from sqlalchemy import create_engine, text
        engine = create_engine(url, future=True, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "SELECT 1 ok"
    except Exception as exc:  # noqa: BLE001  # pragma: no cover
        return False, f"{type(exc).__name__}: {exc}"


def _check_blob_backend(backend: str) -> tuple[bool, str]:
    if backend == "fs":
        base = Path(os.environ.get("REDSIM_BLOB_FS_PATH", "redsim_output/blobs"))
        try:
            base.mkdir(parents=True, exist_ok=True)
            return True, f"fs at {base}"
        except Exception as exc:  # noqa: BLE001  # pragma: no cover
            return False, f"{type(exc).__name__}: {exc}"
    if backend == "s3":
        try:
            import boto3  # noqa: F401
            return True, "boto3 importable; head-bucket probe deferred to runtime"
        except ImportError:  # pragma: no cover
            return False, "boto3 missing — install with pip install redsim-platform[api]"
    return False, f"unknown backend: {backend}"


def _check_oidc(issuer: str) -> tuple[bool, str]:
    try:
        with urlopen(issuer.rstrip("/") + "/.well-known/openid-configuration",
                     timeout=5) as resp:
            if resp.status == 200:
                return True, f"{resp.status} from issuer"
            return False, f"unexpected status {resp.status}"
    except Exception as exc:  # noqa: BLE001  # pragma: no cover
        return False, f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Attack adapters (informational)
# ---------------------------------------------------------------------------


def _ml_campaign_adapter_importable() -> tuple[bool, str]:
    """Import the campaign façade module so its registration side effect runs."""
    if importlib.util.find_spec(ML_CAMPAIGN_ADAPTER_MODULE) is None:
        return False, f"{ML_CAMPAIGN_ADAPTER_MODULE} not present"
    try:
        importlib.import_module(ML_CAMPAIGN_ADAPTER_MODULE)
    except Exception as exc:  # noqa: BLE001 - an adapter that fails to import is reported, not raised
        return False, f"{ML_CAMPAIGN_ADAPTER_MODULE} failed to import — {type(exc).__name__}: {exc}"
    return True, f"{ML_CAMPAIGN_ADAPTER_MODULE} importable"


def _report_attack_adapters() -> None:
    """Informational: which scanner / attack adapters are registered.

    Never flips the overall result. The pentest engines this check once
    validated (Strix / CAI / MCP-Kali) were removed with the pentest domain.
    The adversarial-ML campaign façade (``ml-campaign``, spec 8.3) registers on
    the scanner registry when ``redsim.ml.campaign_adapter`` imports; the roster
    says whether it did.
    """
    importable, adapter_note = _ml_campaign_adapter_importable()
    try:
        from redsim.scanners import list_scanners
        names = list_scanners()
    except Exception as exc:  # noqa: BLE001  # pragma: no cover - defensive
        _warn("Attack adapters", f"registry unavailable — {type(exc).__name__}: {exc}")
        return
    roster = ", ".join(names) if names else "none registered"
    if ML_CAMPAIGN_SCANNER in names:
        _pass("Attack adapters", f"{roster}; {ML_CAMPAIGN_SCANNER} registered")
    elif importable:
        _warn("Attack adapters", f"{roster}; {adapter_note} but {ML_CAMPAIGN_SCANNER} is not registered")
    else:
        _warn("Attack adapters",
              f"{roster}; {adapter_note} — ML attack adapters (redsim.ml.attacks) and the "
              f"{ML_CAMPAIGN_SCANNER} façade register via redsim.scanners")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_doctor(config: RedsimConfig | None = None, *,
               api_mode: bool = False,
               worker_mode: bool = False) -> bool:
    """Validate the Redsim environment.

    Returns True if every *required* check passes, False otherwise. The Pythia
    block and the attack-adapter roster are always informational; the three
    adversarial-ML checks are required only in ``worker_mode``; the Postgres /
    blob / OIDC probes run only in ``api_mode``.
    """
    if config is None:
        config = load_config()

    ok = True
    mode = "worker" if worker_mode else "api" if api_mode else "dev"
    print(f"Redsim Doctor — environment check ({mode} mode)\n")

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

    _report_pythia()

    if not _report_ml_environment(required=worker_mode):
        ok = False

    _report_attack_adapters()

    if api_mode:
        db_url = os.environ.get("REDSIM_DB_URL")
        if db_url:
            db_ok, db_detail = _check_db(db_url)
            (_pass if db_ok else _fail)("Postgres", db_detail)
            if not db_ok:
                ok = False
        else:
            _fail("Postgres", "REDSIM_DB_URL not set (required in --api-mode)")
            ok = False

        backend = os.environ.get("REDSIM_BLOB_BACKEND", "fs")
        blob_ok, blob_detail = _check_blob_backend(backend)
        (_pass if blob_ok else _fail)("Blob backend", blob_detail)
        if not blob_ok:
            ok = False

        issuer = os.environ.get("REDSIM_OIDC_ISSUER")
        if issuer:
            oidc_ok, oidc_detail = _check_oidc(issuer)
            (_pass if oidc_ok else _warn)("OIDC issuer", oidc_detail)
        else:
            _warn("OIDC issuer", "REDSIM_OIDC_ISSUER not set (dev mode allowed only if REDSIM_ENV != prod)")

    print()
    if ok:
        print(f"{_GREEN}All required checks passed.{_RESET}")
    else:
        print(f"{_RED}Some required checks failed.{_RESET}")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if run_doctor() else 1)
