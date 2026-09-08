"""Pythia gateway client for the optional LLM hardening narrative.

Pythia (https://github.com/IntelliBridge/pythia) is IntelliBridge's
OpenAI-compatible agent gateway. Redsim never talks to a model provider
directly: it holds only a Pythia ``pk_…`` key, and the gateway applies
persona, guardrails, metering and audit.

Wire contract (mirrors ``pythia_sdk._common``):

* ``POST {base_url}/v1/chat/completions`` with ``{"model", "messages", ...}``
* ``GET {base_url}/v1/models`` lists the models the key is entitled to use
* ``Authorization: Bearer pk_…``
* optional ``X-Pythia-Persona: <persona>``
* model ids are canonical ``<vendor>/<model>`` or ``pythia/auto``

When the official ``pythia_sdk`` package is importable it is used; otherwise
the same request is made with ``httpx``.

Configuration comes from the process environment, topped up from a ``.env``
file when one is present (``REDSIM_ENV_FILE``, default ``./.env``, then the
repo root). A variable set in the environment always wins over the file.
TLS verification behind a corporate proxy is handled by :func:`tls_verify`:
the operating-system trust store through ``truststore`` by default, or a PEM
bundle named by ``REDSIM_CA_BUNDLE`` / ``SSL_CERT_FILE``.
"""

from __future__ import annotations

import logging
import os
import ssl
import warnings
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

CHAT_PATH = "/v1/chat/completions"
MODELS_PATH = "/v1/models"

#: Canonical name of the model-id variable.
MODEL_ENV = "REDSIM_ML_LLM_MODEL"
#: Older names still accepted for the model id, in precedence order. Reading
#: the value from one of these raises a ``DeprecationWarning``.
DEPRECATED_MODEL_ENV: tuple[str, ...] = ("AEGIS_ML_LLM_MODEL", "REDSIM_LLM_MODEL")

ENV_FILE_VAR = "REDSIM_ENV_FILE"
TRUSTSTORE_VAR = "REDSIM_TLS_TRUSTSTORE"
CA_BUNDLE_VAR = "REDSIM_CA_BUNDLE"

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})

logger = logging.getLogger(__name__)


class PythiaUnavailable(RuntimeError):
    """Raised when the narrative was requested but Pythia is not configured."""


# ---------------------------------------------------------------------------
# .env file handling (no python-dotenv dependency)
# ---------------------------------------------------------------------------


def parse_env_file(text: str) -> dict[str, str]:
    """Parse ``KEY=VALUE`` lines into a dict.

    Blank lines and ``#`` comments are skipped, a leading ``export `` is
    tolerated, a value wrapped in matching single or double quotes is unquoted,
    and an unquoted value loses a trailing `` # comment``. Lines without ``=``
    or with a key that is not an identifier are ignored. Later lines win.
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        if not key.isidentifier():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        out[key] = value
    return out


def env_file_path(environ: Mapping[str, str] | None = None) -> Path | None:
    """Return the ``.env`` file to read, or ``None`` when there is none.

    ``REDSIM_ENV_FILE`` names it explicitly. Otherwise ``./.env`` in the
    current directory is tried first, then ``.env`` at the repo root (the
    directory that contains the ``redsim`` package).
    """
    env = os.environ if environ is None else environ
    explicit = env.get(ENV_FILE_VAR, "").strip()
    if explicit:
        path = Path(explicit).expanduser()
        return path if path.is_file() else None
    for candidate in (Path.cwd() / ".env", _REPO_ROOT / ".env"):
        if candidate.is_file():
            return candidate
    return None


def load_env_file(path: str | os.PathLike[str] | None = None, *,
                  environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the variables in the ``.env`` file (empty when there is none)."""
    target = Path(path) if path is not None else env_file_path(environ)
    if target is None or not target.is_file():
        return {}
    try:
        return parse_env_file(target.read_text(encoding="utf-8"))
    except OSError as exc:  # unreadable file: behave as if absent
        logger.warning("could not read env file %s: %s", target, type(exc).__name__)
        return {}


def resolve_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Process environment layered over the ``.env`` file. The environment wins."""
    env = os.environ if environ is None else environ
    merged = load_env_file(environ=env)
    merged.update(env)
    return merged


def resolve_model(env: Mapping[str, str]) -> tuple[str, str | None]:
    """Return ``(model_id, variable_name)``, or ``("", None)`` when unset.

    ``REDSIM_ML_LLM_MODEL`` is canonical. The deprecated aliases in
    :data:`DEPRECATED_MODEL_ENV` are honoured with a ``DeprecationWarning``.
    """
    value = env.get(MODEL_ENV, "").strip()
    if value:
        return value, MODEL_ENV
    for alias in DEPRECATED_MODEL_ENV:
        value = env.get(alias, "").strip()
        if value:
            warnings.warn(f"{alias} is deprecated, set {MODEL_ENV} instead", DeprecationWarning, stacklevel=3)
            return value, alias
    return "", None


# ---------------------------------------------------------------------------
# TLS verification
# ---------------------------------------------------------------------------


def truststore_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """``REDSIM_TLS_TRUSTSTORE`` defaults on; ``0``/``false``/``no``/``off`` disable it."""
    env = os.environ if environ is None else environ
    return env.get(TRUSTSTORE_VAR, "1").strip().lower() not in _FALSE_VALUES


def tls_verify(environ: Mapping[str, str] | None = None) -> tuple[ssl.SSLContext | bool, str]:
    """Return ``(verify, mode)`` for :class:`httpx.Client`.

    * ``truststore``: ``REDSIM_TLS_TRUSTSTORE`` is not off and the
      ``truststore`` package imports. Certificates are checked against the
      operating-system store (macOS keychain, Windows store, the distro bundle
      on Linux), which is where a corporate proxy root such as Zscaler lives.
    * ``ca-bundle:<path>``: otherwise ``REDSIM_CA_BUNDLE`` or ``SSL_CERT_FILE``
      names a PEM bundle, loaded into a default client context.
    * ``default``: otherwise httpx's bundled certifi roots.
    """
    env = os.environ if environ is None else environ
    if truststore_enabled(env):
        try:
            import truststore
        except ImportError:
            pass
        else:
            return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT), "truststore"
    bundle = env.get(CA_BUNDLE_VAR, "").strip() or env.get("SSL_CERT_FILE", "").strip()
    if bundle:
        return ssl.create_default_context(cafile=bundle), f"ca-bundle:{bundle}"
    return True, "default"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PythiaSettings:
    base_url: str
    api_key: str
    model: str
    persona: str | None = None
    timeout_s: float = 60.0

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None, *,
                 env_file: bool = True) -> PythiaSettings | None:
        """Return settings when all required variables are present, else ``None``.

        Reads ``environ`` (default ``os.environ``) layered over the ``.env``
        file unless ``env_file`` is false. Required: ``PYTHIA_BASE_URL``,
        ``PYTHIA_API_KEY`` and ``REDSIM_ML_LLM_MODEL`` (or a deprecated alias).
        """
        source = os.environ if environ is None else environ
        env = resolve_env(source) if env_file else dict(source)
        base = env.get("PYTHIA_BASE_URL", "").strip()
        key = env.get("PYTHIA_API_KEY", "").strip()
        model, _ = resolve_model(env)
        if not (base and key and model):
            return None
        persona = env.get("PYTHIA_PERSONA", "").strip() or None
        timeout = float(env.get("PYTHIA_TIMEOUT_S", "").strip() or "60")
        return cls(base_url=base.rstrip("/"), api_key=key, model=model, persona=persona, timeout_s=timeout)

    def headers(self) -> dict[str, str]:
        h = {"Authorization": f"Bearer {self.api_key}"}
        if self.persona:
            h["X-Pythia-Persona"] = self.persona
        return h

    def redacted(self) -> dict[str, Any]:
        """Provenance-safe view: never includes the key."""
        return {"gateway": "pythia", "base_url": self.base_url, "model": self.model, "persona": self.persona}


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


class ChatBackend(Protocol):
    def chat(self, model: str, messages: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]: ...


class _HttpxBackend:
    """In-repo client speaking the OpenAI-compatible contract.

    ``transport`` (an :class:`httpx.MockTransport` in tests) bypasses TLS
    entirely. Otherwise ``verify`` defaults to :func:`tls_verify`.
    """

    def __init__(self, settings: PythiaSettings, transport: httpx.BaseTransport | None = None,
                 verify: ssl.SSLContext | bool | None = None) -> None:
        self.tls_mode = "transport"
        kwargs: dict[str, Any] = {"base_url": settings.base_url, "headers": settings.headers(),
                                  "timeout": settings.timeout_s}
        if transport is not None:
            kwargs["transport"] = transport
        else:
            if verify is None:
                verify, self.tls_mode = tls_verify()
            else:
                self.tls_mode = "explicit"
            kwargs["verify"] = verify
        self._client = httpx.Client(**kwargs)

    def chat(self, model: str, messages: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        resp = self._client.post(CHAT_PATH, json={"model": model, "messages": messages, **kwargs})
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        return data

    def models(self) -> list[dict[str, Any]]:
        """``GET /v1/models``: the entries of the OpenAI-style ``data`` list."""
        resp = self._client.get(MODELS_PATH)
        resp.raise_for_status()
        body = resp.json()
        data = body.get("data", body) if isinstance(body, dict) else body
        return [m for m in data if isinstance(m, dict)] if isinstance(data, list) else []

    def close(self) -> None:
        self._client.close()


def make_backend(settings: PythiaSettings, transport: httpx.BaseTransport | None = None) -> ChatBackend:
    """Prefer the official SDK; fall back to the in-repo httpx client."""
    if transport is None:
        try:
            from pythia_sdk import PythiaClient
            backend: ChatBackend = PythiaClient(settings.base_url, settings.api_key, persona=settings.persona,
                                timeout=settings.timeout_s)
            return backend
        except ImportError:
            pass
    return _HttpxBackend(settings, transport=transport)


def list_models(settings: PythiaSettings, *, transport: httpx.BaseTransport | None = None) -> list[dict[str, Any]]:
    """Models the key is entitled to, via the in-repo httpx client."""
    return _HttpxBackend(settings, transport=transport).models()


def extract_text(resp: dict[str, Any]) -> str:
    """Assistant text of the first choice; tolerates the content-block form."""
    try:
        content = resp["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("unexpected Pythia chat response shape") from exc
    if isinstance(content, list):  # content-block form
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    return str(content or "").strip()


def chat_text(settings: PythiaSettings, system: str, user: str, *, backend: ChatBackend | None = None,
              temperature: float = 0.2, max_tokens: int = 800) -> str:
    """One non-streaming chat turn; returns the assistant text."""
    be = backend or make_backend(settings)
    resp = be.chat(settings.model,
                   [{"role": "system", "content": system}, {"role": "user", "content": user}],
                   temperature=temperature, max_tokens=max_tokens)
    return extract_text(resp)
