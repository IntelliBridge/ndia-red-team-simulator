"""``PythiaGenerator``: garak's OpenAI-compatible generator pointed at the Pythia gateway (LLM-06; D5, D6).

Redsim never talks to a model provider directly. garak's ``OpenAICompatible``
generator speaks the OpenAI chat contract that Pythia exposes at
``{PYTHIA_BASE_URL}/v1/``, so this subclass changes only what the gateway
needs and what the redsim contract forbids:

* the probe key (``pk_…``) comes from the caller, as ``api_key=`` or a 0600
  ``key_file`` in the job work directory. It is never read from the
  environment (``ENV_VAR`` is ``None``, ``_validate_env_var`` refuses a missing
  key with a redsim message), never placed in garak's ``_config`` (which
  ``start_run`` dumps into ``report.jsonl``), and never a class attribute
  (``PluginCache.plugin_info`` serialises those);
* ``X-Pythia-Persona`` travels as a default header of the OpenAI client;
* TLS verification is :func:`redsim.llm.pythia.tls_verify` (the operating-system
  trust store through ``truststore`` behind the corporate proxy, or a PEM
  bundle), never ``verify=False``;
* the OpenAI client runs with ``max_retries=0`` and garak's uncapped fibonacci
  backoff on connection errors is replaced by a bounded retry loop
  (``transport_max_tries``), so a dead gateway costs seconds, not the whole
  wall clock;
* chat completions only; ``n``, ``stop``, ``top_p``, ``seed`` and the penalty
  parameters are suppressed so the request body is ``model``, ``messages``,
  ``temperature`` and ``max_tokens``;
* every response feeds a :class:`UsageLedger` (requests, HTTP statuses, prompt
  and completion tokens, wall time, the ``model`` ids the gateway answered
  with) that the probe child writes as ``usage.json``.

garak installs litellm and other provider clients; none is imported here.
:func:`assert_no_litellm` checks that after the generator is built.

garak's plugin bookkeeping (``PluginCache.plugin_info``, the ``report.jsonl``
``plugin_cache`` entry, the ``_load_config`` namespace) only knows classes
under ``garak.<category>.<module>``; this module is therefore also registered
as ``garak.generators.pythia_redsim`` and the class reports that module, so
the YAML run config can carry generator options under
``plugins.generators.pythia_redsim.PythiaGenerator``.

This module imports garak and the OpenAI client: worker child only, never the
API process (``tests/test_api_process_has_no_ml.py``).
"""

from __future__ import annotations

import logging
import math
import os
import re
import stat
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import garak.exception
import httpx
import openai
from garak import _config
from garak.generators.openai import OpenAICompatible

from redsim.llm.pythia import tls_verify
from redsim.ml.errors import MLError

logger = logging.getLogger(__name__)

PERSONA_HEADER = "X-Pythia-Persona"
#: The garak module name this generator is registered under (see the module docstring).
GARAK_MODULE_ALIAS = "garak.generators.pythia_redsim"
#: ``plugins.target_type`` in the run config: ``<module>.<Class>`` relative to ``garak.generators``.
TARGET_TYPE = "pythia_redsim.PythiaGenerator"
#: Shape of a Pythia gateway key; used only to scrub, never to validate a real key.
KEY_PATTERN = re.compile(r"pk_[A-Za-z0-9_\-]{8,}")
REDACTED = "<REDACTED>"

#: garak parameters suppressed from the chat request (Pythia may reject unknown OpenAI params).
SUPPRESSED_PARAMS: frozenset[str] = frozenset({"n", "frequency_penalty", "presence_penalty", "seed", "stop", "top_p"})

_RETRYABLE: tuple[type[BaseException], ...] = (
    openai.RateLimitError,
    openai.InternalServerError,
    openai.APITimeoutError,
    openai.APIConnectionError,
    garak.exception.GeneratorBackoffTrigger,
)
# garak decorates ``_call_model`` with an uncapped ``backoff.on_exception``; ``functools.wraps`` keeps the
# undecorated function at ``__wrapped__``. The bounded loop below calls that one.
_UNDECORATED_CALL: Callable[..., Any] = getattr(OpenAICompatible._call_model, "__wrapped__", OpenAICompatible._call_model)


class ProbeKeyUnavailable(MLError):
    """The probe key was not supplied, or the key file is missing or not private (mode not 0600)."""

    code = "probe_key_unavailable"


def retry_after_seconds(value: str | None, *, now: float | None = None) -> float | None:
    """Parse a Retry-After delay without allowing malformed/non-finite sleeps."""
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            seconds = when.timestamp() - (time.time() if now is None else now)
        except (ValueError, TypeError, OverflowError):
            return None
    return max(0.0, seconds) if math.isfinite(seconds) else None


def gateway_uri(base_url: str) -> str:
    """``PYTHIA_BASE_URL`` -> the OpenAI-compatible root the client appends ``chat/completions`` to."""
    base = str(base_url).strip().rstrip("/")
    if not base:
        raise ValueError("gateway base URL is empty")
    if base.endswith("/v1"):
        return base + "/"
    return base + "/v1/"


def scrub_secrets(text: str, *secrets: str) -> str:
    """Replace every supplied secret and every ``pk_…`` shape in ``text`` with ``<REDACTED>``."""
    out = str(text)
    for secret in secrets:
        if secret:
            out = out.replace(secret, REDACTED)
    return KEY_PATTERN.sub(REDACTED, out)


def read_key_file(path: str | os.PathLike[str]) -> str:
    """Read the probe key from a file that only its owner can read; refuse anything looser."""
    key_path = Path(path)
    try:
        info = key_path.lstat()
    except FileNotFoundError as exc:
        raise ProbeKeyUnavailable(f"probe key file is missing: {key_path.name}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ProbeKeyUnavailable("probe key file must be a regular file")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ProbeKeyUnavailable(f"probe key file mode is {stat.S_IMODE(info.st_mode):o}, expected 0600")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise ProbeKeyUnavailable("probe key file is not owned by this user")
    key = key_path.read_text(encoding="utf-8").strip()
    if not key:
        raise ProbeKeyUnavailable("probe key file is empty")
    return key


@dataclass
class UsageLedger:
    """Counts only: what was sent, what came back, what it cost in tokens and time. Never a prompt."""

    requests: int = 0
    responses_ok: int = 0
    http_errors: dict[str, int] = field(default_factory=dict)
    transport_errors: dict[str, int] = field(default_factory=dict)
    retries: int = 0
    retry_after_honoured: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    responses_with_usage: int = 0
    wall_time_s: float = 0.0
    models_seen: dict[str, int] = field(default_factory=dict)
    tls_mode: str = "unset"
    started_at: float | None = None
    finished_at: float | None = None

    def record_response(self, response: httpx.Response, *, elapsed_s: float | None = None) -> None:
        now = time.time()
        self.started_at = self.started_at or now
        self.finished_at = now
        self.requests += 1
        if elapsed_s is not None:
            self.wall_time_s += max(0.0, float(elapsed_s))
        if response.status_code != 200:
            key = str(response.status_code)
            self.http_errors[key] = self.http_errors.get(key, 0) + 1
            return
        self.responses_ok += 1
        try:
            body = response.json()
        except ValueError:
            return
        if not isinstance(body, dict):
            return
        model = body.get("model")
        if isinstance(model, str) and model:
            self.models_seen[model] = self.models_seen.get(model, 0) + 1
        usage = body.get("usage")
        if isinstance(usage, dict):
            self.responses_with_usage += 1
            self.prompt_tokens += int(usage.get("prompt_tokens") or 0)
            self.completion_tokens += int(usage.get("completion_tokens") or 0)
            total = usage.get("total_tokens")
            self.total_tokens += int(total) if total is not None else (
                int(usage.get("prompt_tokens") or 0) + int(usage.get("completion_tokens") or 0)
            )

    def record_transport_error(self, name: str) -> None:
        self.transport_errors[name] = self.transport_errors.get(name, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "responses_ok": self.responses_ok,
            "http_errors": dict(sorted(self.http_errors.items())),
            "transport_errors": dict(sorted(self.transport_errors.items())),
            "retries": self.retries,
            "retry_after_honoured": self.retry_after_honoured,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "responses_with_usage": self.responses_with_usage,
            "wall_time_s": round(self.wall_time_s, 6),
            "models_seen": dict(sorted(self.models_seen.items())),
            "tls_mode": self.tls_mode,
        }


HttpClientFactory = Callable[["PythiaGenerator"], httpx.Client]


class PythiaGenerator(OpenAICompatible):
    """garak generator for chat models behind the Pythia gateway. See the module docstring for the contract."""

    ENV_VAR = None  # the key never comes from the environment
    active = True
    generator_family_name = "Pythia"
    supports_multiple_generations = False
    parallel_capable = False
    modality: dict = {"in": {"text"}, "out": {"text"}}

    DEFAULT_PARAMS = OpenAICompatible.DEFAULT_PARAMS | {
        "uri": "",
        "persona": None,
        "max_tokens": 400,
        "temperature": 0.7,
        "stop": None,
        "suppressed_params": set(SUPPRESSED_PARAMS),
        "request_timeout_s": 60.0,
        "transport_max_tries": 8,
        "transport_backoff_s": 1.0,
        "transport_max_sleep_s": 60.0,
        "retry_json": True,
    }

    _unsafe_attributes = ["client", "generator", "_http_client", "api_key", "http_client_factory"]

    def __init__(
        self,
        name: str = "",
        config_root: Any = _config,
        *,
        api_key: str | None = None,
        key_file: str | os.PathLike[str] | None = None,
        uri: str | None = None,
        persona: str | None = None,
        http_client_factory: HttpClientFactory | None = None,
    ) -> None:
        if api_key is not None and key_file is not None:
            raise ProbeKeyUnavailable("give the probe key as api_key or key_file, not both")
        if key_file is not None:
            api_key = read_key_file(key_file)
        if not api_key or not str(api_key).strip():
            raise ProbeKeyUnavailable(
                "PythiaGenerator takes the probe key from the caller (api_key= or key_file=), never from the environment"
            )
        self.api_key = str(api_key).strip()
        self.ledger = UsageLedger()
        self.http_client_factory = http_client_factory
        self._http_client: httpx.Client | None = None
        if uri is not None:
            self.uri = uri
        if persona is not None:
            self.persona = persona
        super().__init__(name, config_root=config_root)
        # garak names this in its 401 / 403 message; the key is the caller's, not an environment variable.
        self.key_env_var = "the caller-supplied probe key (AuthProfile)"

    # -- garak hooks ------------------------------------------------------------------------------

    def _validate_env_var(self) -> None:
        """Refuse to run without a caller-supplied key; the environment is never consulted."""
        if not getattr(self, "api_key", None):
            raise ProbeKeyUnavailable("probe key not supplied to PythiaGenerator")

    def _default_headers(self) -> dict[str, str]:
        persona = getattr(self, "persona", None)
        return {PERSONA_HEADER: str(persona)} if persona else {}

    def _build_http_client(self) -> httpx.Client:
        if self.http_client_factory is not None:
            client = self.http_client_factory(self)
            self.ledger.tls_mode = "injected"
        else:
            verify, mode = tls_verify()
            client = httpx.Client(verify=verify, timeout=float(self.request_timeout_s), trust_env=True)
            self.ledger.tls_mode = mode
        hooks = dict(client.event_hooks)
        hooks["request"] = list(hooks.get("request", [])) + [self._on_request]
        hooks["response"] = list(hooks.get("response", [])) + [self._on_response]
        client.event_hooks = hooks
        return client

    def _load_unsafe(self) -> None:
        if self.name in ("", None):
            raise ValueError(f"{self.generator_family_name} requires the canonical model id as name")
        if not str(getattr(self, "uri", "") or "").strip():
            raise ValueError("PythiaGenerator needs the gateway URI (gateway_uri(PYTHIA_BASE_URL))")
        self._http_client = self._build_http_client()
        self.client = openai.OpenAI(
            base_url=str(self.uri),
            api_key=self.api_key,
            default_headers=self._default_headers() or None,
            http_client=self._http_client,
            max_retries=0,
            timeout=float(self.request_timeout_s),
        )
        self.generator = self.client.chat.completions

    @staticmethod
    def _on_request(request: httpx.Request) -> None:
        request.extensions["redsim_started"] = time.monotonic()

    def _on_response(self, response: httpx.Response) -> None:
        try:
            response.read()
        except Exception:  # noqa: BLE001 - a body that cannot be read is still a counted response
            logger.debug("response body could not be read for the usage ledger", exc_info=True)
        started = response.request.extensions.get("redsim_started")
        elapsed = (time.monotonic() - float(started)) if isinstance(started, (int, float)) else None
        self.ledger.record_response(response, elapsed_s=elapsed)

    def _call_model(self, prompt: Any, generations_this_call: int = 1) -> list[Any]:
        """garak's request logic with a bounded retry loop instead of its uncapped backoff."""
        max_tries = max(1, int(self.transport_max_tries))
        tries = 0
        while True:
            try:
                result: list[Any] = _UNDECORATED_CALL(self, prompt, generations_this_call)
                return result
            except _RETRYABLE as exc:
                tries += 1
                self.ledger.record_transport_error(type(exc).__name__)
                if tries >= max_tries:
                    raise garak.exception.GarakException(
                        f"gateway transport failed after {tries} tries: {type(exc).__name__}"
                    ) from exc
                cap = float(self.transport_max_sleep_s)
                requested = retry_after_seconds(exc.response.headers.get("Retry-After")) if isinstance(
                    exc, openai.RateLimitError
                ) else None
                if requested is not None and requested > cap:
                    # Never retry earlier than the gateway permits or exceed the operator's bound.
                    raise garak.exception.GarakException("gateway Retry-After exceeds retry wait budget") from exc
                sleep_s = requested if requested is not None else min(
                    float(self.transport_backoff_s) * (2 ** (tries - 1)), cap
                )
                self.ledger.retries += 1
                if requested is not None:
                    self.ledger.retry_after_honoured += 1
                time.sleep(sleep_s)

    def close(self) -> None:
        super().close()
        client = getattr(self, "_http_client", None)
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001 - teardown
                pass
            self._http_client = None


# garak resolves plugin metadata by ``garak.<category>.<module>``; register this module under that name.
PythiaGenerator.__module__ = GARAK_MODULE_ALIAS
sys.modules.setdefault(GARAK_MODULE_ALIAS, sys.modules[__name__])
DEFAULT_CLASS = "PythiaGenerator"


def assert_no_litellm() -> None:
    """No litellm code path: not imported, and not in the generator's ancestry (plan 12 section 1)."""
    loaded = sorted(name for name in sys.modules if name.split(".")[0] == "litellm")
    if loaded:
        raise RuntimeError(f"litellm was imported by the probe process: {loaded[:3]}")
    for klass in PythiaGenerator.__mro__:
        if "litellm" in str(getattr(klass, "__module__", "")):
            raise RuntimeError(f"litellm class in the generator ancestry: {klass!r}")


__all__ = [
    "GARAK_MODULE_ALIAS",
    "KEY_PATTERN",
    "PERSONA_HEADER",
    "REDACTED",
    "SUPPRESSED_PARAMS",
    "TARGET_TYPE",
    "HttpClientFactory",
    "ProbeKeyUnavailable",
    "PythiaGenerator",
    "UsageLedger",
    "assert_no_litellm",
    "gateway_uri",
    "read_key_file",
    "scrub_secrets",
]
