"""Pythia gateway client for the optional LLM hardening narrative.

Pythia (https://github.com/IntelliBridge/pythia) is IntelliBridge's
OpenAI-compatible agent gateway. Aegis never talks to a model provider
directly: it holds only a Pythia ``pk_…`` key, and the gateway applies
persona, guardrails, metering and audit.

Wire contract (mirrors ``pythia_sdk._common``):

* ``POST {base_url}/v1/chat/completions`` with ``{"model", "messages", ...}``
* ``Authorization: Bearer pk_…``
* optional ``X-Pythia-Persona: <persona>``
* model ids are canonical ``<vendor>/<model>`` or ``pythia/auto``

When the official ``pythia_sdk`` package is importable it is used; otherwise
the same request is made with ``httpx``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

CHAT_PATH = "/v1/chat/completions"


class PythiaUnavailable(RuntimeError):
    """Raised when the narrative was requested but Pythia is not configured."""


@dataclass(frozen=True)
class PythiaSettings:
    base_url: str
    api_key: str
    model: str
    persona: str | None = None
    timeout_s: float = 60.0

    @classmethod
    def from_env(cls) -> "PythiaSettings | None":
        """Return settings when all required variables are present, else ``None``."""
        base = os.environ.get("PYTHIA_BASE_URL", "").strip()
        key = os.environ.get("PYTHIA_API_KEY", "").strip()
        model = os.environ.get("REDSIM_LLM_MODEL", "").strip()
        if not (base and key and model):
            return None
        persona = os.environ.get("PYTHIA_PERSONA", "").strip() or None
        timeout = float(os.environ.get("PYTHIA_TIMEOUT_S", "60"))
        return cls(base_url=base.rstrip("/"), api_key=key, model=model, persona=persona, timeout_s=timeout)

    def headers(self) -> dict[str, str]:
        h = {"Authorization": f"Bearer {self.api_key}"}
        if self.persona:
            h["X-Pythia-Persona"] = self.persona
        return h

    def redacted(self) -> dict[str, Any]:
        """Provenance-safe view: never includes the key."""
        return {"gateway": "pythia", "base_url": self.base_url, "model": self.model, "persona": self.persona}


class ChatBackend(Protocol):
    def chat(self, model: str, messages: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]: ...


class _HttpxBackend:
    def __init__(self, settings: PythiaSettings, transport: httpx.BaseTransport | None = None) -> None:
        self._client = httpx.Client(base_url=settings.base_url, headers=settings.headers(),
                                    timeout=settings.timeout_s, transport=transport)

    def chat(self, model: str, messages: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        resp = self._client.post(CHAT_PATH, json={"model": model, "messages": messages, **kwargs})
        resp.raise_for_status()
        return resp.json()


def make_backend(settings: PythiaSettings, transport: httpx.BaseTransport | None = None) -> ChatBackend:
    """Prefer the official SDK; fall back to the in-repo httpx client."""
    if transport is None:
        try:
            from pythia_sdk import PythiaClient  # type: ignore[import-not-found]
            return PythiaClient(settings.base_url, settings.api_key, persona=settings.persona,
                                timeout=settings.timeout_s)
        except ImportError:
            pass
    return _HttpxBackend(settings, transport=transport)


def chat_text(settings: PythiaSettings, system: str, user: str, *, backend: ChatBackend | None = None,
              temperature: float = 0.2, max_tokens: int = 800) -> str:
    """One non-streaming chat turn; returns the assistant text."""
    be = backend or make_backend(settings)
    resp = be.chat(settings.model,
                   [{"role": "system", "content": system}, {"role": "user", "content": user}],
                   temperature=temperature, max_tokens=max_tokens)
    try:
        content = resp["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("unexpected Pythia chat response shape") from exc
    if isinstance(content, list):  # content-block form
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    return str(content or "").strip()
