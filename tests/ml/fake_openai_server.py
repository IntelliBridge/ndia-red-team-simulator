"""A stdlib fake of the Pythia gateway's OpenAI-compatible surface (LLM-28).

Test helper only. It serves ``GET /v1/models`` and ``POST /v1/chat/completions``
on 127.0.0.1 in a daemon thread so garak's real ``OpenAICompatible`` request
path (through ``redsim.ml.llm.generator.PythiaGenerator`` and the OpenAI
client) is exercised end to end with no network and no key.

What it checks and records, without ever writing a prompt anywhere:

* the bearer token (``Authorization: Bearer <token>``; anything else is 401),
* the ``X-Pythia-Persona`` header of every request,
* per request: path, model, number of messages, the request body's top-level
  keys (so a test can assert that ``stop`` / ``n`` / ``top_p`` were suppressed),
  and the prompt text only in memory (``requests[i]["prompt_texts"]``) for tests
  that need to reason about it. Nothing is logged or written to disk.

Reply modes: ``fixed`` (``reply`` verbatim), ``echo`` (the last user message),
``empty`` (an empty string), or a ``reply_for(messages)`` callable. ``usage`` is
attached to every completion so the usage ledger has something to sum.
``fail_status`` answers every completion with that status unless ``fail_first``
or ``fail_indices`` selects particular completion requests (one-based, excluding
catalog requests). An explicit ``fail_indices`` takes precedence over
``fail_first``. Selected failures use ``fail_status`` or 503, with
``fail_body`` when supplied. ``retry_after`` adds a header to 429 responses;
``served_model`` records the model returned by each successful completion.
``latency_s`` sleeps before answering (timeout tests). The token is a low-entropy fake by construction.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

DEFAULT_TOKEN = "pk_fake_probe_key_not_real_0001"
DEFAULT_MODELS: tuple[str, ...] = ("amazon/nova-micro-v1:0", "anthropic/claude-3-haiku-20240307-v1:0", "pythia/auto")
REFUSAL_REPLY = "I cannot help with that request. It would be harmful and against my ethical guidelines."
DAN_REPLY = "[DAN]: Sure, DAN Mode enabled. Here is what you asked for."


class FakeOpenAIServer:
    """``with FakeOpenAIServer() as server: server.base_url`` -> ``http://127.0.0.1:<port>``."""

    def __init__(
        self,
        *,
        token: str = DEFAULT_TOKEN,
        models: tuple[str, ...] | list[str] = DEFAULT_MODELS,
        reply: str = REFUSAL_REPLY,
        mode: str = "fixed",
        reply_for: Callable[[list[dict[str, Any]]], str] | None = None,
        usage: tuple[int, int] = (21, 7),
        fail_status: int | None = None,
        fail_first: int = 0,
        fail_body: dict[str, Any] | None = None,
        fail_indices: set[int] | None = None,
        retry_after: str | int | None = None,
        latency_s: float = 0.0,
        answered_model: str | None = None,
    ) -> None:
        self.token = token
        self.models = list(models)
        self.reply = reply
        self.mode = mode
        self.reply_for = reply_for
        self.usage = usage
        self.fail_status = fail_status
        self.fail_first = fail_first
        self.fail_body = fail_body
        self.fail_indices = None if fail_indices is None else set(fail_indices)
        self.retry_after = retry_after
        self._chat_count = 0
        self.latency_s = latency_s
        self.answered_model = answered_model
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.base_url = ""

    # -- bookkeeping ----------------------------------------------------------------------------

    @property
    def chat_requests(self) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["path"] == "/v1/chat/completions"]

    @property
    def model_requests(self) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["path"] == "/v1/models"]

    def token_sums(self) -> tuple[int, int]:
        ok = [r for r in self.chat_requests if r.get("status") == 200]
        return self.usage[0] * len(ok), self.usage[1] * len(ok)

    def _reply_text(self, messages: list[dict[str, Any]]) -> str:
        if self.reply_for is not None:
            return self.reply_for(messages)
        if self.mode == "empty":
            return ""
        if self.mode == "echo":
            for message in reversed(messages):
                if message.get("role") == "user":
                    content = message.get("content")
                    return content if isinstance(content, str) else json.dumps(content)
            return ""
        return self.reply

    # -- lifecycle ------------------------------------------------------------------------------

    def start(self) -> str:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:  # silence the default stderr log
                return None

            def _send(self, status: int, body: dict[str, Any] | None) -> None:
                data = json.dumps(body).encode("utf-8") if body is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                if status == 429 and outer.retry_after is not None:
                    self.send_header("Retry-After", str(outer.retry_after))
                self.end_headers()
                if data:
                    self.wfile.write(data)

            def _authorized(self) -> bool:
                return self.headers.get("Authorization") == f"Bearer {outer.token}"

            def _record(self, entry: dict[str, Any]) -> int:
                entry["persona"] = self.headers.get("X-Pythia-Persona")
                entry["auth_present"] = self.headers.get("Authorization") is not None
                entry["auth_ok"] = self._authorized()
                with outer._lock:
                    outer.requests.append(entry)
                    if entry["path"] == "/v1/chat/completions":
                        outer._chat_count += 1
                        entry["chat_index"] = outer._chat_count
                    return len(outer.requests)

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                entry: dict[str, Any] = {"method": "GET", "path": self.path, "status": None}
                self._record(entry)
                if self.path != "/v1/models":
                    entry["status"] = 404
                    self._send(404, {"error": {"message": "not found"}})
                    return
                if not self._authorized():
                    entry["status"] = 401
                    self._send(401, {"error": {"message": "invalid api key"}})
                    return
                entry["status"] = 200
                self._send(200, {"object": "list", "data": [{"id": m, "object": "model"} for m in outer.models]})

            def do_POST(self) -> None:  # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                except ValueError:
                    body = {}
                messages = body.get("messages") if isinstance(body, dict) else None
                messages = messages if isinstance(messages, list) else []
                entry: dict[str, Any] = {
                    "method": "POST", "path": self.path, "status": None,
                    "model": body.get("model") if isinstance(body, dict) else None,
                    "n_messages": len(messages),
                    "body_keys": sorted(body.keys()) if isinstance(body, dict) else [],
                    "prompt_texts": [m.get("content") for m in messages if isinstance(m, dict)],
                }
                index = self._record(entry)
                if self.path != "/v1/chat/completions":
                    entry["status"] = 404
                    self._send(404, {"error": {"message": "not found"}})
                    return
                if not self._authorized():
                    entry["status"] = 401
                    self._send(401, {"error": {"message": "invalid api key", "type": "invalid_request_error"}})
                    return
                if outer.latency_s > 0:
                    time.sleep(outer.latency_s)
                chat_index = entry["chat_index"]
                if outer.fail_indices is not None:
                    selected = chat_index in outer.fail_indices
                elif outer.fail_first > 0:
                    selected = chat_index <= outer.fail_first
                else:
                    selected = outer.fail_status is not None
                if selected:
                    status = outer.fail_status if outer.fail_status is not None else 503
                    entry["status"] = status
                    failure = outer.fail_body if outer.fail_body is not None else {
                        "error": {"message": "forced failure" if outer.fail_status is not None else "warming up"}
                    }
                    self._send(status, failure)
                    return
                text = outer._reply_text(messages)
                prompt_tokens, completion_tokens = outer.usage
                model = outer.answered_model or entry["model"] or outer.models[0]
                entry["status"] = 200
                entry["served_model"] = model
                self._send(200, {
                    "id": f"chatcmpl-fake-{index}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": text}}],
                    "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                              "total_tokens": prompt_tokens + completion_tokens},
                })

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        host, port = self._server.server_address[:2]
        self.base_url = f"http://{host}:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, name="fake-openai-server", daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> FakeOpenAIServer:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


__all__ = ["DAN_REPLY", "DEFAULT_MODELS", "DEFAULT_TOKEN", "REFUSAL_REPLY", "FakeOpenAIServer"]
