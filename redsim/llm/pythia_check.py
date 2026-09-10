"""Connectivity check for the Pythia gateway.

Run with ``python -m redsim.llm.pythia_check``. It reads the same settings as
the hardening writer (process environment first, then the ``.env`` file named
by ``REDSIM_ENV_FILE``, default ``./.env``), reports which ones are present
without ever printing the key, lists the models the key is entitled to, and
runs one short chat completion. Exit status is 0 on success and 1 on any
failure, with a plain one-line reason.
"""

from __future__ import annotations

import argparse
import sys
import time
import warnings
from collections.abc import Mapping, Sequence
from typing import Any, TextIO

import httpx

from redsim.llm import pythia

PROBE_SYSTEM = "You are a connectivity probe. Answer in one short sentence."
PROBE_USER = "Reply with the single word: pong."
KEY_PREFIX_CHARS = 3


def _mask(key: str) -> str:
    """Only the first three characters of the key are ever shown."""
    if not key:
        return "(unset)"
    return f"{key[:KEY_PREFIX_CHARS]}… ({len(key)} chars)"


class _Printer:
    """Writes lines to ``out`` with the API key scrubbed from anything printed."""

    def __init__(self, out: TextIO, secret: str = "") -> None:
        self._out = out
        self._secret = secret

    def __call__(self, line: str = "") -> None:
        if self._secret and self._secret in line:
            line = line.replace(self._secret, _mask(self._secret))
        self._out.write(line + "\n")


def _http_failure(step: str, exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        body = exc.response.text.strip().replace("\n", " ")
        return f"{step} failed: HTTP {exc.response.status_code} {body[:200]}"
    if isinstance(exc, httpx.HTTPError):
        return f"{step} failed: {type(exc).__name__}: {exc}"
    return f"{step} failed: {type(exc).__name__}: {exc}"


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m redsim.llm.pythia_check",
                                     description="Check that redsim can reach the Pythia gateway.")
    parser.add_argument("--model", help=f"override {pythia.MODEL_ENV} for the chat probe")
    parser.add_argument("--show-models", type=int, default=8, metavar="N",
                        help="how many entitled model ids to print (default 8)")
    parser.add_argument("--skip-chat", action="store_true", help="stop after GET /v1/models")
    parser.add_argument("--timeout", type=float, default=None, metavar="SECONDS",
                        help="request timeout (default PYTHIA_TIMEOUT_S or 60)")
    return parser.parse_args(argv)


def run(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None, out: TextIO | None = None) -> int:
    """Run the check. ``environ`` and ``transport`` exist for tests."""
    args = parse_args(argv)
    stream = out if out is not None else sys.stdout

    env = pythia.resolve_env(environ)
    env_path = pythia.env_file_path(environ)
    base = env.get("PYTHIA_BASE_URL", "").strip()
    key = env.get("PYTHIA_API_KEY", "").strip()
    persona = env.get("PYTHIA_PERSONA", "").strip()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        model, model_source = pythia.resolve_model(env)
    if args.model:
        model, model_source = args.model, "--model"

    say = _Printer(stream, key)
    say("Pythia connectivity check")
    say(f"  env file:         {env_path if env_path else '(none found)'}")
    say(f"  PYTHIA_BASE_URL:  {base or '(unset)'}")
    say(f"  PYTHIA_API_KEY:   {_mask(key)}")
    say(f"  PYTHIA_PERSONA:   {persona or '(unset)'}")
    model_note = ""
    if model_source and model_source not in (pythia.MODEL_ENV, "--model"):
        model_note = f"  (read from deprecated {model_source}, rename it to {pythia.MODEL_ENV})"
    elif model_source == "--model":
        model_note = "  (from --model)"
    say(f"  {pythia.MODEL_ENV}: {model or '(unset)'}{model_note}")

    # The model roster needs the gateway and the key only, so --skip-chat can
    # prove a key without a narrative model having been chosen (the same
    # rule GET /v1/llm/models applies); the chat probe still needs the model.
    required = [("PYTHIA_BASE_URL", base), ("PYTHIA_API_KEY", key)]
    if not args.skip_chat:
        required.append((pythia.MODEL_ENV, model))
    missing = [name for name, value in required if not value]
    if missing:
        say(f"FAIL: missing {', '.join(missing)}. Set them in the environment or in {env_path or './.env'}.")
        return 1

    timeout = args.timeout if args.timeout is not None else float(env.get("PYTHIA_TIMEOUT_S", "").strip() or "60")
    settings = pythia.PythiaSettings(base_url=base.rstrip("/"), api_key=key, model=model,
                                     persona=persona or None, timeout_s=timeout)
    backend = pythia._HttpxBackend(settings, transport=transport)
    say(f"  TLS:              {backend.tls_mode}")

    try:
        models = backend.models()
    except Exception as exc:  # noqa: BLE001 - report any failure plainly and exit 1
        say("FAIL: " + _http_failure("GET /v1/models", exc))
        return 1
    ids = [str(m.get("id")) for m in models if m.get("id")]
    shown = ", ".join(ids[: max(args.show_models, 0)]) if ids else "(none)"
    say(f"models: {len(ids)} entitled. First: {shown}")
    if ids and model and model != "pythia/auto" and model not in ids:
        say(f"  note: {model} is not in the entitled list, the chat probe may be refused")

    if args.skip_chat:
        say("OK (chat probe skipped)")
        return 0

    messages: list[dict[str, Any]] = [{"role": "system", "content": PROBE_SYSTEM},
                                      {"role": "user", "content": PROBE_USER}]
    started = time.perf_counter()
    try:
        resp = backend.chat(model, messages, temperature=0, max_tokens=32)
        reply = pythia.extract_text(resp)
    except Exception as exc:  # noqa: BLE001 - report any failure plainly and exit 1
        say("FAIL: " + _http_failure("POST /v1/chat/completions", exc))
        return 1
    latency_ms = (time.perf_counter() - started) * 1000.0
    raw_usage = resp.get("usage")
    usage: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
    say(f"chat: ok in {latency_ms:.0f} ms via model {resp.get('model') or model}")
    say(f"  reply: {reply!r}")
    say(f"  usage: prompt={usage.get('prompt_tokens', '?')} completion={usage.get('completion_tokens', '?')} "
        f"total={usage.get('total_tokens', '?')}")
    say("OK")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
