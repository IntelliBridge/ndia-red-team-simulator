"""Tests for ``python -m redsim.llm.pythia_check`` against a mock gateway."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from redsim.llm import pythia, pythia_check

# Synthetic gateway key: hyphenated so no secret scanner mistakes it for a real token.
KEY = "pk_fixture-not-a-real-key-0123456789-abcdef"
ENV = {"PYTHIA_BASE_URL": "https://gw.example/", "PYTHIA_API_KEY": KEY, "PYTHIA_PERSONA": "analyst",
       "REDSIM_ML_LLM_MODEL": "amazon/nova-lite-v1:0"}

MODELS = {"object": "list", "data": [{"id": "pythia/auto"}, {"id": "amazon/nova-lite-v1:0"},
                                     {"id": "anthropic/claude-3-5-haiku"}]}
CHAT = {"id": "chatcmpl-1", "model": "amazon/nova-lite-v1:0",
        "choices": [{"message": {"role": "assistant", "content": "pong"}}],
        "usage": {"prompt_tokens": 21, "completion_tokens": 2, "total_tokens": 23}}


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """No stray .env can leak in: point REDSIM_ENV_FILE at a file that does not exist."""
    monkeypatch.setenv(pythia.ENV_FILE_VAR, str(tmp_path / "absent.env"))
    return tmp_path


def _env(**overrides):
    env = dict(ENV)
    env.update(overrides)
    env[pythia.ENV_FILE_VAR] = "/nonexistent/redsim-test.env"
    return env


def _gateway(seen, *, models=MODELS, chat=CHAT, chat_status=200, models_status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "GET" and request.url.path == "/v1/models":
            return httpx.Response(models_status, json=models)
        if request.method == "POST" and request.url.path == "/v1/chat/completions":
            return httpx.Response(chat_status, json=chat)
        return httpx.Response(404, json={"error": "unknown path"})

    return httpx.MockTransport(handler)


def _run(env, transport, argv=()):
    out = io.StringIO()
    code = pythia_check.run(list(argv), environ=env, transport=transport, out=out)
    return code, out.getvalue()


def test_happy_path_reports_models_reply_latency_and_usage(isolated):
    seen = []
    code, text = _run(_env(), _gateway(seen))
    assert code == 0, text
    assert "PYTHIA_BASE_URL:  https://gw.example/" in text
    assert "PYTHIA_PERSONA:   analyst" in text
    assert "REDSIM_ML_LLM_MODEL: amazon/nova-lite-v1:0" in text
    assert "TLS:              transport" in text
    assert "models: 3 entitled. First: pythia/auto, amazon/nova-lite-v1:0, anthropic/claude-3-5-haiku" in text
    assert "chat: ok in " in text and " ms via model amazon/nova-lite-v1:0" in text
    assert "reply: 'pong'" in text
    assert "usage: prompt=21 completion=2 total=23" in text
    assert text.rstrip().endswith("OK")
    # exactly one GET then one short POST, with the persona header and no tools
    assert [(r.method, r.url.path) for r in seen] == [("GET", "/v1/models"), ("POST", "/v1/chat/completions")]
    body = json.loads(seen[1].content)
    assert body["model"] == "amazon/nova-lite-v1:0" and body["max_tokens"] <= 64 and "tools" not in body
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert seen[1].headers["x-pythia-persona"] == "analyst"


def test_key_is_never_printed_only_its_three_char_prefix(isolated):
    code, text = _run(_env(), _gateway([]))
    assert code == 0
    assert KEY not in text
    assert f"PYTHIA_API_KEY:   pk_… ({len(KEY)} chars)" in text


def test_key_is_scrubbed_from_error_output(isolated):
    """A gateway error body that echoes the key must still not reach the terminal."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/models":
            return httpx.Response(500, text=f"boom {KEY} boom")
        return httpx.Response(200, json=CHAT)

    code, text = _run(_env(), httpx.MockTransport(handler))
    assert code == 1
    assert KEY not in text and "FAIL: GET /v1/models failed: HTTP 500 boom pk_…" in text


def test_missing_settings_exit_1_and_name_them(isolated):
    env = _env()
    env.pop("PYTHIA_API_KEY")
    env["REDSIM_ML_LLM_MODEL"] = ""
    code, text = _run(env, _gateway([]))
    assert code == 1
    assert "PYTHIA_API_KEY:   (unset)" in text
    assert "REDSIM_ML_LLM_MODEL: (unset)" in text
    assert "FAIL: missing PYTHIA_API_KEY, REDSIM_ML_LLM_MODEL." in text


def test_deprecated_alias_is_accepted_and_flagged(isolated, recwarn):
    env = _env()
    env["AEGIS_ML_LLM_MODEL"] = env.pop("REDSIM_ML_LLM_MODEL")
    code, text = _run(env, _gateway([]))
    assert code == 0
    assert "REDSIM_ML_LLM_MODEL: amazon/nova-lite-v1:0  (read from deprecated AEGIS_ML_LLM_MODEL" in text
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning)], "check swallows the warning"


def test_model_override_and_not_entitled_note(isolated):
    seen = []
    code, text = _run(_env(), _gateway(seen), argv=["--model", "openai/gpt-4o-mini"])
    assert code == 0
    assert "REDSIM_ML_LLM_MODEL: openai/gpt-4o-mini  (from --model)" in text
    assert "note: openai/gpt-4o-mini is not in the entitled list" in text
    assert json.loads(seen[1].content)["model"] == "openai/gpt-4o-mini"


def test_skip_chat_stops_after_models(isolated):
    seen = []
    code, text = _run(_env(), _gateway(seen), argv=["--skip-chat", "--show-models", "1"])
    assert code == 0
    assert "models: 3 entitled. First: pythia/auto" in text and "anthropic" not in text
    assert text.rstrip().endswith("OK (chat probe skipped)")
    assert [r.url.path for r in seen] == ["/v1/models"]


def test_models_http_error_exits_1(isolated):
    code, text = _run(_env(), _gateway([], models={"error": "bad key"}, models_status=401))
    assert code == 1
    assert 'FAIL: GET /v1/models failed: HTTP 401 {"error":"bad key"}' in text


def test_chat_http_error_exits_1(isolated):
    code, text = _run(_env(), _gateway([], chat={"error": {"code": "model_forbidden"}}, chat_status=403))
    assert code == 1
    assert "models: 3 entitled" in text
    assert "FAIL: POST /v1/chat/completions failed: HTTP 403" in text and "model_forbidden" in text


def test_transport_error_exits_1(isolated):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("name resolution failed")

    code, text = _run(_env(), httpx.MockTransport(handler))
    assert code == 1
    assert "FAIL: GET /v1/models failed: ConnectError: name resolution failed" in text


def test_bad_chat_shape_exits_1(isolated):
    code, text = _run(_env(), _gateway([], chat={"choices": []}))
    assert code == 1
    assert "FAIL: POST /v1/chat/completions failed: RuntimeError: unexpected Pythia chat response shape" in text


def test_settings_come_from_env_file_when_environment_is_empty(isolated):
    env_file = isolated / "pythia.env"
    env_file.write_text("\n".join(f"{k}={v}" for k, v in ENV.items()) + "\n")
    code, text = _run({pythia.ENV_FILE_VAR: str(env_file)}, _gateway([]))
    assert code == 0
    assert f"env file:         {env_file}" in text
    assert KEY not in text


def test_module_is_runnable_with_python_dash_m_and_exits_1_without_settings(isolated):
    """The documented entry point is ``python -m redsim.llm.pythia_check``."""
    env = {k: v for k, v in os.environ.items()
           if k not in {"PYTHIA_BASE_URL", "PYTHIA_API_KEY", "PYTHIA_PERSONA", pythia.MODEL_ENV,
                        *pythia.DEPRECATED_MODEL_ENV}}
    env[pythia.ENV_FILE_VAR] = str(isolated / "absent.env")
    repo_root = Path(pythia.__file__).resolve().parents[2]  # the package is imported from the checkout
    proc = subprocess.run([sys.executable, "-m", "redsim.llm.pythia_check", "--skip-chat"], env=env,
                          cwd=str(repo_root), capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    # --skip-chat proves the key alone, so the narrative model is not required.
    assert "FAIL: missing PYTHIA_BASE_URL, PYTHIA_API_KEY." in proc.stdout
