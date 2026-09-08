import json

import httpx
import pytest

from aegis.llm.pythia import PythiaSettings, _HttpxBackend, chat_text


def _settings(**kw):
    base = dict(base_url="https://gw.example", api_key="pk_test", model="pythia/auto", persona="analyst")
    base.update(kw)
    return PythiaSettings(**base)


def test_from_env_requires_all_three(monkeypatch):
    for k in ("PYTHIA_BASE_URL", "PYTHIA_API_KEY", "REDSIM_LLM_MODEL", "PYTHIA_PERSONA"):
        monkeypatch.delenv(k, raising=False)
    assert PythiaSettings.from_env() is None
    monkeypatch.setenv("PYTHIA_BASE_URL", "https://gw.example/")
    monkeypatch.setenv("PYTHIA_API_KEY", "pk_x")
    assert PythiaSettings.from_env() is None
    monkeypatch.setenv("REDSIM_LLM_MODEL", "amazon/nova-lite-v1:0")
    s = PythiaSettings.from_env()
    assert s is not None and s.base_url == "https://gw.example" and s.persona is None


def test_headers_and_redaction():
    s = _settings()
    assert s.headers() == {"Authorization": "Bearer pk_test", "X-Pythia-Persona": "analyst"}
    assert "pk_test" not in json.dumps(s.redacted())


def test_chat_text_hits_openai_compatible_path():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["headers"] = dict(request.headers)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "  hello  "}}]})

    s = _settings()
    be = _HttpxBackend(s, transport=httpx.MockTransport(handler))
    assert chat_text(s, "sys", "usr", backend=be) == "hello"
    assert seen["url"] == "https://gw.example/v1/chat/completions"
    assert seen["headers"]["authorization"] == "Bearer pk_test"
    assert seen["headers"]["x-pythia-persona"] == "analyst"
    assert seen["body"]["model"] == "pythia/auto"
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]


def test_chat_text_raises_on_gateway_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"code": "model_forbidden"}})

    s = _settings()
    be = _HttpxBackend(s, transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        chat_text(s, "sys", "usr", backend=be)
