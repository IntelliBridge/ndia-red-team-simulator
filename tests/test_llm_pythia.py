import json
import ssl

import httpx
import pytest

from redsim.llm import pythia
from redsim.llm.pythia import PythiaSettings, _HttpxBackend, chat_text, list_models


def _settings(**kw):
    base = {"base_url": "https://gw.example", "api_key": "pk_test", "model": "pythia/auto", "persona": "analyst"}
    base.update(kw)
    return PythiaSettings(**base)


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    """No Pythia variables set and no .env file in reach."""
    for k in ("PYTHIA_BASE_URL", "PYTHIA_API_KEY", "PYTHIA_PERSONA", "PYTHIA_TIMEOUT_S",
              pythia.MODEL_ENV, *pythia.DEPRECATED_MODEL_ENV):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv(pythia.ENV_FILE_VAR, str(tmp_path / "absent.env"))
    # The repo-root fallback must not find a developer's real .env during tests.
    monkeypatch.setattr(pythia, "_REPO_ROOT", tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# from_env
# ---------------------------------------------------------------------------


def test_from_env_requires_all_three(clean_env, monkeypatch):
    assert PythiaSettings.from_env() is None
    monkeypatch.setenv("PYTHIA_BASE_URL", "https://gw.example/")
    monkeypatch.setenv("PYTHIA_API_KEY", "pk_x")
    assert PythiaSettings.from_env() is None
    monkeypatch.setenv(pythia.MODEL_ENV, "amazon/nova-lite-v1:0")
    s = PythiaSettings.from_env()
    assert s is not None and s.base_url == "https://gw.example" and s.persona is None
    assert s.model == "amazon/nova-lite-v1:0" and s.timeout_s == 60.0


def test_from_env_accepts_deprecated_aegis_alias_with_warning(clean_env, monkeypatch):
    monkeypatch.setenv("PYTHIA_BASE_URL", "https://gw.example")
    monkeypatch.setenv("PYTHIA_API_KEY", "pk_x")
    monkeypatch.setenv("AEGIS_ML_LLM_MODEL", "anthropic/claude-3-5-haiku")
    with pytest.warns(DeprecationWarning, match="AEGIS_ML_LLM_MODEL is deprecated"):
        s = PythiaSettings.from_env()
    assert s is not None and s.model == "anthropic/claude-3-5-haiku"


def test_from_env_canonical_name_wins_over_alias_without_warning(clean_env, monkeypatch, recwarn):
    monkeypatch.setenv("PYTHIA_BASE_URL", "https://gw.example")
    monkeypatch.setenv("PYTHIA_API_KEY", "pk_x")
    monkeypatch.setenv("AEGIS_ML_LLM_MODEL", "old/model")
    monkeypatch.setenv(pythia.MODEL_ENV, "new/model")
    s = PythiaSettings.from_env()
    assert s is not None and s.model == "new/model"
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning)]


def test_resolve_model_precedence_and_source(clean_env):
    assert pythia.resolve_model({}) == ("", None)
    assert pythia.resolve_model({pythia.MODEL_ENV: " a/b "}) == ("a/b", pythia.MODEL_ENV)
    with pytest.warns(DeprecationWarning):
        assert pythia.resolve_model({"REDSIM_LLM_MODEL": "c/d"}) == ("c/d", "REDSIM_LLM_MODEL")
    with pytest.warns(DeprecationWarning):
        assert pythia.resolve_model({"AEGIS_ML_LLM_MODEL": "e/f", "REDSIM_LLM_MODEL": "c/d"}) == (
            "e/f", "AEGIS_ML_LLM_MODEL")


def test_from_env_reads_explicit_mapping_without_touching_os_environ(clean_env):
    env = {"PYTHIA_BASE_URL": "https://gw.example", "PYTHIA_API_KEY": "pk_m", pythia.MODEL_ENV: "x/y",
           "PYTHIA_PERSONA": "  ", "PYTHIA_TIMEOUT_S": "12.5"}
    s = PythiaSettings.from_env(env)
    assert s == PythiaSettings(base_url="https://gw.example", api_key="pk_m", model="x/y", persona=None,
                               timeout_s=12.5)


# ---------------------------------------------------------------------------
# .env file loading
# ---------------------------------------------------------------------------


def test_parse_env_file_handles_comments_quotes_export_and_inline_comments():
    text = """# comment

export PYTHIA_BASE_URL=https://gw.example/
PYTHIA_API_KEY='pk_quoted'
PYTHIA_PERSONA="analyst"
REDSIM_ML_LLM_MODEL=pythia/auto # trailing comment
not a key value line
1BAD=key
EMPTY=
LAST=one
LAST=two
"""
    parsed = pythia.parse_env_file(text)
    assert parsed == {"PYTHIA_BASE_URL": "https://gw.example/", "PYTHIA_API_KEY": "pk_quoted",
                      "PYTHIA_PERSONA": "analyst", "REDSIM_ML_LLM_MODEL": "pythia/auto", "EMPTY": "",
                      "LAST": "two"}


def test_from_env_loads_env_file_and_environment_wins(clean_env, monkeypatch):
    env_file = clean_env / "my.env"
    env_file.write_text("PYTHIA_BASE_URL=https://file.example\nPYTHIA_API_KEY=pk_file\n"
                        "REDSIM_ML_LLM_MODEL=file/model\nPYTHIA_PERSONA=file-persona\n")
    monkeypatch.setenv(pythia.ENV_FILE_VAR, str(env_file))
    s = PythiaSettings.from_env()
    assert s == PythiaSettings(base_url="https://file.example", api_key="pk_file", model="file/model",
                               persona="file-persona")
    # the process environment overrides the file, key by key
    monkeypatch.setenv("PYTHIA_API_KEY", "pk_env")
    monkeypatch.setenv("PYTHIA_PERSONA", "")
    s = PythiaSettings.from_env()
    assert s is not None and s.api_key == "pk_env" and s.persona is None and s.base_url == "https://file.example"
    # loading never mutates os.environ
    import os
    assert "PYTHIA_BASE_URL" not in os.environ


def test_env_file_defaults_to_cwd_dot_env(clean_env, monkeypatch):
    monkeypatch.delenv(pythia.ENV_FILE_VAR, raising=False)
    monkeypatch.chdir(clean_env)
    assert pythia.env_file_path() is None
    (clean_env / ".env").write_text("PYTHIA_BASE_URL=https://cwd.example\n")
    assert pythia.env_file_path() == clean_env / ".env"
    assert pythia.load_env_file() == {"PYTHIA_BASE_URL": "https://cwd.example"}


def test_env_file_can_be_disabled(clean_env, monkeypatch):
    env_file = clean_env / "my.env"
    env_file.write_text("PYTHIA_BASE_URL=https://file.example\nPYTHIA_API_KEY=pk_file\n"
                        "REDSIM_ML_LLM_MODEL=file/model\n")
    monkeypatch.setenv(pythia.ENV_FILE_VAR, str(env_file))
    assert PythiaSettings.from_env() is not None
    assert PythiaSettings.from_env(env_file=False) is None


def test_missing_explicit_env_file_is_ignored(clean_env):
    assert pythia.env_file_path() is None
    assert pythia.load_env_file() == {}
    assert pythia.resolve_env({"A": "1"}) == {"A": "1"}


# ---------------------------------------------------------------------------
# TLS verification
# ---------------------------------------------------------------------------


def test_tls_verify_prefers_truststore_when_enabled():
    truststore = pytest.importorskip("truststore")
    verify, mode = pythia.tls_verify({})
    assert mode == "truststore"
    assert isinstance(verify, truststore.SSLContext)


@pytest.mark.parametrize("off", ["0", "false", "No", "OFF"])
def test_tls_verify_falls_back_to_default_when_truststore_off(off):
    verify, mode = pythia.tls_verify({pythia.TRUSTSTORE_VAR: off})
    assert (verify, mode) == (True, "default")


def test_tls_verify_uses_ca_bundle_path(monkeypatch, tmp_path):
    seen = {}

    def fake_create_default_context(*, cafile=None):
        seen["cafile"] = cafile
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    monkeypatch.setattr(pythia.ssl, "create_default_context", fake_create_default_context)
    bundle = tmp_path / "zscaler.pem"
    verify, mode = pythia.tls_verify({pythia.TRUSTSTORE_VAR: "0", "SSL_CERT_FILE": str(bundle)})
    assert isinstance(verify, ssl.SSLContext) and mode == f"ca-bundle:{bundle}"
    assert seen["cafile"] == str(bundle)
    # REDSIM_CA_BUNDLE takes precedence over SSL_CERT_FILE
    other = tmp_path / "other.pem"
    _, mode = pythia.tls_verify({pythia.TRUSTSTORE_VAR: "0", "SSL_CERT_FILE": str(bundle),
                                 pythia.CA_BUNDLE_VAR: str(other)})
    assert mode == f"ca-bundle:{other}" and seen["cafile"] == str(other)


def test_httpx_backend_uses_tls_verify_unless_a_transport_is_given(monkeypatch):
    calls = []
    real_client = httpx.Client

    class SpyClient(real_client):
        def __init__(self, **kw):
            calls.append(dict(kw))
            kw.pop("verify", None)  # keep the spy independent of the verify object
            super().__init__(**kw)

    monkeypatch.setattr(pythia.httpx, "Client", SpyClient)
    monkeypatch.setattr(pythia, "tls_verify", lambda environ=None: ("sentinel-verify", "stubbed"))
    be = _HttpxBackend(_settings())
    assert be.tls_mode == "stubbed" and calls[-1]["verify"] == "sentinel-verify"
    be = _HttpxBackend(_settings(), transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    assert be.tls_mode == "transport" and "verify" not in calls[-1]
    explicit_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    be = _HttpxBackend(_settings(), verify=explicit_ctx)
    assert be.tls_mode == "explicit" and calls[-1]["verify"] is explicit_ctx


# ---------------------------------------------------------------------------
# Wire contract
# ---------------------------------------------------------------------------


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


def test_chat_text_handles_content_blocks_and_bad_shapes():
    assert pythia.extract_text({"choices": [{"message": {"content": [{"type": "text", "text": "a"},
                                                                     {"type": "text", "text": "b"}]}}]}) == "ab"
    with pytest.raises(RuntimeError, match="unexpected Pythia chat response shape"):
        pythia.extract_text({"choices": []})


def test_chat_text_raises_on_gateway_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"code": "model_forbidden"}})

    s = _settings()
    be = _HttpxBackend(s, transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        chat_text(s, "sys", "usr", backend=be)


def test_list_models_reads_openai_style_data_list():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["method"] = request.method
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"object": "list", "data": [
            {"id": "pythia/auto", "object": "model"}, {"id": "amazon/nova-lite-v1:0", "object": "model"}, "junk"]})

    models = list_models(_settings(), transport=httpx.MockTransport(handler))
    assert [m["id"] for m in models] == ["pythia/auto", "amazon/nova-lite-v1:0"]
    assert seen == {"url": "https://gw.example/v1/models", "method": "GET", "auth": "Bearer pk_test"}


def test_list_models_accepts_bare_list_and_raises_on_error():
    ok = httpx.MockTransport(lambda r: httpx.Response(200, json=[{"id": "x/y"}]))
    assert list_models(_settings(), transport=ok) == [{"id": "x/y"}]
    denied = httpx.MockTransport(lambda r: httpx.Response(401, json={"error": "bad key"}))
    with pytest.raises(httpx.HTTPStatusError):
        list_models(_settings(), transport=denied)
