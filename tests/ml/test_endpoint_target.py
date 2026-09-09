"""``EndpointTarget``, ``PredictBroker`` and the sandbox socket plumbing (ENDPOINT-04, -05, -08, -09; ``ml`` tier).

Everything runs offline against ``tests/ml/tiny_endpoint_server.py`` on 127.0.0.1. The two tests that
spawn the REAL sandbox child (``python -m redsim.ml.sandbox_worker``) assert what the child saw: no
credential, no proxy configuration, no ``REDSIM_*`` setting beyond the four pins, and only a unix-socket
path inside a 0700 directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("torch")
pytest.importorskip("art")

import numpy as np

from redsim.ml import sandbox
from redsim.ml.artifacts import FilesystemSink
from redsim.ml.campaign import run_campaign
from redsim.ml.endpoint_broker import (
    CONTRACT_VERSION,
    EgressRefused,
    EndpointAuthFailed,
    EndpointLimits,
    EndpointSchemaMismatch,
    EndpointUnreachable,
    HttpPredictTransport,
    PredictBroker,
    QueryBudgetExceeded,
    TokenBucket,
    validate_predict_response,
)
from redsim.ml.errors import MLError
from redsim.ml.sandbox import probe_endpoint_sandboxed, run_campaign_sandboxed
from redsim.ml.schema import CampaignConfig, MLModelManifest
from redsim.ml.targets.base import Target
from redsim.ml.targets.endpoint import ACCESS_LABEL, EndpointTarget, SocketPredictTransport
from tests.ml.fakes import CLASS_NAMES, TinyTarget
from tests.ml.tiny_endpoint_server import DEFAULT_TOKEN, TinyEndpointServer

pytestmark = pytest.mark.ml

AUTH: dict[str, Any] = {"kind": "bearer", "config": {}, "secret": DEFAULT_TOKEN}
FAST = EndpointLimits(rps=10_000.0, batch_rows=32, timeout_s=10.0, max_rows=500_000, max_requests=20_000)
HSJ = {"max_iter": 1, "max_eval": 100, "init_eval": 10, "init_size": 3, "batch_size": 64}
DATASET = "synthetic/tiny"

# Values a worker parent realistically holds; none may reach the child (mirrors test_sandbox_loader).
_PARENT_SECRETS = {
    "PYTHIA_API_KEY": "pk_test_never_forward", "REDSIM_AUTH_PROFILES_KEY": "fernet-key-never-forward",
    "REDSIM_DB_URL": "postgresql://user:pw@db/redsim", "AWS_SECRET_ACCESS_KEY": "aws-secret",
    "HTTPS_PROXY": "http://proxy.example:3128", "https_proxy": "http://proxy.example:3128",
    "HTTP_PROXY": "http://proxy.example:3128", "NO_PROXY": "localhost",
}


def _eval_data(n: int = 24, seed: int = 1) -> tuple[np.ndarray, np.ndarray]:
    sample = TinyTarget(seed=0).sample(n, seed)
    return sample.x, sample.y


def _target(transport: Any, **overrides: Any) -> EndpointTarget:
    kwargs: dict[str, Any] = {
        "transport": transport, "url_host": "127.0.0.1:1", "auth_profile_id": "ap-1",
        "class_names": list(CLASS_NAMES), "eval_data": _eval_data(), "dataset_id": DATASET,
        "dataset_split": "eval", "dataset_revision": "deadbeef", "domain": "image", "scheme": "http",
        "batch_rows": 32, "timeout_s": 10.0,
    }
    kwargs.update(overrides)
    return EndpointTarget("endpoint-tiny", **kwargs)


def _config(**overrides: Any) -> CampaignConfig:
    cfg: dict[str, Any] = {
        "target_id": "endpoint-tiny", "modality": "image", "attack_ids": ["hopskipjump"],
        "attack_params": {"hopskipjump": dict(HSJ)}, "eps_grid": [0.1, 0.3], "reference_eps": 0.1,
        "n_samples": 10, "seed": 0, "explain_k": 0, "dataset_id": DATASET, "dataset_split": "eval",
    }
    cfg.update(overrides)
    return CampaignConfig(**cfg)


@pytest.fixture
def server() -> Any:
    with TinyEndpointServer() as srv:
        yield srv


@pytest.fixture
def work_root(monkeypatch: pytest.MonkeyPatch) -> Any:
    """A short 0700 work-dir root (pytest's tmp_path is too long for ``sun_path`` on macOS)."""
    root = Path(tempfile.mkdtemp(prefix="rs-"))
    os.chmod(root, 0o700)
    for name in (sandbox.ENV_TIMEOUT_S, sandbox.ENV_CPU_SECONDS, sandbox.ENV_MEMORY_MB,
                 sandbox.ENV_FILESIZE_MB, sandbox.ENV_THREADS, sandbox.KEEP_WORK_DIR_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(sandbox.WORK_DIR_ENV, str(root))
    yield root
    shutil.rmtree(root, ignore_errors=True)


# --- EndpointTarget over the HTTP transport (ENDPOINT-04) ----------------------------------------------


def test_endpoint_target_satisfies_the_protocol_over_http(server: TinyEndpointServer) -> None:
    from art.estimators.classification import BlackBoxClassifier

    transport = HttpPredictTransport(server.url, AUTH, limits=FAST, n_classes=3)
    target = _target(transport, url_host=server.url.split("//")[1].split("/")[0])
    assert isinstance(target, Target)
    target.load()
    # load() is the connection probe: 8 seeded rows, purpose "probe".
    assert server.n_requests == 1 and server.requests[0]["rows"] == 8 and server.requests[0]["auth_ok"]
    assert transport.stats.by_purpose == {"probe": {"requests": 1, "rows": 8}}

    sample = target.sample(12, 0)
    assert sample.x.shape == (12, 3, 8, 8) and sample.class_names == list(CLASS_NAMES)
    proba = target.predict_proba(sample.x)
    reference = TinyTarget(seed=0).predict_proba(sample.x)
    assert proba.shape == (12, 3) and proba.dtype == np.float32
    np.testing.assert_allclose(proba, reference, atol=1e-5)
    assert isinstance(target.art_classifier(), BlackBoxClassifier)
    assert target.torch_model() is None and target.surrogate_art_classifier() is None
    assert target.info().metadata["access"] == ACCESS_LABEL and target.info().metadata["gradients"] is False
    # Every request carried the bearer credential; the probe and the predicts are counted separately.
    assert all(r["auth_ok"] for r in server.requests)
    with target.purpose("explain"):
        target.predict_proba(sample.x[:2])
    q = target.queries()
    assert q["by_purpose"]["probe"] == {"requests": 1, "rows": 8}
    assert q["by_purpose"]["predict"] == {"requests": 1, "rows": 12}
    assert q["by_purpose"]["explain"] == {"requests": 1, "rows": 2}
    assert q["rows"] == server.rows_total == transport.stats.rows == 22

    manifest = target.manifest()
    parsed = MLModelManifest.model_validate(manifest)
    assert parsed.format == "endpoint" and parsed.gradients is False and parsed.size_bytes == 0
    assert parsed.n_classes == 3 and parsed.input_shape == [3, 8, 8] and parsed.dataset_id == DATASET
    assert manifest["endpoint"] == {
        "url_host": server.url.split("//")[1].split("/")[0], "auth_profile_id": "ap-1",
        "contract_version": CONTRACT_VERSION, "input_shape": [3, 8, 8], "batch_rows": 32, "timeout_s": 10.0,
    }
    assert manifest["endpoint_probe"]["http_status"] == 200 and manifest["endpoint_probe"]["n_rows"] == 8
    fp = manifest["endpoint_fingerprint"]
    assert len(fp["sha256"]) == 64 and fp["sha256"] == transport.stats.fingerprint_sha256
    assert "remote model identity" in fp["label"] and "not a weights digest" in fp["label"]
    assert manifest["endpoint_queries"]["rows"] == 22
    assert manifest["endpoint_broker"]["tls_mode"] == "plaintext" and manifest["endpoint_broker"]["plaintext_loopback"]
    assert manifest["torch_model"] is None and DEFAULT_TOKEN not in json.dumps(manifest)
    transport.close()


def test_logits_are_softmaxed_client_side_and_recorded() -> None:
    with TinyEndpointServer(logits=True) as srv:
        transport = HttpPredictTransport(srv.url, AUTH, limits=FAST, n_classes=3)
        target = _target(transport)
        target.load()
        x, _ = _eval_data(6)
        np.testing.assert_allclose(target.predict_proba(x), TinyTarget(seed=0).predict_proba(x), atol=1e-5)
        assert target.manifest()["endpoint_fingerprint"]["output_kind"] == "logits"
        assert transport.stats.output_kind == "logits"
        transport.close()


def test_response_contract_is_never_coerced() -> None:
    rows, kind = validate_predict_response({"probabilities": [[0.2, 0.3, 0.5]] * 2}, n_rows=2, n_classes=3)
    assert kind == "probabilities" and rows[0] == [0.2, 0.3, 0.5]
    rows, kind = validate_predict_response({"logits": [[0.0, 0.0, 0.0]]}, n_rows=1, n_classes=3)
    assert kind == "logits" and abs(sum(rows[0]) - 1.0) < 1e-9
    bad: list[tuple[Any, str]] = [
        ({"probabilities": [[0.2, 0.3, 0.5]]}, "rows"),                        # wrong row count
        ({"probabilities": [[0.5, 0.5]] * 2}, "columns"),                      # wrong class count
        ({"probabilities": [[0.5, 0.4, 0.0]] * 2}, "sums"),                    # row sum 0.9
        ({"probabilities": [[float("nan"), 0.5, 0.5]] * 2}, "finite"),         # NaN
        ({"probabilities": [[1.5, -0.5, 0.0]] * 2}, "outside"),                # out of range
        ({"scores": [[0.2, 0.3, 0.5]] * 2}, "neither"),                        # unknown key
        ([[0.2, 0.3, 0.5]] * 2, "object"),                                     # not an object
    ]
    for body, needle in bad:
        with pytest.raises(EndpointSchemaMismatch, match=needle):
            validate_predict_response(body, n_rows=2, n_classes=3)


# --- typed failures (spec 6.3; ENDPOINT-05, -07, -08) -------------------------------------------------


def test_schema_mismatch_is_a_typed_failure_in_probe_and_campaign(tmp_path: Path) -> None:
    with TinyEndpointServer(n_columns=2) as srv:
        transport = HttpPredictTransport(srv.url, AUTH, limits=FAST, n_classes=3)
        target = _target(transport)
        with pytest.raises(EndpointSchemaMismatch, match="2 columns") as info:
            target.load()
        assert info.value.code == "endpoint_schema_mismatch"
        assert transport.stats.failures == 1 and transport.stats.rows == 0, "a refused response counts no row"
        # Through the campaign the same failure surfaces before any measurement exists.
        with pytest.raises(EndpointSchemaMismatch):
            run_campaign(_config(), FilesystemSink(tmp_path / "sink"), explain=False, target_override=_target(transport))
        transport.close()
    # The child names the class in its envelope; the parent rebuilds the typed class (validate mode).
    err = sandbox._typed_error(
        {"ok": False, "error_class": "EndpointSchemaMismatch", "error": "probe response has 2 columns"},
        mode="validate",
    )
    assert isinstance(err, EndpointSchemaMismatch) and isinstance(err, MLError)


def test_auth_failure_unreachable_and_retries_are_typed(server: TinyEndpointServer) -> None:
    wrong = HttpPredictTransport(server.url, {"kind": "bearer", "secret": "tok-wrong"}, limits=FAST, n_classes=3)
    with pytest.raises(EndpointAuthFailed) as info:
        wrong.predict([[[[0.0] * 8] * 8] * 3])
    assert info.value.code == "endpoint_auth_failed" and wrong.stats.http_status_last == 401
    wrong.close()

    sleeps: list[float] = []
    with TinyEndpointServer(fail_first=2) as flaky:
        transport = HttpPredictTransport(flaky.url, AUTH, limits=FAST, n_classes=3, sleep=sleeps.append)
        result = transport.predict([[[[0.0] * 8] * 8] * 3])
        assert result.http_status == 200 and transport.stats.retries == 2 and sleeps == [0.2, 0.5]
        transport.close()

    dead = TinyEndpointServer()
    url = dead.start()
    dead.stop()
    transport = HttpPredictTransport(url, AUTH, limits=FAST, n_classes=3, sleep=lambda _s: None)
    with pytest.raises(EndpointUnreachable) as info2:
        transport.predict([[[[0.0] * 8] * 8] * 3])
    assert info2.value.code == "endpoint_unreachable" and transport.stats.retries == 2
    transport.close()


@pytest.mark.parametrize("url,needle", [
    ("https://a:b@127.0.0.1/predict", "userinfo"),
    ("http://127.0.0.1/predict?k=v", "query"),
    ("http://127.0.0.1/predict#frag", "fragment"),
    ("ftp://127.0.0.1/predict", "scheme"),
    ("http://10.0.0.5/predict", "allowlist"),
    ("https://models.example.mil/predict", "allowlist"),
])
def test_egress_refusals_happen_before_any_request(url: str, needle: str) -> None:
    with pytest.raises(EgressRefused, match=needle) as info:
        HttpPredictTransport(url, AUTH, limits=FAST)
    assert info.value.code == "egress_refused"


def test_plaintext_to_a_non_loopback_host_and_private_resolution_are_refused() -> None:
    with pytest.raises(EgressRefused, match="plaintext"):
        HttpPredictTransport("http://models.example.mil/predict", AUTH, limits=FAST,
                             allowlist=["models.example.mil"])

    def resolves_private(*_a: Any, **_k: Any) -> list[Any]:
        return [(2, 1, 6, "", ("10.0.0.5", 443))]

    with pytest.raises(EgressRefused, match="10.0.0.5"):
        HttpPredictTransport("https://models.example.mil/predict", AUTH, limits=FAST,
                             allowlist=["models.example.mil"], resolver=resolves_private)
    # A CIDR on the allowlist that contains the resolved address permits it (no request is made here).
    transport = HttpPredictTransport("https://models.example.mil/predict", AUTH, limits=FAST,
                                     allowlist=["models.example.mil", "10.0.0.0/8"], resolver=resolves_private)
    assert transport.stats.resolved_addresses == ["10.0.0.5"]
    assert transport.stats.tls_mode in {"truststore", "default"} or transport.stats.tls_mode.startswith("ca-bundle:")
    assert transport.stats.proxy_env_honoured is True
    transport.close()


def test_query_budget_stops_at_the_cap_with_no_invented_rows(server: TinyEndpointServer) -> None:
    limits = EndpointLimits(rps=10_000.0, batch_rows=8, timeout_s=10.0, max_rows=20, max_requests=20_000)
    transport = HttpPredictTransport(server.url, AUTH, limits=limits, n_classes=3)
    target = _target(transport, batch_rows=8, probe_rows=4)
    target.load()   # 4 rows
    x, _ = _eval_data(24)
    with pytest.raises(QueryBudgetExceeded, match="max_rows=20") as info:
        target.predict_proba(x)   # 4 + 8 + 8 = 20 served; the third batch would exceed the cap
    assert info.value.code == "query_budget_exceeded"
    assert server.rows_total == 20 == transport.stats.rows
    assert transport.stats.requests == 3 and transport.stats.limits["max_rows"] == 20
    transport.close()

    requests_cap = EndpointLimits(rps=10_000.0, batch_rows=8, timeout_s=10.0, max_rows=500_000, max_requests=2)
    transport2 = HttpPredictTransport(server.url, AUTH, limits=requests_cap, n_classes=3)
    transport2.predict([[[[0.0] * 8] * 8] * 3])
    transport2.predict([[[[0.0] * 8] * 8] * 3])
    with pytest.raises(QueryBudgetExceeded, match="max_requests=2"):
        transport2.predict([[[[0.0] * 8] * 8] * 3])
    transport2.close()


def test_token_bucket_paces_requests() -> None:
    now = [0.0]
    slept: list[float] = []

    def clock() -> float:
        return now[0]

    def sleep(s: float) -> None:
        slept.append(s)
        now[0] += s

    bucket = TokenBucket(5.0, clock=clock, sleep=sleep)
    waits = [bucket.acquire() for _ in range(10)]
    assert waits[:5] == [0.0] * 5, "the bucket starts full: the first `rate` requests do not wait"
    assert all(abs(w - 0.2) < 1e-9 for w in waits[5:]), "then one request per 1/rate seconds"
    assert abs(sum(slept) - 1.0) < 1e-9 and now[0] <= 1.0 + 1e-9, "10 requests at 5 rps take 1 s"


def test_limits_from_env_and_admission_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("REDSIM_ML_ENDPOINT_RPS", "REDSIM_ML_ENDPOINT_BATCH_ROWS", "REDSIM_ML_ENDPOINT_TIMEOUT_S",
                 "REDSIM_ML_ENDPOINT_MAX_ROWS", "REDSIM_ML_ENDPOINT_MAX_REQUESTS"):
        monkeypatch.delenv(name, raising=False)
    assert EndpointLimits.from_env("image").as_dict() == {
        "rps": 10.0, "batch_rows": 32, "timeout_s": 30.0, "max_rows": 500_000, "max_requests": 20_000,
    }
    assert EndpointLimits.from_env("tabular").batch_rows == 256
    monkeypatch.setenv("REDSIM_ML_ENDPOINT_RPS", "50")
    monkeypatch.setenv("REDSIM_ML_ENDPOINT_BATCH_ROWS", "5000")     # capped at 1024
    monkeypatch.setenv("REDSIM_ML_ENDPOINT_MAX_ROWS", "abc")        # malformed keeps the default
    limits = EndpointLimits.from_env("image")
    assert (limits.rps, limits.batch_rows, limits.max_rows) == (50.0, 1024, 500_000)
    merged = limits.merged({"max_rows": 200, "rps": -1, "timeout_s": "x"})
    assert (merged.max_rows, merged.rps, merged.timeout_s) == (200, 50.0, 30.0)


# --- broker + socket, in process (ENDPOINT-05) --------------------------------------------------------


def test_campaign_completes_through_the_broker_socket_in_process(server: TinyEndpointServer, tmp_path: Path,
                                                                  work_root: Path) -> None:
    work_dir = Path(tempfile.mkdtemp(prefix="job-", dir=work_root))
    os.chmod(work_dir, 0o700)
    broker = PredictBroker(server.url, AUTH, work_dir=work_dir, limits=FAST, n_classes=3)
    socket_path = broker.start()
    assert socket_path.is_socket() and stat.S_IMODE(socket_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o700
    transport = SocketPredictTransport(socket_path)
    target = _target(transport, url_host=server.url.split("//")[1].split("/")[0])

    record = run_campaign(_config(attack_ids=["fgsm", "hopskipjump"],
                                  attack_params={"hopskipjump": dict(HSJ)}),
                          FilesystemSink(tmp_path / "sink"), explain=False, target_override=target)
    stats = broker.stop()
    assert not socket_path.exists(), "stop() removes the socket"

    assert record.status == "succeeded" and record.target.metadata["access"] == ACCESS_LABEL
    # The white-box attack finds no gradient on a black-box endpoint and is recorded not_run (spec 9.5).
    assert any("fgsm" in i.statement and "not_run" in i.statement for i in record.interpretation)
    hsj_rows = [m for m in record.measurements if m.attack_id == "hopskipjump"]
    assert hsj_rows and all(m.n == 10 for m in hsj_rows)
    assert all(any("predict rows" in n for n in m.notes) for m in hsj_rows), "query totals are on every row"
    assert [m for m in record.measurements if m.family == "control"], "the control ran at the same budget"
    # Query counts: the target's client-side counters, the broker's counters and the server agree. The
    # provenance copy of the manifest is the load_target-time snapshot (probe rows only); the sandbox path
    # attaches the broker's final counters under ``endpoint_broker`` after the child exits.
    manifest = record.provenance.model_manifest if record.provenance is not None else {}
    assert target.queries()["rows"] == stats.rows == server.rows_total > 8
    assert manifest["endpoint_queries"]["by_purpose"] == {"probe": {"requests": 1, "rows": 8}}
    assert stats.requests == server.n_requests and all(r["auth_ok"] for r in server.requests)
    assert set(stats.by_purpose) == {"probe", "predict"} and stats.by_purpose["probe"]["rows"] == 8
    assert manifest["endpoint"]["auth_profile_id"] == "ap-1" and manifest["gradients"] is False
    assert manifest["endpoint_fingerprint"]["sha256"] == stats.fingerprint_sha256
    assert stats.limits == FAST.as_dict() and stats.rate_limit_wait_s >= 0.0
    dumped = record.model_dump_json()
    assert DEFAULT_TOKEN not in dumped and "Bearer" not in dumped


def test_broker_error_frames_reach_the_child_typed(work_root: Path) -> None:
    with TinyEndpointServer(n_columns=2) as srv:
        work_dir = Path(tempfile.mkdtemp(prefix="job-", dir=work_root))
        with PredictBroker(srv.url, AUTH, work_dir=work_dir, limits=FAST, n_classes=3) as broker:
            transport = SocketPredictTransport(broker.socket_path)
            with pytest.raises(EndpointSchemaMismatch, match="2 columns"):
                transport.predict([[[[0.0] * 8] * 8] * 3])
            assert transport.stats_dict()["failures"] == 1
    # A socket nobody serves is "unreachable", never a fabricated prediction.
    with pytest.raises(EndpointUnreachable):
        SocketPredictTransport(work_dir / "absent.sock").predict([[[[0.0] * 8] * 8] * 3])


# --- the REAL sandbox child (ENDPOINT-05, -09) --------------------------------------------------------


def _assets_tree(root: Path) -> None:
    """A minimal bundled asset tree binding ``synthetic/tiny`` to a 24-row 8x8 evaluation split."""
    x, y = _eval_data(24)
    split = root / "datasets" / "tiny" / "eval.npz"
    split.parent.mkdir(parents=True)
    np.savez(split, x=x, y=y, indices=np.arange(24))
    digest = hashlib.sha256(split.read_bytes()).hexdigest()
    (root / "MANIFEST.json").write_text(json.dumps({
        "schema_version": 1,
        "datasets": {DATASET: {
            "id": DATASET, "revision": "deadbeef", "class_names": list(CLASS_NAMES), "license": "test double",
            "splits": {"eval": {"name": "eval", "n": 24,
                                "file": {"path": "datasets/tiny/eval.npz", "sha256": digest,
                                         "size_bytes": split.stat().st_size}}},
        }},
        "models": {},
    }))


_REAL_POPEN = subprocess.Popen


def _capture_child(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Run the real child but record the env Popen was given, the request file and the socket at spawn time."""
    captured: dict[str, Any] = {"spawns": 0}

    def child(argv: list[str], **kwargs: Any) -> subprocess.Popen[str]:
        captured["spawns"] += 1
        request_path = Path(argv[argv.index("--request") + 1])
        captured["work_dir"] = Path(argv[argv.index("--work-dir") + 1])
        captured["request_text"] = request_path.read_text(encoding="utf-8")
        captured["request"] = json.loads(captured["request_text"])
        captured["env"] = dict(kwargs["env"])
        sock = Path(captured["request"]["target_endpoint"]["socket"])
        captured["socket_is_socket"] = sock.is_socket()
        captured["socket_mode"] = stat.S_IMODE(sock.stat().st_mode)
        captured["socket_dir_mode"] = stat.S_IMODE(sock.parent.stat().st_mode)
        captured["socket_in_work_dir"] = sock.parent == captured["work_dir"]
        captured["work_dir_mode"] = stat.S_IMODE(captured["work_dir"].stat().st_mode)
        return _REAL_POPEN(argv, **kwargs)

    monkeypatch.setattr("redsim.ml.sandbox.subprocess.Popen", child)
    return captured


def _target_endpoint(url: str) -> dict[str, Any]:
    return {
        "url": url, "auth_profile_id": "ap-1", "batch_rows": 32, "timeout_s": 10.0,
        "limits": {"rps": 10_000},
        "manifest": {"modality": "image", "dataset_id": DATASET, "dataset_split": "eval", "n_classes": 3,
                     "name": "tiny endpoint"},
    }


def test_real_child_never_sees_the_credential_and_the_campaign_completes(
    server: TinyEndpointServer, tmp_path: Path, work_root: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    _assets_tree(assets)
    monkeypatch.setenv(sandbox.ASSETS_DIR_ENV, str(assets))
    for key, value in _PARENT_SECRETS.items():
        monkeypatch.setenv(key, value)
    captured = _capture_child(monkeypatch)
    sink = FilesystemSink(tmp_path / "sink")

    record = run_campaign_sandboxed(
        _config(), sink, target_endpoint=_target_endpoint(server.url), endpoint_auth=AUTH, job_id="ep-job-1",
    )

    assert record.status == "succeeded", record.error
    # What the child saw: no credential, no proxy, no REDSIM_* setting beyond the four pins.
    env = captured["env"]
    assert DEFAULT_TOKEN not in json.dumps(env) and DEFAULT_TOKEN not in captured["request_text"]
    assert "Bearer" not in captured["request_text"] and "secret" not in captured["request"]["target_endpoint"]
    for key in _PARENT_SECRETS:
        assert key not in env, f"{key} leaked into the sandbox child env"
    assert not any(k.lower().endswith("_proxy") for k in env)
    assert sorted(k for k in env if k.startswith("REDSIM_")) == [
        "REDSIM_DISABLE_LLM", "REDSIM_ENV_FILE", "REDSIM_ML_ASSETS_DIR", "REDSIM_PLUGINS",
    ]
    spec = captured["request"]["target_endpoint"]
    assert "url" not in spec and spec["url_host"] == server.url.split("//")[1].split("/")[0]
    assert spec["scheme"] == "http" and spec["auth_profile_id"] == "ap-1" and spec["limits"]["rps"] == 10_000
    # The socket lived under a 0700 directory (the work dir when the path fits sun_path) and is gone now.
    assert captured["socket_is_socket"] and captured["socket_mode"] == 0o600
    assert captured["socket_dir_mode"] == 0o700 and captured["work_dir_mode"] == 0o700
    assert captured["socket_in_work_dir"], "the short work root keeps the socket inside the job directory"
    assert not Path(spec["socket"]).exists() and not captured["work_dir"].exists()
    # The server saw the bearer credential on every request and the counters agree end to end.
    assert server.n_requests > 0 and all(r["auth_ok"] for r in server.requests)
    manifest = record.provenance.model_manifest if record.provenance is not None else {}
    broker = manifest["endpoint_broker"]
    assert broker["rows"] == server.rows_total and broker["requests"] == server.n_requests
    assert broker["by_purpose"]["probe"] == {"requests": 1, "rows": 8} and broker["rows"] > 8
    assert manifest["endpoint_queries"]["by_purpose"]["probe"] == {"requests": 1, "rows": 8}
    assert manifest["endpoint"]["url_host"] == spec["url_host"] and manifest["format"] == "endpoint"
    assert manifest["gradients"] is False and len(broker["fingerprint_sha256"]) == 64
    assert broker["limits"]["rps"] == 10_000 and broker["tls_mode"] == "plaintext"
    hsj = [m for m in record.measurements if m.attack_id == "hopskipjump"]
    assert hsj and all(m.n == 10 for m in hsj)
    assert DEFAULT_TOKEN not in record.model_dump_json()


def test_probe_endpoint_sandboxed_is_the_endpoint_variant_of_validate(
    tmp_path: Path, work_root: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    _assets_tree(assets)
    monkeypatch.setenv(sandbox.ASSETS_DIR_ENV, str(assets))
    monkeypatch.setenv("PYTHIA_API_KEY", "pk_test_never_forward")
    captured = _capture_child(monkeypatch)

    with TinyEndpointServer() as srv:
        manifest = probe_endpoint_sandboxed("endpoint-tiny", _target_endpoint(srv.url), AUTH, job_id="ep-probe-1")
        assert srv.n_requests == 1 and srv.requests[0]["rows"] == 8 and srv.requests[0]["auth_ok"]
    parsed = MLModelManifest.model_validate(manifest)
    assert parsed.format == "endpoint" and parsed.status == "available" and parsed.gradients is False
    assert manifest["endpoint_probe"]["http_status"] == 200 and manifest["endpoint_probe"]["n_rows"] == 8
    assert manifest["endpoint_broker"]["rows"] == 8 and manifest["endpoint_broker"]["by_purpose"] == {
        "probe": {"requests": 1, "rows": 8},
    }
    assert manifest["endpoint_fingerprint"]["sha256"] == manifest["endpoint_broker"]["fingerprint_sha256"]
    assert DEFAULT_TOKEN not in captured["request_text"] and DEFAULT_TOKEN not in json.dumps(captured["env"])
    assert DEFAULT_TOKEN not in json.dumps(manifest)

    # A contract violation at probe time is the typed refusal, rebuilt in the parent from the envelope.
    with TinyEndpointServer(n_columns=2) as bad:
        with pytest.raises(EndpointSchemaMismatch, match="2 columns"):
            probe_endpoint_sandboxed("endpoint-tiny", _target_endpoint(bad.url), AUTH, job_id="ep-probe-2")
    # A wrong credential is an auth failure, and the egress policy refuses before any child is spawned.
    with TinyEndpointServer() as srv2:
        with pytest.raises(EndpointAuthFailed):
            probe_endpoint_sandboxed("endpoint-tiny", _target_endpoint(srv2.url),
                                     {"kind": "bearer", "secret": "tok-wrong"}, job_id="ep-probe-3")
    spawned_before = captured["spawns"]
    assert spawned_before == 3, "the three probes above each ran a real child"
    with pytest.raises(EgressRefused):
        probe_endpoint_sandboxed("endpoint-tiny", _target_endpoint("http://10.0.0.5/predict"), AUTH,
                                 job_id="ep-probe-4")
    assert captured["spawns"] == spawned_before, "no child is spawned for a URL the egress policy refuses"
    assert not (Path(sandbox.work_dir_root()) / "ep-probe-4").exists(), "the refused job's work dir is removed"
    assert sys.executable  # the real interpreter ran the children above
