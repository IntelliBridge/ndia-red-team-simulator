"""G-ASSET10: the ML sandbox parent/child contract (spec 9.4, 9.5, 10.6, 20.3).

The child is a real subprocess, but a stand-in interpreter script replaces
``redsim.ml.sandbox_worker`` so nothing here imports torch or loads a model:
what is asserted is what the child saw (its env, cwd, work dir) and what the
parent did with what the child wrote (or failed to write).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from redsim.ml import sandbox, sandbox_worker
from redsim.ml.errors import (
    ArtifactDigestMismatch,
    EnvelopeInvalid,
    ModelLoadRefused,
    SandboxKilled,
    SandboxTimeout,
    UnsupportedArtifact,
)
from redsim.ml.sandbox import (
    MlSandboxConfig,
    run_campaign_sandboxed,
    validate_model_sandboxed,
)
from redsim.ml.schema import CampaignConfig

# Values a parent worker process realistically holds. None may reach the child.
_PARENT_SECRETS = {
    "PYTHIA_API_KEY": "pk_test_never_forward",
    "PYTHIA_BASE_URL": "https://pythia.example",
    "KAGGLE_API_TOKEN": "kaggle-token-never-forward",
    "KAGGLE_USERNAME": "kaggle-user",
    "KAGGLE_KEY": "kaggle-key",
    "REDSIM_DB_URL": "postgresql://user:pw@db/redsim",
    "REDSIM_BROKER_URL": "redis://broker",
    "REDSIM_WORKER_SIGNING_KEY": "signing-key",
    "REDSIM_AUTH_PROFILES_KEY": "fernet-key",
    "REDSIM_S3_SECRET_ACCESS_KEY": "s3-secret",
    "AWS_SECRET_ACCESS_KEY": "aws-secret",
    "HF_TOKEN": "hf-token",
    "HTTPS_PROXY": "http://proxy.example:3128",
    "https_proxy": "http://proxy.example:3128",
    "HTTP_PROXY": "http://proxy.example:3128",
    "NO_PROXY": "localhost",
}

# Child stand-ins. Each receives the work dir as argv[1] and writes the typed envelope.
_ENV_DUMP = (
    "import json, os, sys, stat\n"
    "work = sys.argv[1]\n"
    "mode = stat.S_IMODE(os.stat(work).st_mode)\n"
    "manifest = {'env': dict(os.environ), 'cwd': os.getcwd(), 'work_dir': work, 'work_mode': mode}\n"
    "open(work + '/result.json', 'w').write(json.dumps({'ok': True, 'result': {'manifest': manifest}}))\n"
)
_SLEEP_AFTER_PARTIAL = (
    "import hashlib, json, os, sys, time\n"
    "work = sys.argv[1]\n"
    "os.makedirs(work + '/artifacts/curve', exist_ok=True)\n"
    "data = json.dumps({'attack': 'fgsm', 'points': [{'eps': 0.03, 'n': 10, 'n_correct': 4}]}).encode()\n"
    "open(work + '/artifacts/curve/fgsm.json', 'wb').write(data)\n"
    "digest = hashlib.sha256(data).hexdigest()\n"
    "open(work + '/artifacts.json', 'w').write(json.dumps([{'name': 'curve/fgsm.json',"
    " 'content_type': 'application/json', 'sha256': digest, 'reference': 'sandbox:curve/fgsm.json:' + digest}]))\n"
    "open(work + '/artifacts/curve/truncated.json', 'wb').write(b'partial write')\n"
    "open(work + '/events.jsonl', 'a').write(json.dumps({'stage': 'attack'}) + '\\n')\n"
    "time.sleep(60)\n"
)


class _Sink:
    def __init__(self) -> None:
        self.rows: list[tuple[str, bytes, str]] = []

    def put(self, name: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        self.rows.append((name, data, content_type))
        return f"test:{name}"

    def sha256(self, _name: str) -> str:
        return "0" * 64

    def names(self) -> list[str]:
        return [name for name, _data, _ct in self.rows]


def _config() -> CampaignConfig:
    detail: dict[str, Any] = {
        "name": "sandbox loader test model",
        "status": "available",
        "modality": "image",
        "format": "torch_state_dict",
        "architecture_id": "smallcnn",
        "dataset_id": "missing-test-dataset",
        "dataset_split": "test",
        "sha256": "0" * 64,
    }
    return CampaignConfig(
        target_id="sandbox-loader-model",
        modality="image",
        attack_ids=["fgsm"],
        eps_grid=[0.03],
        reference_eps=0.03,
        n_samples=10,
        seed=7,
        dataset_id="missing-test-dataset",
        target_snapshot={
            "id": "sandbox-loader-model",
            "kind": "ml_model_artifact",
            "value": "test",
            "detail": detail,
        },
    )


# Captured once: ``redsim.ml.sandbox.subprocess`` is this same module object, so a
# monkeypatched Popen would otherwise be what a second _fake_child wraps.
_REAL_POPEN = subprocess.Popen


def _fake_child(monkeypatch: pytest.MonkeyPatch, script: str) -> dict[str, Any]:
    """Replace the sandbox child with ``script`` (argv[1] = work dir); return what Popen was given."""
    real_popen = _REAL_POPEN
    captured: dict[str, Any] = {}

    def child(argv: list[str], **kwargs: Any) -> subprocess.Popen[str]:
        work_dir = argv[argv.index("--work-dir") + 1]
        request_path = Path(argv[argv.index("--request") + 1])
        captured["argv"] = list(argv)
        captured["work_dir"] = Path(work_dir)
        captured["request"] = json.loads(request_path.read_text(encoding="utf-8"))
        captured["popen_env"] = dict(kwargs["env"])
        captured["popen_kwargs"] = {k: v for k, v in kwargs.items() if k != "env"}
        proc = real_popen([sys.executable, "-c", script, work_dir], **kwargs)
        captured["proc"] = proc
        return proc

    monkeypatch.setattr("redsim.ml.sandbox.subprocess.Popen", child)
    return captured


def _writer(envelope: str) -> str:
    """A child that writes ``envelope`` verbatim to result.json and exits 0."""
    return (
        "import sys\n"
        f"open(sys.argv[1] + '/result.json', 'w').write({envelope!r})\n"
    )


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in (
        sandbox.ENV_TIMEOUT_S, sandbox.ENV_CPU_SECONDS, sandbox.ENV_MEMORY_MB,
        sandbox.ENV_FILESIZE_MB, sandbox.ENV_THREADS, sandbox.KEEP_WORK_DIR_ENV,
        "REDSIM_PLUGIN_SANDBOX_NETWORK", "REDSIM_PLUGIN_SANDBOX_CPU_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(sandbox.WORK_DIR_ENV, str(tmp_path / "work"))


# --- MlSandboxConfig ---------------------------------------------------------


def test_ml_sandbox_config_spec_defaults() -> None:
    cfg = MlSandboxConfig.from_env()
    assert (cfg.timeout_s, cfg.cpu_seconds, cfg.memory_mb, cfg.file_size_mb, cfg.threads) == (
        1200, 900, 4096, 1024, 2,
    )
    limits = cfg.rlimits()
    assert (limits.timeout_s, limits.cpu_seconds, limits.memory_mb, limits.file_size_mb) == (
        1200, 900, 4096, 1024,
    )
    assert limits.allow_network is False


def test_ml_sandbox_config_reads_only_its_own_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(sandbox.ENV_TIMEOUT_S, "30")
    monkeypatch.setenv(sandbox.ENV_CPU_SECONDS, "25")
    monkeypatch.setenv(sandbox.ENV_MEMORY_MB, "512")
    monkeypatch.setenv(sandbox.ENV_FILESIZE_MB, "64")
    monkeypatch.setenv(sandbox.ENV_THREADS, "3")
    # Plugin-sandbox knobs must not bleed into the ML config (spec 9.4 table).
    monkeypatch.setenv("REDSIM_PLUGIN_SANDBOX_CPU_SECONDS", "1")
    monkeypatch.setenv("REDSIM_PLUGIN_SANDBOX_NETWORK", "1")
    cfg = MlSandboxConfig.from_env()
    assert (cfg.timeout_s, cfg.cpu_seconds, cfg.memory_mb, cfg.file_size_mb, cfg.threads) == (
        30, 25, 512, 64, 3,
    )
    assert cfg.rlimits().allow_network is False


@pytest.mark.parametrize("bad", ["", "  ", "abc", "0", "-5"])
def test_ml_sandbox_config_malformed_values_keep_defaults(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    monkeypatch.setenv(sandbox.ENV_TIMEOUT_S, bad)
    monkeypatch.setenv(sandbox.ENV_THREADS, bad)
    cfg = MlSandboxConfig.from_env()
    assert cfg.timeout_s == 1200
    assert cfg.threads == 2


# --- child environment -------------------------------------------------------


def test_child_env_has_no_secrets_and_forwards_assets_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    assets = tmp_path / "mounted-assets"
    assets.mkdir()
    monkeypatch.setenv(sandbox.ASSETS_DIR_ENV, str(assets))
    monkeypatch.setenv(sandbox.ENV_THREADS, "3")
    # Even with the plugin sandbox opted into the network, the ML child gets no proxy.
    monkeypatch.setenv("REDSIM_PLUGIN_SANDBOX_NETWORK", "1")
    for key, value in _PARENT_SECRETS.items():
        monkeypatch.setenv(key, value)
    captured = _fake_child(monkeypatch, _ENV_DUMP)

    manifest = validate_model_sandboxed(
        "env-target", Path("/nonexistent/model.pt"), {"format": "torch_state_dict"},
    )

    # macOS adds __CF_USER_TEXT_ENCODING to every child; compare the rest exactly.
    child_env = {k: v for k, v in manifest["env"].items() if not k.startswith("__CF_")}
    assert captured["popen_env"] == child_env, "the env Popen was given is the env the child saw"
    for key in _PARENT_SECRETS:
        assert key not in child_env, f"{key} leaked into the sandbox child env"
    assert not any(k.lower().endswith("_proxy") for k in child_env)
    expected = str(assets.resolve())
    assert captured["request"]["assets_dir"] == expected
    assert child_env[sandbox.ASSETS_DIR_ENV] == expected
    assert sorted(k for k in child_env if k.startswith("REDSIM_")) == [
        "REDSIM_ML_ASSETS_DIR", "REDSIM_PLUGINS",
    ]
    assert child_env["REDSIM_PLUGINS"] == "0"
    # Spec 9.4 additions.
    assert child_env["OMP_NUM_THREADS"] == "3"
    assert child_env["MKL_NUM_THREADS"] == "3"
    assert child_env["MPLBACKEND"] == "Agg"
    assert child_env["HF_HUB_OFFLINE"] == "1"
    assert child_env["HF_DATASETS_OFFLINE"] == "1"
    assert child_env["PYTHONHASHSEED"] == "0"
    assert child_env["PYTHONUNBUFFERED"] == "1"
    assert captured["popen_kwargs"]["start_new_session"] is True


def test_campaign_child_hash_seed_is_the_campaign_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _fake_child(monkeypatch, _ENV_DUMP)
    # The env dump is not a campaign record, so the parent must refuse it as malformed...
    with pytest.raises(EnvelopeInvalid, match="no valid record"):
        run_campaign_sandboxed(_config(), _Sink())
    # ...but the env the child ran with is what we are checking here.
    assert captured["popen_env"]["PYTHONHASHSEED"] == "7"


# --- work directory ----------------------------------------------------------


def test_work_dir_is_keyed_by_job_id_mode_0700_and_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    captured = _fake_child(monkeypatch, _ENV_DUMP)
    manifest = validate_model_sandboxed(
        "t", Path("/nonexistent/model.pt"), {"format": "onnx"}, job_id="job-0001",
    )
    expected = (tmp_path / "work" / "job-0001").resolve()
    assert captured["work_dir"] == expected
    assert Path(manifest["work_dir"]) == expected
    assert manifest["work_mode"] == 0o700
    assert not expected.exists(), "work dir is removed after the run by default"
    assert (tmp_path / "work").is_dir()


def test_keep_flag_preserves_work_dir_and_retry_reuses_envelope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv(sandbox.KEEP_WORK_DIR_ENV, "1")
    _fake_child(monkeypatch, _ENV_DUMP)
    first = validate_model_sandboxed("t", Path("/nonexistent/model.pt"), {"format": "onnx"}, job_id="job-keep")
    kept = tmp_path / "work" / "job-keep"
    assert kept.is_dir()
    assert stat.S_IMODE(kept.stat().st_mode) == 0o700
    assert (kept / "request.json").is_file() and (kept / "result.json").is_file()

    # Spec 10.6: a completed child is not re-run on a retry; the envelope is re-read.
    def never(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("the child must not be respawned when its envelope exists")

    monkeypatch.setattr("redsim.ml.sandbox.subprocess.Popen", never)
    second = validate_model_sandboxed("t", Path("/nonexistent/model.pt"), {"format": "onnx"}, job_id="job-keep")
    assert second == first

    # A different request under the same job id is not served from the stale envelope.
    with pytest.raises(AssertionError, match="must not be respawned"):
        validate_model_sandboxed("t", Path("/nonexistent/other.pt"), {"format": "onnx"}, job_id="job-keep")


@pytest.mark.parametrize("bad", ["", "..", ".", "../escape", "a/b", "job id", "-leading"])
def test_unsafe_job_ids_are_refused(bad: str) -> None:
    with pytest.raises(ValueError, match="work directory name"):
        sandbox.job_work_dir(bad)


def test_default_work_dir_root_is_tmp_redsim_ml(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(sandbox.WORK_DIR_ENV, raising=False)
    assert sandbox.work_dir_root() == Path(tempfile.gettempdir()).resolve() / "redsim-ml"
    monkeypatch.setenv(sandbox.WORK_DIR_ENV, "~/ml-work/../ml-work")
    assert sandbox.work_dir_root() == (Path.home() / "ml-work").resolve()


# --- timeout, kill, cancel ---------------------------------------------------


def test_timeout_raises_sandboxtimeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(sandbox.ENV_TIMEOUT_S, "1")
    captured = _fake_child(monkeypatch, _SLEEP_AFTER_PARTIAL)
    sink = _Sink()
    stages: list[str] = []
    started = time.monotonic()

    with pytest.raises(SandboxTimeout, match="timed out after 1s") as info:
        run_campaign_sandboxed(_config(), sink, on_stage=stages.append)

    assert time.monotonic() - started < 20, "the parent did not stop at the wall clock"
    assert not isinstance(info.value, UnsupportedArtifact), "a timeout is not a model refusal"
    assert info.value.code == "sandbox_timeout"
    proc = captured["proc"]
    assert proc.poll() is not None, "the process group was not killed"
    assert stages == ["attack"]
    # Files written before the kill are kept under ml/partial/ (spec 9.5, 10.6); the
    # digest-verified curve, the stage log and a partial campaign record. The file
    # the child never listed (a write in flight) is not promoted to evidence.
    names = sink.names()
    assert "ml/partial/curve/fgsm.json" in names
    assert "ml/partial/events.jsonl" in names
    assert "ml/partial/run_record.json" in names
    assert not any("truncated" in name for name in names)
    assert all(name.startswith("ml/partial/") for name in names)
    record = json.loads(dict((n, d) for n, d, _c in sink.rows)["ml/partial/run_record.json"])
    assert record["status"] == "failed"
    assert record["completeness"] == "partial"
    assert record["stages_done"] == ["attack"]
    assert record["error"].startswith("SandboxTimeout: ML sandbox timed out after 1s")
    assert record["score"] is None
    assert "2 partial file(s)" in str(info.value)


def test_validate_timeout_raises_sandboxtimeout_not_runtimeerror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(sandbox.ENV_TIMEOUT_S, "1")
    _fake_child(monkeypatch, "import time; time.sleep(60)")
    with pytest.raises(SandboxTimeout) as info:
        validate_model_sandboxed("t", Path("/nonexistent/model.pt"), {"format": "onnx"})
    assert not isinstance(info.value, RuntimeError)


def test_nonzero_exit_raises_sandbox_killed_with_exit_status(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_child(monkeypatch, "import sys; print('rlimit hit', file=sys.stderr); sys.exit(3)")
    sink = _Sink()
    with pytest.raises(SandboxKilled, match="status 3") as info:
        run_campaign_sandboxed(_config(), sink)
    assert "rlimit hit" in str(info.value)
    assert info.value.code == "sandbox_killed"
    assert sink.names() == ["ml/partial/run_record.json"]
    record = json.loads(sink.rows[0][1])
    assert record["status"] == "failed" and record["completeness"] == "partial"
    assert record["error"].startswith("SandboxKilled:")

    _fake_child(monkeypatch, "import sys; sys.exit(3)")
    with pytest.raises(SandboxKilled):
        validate_model_sandboxed("t", Path("/nonexistent/model.pt"), {"format": "onnx"})


def test_bad_request_exit_is_a_contract_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_child(monkeypatch, f"import sys; sys.exit({sandbox_worker.EXIT_BAD_REQUEST})")
    with pytest.raises(EnvelopeInvalid, match="could not read its request"):
        validate_model_sandboxed("t", Path("/nonexistent/model.pt"), {"format": "onnx"})


def test_cancel_keeps_partial_files_and_returns_cancelled_record(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_child(monkeypatch, _SLEEP_AFTER_PARTIAL)
    sink = _Sink()
    record = run_campaign_sandboxed(_config(), sink, is_cancelled=lambda: True)
    assert record.status == "cancelled"
    assert record.completeness == "partial"
    assert "cancelled while sandbox child" in (record.error or "")
    # The cancel fires on the first poll, so the child may not have written yet;
    # whatever it did write is promoted only under the partial prefix.
    assert all(name.startswith("ml/partial/") for name in sink.names())
    # Validation keeps the RuntimeError marker the validate task recognises.
    _fake_child(monkeypatch, "import time; time.sleep(60)")
    with pytest.raises(RuntimeError, match="cancelled while sandbox child"):
        validate_model_sandboxed("t", Path("/nonexistent/model.pt"), {"format": "onnx"}, is_cancelled=lambda: True)


# --- envelope ----------------------------------------------------------------


@pytest.mark.parametrize("envelope", [
    "not json",
    "[]",
    '"string"',
    '{"ok": "yes"}',
    '{"ok": true}',
    '{"ok": true, "result": 5}',
    '{"ok": false}',
    '{"ok": false, "error_class": 3, "error": "x"}',
    '{"ok": true, "result": {"nope": 1}}',
    '{"ok": true, "result": {"manifest": "flat"}}',
])
def test_malformed_validate_envelope_raises_envelope_invalid(monkeypatch: pytest.MonkeyPatch, envelope: str) -> None:
    _fake_child(monkeypatch, _writer(envelope))
    with pytest.raises(EnvelopeInvalid) as info:
        validate_model_sandboxed("t", Path("/nonexistent/model.pt"), {"format": "onnx"})
    assert info.value.code == "envelope_invalid"


def test_missing_envelope_after_clean_exit_is_envelope_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_child(monkeypatch, "pass")
    with pytest.raises(EnvelopeInvalid, match="without writing result.json"):
        validate_model_sandboxed("t", Path("/nonexistent/model.pt"), {"format": "onnx"})


def test_malformed_campaign_record_is_envelope_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_child(monkeypatch, _writer('{"ok": true, "result": {"record": {"run_id": 1}}}'))
    with pytest.raises(EnvelopeInvalid, match="no valid record"):
        run_campaign_sandboxed(_config(), _Sink())


def test_pre_envelope_bare_manifest_is_still_read(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_child(monkeypatch, _writer('{"manifest": {"format": "onnx", "n_classes": 3}}'))
    assert validate_model_sandboxed("t", Path("/x.onnx"), {"format": "onnx"}) == {
        "format": "onnx", "n_classes": 3,
    }


@pytest.mark.parametrize(("error_class", "expected"), [
    ("ModelLoadRefused", ModelLoadRefused),
    ("ArtifactDigestMismatch", ArtifactDigestMismatch),
    ("UnsupportedArtifact", UnsupportedArtifact),
])
def test_ok_false_envelope_becomes_the_named_typed_class(
    monkeypatch: pytest.MonkeyPatch, error_class: str, expected: type[Exception],
) -> None:
    envelope = json.dumps({"ok": False, "error_class": error_class, "error": "pickle_refused: PROTO opcode"})
    _fake_child(monkeypatch, _writer(envelope))
    with pytest.raises(expected, match="pickle_refused: PROTO opcode") as info:
        validate_model_sandboxed("t", Path("/x.pt"), {"format": "torch_state_dict"})
    assert type(info.value) is expected
    assert isinstance(info.value, UnsupportedArtifact)  # the validate task's refusal branch still catches it
    assert not isinstance(info.value, SandboxTimeout)


def test_unknown_child_error_class_in_validate_is_a_load_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    envelope = json.dumps({"ok": False, "error_class": "RuntimeError", "error": "torch could not map the file"})
    _fake_child(monkeypatch, _writer(envelope))
    with pytest.raises(ModelLoadRefused, match="load_failed: RuntimeError: torch could not map the file"):
        validate_model_sandboxed("t", Path("/x.pt"), {"format": "torch_state_dict"})


def test_ok_false_envelope_in_campaign_mode_is_typed_too(monkeypatch: pytest.MonkeyPatch) -> None:
    envelope = json.dumps({"ok": False, "error_class": "ValidationError", "error": "config.eps_grid"})
    _fake_child(monkeypatch, _writer(envelope))
    with pytest.raises(EnvelopeInvalid, match="rejected the campaign request"):
        run_campaign_sandboxed(_config(), _Sink())


def test_success_path_digest_mismatch_is_envelope_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    script = (
        "import json, os, sys\n"
        "work = sys.argv[1]\n"
        "os.makedirs(work + '/artifacts', exist_ok=True)\n"
        "open(work + '/artifacts/score.json', 'wb').write(b'{}')\n"
        "open(work + '/artifacts.json', 'w').write(json.dumps([{'name': 'score.json',"
        " 'content_type': 'application/json', 'sha256': '0' * 64, 'reference': 'sandbox:score.json:0'}]))\n"
        "open(work + '/result.json', 'w').write(json.dumps({'ok': True, 'result': {'record': {}}}))\n"
    )
    _fake_child(monkeypatch, script)
    sink = _Sink()
    with pytest.raises(EnvelopeInvalid, match="digest mismatch"):
        run_campaign_sandboxed(_config(), sink)
    assert sink.rows == []


# --- the real child module, in-process -----------------------------------------


class _FakeTarget:
    def __init__(self, manifest: dict[str, Any]) -> None:
        self._manifest = manifest

    def load(self) -> None:
        return None

    def manifest(self) -> dict[str, Any]:
        return self._manifest


def test_validate_child_emits_typed_success_envelope(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ml_models = pytest.importorskip("redsim.services.ml_models")
    manifest = {"format": "onnx", "input_shape": [3, 8, 8], "n_classes": 3, "gradients": True}
    monkeypatch.setattr(ml_models, "artifact_target_from_path", lambda *_a, **_k: _FakeTarget(manifest))
    sandbox_worker._validate({"target_id": "t", "target_file": "/x.onnx", "target_detail": {}}, tmp_path)
    envelope = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert envelope == {"ok": True, "result": {"manifest": manifest}}
    assert not (tmp_path / "result.json.tmp").exists()


def test_validate_child_emits_typed_refusal_envelope(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ml_models = pytest.importorskip("redsim.services.ml_models")

    def refuse(*_a: Any, **_k: Any) -> Any:
        raise ModelLoadRefused("pickle_refused: model.pt starts with a pickle PROTO opcode")

    monkeypatch.setattr(ml_models, "artifact_target_from_path", refuse)
    sandbox_worker._validate({"target_id": "t", "target_file": "/model.pt", "target_detail": {}}, tmp_path)
    envelope = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert envelope == {
        "ok": False,
        "error_class": "ModelLoadRefused",
        "error": "pickle_refused: model.pt starts with a pickle PROTO opcode",
        "code": "model_load_refused",
    }


def test_validate_child_reports_non_ml_exceptions_as_data(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ml_models = pytest.importorskip("redsim.services.ml_models")

    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("model file vanished")

    monkeypatch.setattr(ml_models, "artifact_target_from_path", boom)
    sandbox_worker._validate({"target_id": "t", "target_file": "/model.pt", "target_detail": {}}, tmp_path)
    envelope = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert envelope["ok"] is False
    assert envelope["error_class"] == "OSError"
    assert envelope["error"] == "model file vanished"
    assert "code" not in envelope


def test_campaign_child_reports_bad_config_as_envelope(tmp_path: Path) -> None:
    pytest.importorskip("numpy")
    sandbox_worker._campaign({"config": {"target_id": 5}}, tmp_path)
    envelope = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert envelope["ok"] is False
    assert envelope["error_class"] == "ValidationError"


def test_worker_main_exit_codes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(sys, "argv", ["sandbox_worker", "--request", str(tmp_path / "absent.json"),
                                      "--work-dir", str(work)])
    assert sandbox_worker.main() == sandbox_worker.EXIT_BAD_REQUEST
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["sandbox_worker", "--request", str(bad), "--work-dir", str(work)])
    assert sandbox_worker.main() == sandbox_worker.EXIT_BAD_REQUEST
    unknown = tmp_path / "unknown.json"
    unknown.write_text(json.dumps({"mode": "explain"}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["sandbox_worker", "--request", str(unknown), "--work-dir", str(work)])
    assert sandbox_worker.main() == sandbox_worker.EXIT_BAD_REQUEST
    assert not (work / "result.json").exists()


def test_directory_sink_manifest_is_replaced_atomically(tmp_path: Path) -> None:
    sink = sandbox_worker.DirectoryArtifactSink(tmp_path)
    ref = sink.put("curve/fgsm.json", b"{}", "application/json")
    assert ref.startswith("sandbox:curve/fgsm.json:")
    assert not (tmp_path / "artifacts.json.tmp").exists()
    manifest = json.loads((tmp_path / "artifacts.json").read_text(encoding="utf-8"))
    assert [item["name"] for item in manifest] == ["curve/fgsm.json"]
    assert os.path.isfile(tmp_path / "artifacts" / "curve" / "fgsm.json")
