from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("art")
pytest.importorskip("torch")

from redsim.llm import pythia
from redsim.ml import sandbox
from redsim.ml.errors import UnsupportedArtifact
from redsim.ml.reporting import render_campaign_reports
from redsim.ml.sandbox import (
    MlSandboxConfig,
    _ml_child_env,
    _persist_child_artifacts,
    no_env_file,
    run_campaign_sandboxed,
    validate_model_sandboxed,
)
from redsim.ml.schema import CampaignConfig, CampaignRecord

# What a worker parent's environment holds and the child must never see.
_PARENT_SECRETS = {
    "PYTHIA_API_KEY": "fake-parent-key-not-a-secret",
    "PYTHIA_BASE_URL": "https://pythia.gateway.example.internal",
    "PYTHIA_PERSONA": "ndia-demo",
    "REDSIM_ML_LLM_MODEL": "pythia/auto",
    "REDSIM_DB_URL": "postgresql://user:pw@db/redsim",
}
_DOT_ENV = (
    "PYTHIA_API_KEY=fake-dotenv-key-not-a-secret\n"
    "PYTHIA_BASE_URL=https://dotenv.example.internal\n"
    "REDSIM_ML_LLM_MODEL=pythia/auto\n"
)

# Stand-in child: writes a validate envelope whose manifest is the environment it
# ran with plus whether the pinned REDSIM_ENV_FILE exists from where it stands.
_ENV_FILE_DUMP = r"""
import json, os, sys
work_dir = sys.argv[1]
env_file = os.environ.get("REDSIM_ENV_FILE", "")
result = {"ok": True, "result": {"manifest": {
    "env": dict(os.environ),
    "env_file": env_file,
    "env_file_exists": os.path.exists(env_file),
}}}
with open(os.path.join(work_dir, "result.json"), "w", encoding="utf-8") as fh:
    json.dump(result, fh)
"""


class _Sink:
    def __init__(self) -> None:
        self.rows: list[tuple[str, bytes, str]] = []

    def put(
        self,
        name: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str:
        self.rows.append((name, data, content_type))
        return f"test:{name}"

    def sha256(self, _name: str) -> str:
        return "0" * 64


def _config() -> CampaignConfig:
    detail: dict[str, Any] = {
        "name": "sandbox test model",
        "status": "available",
        "modality": "image",
        "format": "torch_state_dict",
        "architecture_id": "smallcnn",
        "dataset_id": "missing-test-dataset",
        "dataset_split": "test",
        "sha256": "0" * 64,
    }
    return CampaignConfig(
        target_id="sandbox-test-model",
        modality="image",
        attack_ids=["fgsm"],
        eps_grid=[0.03],
        reference_eps=0.03,
        n_samples=10,
        dataset_id="missing-test-dataset",
        target_snapshot={
            "id": "sandbox-test-model",
            "kind": "ml_model_artifact",
            "value": "test",
            "detail": detail,
        },
    )


def test_sandbox_returns_partial_record_when_child_fails(tmp_path: Path) -> None:
    model = tmp_path / "model.pt"
    model.write_bytes(b"PK\x03\x04not-a-model")

    config = _config()
    record = run_campaign_sandboxed(
        config,
        _Sink(),
        target_file=model,
        target_detail=config.target_snapshot["detail"],
    )

    assert record.status == "failed"
    assert record.completeness == "partial"
    assert record.score is None
    assert record.score_status is not None
    # The refusal travels as typed evidence in the envelope, not as a stderr tail.
    error = record.error or ""
    assert error.startswith(("UnsupportedArtifact:", "ModelLoadRefused:", "TargetUnavailable:"))
    assert "ML sandbox exited" not in error
    assert "Traceback" not in error


def test_real_child_reports_validate_refusal_as_typed_class(tmp_path: Path) -> None:
    """The real child writes ``{"ok": false, "error_class": ...}``; the parent raises that class."""
    model = tmp_path / "model.pt"
    model.write_bytes(b"PK\x03\x04not-a-model")

    with pytest.raises(UnsupportedArtifact) as info:
        validate_model_sandboxed(
            "sandbox-test-model", model, _config().target_snapshot["detail"],
        )

    assert not isinstance(info.value, RuntimeError)
    assert "Traceback" not in str(info.value)


def test_sandbox_kills_process_group_when_cancelled(
    monkeypatch: Any,
) -> None:
    real_popen = subprocess.Popen

    def sleeping_child(_argv: list[str], **kwargs: Any) -> subprocess.Popen[str]:
        return real_popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            **kwargs,
        )

    monkeypatch.setattr("redsim.ml.sandbox.subprocess.Popen", sleeping_child)
    record = run_campaign_sandboxed(
        _config(),
        _Sink(),
        is_cancelled=lambda: True,
    )

    assert record.status == "cancelled"
    assert "cancelled while sandbox child" in (record.error or "")


def test_campaign_report_renders_canonical_measurements() -> None:
    fixture = Path(__file__).parent / "ml" / "fixtures" / "run_record.json"
    record = CampaignRecord.model_validate_json(fixture.read_bytes())

    reports = {name: data for name, data, _content_type in render_campaign_reports(record)}

    markdown = reports["report.md"].decode()
    assert "| fgsm | 0.03 |" in markdown
    assert "| Attack | Epsilon | N | Clean correct |" in markdown
    assert json.loads(reports["report.json"])["run_id"] == record.run_id


def test_parent_verifies_and_maps_child_artifacts(tmp_path: Path) -> None:
    work = tmp_path / "work"
    artifact_root = work / "artifacts" / "evidence"
    artifact_root.mkdir(parents=True)
    data = b"trusted evidence"
    (artifact_root / "sample.json").write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    reference = f"sandbox:evidence/sample.json:{digest}"
    (work / "artifacts.json").write_text(json.dumps([{
        "name": "evidence/sample.json",
        "content_type": "application/json",
        "sha256": digest,
        "reference": reference,
    }]))
    sink = _Sink()

    mapping = _persist_child_artifacts(work, sink)

    assert mapping == {reference: "test:evidence/sample.json"}
    assert sink.rows == [
        ("evidence/sample.json", data, "application/json")
    ]


# --- child environment: no .env fallback, no LLM (spec 10.8 / 16.1) ----------------------


def test_sandbox_env_names_match_their_readers() -> None:
    """The literals declared in ``redsim.ml.sandbox`` are the names the readers use."""
    assert sandbox.ENV_FILE_VAR == pythia.ENV_FILE_VAR == "REDSIM_ENV_FILE"
    assert sandbox.DISABLE_LLM_ENV == "REDSIM_DISABLE_LLM"
    assert sandbox.NO_ENV_FILE_NAME == "no-env"


def _checkout_with_real_dot_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A cwd and a repo root that both hold a ``.env`` with a gateway key, plus a live parent env."""
    dot_env = tmp_path / ".env"
    dot_env.write_text(_DOT_ENV, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(pythia, "_REPO_ROOT", tmp_path)
    for key, value in _PARENT_SECRETS.items():
        monkeypatch.setenv(key, value)
    # The parent itself points at that file explicitly, the way a worker deployment would.
    monkeypatch.setenv("REDSIM_ENV_FILE", str(dot_env))
    return dot_env


def test_child_env_pins_env_file_absent_and_disables_llm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    dot_env = _checkout_with_real_dot_env(tmp_path, monkeypatch)
    # Control: from a bare environment the gateway client does find ./.env, so what
    # follows proves the pin, not the absence of a file.
    assert pythia.env_file_path({}) == dot_env
    work_dir = tmp_path / "job-1"
    work_dir.mkdir()

    env = _ml_child_env(MlSandboxConfig(), assets="/assets", hash_seed=0, work_dir=work_dir)

    assert env["REDSIM_ENV_FILE"] == str(work_dir / "no-env") == str(no_env_file(work_dir))
    assert not Path(env["REDSIM_ENV_FILE"]).exists()
    assert env["REDSIM_DISABLE_LLM"] == "1"
    assert not any(key.startswith("PYTHIA_") for key in env), sorted(env)
    for key in _PARENT_SECRETS:
        assert key not in env, f"{key} leaked into the sandbox child env"
    assert sorted(key for key in env if key.startswith("REDSIM_")) == [
        "REDSIM_DISABLE_LLM", "REDSIM_ENV_FILE", "REDSIM_ML_ASSETS_DIR", "REDSIM_PLUGINS",
    ]
    # Given the child's environment, the gateway client finds no .env and no settings even
    # though ./.env and the repo-root .env exist and carry a key.
    assert pythia.env_file_path(env) is None
    assert "PYTHIA_API_KEY" not in pythia.resolve_env(env)
    assert pythia.PythiaSettings.from_env(env) is None


def test_child_env_without_work_dir_pins_under_the_work_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The doctor / adapter ``--help`` probes build the env with no job directory."""
    monkeypatch.setenv(sandbox.WORK_DIR_ENV, str(tmp_path / "work"))

    env = _ml_child_env(MlSandboxConfig(), assets="/assets", hash_seed=0)

    assert no_env_file() == (tmp_path / "work").resolve() / "no-env"
    assert env["REDSIM_ENV_FILE"] == str(no_env_file())
    assert not Path(env["REDSIM_ENV_FILE"]).exists()
    assert env["REDSIM_DISABLE_LLM"] == "1"


def test_real_spawn_carries_env_pins_and_the_env_file_is_absent_for_the_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end through ``validate_model_sandboxed``: the env Popen gets is the env the child sees."""
    _checkout_with_real_dot_env(tmp_path, monkeypatch)
    monkeypatch.setenv(sandbox.WORK_DIR_ENV, str(tmp_path / "work"))
    real_popen = subprocess.Popen
    captured: dict[str, Any] = {}

    def dumping_child(argv: list[str], **kwargs: Any) -> subprocess.Popen[str]:
        captured["work_dir"] = argv[argv.index("--work-dir") + 1]
        captured["popen_env"] = dict(kwargs["env"])
        return real_popen([sys.executable, "-c", _ENV_FILE_DUMP, captured["work_dir"]], **kwargs)

    monkeypatch.setattr("redsim.ml.sandbox.subprocess.Popen", dumping_child)

    manifest = validate_model_sandboxed(
        "env-pin-target", Path("/nonexistent/model.pt"), {"format": "torch_state_dict"},
    )

    child_env = manifest["env"]
    expected_env_file = os.path.join(captured["work_dir"], "no-env")
    assert captured["popen_env"]["REDSIM_ENV_FILE"] == expected_env_file
    assert manifest["env_file"] == expected_env_file
    assert manifest["env_file_exists"] is False
    assert child_env["REDSIM_DISABLE_LLM"] == "1"
    assert child_env["REDSIM_PLUGINS"] == "0"
    assert not any(key.startswith("PYTHIA_") for key in child_env), sorted(child_env)
    for key in _PARENT_SECRETS:
        assert key not in child_env, f"{key} leaked into the sandbox child env"
    # The work directory (and with it the pinned path) is gone once the job returns.
    assert not Path(captured["work_dir"]).exists()