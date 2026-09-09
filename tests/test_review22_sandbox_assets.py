"""Review #22 F7: the ML sandbox child learns the assets directory, and nothing else.

``_child_env`` starts from an empty environment and copies only the interpreter
allowlist, which drops every ``REDSIM_*`` variable. Bundled targets, tabular
targets and the uploaded-model evaluation binding all resolve ``MANIFEST.json``
from ``REDSIM_ML_ASSETS_DIR`` inside the child, so a deployment with a
non-default assets mount used to fail validation and campaigns there. The parent
now hands the resolved directory over explicitly, as ``request["assets_dir"]``
and as the single non-secret ``REDSIM_*`` variable in the child env, while
``PYTHIA_API_KEY``, ``KAGGLE_*``, the other ``REDSIM_*`` secrets and proxy
variables stay behind.

These tests never load a model: the child is a real subprocess that reports the
environment it was started with, so what is asserted is what the child saw.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("numpy")

from redsim.ml import sandbox, sandbox_worker
from redsim.ml.sandbox import validate_model_sandboxed
from redsim.scanners.sandbox import ENV_NETWORK

# Values a parent worker process realistically holds. None may reach the child.
_PARENT_SECRETS = {
    "PYTHIA_API_KEY": "pk_test_never_forward",
    "KAGGLE_API_TOKEN": "kaggle-token-never-forward",
    "KAGGLE_USERNAME": "kaggle-user",
    "KAGGLE_KEY": "kaggle-key",
    "REDSIM_DB_URL": "postgresql://user:pw@db/redsim",
    "REDSIM_WORKER_SIGNING_KEY": "signing-key",
    "REDSIM_AUTH_PROFILES_KEY": "fernet-key",
    "REDSIM_BROKER_URL": "redis://broker",
    "HTTPS_PROXY": "http://proxy.example:3128",
    "https_proxy": "http://proxy.example:3128",
    "AWS_SECRET_ACCESS_KEY": "aws-secret",
}

# The child dumps its own environment as the "manifest" so the parent's
# validate_model_sandboxed hands it straight back to the test.
_ENV_DUMP = (
    "import json, os, sys\n"
    "work = sys.argv[1]\n"
    "payload = {'manifest': {'env': dict(os.environ), 'cwd': os.getcwd()}}\n"
    "open(work + '/result.json', 'w').write(json.dumps(payload))\n"
)


def _observe_child(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run validate_model_sandboxed against an env-dumping child.

    Returns ``(request_json_as_written, child_env_as_seen_by_the_child)``.
    """
    real_popen = subprocess.Popen
    captured: dict[str, Any] = {}

    def dumping_child(argv: list[str], **kwargs: Any) -> subprocess.Popen[str]:
        request_path = Path(argv[argv.index("--request") + 1])
        work_dir = argv[argv.index("--work-dir") + 1]
        captured["request"] = json.loads(request_path.read_text(encoding="utf-8"))
        captured["popen_env"] = dict(kwargs["env"])
        return real_popen([sys.executable, "-c", _ENV_DUMP, work_dir], **kwargs)

    monkeypatch.setattr("redsim.ml.sandbox.subprocess.Popen", dumping_child)
    manifest = validate_model_sandboxed(
        "review22-target",
        Path("/nonexistent/model.pt"),
        {"format": "torch_state_dict"},
    )
    assert isinstance(manifest, dict)
    child_env = manifest["env"]
    # Sanity: the env Popen was given is the env the child actually saw.
    assert child_env.get("REDSIM_PLUGINS") == "0"
    assert captured["popen_env"].get("REDSIM_PLUGINS") == "0"
    return captured["request"], child_env


def _set_parent_env(monkeypatch: pytest.MonkeyPatch, assets: Path) -> None:
    monkeypatch.setenv(sandbox.ASSETS_DIR_ENV, str(assets))
    for key, value in _PARENT_SECRETS.items():
        monkeypatch.setenv(key, value)
    # Network stays off so proxy variables are stripped regardless of the shell.
    monkeypatch.delenv(ENV_NETWORK, raising=False)


def test_child_carries_assets_dir_but_no_parent_secrets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assets = tmp_path / "mounted-assets"
    assets.mkdir()
    _set_parent_env(monkeypatch, assets)

    request, child_env = _observe_child(monkeypatch)

    expected = str(assets.resolve())
    assert request["assets_dir"] == expected
    assert child_env[sandbox.ASSETS_DIR_ENV] == expected
    for key in _PARENT_SECRETS:
        assert key not in child_env, f"{key} leaked into the sandbox child env"
    # The assets directory is the ONLY REDSIM_* value beside the plugin pin and the two
    # LLM pins (REDSIM_ENV_FILE -> absent file, REDSIM_DISABLE_LLM=1).
    redsim_keys = sorted(k for k in child_env if k.startswith("REDSIM_"))
    assert redsim_keys == ["REDSIM_DISABLE_LLM", "REDSIM_ENV_FILE", "REDSIM_ML_ASSETS_DIR", "REDSIM_PLUGINS"]


def test_child_assets_dir_is_resolved_not_echoed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``~``, ``..`` and a relative cwd-anchored value are normalized before hand-off."""
    real = tmp_path / "tree"
    real.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(sandbox.ASSETS_DIR_ENV, "~/tree/../tree")
    for key, value in _PARENT_SECRETS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv(ENV_NETWORK, raising=False)

    request, child_env = _observe_child(monkeypatch)

    assert request["assets_dir"] == str(real.resolve())
    assert child_env[sandbox.ASSETS_DIR_ENV] == str(real.resolve())
    assert Path(child_env[sandbox.ASSETS_DIR_ENV]).is_absolute()


def test_default_assets_dir_is_absolute_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(sandbox.ASSETS_DIR_ENV, raising=False)
    resolved = sandbox._assets_dir()
    assert resolved.is_absolute()
    assert resolved == Path(sandbox.DEFAULT_ASSETS_DIR).resolve()

    monkeypatch.setenv(sandbox.ASSETS_DIR_ENV, "   ")
    assert sandbox._assets_dir() == Path(sandbox.DEFAULT_ASSETS_DIR).resolve()


def test_env_name_and_default_agree_with_bundled_targets() -> None:
    """sandbox.py declares the constants locally; they must track bundled.py."""
    bundled = pytest.importorskip("redsim.ml.targets.bundled")
    assert sandbox.ASSETS_DIR_ENV == bundled.ASSETS_DIR_ENV
    assert sandbox_worker.ASSETS_DIR_ENV == bundled.ASSETS_DIR_ENV
    assert sandbox.DEFAULT_ASSETS_DIR == bundled.DEFAULT_ASSETS_DIR


def test_worker_applies_request_assets_dir_to_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(sandbox_worker.ASSETS_DIR_ENV, raising=False)

    applied = sandbox_worker._apply_assets_dir({"assets_dir": str(tmp_path)})

    assert applied == tmp_path
    assert os.environ[sandbox_worker.ASSETS_DIR_ENV] == str(tmp_path)
    bundled = pytest.importorskip("redsim.ml.targets.bundled")
    assert bundled.assets_dir() == tmp_path


def test_worker_leaves_environment_alone_without_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(sandbox_worker.ASSETS_DIR_ENV, raising=False)
    assert sandbox_worker._apply_assets_dir({"mode": "validate"}) is None
    assert sandbox_worker.ASSETS_DIR_ENV not in os.environ


@pytest.mark.parametrize("bad", ["./assets", "assets", "", "   ", 123, ["/x"]])
def test_worker_refuses_non_absolute_assets_dir(
    monkeypatch: pytest.MonkeyPatch, bad: Any
) -> None:
    """A relative value would re-anchor on the child's cwd; refuse explicitly."""
    monkeypatch.delenv(sandbox_worker.ASSETS_DIR_ENV, raising=False)
    with pytest.raises(ValueError, match="assets_dir"):
        sandbox_worker._apply_assets_dir({"assets_dir": bad})
    assert sandbox_worker.ASSETS_DIR_ENV not in os.environ


def test_worker_main_applies_assets_dir_before_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """main() sets the env before the mode handler (and its ML imports) runs."""
    monkeypatch.delenv(sandbox_worker.ASSETS_DIR_ENV, raising=False)
    assets = tmp_path / "assets"
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    request = tmp_path / "request.json"
    request.write_text(json.dumps({
        "mode": "validate",
        "target_id": "t",
        "target_file": "/nonexistent/model.pt",
        "target_detail": {},
        "assets_dir": str(assets),
    }), encoding="utf-8")
    seen: dict[str, str | None] = {}

    def fake_validate(_request: dict[str, Any], _work_dir: Path) -> None:
        seen["assets"] = os.environ.get(sandbox_worker.ASSETS_DIR_ENV)

    monkeypatch.setattr(sandbox_worker, "_validate", fake_validate)
    monkeypatch.setattr(
        sys, "argv",
        ["sandbox_worker", "--request", str(request), "--work-dir", str(work_dir)],
    )

    assert sandbox_worker.main() == 0
    assert seen["assets"] == str(assets)
