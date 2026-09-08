"""``redsim ml build-assets`` is wired through P0's entry points and runs the real builder.

The parsing tests need no ``ml`` extra. The offline smoke build trains the URL
classifier on the committed CI sample (no Kaggle credentials in reach, no
network) and checks that every model entry the CLI writes is a
``schema.MLModelManifest``.
"""

from __future__ import annotations

import argparse
import importlib
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from redsim.cli.ml import BUILD_ASSETS_REASON, BUILD_ASSETS_STATUS, DATASET_CACHE_ENV, cmd_ml
from redsim.ml.assets import ASSET_IDS, DATASET_CHOICES, MODEL_IDS

# ``redsim.cli`` re-exports the ``main`` function under the same name as the
# module, so resolve the module through importlib.
cli_main = importlib.import_module("redsim.cli.main")


def _parse(argv: list[str]) -> argparse.Namespace:
    return cli_main.build_parser().parse_args(argv)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def test_parser_has_ml_build_assets_with_defaults():
    args = _parse(["ml", "build-assets"])
    assert args.command == "ml" and args.ml_action == "build-assets"
    assert args.dataset == "all" and args.only is None and args.epochs == 3 and args.out == "assets"
    assert args.cache_dir is None and args.seed == 0 and args.image_size == 128 and args.prefer_xgboost is True
    assert "ml" in cli_main._COMMANDS


def test_dataset_choices_match_the_builder():
    assert DATASET_CHOICES == ("image", "tabular", "cifar10", "all")
    for choice in DATASET_CHOICES:
        assert _parse(["ml", "build-assets", "--dataset", choice]).dataset == choice
    with pytest.raises(SystemExit):
        _parse(["ml", "build-assets", "--dataset", "bogus"])


def test_only_accepts_the_bundled_model_ids():
    assert set(ASSET_IDS) == {"vehicles_cnn", "cifar10_smallcnn", "url_classifier"}
    assert {ASSET_IDS[m] for m in ASSET_IDS} == {"image", "cifar10", "tabular"}
    assert MODEL_IDS == {"image": "vehicles_cnn", "cifar10": "cifar10_smallcnn", "tabular": "url_classifier"}
    args = _parse(["ml", "build-assets", "--only", "cifar10_smallcnn", "--only", "url_classifier"])
    assert args.only == ["cifar10_smallcnn", "url_classifier"]
    with pytest.raises(SystemExit):
        _parse(["ml", "build-assets", "--only", "resnet_from_upload"])


def test_numeric_and_flag_options_parse():
    args = _parse(["ml", "build-assets", "--dataset", "cifar10", "--epochs", "1", "--max-train", "512",
                   "--max-eval", "256", "--image-size", "32", "--seed", "7", "--no-xgboost",
                   "--out", "/tmp/x", "--cache-dir", "/tmp/c", "--cifar10-revision", "abc"])
    assert (args.epochs, args.max_train, args.max_eval, args.image_size, args.seed) == (1, 512, 256, 32, 7)
    assert args.prefer_xgboost is False and args.out == "/tmp/x" and args.cache_dir == "/tmp/c"
    assert args.cifar10_revision == "abc"


def test_ml_requires_an_action():
    with pytest.raises(SystemExit):
        _parse(["ml"])


def test_help_text_describes_the_real_builder(capsys):
    with pytest.raises(SystemExit) as exc:
        _parse(["ml", "build-assets", "--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    for needle in ("MANIFEST.json", "--dataset", "--only", "--epochs", "KAGGLE_API_TOKEN", "REDSIM_ENV_FILE",
                   "KAGGLE_USERNAME", "KAGGLE_KEY", "MLModelManifest", DATASET_CACHE_ENV, "vehicles_cnn",
                   "cifar10_smallcnn", "url_classifier"):
        assert needle in text, needle
    assert "not implemented" not in text.lower()


def test_status_is_implemented():
    assert BUILD_ASSETS_STATUS == "implemented"
    assert BUILD_ASSETS_REASON == ""


def test_parser_build_imports_no_ml_library():
    code = (
        "import sys\n"
        "from redsim.cli.main import build_parser\n"
        "build_parser().parse_args(['ml', 'build-assets', '--only', 'url_classifier'])\n"
        "heavy = sorted(m for m in ('torch', 'sklearn', 'xgboost', 'redsim.ml.assets.build',\n"
        "                            'redsim.ml.assets.datasets') if m in sys.modules)\n"
        "print(heavy)\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         cwd=Path(__file__).resolve().parents[2])
    assert out.stdout.strip() == "[]", out.stdout


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def test_main_dispatches_ml_to_cmd_ml_build_assets():
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.cli.ml.cmd_ml_build_assets") as body:
        cli_main.main(["ml", "build-assets", "--dataset", "tabular"])
    body.assert_called_once()
    args, config = body.call_args.args
    assert args.dataset == "tabular" and config is None


def test_cmd_ml_rejects_an_unknown_action(capsys):
    with pytest.raises(SystemExit) as exc:
        cmd_ml(argparse.Namespace(ml_action="bogus"), config=None)  # type: ignore[arg-type]
    assert exc.value.code == 2
    assert "Unknown ml action: bogus" in capsys.readouterr().err


def test_build_options_come_from_args_and_the_cache_env(tmp_path, monkeypatch):
    pytest.importorskip("numpy")
    monkeypatch.setenv(DATASET_CACHE_ENV, str(tmp_path / "shared-cache"))
    captured: dict[str, object] = {}

    def fake_build(opts, log, warn):
        captured["opts"] = opts
        from redsim.ml.assets.manifest import AssetManifest
        return AssetManifest.new()

    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.build_assets", side_effect=fake_build):
        cli_main.main(["ml", "build-assets", "--only", "url_classifier", "--out", str(tmp_path / "assets"),
                       "--seed", "3", "--no-xgboost"])
    opts = captured["opts"]
    assert opts.only == ("url_classifier",) and opts.selected == {"tabular"}
    assert opts.cache_dir == tmp_path / "shared-cache" and opts.out == tmp_path / "assets"
    assert opts.seed == 3 and opts.prefer_xgboost is False

    # An explicit --cache-dir wins over the environment; without either, the cache sits under <out>.
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.build_assets", side_effect=fake_build):
        cli_main.main(["ml", "build-assets", "--dataset", "tabular", "--cache-dir", str(tmp_path / "explicit")])
    assert captured["opts"].cache_dir == tmp_path / "explicit"
    monkeypatch.delenv(DATASET_CACHE_ENV)
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.build_assets", side_effect=fake_build):
        cli_main.main(["ml", "build-assets", "--dataset", "tabular", "--out", str(tmp_path / "o")])
    assert captured["opts"].cache_dir == tmp_path / "o" / "cache"


def test_bad_options_exit_2(tmp_path, capsys):
    pytest.importorskip("numpy")
    with patch("redsim.config.load_config", return_value=None), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "build-assets", "--dataset", "tabular", "--epochs", "0", "--out", str(tmp_path)])
    assert exc.value.code == 2
    assert "epochs must be >= 1" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Offline smoke build through the CLI (committed sample, no Kaggle, no network)
# ---------------------------------------------------------------------------

@pytest.mark.ml
def test_tabular_build_through_the_cli_writes_ml_model_manifest_entries(tmp_path, no_kaggle, capsys):
    pytest.importorskip("numpy")
    pytest.importorskip("sklearn")
    from redsim.ml.assets.manifest import MANIFEST_NAME, load_manifest, manifest_digest, verify_manifest
    from redsim.ml.schema import MLModelManifest

    out = tmp_path / "assets"
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.inject_truststore", return_value=False):
        cli_main.main(["ml", "build-assets", "--dataset", "tabular", "--out", str(out), "--no-xgboost"])
    text = capsys.readouterr().out
    assert "KAGGLE_API_TOKEN is not set" in text
    assert "url_classifier" in text and "[fixture only]" in text

    raw = json.loads((out / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert set(raw["models"]) == {"url_classifier"}
    entry = raw["models"]["url_classifier"]
    projected = MLModelManifest.model_validate(entry)
    assert projected.modality == "tabular" and projected.format == "sklearn_joblib"
    assert projected.status == "available" and projected.refusal_reason is None
    assert projected.bundled is True and projected.gradients is False
    assert projected.n_classes == 4 and len(projected.class_names) == 4 and projected.input_shape == [16]
    assert projected.features is not None and len(projected.features) == 16
    assert projected.surrogate is not None and projected.surrogate.agreement_clean is not None
    assert projected.clean_accuracy is not None and projected.clean_accuracy.split == projected.dataset_split
    assert projected.manifest_sha256 == manifest_digest(projected)
    assert entry["fixture_only"] is True, "the committed sample never builds a demo target"
    assert entry["sha256"] == entry["file"]["sha256"] and (out / entry["file"]["path"]).exists()
    sample = raw["datasets"]["local:tests/ml/fixtures/malicious_urls_sample.csv"]
    assert sample["fixture_only"] is True and sample["sampled_from"]["source_file_sha256"]
    assert sample["source_file_sha256"] == sample["revision"] and sample["n_rows"] == 60

    loaded = load_manifest(out / MANIFEST_NAME)
    assert verify_manifest(loaded, out) == []
    assert (out / "cache").is_dir(), "the default cache lives under <out>"
