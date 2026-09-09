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
from redsim.ml.assets import ARCH_CHOICES, ASSET_IDS, DATASET_CHOICES, LEGACY_MODEL_IDS, MODEL_IDS

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
    assert args.dataset is None and args.only is None and args.epochs == 3 and args.out == "assets"
    assert args.cache_dir is None and args.seed == 0 and args.image_size == 128
    assert args.prefer_xgboost is False, "sklearn_joblib is the default bundled format (spec 9.2)"
    assert args.arch == "small_cnn" and args.fixture is False and args.fixture_out is None
    assert args.fixture_sidecar is None and args.fixture_allow_synthetic is False
    assert "ml" in cli_main._COMMANDS


def test_dataset_choices_match_the_builder():
    assert DATASET_CHOICES == ("image", "tabular", "cifar10", "all")
    for choice in DATASET_CHOICES:
        assert _parse(["ml", "build-assets", "--dataset", choice]).dataset == choice
    with pytest.raises(SystemExit):
        _parse(["ml", "build-assets", "--dataset", "bogus"])


def test_only_accepts_the_bundled_model_ids():
    # The builder writes the ids the target registry serves; the legacy tabular id stays accepted as an alias.
    assert MODEL_IDS == {"image": "vehicles_cnn", "cifar10": "cifar10_smallcnn", "tabular": "url_trees"}
    assert LEGACY_MODEL_IDS == {"url_classifier": "url_trees"}
    assert set(ASSET_IDS) == {"vehicles_cnn", "cifar10_smallcnn", "url_trees", "url_classifier"}
    assert ASSET_IDS["url_classifier"] == ASSET_IDS["url_trees"] == "tabular"
    assert {ASSET_IDS[m] for m in ASSET_IDS} == {"image", "cifar10", "tabular"}
    args = _parse(["ml", "build-assets", "--only", "cifar10_smallcnn", "--only", "url_trees"])
    assert args.only == ["cifar10_smallcnn", "url_trees"]
    assert _parse(["ml", "build-assets", "--only", "url_classifier"]).only == ["url_classifier"]
    with pytest.raises(SystemExit):
        _parse(["ml", "build-assets", "--only", "resnet_from_upload"])


def test_numeric_and_flag_options_parse():
    args = _parse(["ml", "build-assets", "--dataset", "cifar10", "--epochs", "1", "--max-train", "512",
                   "--max-eval", "256", "--image-size", "32", "--seed", "7", "--no-xgboost",
                   "--out", "/tmp/x", "--cache-dir", "/tmp/c", "--cifar10-revision", "abc"])
    assert (args.epochs, args.max_train, args.max_eval, args.image_size, args.seed) == (1, 512, 256, 32, 7)
    assert args.prefer_xgboost is False and args.out == "/tmp/x" and args.cache_dir == "/tmp/c"
    assert args.cifar10_revision == "abc"
    assert _parse(["ml", "build-assets", "--xgboost"]).prefer_xgboost is True
    assert ARCH_CHOICES == ("small_cnn", "resnet18")
    for arch in ARCH_CHOICES:
        assert _parse(["ml", "build-assets", "--arch", arch]).arch == arch
    with pytest.raises(SystemExit):
        _parse(["ml", "build-assets", "--arch", "vgg_from_the_internet"])
    fx = _parse(["ml", "build-assets", "--fixture", "--fixture-out", "/tmp/f.npz", "--fixture-sidecar", "/tmp/M.json",
                 "--fixture-synthetic-ok"])
    assert fx.fixture is True and fx.fixture_out == "/tmp/f.npz" and fx.fixture_sidecar == "/tmp/M.json"
    assert fx.fixture_allow_synthetic is True and fx.dataset is None


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
                   "cifar10_smallcnn", "url_trees", "url_classifier", "--fixture", "cifar10_test_500.npz", "--arch",
                   "resnet18", "--xgboost"):
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
    assert opts.only == ("url_trees",) and opts.selected == {"tabular"}   # the legacy id is canonicalised
    assert opts.cache_dir == tmp_path / "shared-cache" and opts.out == tmp_path / "assets"
    assert opts.seed == 3 and opts.prefer_xgboost is False and opts.arch == "small_cnn"
    assert opts.build_models is True and opts.fixture is False

    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.build_assets", side_effect=fake_build):
        cli_main.main(["ml", "build-assets", "--dataset", "image", "--arch", "resnet18", "--xgboost",
                       "--out", str(tmp_path / "assets")])
    assert captured["opts"].arch == "resnet18" and captured["opts"].prefer_xgboost is True

    # --fixture alone builds no model; with an explicit selection it runs after the builds.
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.build_assets", side_effect=fake_build):
        cli_main.main(["ml", "build-assets", "--fixture", "--out", str(tmp_path / "assets"),
                       "--fixture-out", str(tmp_path / "fx" / "cifar10_test_500.npz")])
    fixture_only = captured["opts"]
    assert fixture_only.fixture is True and fixture_only.build_models is False and fixture_only.selected == set()
    assert fixture_only.fixture_out == tmp_path / "fx" / "cifar10_test_500.npz"
    assert fixture_only.fixture_sidecar is None and fixture_only.fixture_allow_synthetic is False
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.build_assets", side_effect=fake_build):
        cli_main.main(["ml", "build-assets", "--fixture", "--dataset", "tabular", "--out", str(tmp_path / "assets")])
    assert captured["opts"].fixture is True and captured["opts"].build_models is True
    assert captured["opts"].selected == {"tabular"}
    from redsim.ml.assets.build import DEFAULT_FIXTURE_PATH
    assert captured["opts"].fixture_out == DEFAULT_FIXTURE_PATH
    assert DEFAULT_FIXTURE_PATH.name == "cifar10_test_500.npz" and DEFAULT_FIXTURE_PATH.parent.name == "fixtures"

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
    assert "url_trees" in text and "[fixture only]" in text and "sklearn_hist_gradient_boosting" in text

    raw = json.loads((out / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert set(raw["models"]) == {"url_trees"}, "the builder writes the id the target registry serves"
    entry = raw["models"]["url_trees"]
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
    eval_split = sample["splits"]["eval"]
    assert eval_split["file"]["path"].endswith("eval.npz") and eval_split["rows_csv"]["path"].endswith("eval.csv")
    assert (out / eval_split["file"]["path"]).exists() and (out / eval_split["rows_csv"]["path"]).exists()

    loaded = load_manifest(out / MANIFEST_NAME)
    assert verify_manifest(loaded, out) == []
    assert (out / "cache").is_dir(), "the default cache lives under <out>"

    # The registry target reads exactly what the CLI wrote (the round trip is proven in test_assets_roundtrip.py).
    from redsim.ml.targets.tabular import BundledTabularTarget
    target = BundledTabularTarget("url_trees", assets_dir=out)
    assert target.info().status == "available"
    target.load()
    assert target.manifest()["manifest_verified"] is True
