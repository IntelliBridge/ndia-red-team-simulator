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
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from redsim.cli.ml import BUILD_ASSETS_REASON, BUILD_ASSETS_STATUS, DATASET_CACHE_ENV, cmd_ml
from redsim.ml.assets import ARCH_CHOICES, ASSET_IDS, DATASET_CHOICES, LEGACY_MODEL_IDS, MODEL_IDS
from redsim.ml.assets.manifest import (
    BUILD_ASSET_IDS,
    BUILD_DATASET_CHOICES,
    BUILD_MODEL_IDS,
    EXPLICIT_ONLY_DATASETS,
    all_build_datasets,
)

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
    assert args.train_slice is True and args.train_slice_n == 1536 and args.attach_train_slice is None
    assert args.detection_image_size == 320 and args.detection_subset is None
    assert "ml" in cli_main._COMMANDS


def test_dataset_choices_match_the_builder():
    # The P0 table is untouched; the build vocabulary (manifest.BUILD_*) adds text and detection before ``all``.
    assert DATASET_CHOICES == ("image", "tabular", "cifar10", "all")
    assert BUILD_DATASET_CHOICES == ("image", "tabular", "cifar10", "text", "detection", "all")
    assert EXPLICIT_ONLY_DATASETS == ("detection",) and all_build_datasets() == {"image", "tabular", "cifar10", "text"}
    for choice in BUILD_DATASET_CHOICES:
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
    # Phase B: the text and detection ids join through the build vocabulary, on top of the P0 rows.
    assert BUILD_MODEL_IDS == {**MODEL_IDS, "text": "sms_tfidf_lr", "detection": "assets_frcnn_mnv3"}
    assert set(BUILD_ASSET_IDS) == set(ASSET_IDS) | {"sms_tfidf_lr", "assets_frcnn_mnv3"}
    assert BUILD_ASSET_IDS["sms_tfidf_lr"] == "text" and BUILD_ASSET_IDS["assets_frcnn_mnv3"] == "detection"
    args = _parse(["ml", "build-assets", "--only", "cifar10_smallcnn", "--only", "url_trees"])
    assert args.only == ["cifar10_smallcnn", "url_trees"]
    assert _parse(["ml", "build-assets", "--only", "url_classifier"]).only == ["url_classifier"]
    assert _parse(["ml", "build-assets", "--only", "sms_tfidf_lr", "--only", "assets_frcnn_mnv3"]).only == [
        "sms_tfidf_lr", "assets_frcnn_mnv3"]
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
    phase_b = _parse(["ml", "build-assets", "--no-train-slice", "--train-slice-n", "64", "--attach-train-slice",
                      "vehicles_cnn", "--attach-train-slice", "cifar10_smallcnn", "--detection-image-size", "160",
                      "--detection-subset", "/tmp/subset"])
    assert phase_b.train_slice is False and phase_b.train_slice_n == 64
    assert phase_b.attach_train_slice == ["vehicles_cnn", "cifar10_smallcnn"]
    assert phase_b.detection_image_size == 160 and phase_b.detection_subset == "/tmp/subset"


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
                   "resnet18", "--xgboost", "sms_tfidf_lr", "assets_frcnn_mnv3", "SMS Spam", "train_slice.npz",
                   "--attach-train-slice", "--no-train-slice", "--detection-subset", "military_assets_subset"):
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

    # Phase B options reach the builder: the text / detection selections, the slice options, the subset location.
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.build_assets", side_effect=fake_build):
        cli_main.main(["ml", "build-assets", "--dataset", "detection", "--detection-image-size", "160",
                       "--detection-subset", str(tmp_path / "subset"), "--no-train-slice", "--train-slice-n", "32",
                       "--out", str(tmp_path / "assets")])
    det = captured["opts"]
    assert det.selected == {"detection"} and det.detection_image_size == 160
    assert det.detection_subset == tmp_path / "subset" and det.train_slice is False and det.train_slice_n == 32
    assert det.train_slice_options.enabled is False and det.train_slice_options.n == 32
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.build_assets", side_effect=fake_build):
        cli_main.main(["ml", "build-assets", "--only", "sms_tfidf_lr", "--out", str(tmp_path / "assets")])
    assert captured["opts"].selected == {"text"} and captured["opts"].only == ("sms_tfidf_lr",)
    # ``--dataset all`` never includes the detector; ``--attach-train-slice`` alone builds nothing.
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.build_assets", side_effect=fake_build):
        cli_main.main(["ml", "build-assets", "--out", str(tmp_path / "assets")])
    assert captured["opts"].selected == {"image", "cifar10", "tabular", "text"}
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.build_assets", side_effect=fake_build):
        cli_main.main(["ml", "build-assets", "--attach-train-slice", "vehicles_cnn", "--out", str(tmp_path / "assets")])
    attach = captured["opts"]
    assert attach.build_models is False and attach.selected == set() and attach.attach_train_slice == ("vehicles_cnn",)
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.build_assets", side_effect=fake_build):
        cli_main.main(["ml", "build-assets", "--attach-train-slice", "vehicles_cnn", "--dataset", "tabular",
                       "--out", str(tmp_path / "assets")])
    assert captured["opts"].build_models is True and captured["opts"].attach_train_slice == ("vehicles_cnn",)


def test_bad_options_exit_2(tmp_path, capsys):
    pytest.importorskip("numpy")
    with patch("redsim.config.load_config", return_value=None), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "build-assets", "--dataset", "tabular", "--epochs", "0", "--out", str(tmp_path)])
    assert exc.value.code == 2
    assert "epochs must be >= 1" in capsys.readouterr().err
    with patch("redsim.config.load_config", return_value=None), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "build-assets", "--attach-train-slice", "url_trees", "--out", str(tmp_path)])
    assert exc.value.code == 2 and "non-image model" in capsys.readouterr().err


def test_attach_train_slice_refusals_exit_1(tmp_path, capsys):
    """A slice that is not there (or a model that was never built) is a refusal, not a traceback."""
    pytest.importorskip("numpy")
    from redsim.ml.assets.manifest import MANIFEST_NAME, AssetManifest, write_manifest

    out = tmp_path / "assets"
    write_manifest(AssetManifest.new(), out / MANIFEST_NAME)
    with patch("redsim.config.load_config", return_value=None), \
            patch("redsim.ml.assets.build.inject_truststore", return_value=False), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "build-assets", "--attach-train-slice", "vehicles_cnn", "--out", str(out)])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "asset build failed" in captured.err and "no entry in the manifest" in captured.err
    assert "attach-train-slice: recording vehicles_cnn" in captured.out


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


# ---------------------------------------------------------------------------
# redsim ml attack / redsim ml seed (G-CLI-ATTACK, G-ASSET4)
# ---------------------------------------------------------------------------

from redsim.cli import ml as cli_ml  # noqa: E402
from redsim.config import RedsimConfig  # noqa: E402

SAMPLE_URLS = Path(__file__).parent / "fixtures" / "malicious_urls_sample.csv"


def test_parser_has_ml_attack_with_campaign_defaults():
    args = _parse(["ml", "attack", "vehicles_cnn"])
    assert args.ml_action == "attack" and args.target_id == "vehicles_cnn"
    assert args.attacks == "fgsm,pgd" and args.eps is None and args.reference_eps is None
    assert args.n_samples == 200 and args.seed == 0 and args.explain_k == 8
    assert args.no_control is False and args.norm == "linf" and args.out is None and args.assets_dir is None
    assert args.actor == "cli:anonymous"
    full = _parse(["ml", "attack", "url_trees", "--attacks", "fgsm", "--eps", "0.01,0.03", "--reference-eps", "0.03",
                   "--n-samples", "50", "--seed", "7", "--explain-k", "0", "--no-control", "--norm", "l2",
                   "--out", "/tmp/runs", "--assets-dir", "/tmp/assets", "--actor", "cli:me"])
    assert (full.attacks, full.eps, full.reference_eps, full.n_samples, full.seed) == ("fgsm", "0.01,0.03", 0.03, 50, 7)
    assert full.explain_k == 0 and full.no_control is True and full.norm == "l2"
    assert full.out == "/tmp/runs" and full.assets_dir == "/tmp/assets" and full.actor == "cli:me"
    with pytest.raises(SystemExit):
        _parse(["ml", "attack"])                    # target id is required
    with pytest.raises(SystemExit):
        _parse(["ml", "attack", "x", "--norm", "l1"])


def test_parser_has_ml_seed():
    args = _parse(["ml", "seed"])
    assert args.ml_action == "seed" and args.project is None and args.only is None and args.assets_dir is None
    args = _parse(["ml", "seed", "--project", "demo", "--only", "vehicles_cnn,url_trees", "--assets-dir", "/a"])
    assert args.project == "demo" and args.only == "vehicles_cnn,url_trees" and args.assets_dir == "/a"


def test_attack_help_says_offline_and_rules_only(capsys):
    with pytest.raises(SystemExit) as exc:
        _parse(["ml", "attack", "--help"])
    assert exc.value.code == 0
    text = " ".join(capsys.readouterr().out.split())      # argparse wraps the description
    for needle in ("audit.jsonl", "redsim audit verify --run", "not_implemented", "fixture_only",
                   "narrative_source=rules", "Pythia is never called", "REDSIM_ML_ASSETS_DIR"):
        assert needle in text, needle


def _tiny_cnn_tree(root: Path) -> Path:
    """A complete asset tree written by the real builder: one tiny image model on synthetic 8x8 images.

    The synthetic dataset entry is not flagged ``fixture_only`` so the CLI can run against it; it stands
    in for a built asset tree under ``tmp_path`` and nothing it produces is evidence.
    """
    import numpy as np

    from redsim.ml.assets import datasets as ds
    from redsim.ml.assets.build import build_cnn_asset
    from redsim.ml.assets.manifest import MANIFEST_NAME, AssetManifest, DatasetEntry, write_manifest

    class_names = ["class_0", "class_1", "class_2"]
    n, size = 48, 8
    rng = np.random.default_rng(0)
    x = rng.integers(0, 256, size=(n, 3, size, size), dtype=np.uint8)
    y = (np.arange(n) % len(class_names)).astype(np.int64)
    entry = DatasetEntry(id="local:synthetic-images", source="local", revision="synthetic-v1", license="n/a",
                         class_names=list(class_names), fixture_only=False,
                         notes=["unit-test stand-in for a built asset tree; never a result"])
    train = ds.ImageSplit(name="train", x=x, y=y, indices=np.arange(n, dtype=np.int64), class_names=list(class_names))
    n_eval = n // 2
    evaluation = ds.ImageSplit(name="test", x=x[:n_eval], y=y[:n_eval], indices=np.arange(n_eval, dtype=np.int64),
                               class_names=list(class_names))
    data = ds.ImageDataset(dataset=entry, train=train, eval=evaluation)
    img_ds, img_model = build_cnn_asset(data, model_id="vehicles_cnn", root=root, epochs=1, seed=0, log=lambda _m: None)
    manifest = AssetManifest.new()
    manifest.datasets[img_ds.id] = img_ds
    manifest.models[img_model.id] = img_model
    write_manifest(manifest, root / MANIFEST_NAME)
    return root


@pytest.mark.ml
def test_ml_attack_offline_writes_verifiable_chain(tmp_path, monkeypatch, capsys):
    pytest.importorskip("numpy")
    pytest.importorskip("torch")
    pytest.importorskip("art")
    from redsim.audit.chain import JsonlAuditWriter, verify_chain
    from redsim.ml.schema import CampaignRecord

    assets = _tiny_cnn_tree(tmp_path / "assets")
    out = tmp_path / "runs"
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(assets))
    monkeypatch.setenv("REDSIM_ML_WORK_DIR", str(tmp_path / "work"))
    for key in ("REDSIM_DB_URL", "REDSIM_TEST_AUDIT", "REDSIM_PLUGINS", "PYTHIA_BASE_URL", "PYTHIA_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    config = RedsimConfig(output_dir=str(tmp_path / "unused-output-dir"))

    with patch("redsim.config.load_config", return_value=config):
        cli_main.main(["ml", "attack", "vehicles_cnn", "--attacks", "fgsm", "--eps", "0.03,0.1", "--n-samples", "12",
                       "--explain-k", "0", "--seed", "0", "--out", str(out)])
    text = capsys.readouterr().out
    run_dirs = [p for p in out.iterdir() if p.is_dir()]
    assert len(run_dirs) == 1
    run_dir = run_dirs[0]
    run_id = run_dir.name
    assert run_id in text and "narrative_source=rules" in text and "Pythia is not called" in text
    assert f"redsim audit verify --run {run_id}" in text

    # The run record, the six-section reports and the curve live under <out>/<run_id>/.
    for name in ("audit.jsonl", "run_record.json", "report.md", "report.json", "report.html"):
        assert (run_dir / name).is_file(), name
    assert (run_dir / "artifacts" / "curve" / "robustness_curve.png").is_file()
    record = CampaignRecord.model_validate_json((run_dir / "run_record.json").read_text(encoding="utf-8"))
    assert record.status == "succeeded" and record.run_id == run_id and record.target.id == "vehicles_cnn"
    assert record.config.llm_narrative is False and record.config.attack_ids == ["fgsm"]
    assert record.config.eps_grid == [0.03, 0.1] and record.config.n_samples == 12 and record.config.explain_k == 0
    assert record.config.target_snapshot["value"] == "bundled:vehicles_cnn"
    assert all(r.narrative_source == "rules" and r.narrative is None for r in record.recommendations)
    assert record.measurements and record.curve and record.stages_done[-1] == "report"
    report_json = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert report_json["run_id"] == run_id and report_json["status"] == "succeeded"
    markdown = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "Limitations" in markdown and "fgsm" in markdown

    # Every event of the run is on the single chain run:<run_id>, attack.run first, job.complete last.
    lines = [json.loads(line) for line in (run_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
             if line.strip()]
    actions = [line["action"] for line in lines]
    assert actions[0] == "attack.run" and actions[-1] == "job.complete"
    assert {"score.compute", "report.render"} <= set(actions)
    assert {line["chain_id"] for line in lines} == {f"run:{run_id}"}
    assert [line["seq"] for line in lines] == list(range(1, len(lines) + 1))
    first = lines[0]["detail"]
    assert first["target_id"] == "vehicles_cnn" and first["mode"] == "offline" and first["attack_ids"] == ["fgsm"]
    assert first["settings_hash"] == record.settings_hash and first["llm_narrative"] is False
    assert lines[-1]["success"] is True and lines[-1]["detail"]["status"] == "succeeded"
    assert verify_chain(iter(lines)).verified

    # `redsim audit verify --run <id>` accepts the chain: resolve the writer at the offline run directory
    # (the single-file layout the offline path writes, as tests/test_cli_commands_coverage.py does).
    writer = JsonlAuditWriter(run_dir, single_file="audit.jsonl")
    with patch("redsim.config.load_config", return_value=config), \
            patch("redsim.audit.chain.resolve_writer", return_value=writer), \
            pytest.raises(SystemExit) as ok:
        cli_main.main(["audit", "verify", "--run", run_id])
    assert ok.value.code == 0
    assert f"{len(lines)} events verified" in capsys.readouterr().out

    # Mutating one line breaks the chain and the same command exits 1.
    raw = (run_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    tampered = json.loads(raw[1])
    tampered["success"] = not tampered["success"]
    raw[1] = json.dumps(tampered)
    (run_dir / "audit.jsonl").write_text("\n".join(raw) + "\n", encoding="utf-8")
    with patch("redsim.config.load_config", return_value=config), \
            patch("redsim.audit.chain.resolve_writer", return_value=writer), \
            pytest.raises(SystemExit) as broken:
        cli_main.main(["audit", "verify", "--run", run_id])
    assert broken.value.code == 1
    assert "broken at seq=" in capsys.readouterr().out


def test_ml_attack_refuses_endpoint_and_fixture(tmp_path, monkeypatch, capsys):
    pytest.importorskip("numpy")
    from redsim.ml.campaign_adapter import (
        OfflineCampaignRefused,
        OfflineCampaignRequest,
        build_offline_config,
    )

    assets = tmp_path / "assets"
    assets.mkdir()                      # no MANIFEST.json: no bundled model is loadable here
    out = tmp_path / "runs"
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(assets))
    config = RedsimConfig(output_dir=str(out))

    for target_id, reason, needle in (
        ("endpoint_stub", "not_implemented", "Phase B"),
        ("cifar10_smallcnn", "fixture_only", "never served as a result"),
    ):
        with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
            cli_main.main(["ml", "attack", target_id, "--attacks", "fgsm", "--out", str(out)])
        assert exc.value.code != 0
        err = capsys.readouterr().err
        assert f"refused ({reason})" in err and needle in err, err
    assert not out.exists() or not any(out.iterdir()), "a refusal writes nothing"

    # The same refusals as typed exceptions, and an unknown target / attack refuse too.
    with pytest.raises(OfflineCampaignRefused) as info:
        build_offline_config(OfflineCampaignRequest(target_id="endpoint_stub"))
    assert info.value.reason == "not_implemented"
    with pytest.raises(OfflineCampaignRefused) as info:
        build_offline_config(OfflineCampaignRequest(target_id="cifar10_smallcnn"))
    assert info.value.reason == "fixture_only"
    with pytest.raises(OfflineCampaignRefused) as info:
        build_offline_config(OfflineCampaignRequest(target_id="no-such-target"))
    assert info.value.reason == "not_found"
    # vehicles_cnn without a manifest is not_implemented with the build hint, never a placeholder result.
    with pytest.raises(OfflineCampaignRefused) as info:
        build_offline_config(OfflineCampaignRequest(target_id="vehicles_cnn"))
    assert info.value.reason == "not_implemented" and "build-assets" in info.value.message


# ---------------------------------------------------------------------------
# redsim ml seed against the real admission service on a sqlite database
# ---------------------------------------------------------------------------

SEED_WEIGHTS = b"PK\x03\x04 vehicles state_dict placeholder: digest-checked, never deserialized by seed"
SEED_JOBLIB = b"\x80\x04\x95 url_trees joblib placeholder: digest-checked, never deserialized by seed"
SEED_TEXT_JOBLIB = b"\x80\x04\x95 sms_tfidf_lr joblib placeholder: digest-checked, never deserialized by seed"
SEED_IMAGE_DS = "hf:example/vehicles"
SEED_TABULAR_DS = "kaggle:example/urls"
SEED_TEXT_DS = "uci:sms-spam-collection"
SEED_CIFAR_DS = "hf:uoft-cs/cifar10"
SEED_IMAGE_CLASSES = ["Air Defense", "BMP", "Tank"]
SEED_URL_CLASSES = ["benign", "defacement", "malware", "phishing"]
SEED_TEXT_CLASSES = ["ham", "spam"]


def _seedable_asset_tree(root: Path) -> Path:
    """An asset tree in the shape ``redsim ml build-assets`` writes, with two bundled demo models.

    ``vehicles_cnn`` (image, torch_state_dict), ``url_trees`` (tabular, sklearn_joblib) and the Phase B
    ``sms_tfidf_lr`` (text, sklearn_joblib) carry digest-consistent files and evaluation splits so
    ``register_bundled_model`` verifies them; ``cifar10_smallcnn`` is the fixture-only entry the seed must
    skip. The bytes are placeholders: the seed path hashes files and never deserializes a model, and nothing
    here is evidence.
    """
    from redsim.ml.assets.manifest import (
        MANIFEST_NAME,
        AssetManifest,
        DatasetEntry,
        FileEntry,
        ModelEntry,
        SplitEntry,
        sha256_bytes,
        stamp_manifest_sha256,
        write_manifest,
    )
    from redsim.ml.schema import CleanAccuracy

    def write(rel: str, payload: bytes) -> FileEntry:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return FileEntry(path=rel, sha256=sha256_bytes(payload), size_bytes=len(payload))

    root.mkdir(parents=True, exist_ok=True)
    image_split = write("datasets/hf--example--vehicles/rev1/test_coarse.npz", b"npz placeholder")
    cifar_split = write("datasets/hf--uoft-cs--cifar10/rev1/test.npz", b"cifar placeholder")
    url_split = write("datasets/kaggle--example--urls/rev2/eval.npz", b"features placeholder")
    text_split = write("datasets/uci--sms-spam-collection/rev3/eval.jsonl", b'{"index": 0, "text": "x", "label": 0}\n')
    vehicles_weights = write("bundled/vehicles_cnn/weights.pt", SEED_WEIGHTS)
    cifar_weights = write("bundled/cifar10_smallcnn/weights.pt", SEED_WEIGHTS + b"-cifar")
    url_model = write("bundled/url_trees/model.joblib", SEED_JOBLIB)
    text_model = write("bundled/sms_tfidf_lr/model.joblib", SEED_TEXT_JOBLIB)

    manifest = AssetManifest.new()
    manifest.datasets[SEED_IMAGE_DS] = DatasetEntry(
        id=SEED_IMAGE_DS, source="huggingface", revision="rev1", license="MIT", class_names=SEED_IMAGE_CLASSES,
        splits={"test_coarse": SplitEntry(name="test_coarse", n=4, file=image_split)},
        preprocessing={"resolution": 8, "layout": "NCHW", "channel_order": "RGB"},
    )
    manifest.datasets[SEED_CIFAR_DS] = DatasetEntry(
        id=SEED_CIFAR_DS, source="huggingface", revision="rev1", license="MIT", fixture_only=True,
        class_names=[f"c{i}" for i in range(10)], splits={"test": SplitEntry(name="test", n=4, file=cifar_split)},
        preprocessing={"resolution": 8, "layout": "NCHW", "channel_order": "RGB"},
    )
    manifest.datasets[SEED_TABULAR_DS] = DatasetEntry(
        id=SEED_TABULAR_DS, source="kaggle", revision="rev2", license="CC0: Public Domain",
        class_names=SEED_URL_CLASSES, splits={"eval": SplitEntry(name="eval", n=4, seed=0, file=url_split)},
        preprocessing={"features": [f"f{i}" for i in range(16)], "extractor": "redsim.ml.datasets.url_features"},
    )
    manifest.datasets[SEED_TEXT_DS] = DatasetEntry(
        id=SEED_TEXT_DS, source="uci", revision="rev3", license="CC BY 4.0", class_names=SEED_TEXT_CLASSES,
        splits={"eval": SplitEntry(name="eval", n=1, seed=0, file=text_split)},
        preprocessing={"tokenizer": r"(?u)\\w+", "eval_slice": "eval.jsonl"},
    )

    def image_model(model_id: str, weights: FileEntry, dataset_id: str, split: str, classes: list[str],
                    **over: object) -> ModelEntry:
        fields: dict[str, object] = {
            "id": model_id, "name": f"{model_id} (test build)", "modality": "image", "format": "torch_state_dict",
            "sha256": weights.sha256, "size_bytes": weights.size_bytes, "file": weights,
            "architecture_id": "small_cnn",
            "architecture": {"architecture_id": "small_cnn", "in_channels": 3, "n_classes": len(classes), "image_size": 8},
            "input_shape": [3, 8, 8], "n_classes": len(classes), "class_names": classes,
            "dataset_id": dataset_id, "dataset_revision": "rev1", "dataset_split": split, "train_split": "train",
            "seed": 0, "epochs": 1, "gradients": True, "license": "MIT",
            "clean_accuracy": CleanAccuracy(value=0.5, n=4, split=split), "metrics": {"clean_accuracy": 0.5, "n": 4},
        }
        fields.update(over)
        return stamp_manifest_sha256(ModelEntry(**fields))  # type: ignore[arg-type]

    manifest.models["vehicles_cnn"] = image_model("vehicles_cnn", vehicles_weights, SEED_IMAGE_DS, "test_coarse",
                                                  SEED_IMAGE_CLASSES)
    manifest.models["cifar10_smallcnn"] = image_model(
        "cifar10_smallcnn", cifar_weights, SEED_CIFAR_DS, "test", [f"c{i}" for i in range(10)], fixture_only=True,
        architecture={"architecture_id": "small_cnn", "in_channels": 3, "n_classes": 10, "image_size": 8},
    )
    manifest.models["url_trees"] = stamp_manifest_sha256(ModelEntry(
        id="url_trees", name="url_trees (test build)", modality="tabular", format="sklearn_joblib",
        sha256=url_model.sha256, size_bytes=url_model.size_bytes, file=url_model,
        architecture_id="sklearn_hist_gradient_boosting", architecture={"library": "scikit-learn"},
        input_shape=[16], n_classes=len(SEED_URL_CLASSES), class_names=SEED_URL_CLASSES,
        dataset_id=SEED_TABULAR_DS, dataset_revision="rev2", dataset_split="eval", train_split="train",
        seed=0, epochs=None, gradients=False, license="CC0: Public Domain",
        clean_accuracy=CleanAccuracy(value=0.5, n=4, split="eval"), metrics={"clean_accuracy": 0.5, "n": 4},
    ))
    manifest.models["sms_tfidf_lr"] = stamp_manifest_sha256(ModelEntry(
        id="sms_tfidf_lr", name="sms_tfidf_lr (test build)", modality="text", format="sklearn_joblib",
        sha256=text_model.sha256, size_bytes=text_model.size_bytes, file=text_model,
        architecture_id="sklearn_tfidf_logreg", architecture={"library": "scikit-learn"},
        input_shape=[], n_classes=2, class_names=SEED_TEXT_CLASSES,
        dataset_id=SEED_TEXT_DS, dataset_revision="rev3", dataset_split="eval", train_split="train",
        seed=0, epochs=None, gradients=False, license="CC BY 4.0",
        clean_accuracy=CleanAccuracy(value=0.5, n=1, split="eval"), metrics={"clean_accuracy": 0.5, "n": 1},
    ))
    write_manifest(manifest, root / MANIFEST_NAME)
    return root


def test_seed_candidates_include_every_non_fixture_manifest_model(tmp_path):
    """The seed offers whatever the manifest holds (text and detection included) minus fixture-only entries."""
    pytest.importorskip("numpy")
    from redsim.ml.assets.manifest import load_manifest

    assets = _seedable_asset_tree(tmp_path / "assets")
    document = json.loads((assets / "MANIFEST.json").read_text(encoding="utf-8"))
    bundled, skipped = cli_ml._seed_candidates(document, [])
    assert bundled == ["sms_tfidf_lr", "url_trees", "vehicles_cnn"] and skipped == ["cifar10_smallcnn"]
    assert cli_ml._seed_candidates(document, ["sms_tfidf_lr"]) == (["sms_tfidf_lr"], [])
    # A detector entry, once built, is offered the same way (the loaded manifest is the shape the CLI reads).
    manifest = load_manifest(assets / "MANIFEST.json")
    document["models"]["assets_frcnn_mnv3"] = {**manifest.models["vehicles_cnn"].model_dump(mode="json"),
                                               "id": "assets_frcnn_mnv3", "modality": "detection"}
    bundled, skipped = cli_ml._seed_candidates(document, [])
    assert bundled == ["assets_frcnn_mnv3", "sms_tfidf_lr", "url_trees", "vehicles_cnn"]
    with pytest.raises(cli_ml.SeedUnavailable, match="manifest lacks"):
        cli_ml._seed_candidates(document, ["resnet_from_upload"])


@pytest.mark.integration
def test_ml_seed_registers_or_explains(tmp_path, monkeypatch, capsys):
    """``redsim ml seed`` drives the real ``register_bundled_model`` on a sqlite database.

    Seeding twice: the first run registers both non-fixture models (audit row on the project chain,
    weights blob, ``Target`` row per model, committed one by one), the second finds them by the read-only
    ``find_bundled_registration`` lookup, reports them as already present and writes nothing at all: no
    Target, no blob and no audit row, because a re-seed is the expected idempotent operation and not a
    refused admission. Genuine refusals still write a ``success=False`` row and exit 1 after the other
    models were tried.
    """
    pytest.importorskip("numpy")        # the target registry the service resolves ids through
    pytest.importorskip("sqlalchemy")
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    import redsim.ml.targets.text  # noqa: F401  (registers sms_tfidf_lr; the service refuses ids the registry lacks)
    import redsim.services.ml_models as ml_models
    from redsim.db import session as db_session
    from redsim.db.models import AuditEvent, Base, Organization, Project, Target
    from redsim.ml.assets.manifest import sha256_bytes
    from tests.conftest import patch_jsonb_for_sqlite

    assets = _seedable_asset_tree(tmp_path / "assets")
    blob_root = tmp_path / "blobs"
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(assets))
    monkeypatch.setenv("REDSIM_BLOB_BACKEND", "fs")
    monkeypatch.setenv("REDSIM_BLOB_FS_PATH", str(blob_root))
    for key in (cli_ml.DB_URL_ENV, "REDSIM_TEST_AUDIT", "PYTHIA_BASE_URL", "PYTHIA_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    config = RedsimConfig(output_dir=str(tmp_path / "out"))
    real_service = ml_models.register_bundled_model

    # 1. The admission service is absent in this build: say so, exit non-zero, register nothing.
    monkeypatch.delattr(ml_models, "register_bundled_model")
    with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "seed", "--project", "demo"])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "register_bundled_model" in err and "nothing was registered" in err
    monkeypatch.setattr(ml_models, "register_bundled_model", real_service, raising=False)

    # 2. The service is present but the database is not configured: the env var is named, nothing is written.
    with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "seed", "--project", "demo"])
    assert exc.value.code == 1 and cli_ml.DB_URL_ENV in capsys.readouterr().err
    assert not blob_root.exists() and not (tmp_path / "out").exists()

    # 3. A real database: the platform schema on a file-backed sqlite, one org, two projects.
    patch_jsonb_for_sqlite()
    db_url = f"sqlite:///{tmp_path / 'redsim.db'}"
    engine = create_engine(db_url, future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        sess.add(Organization(id="org-1", name="Org", slug="org"))
        sess.add(Project(id="p1", org_id="org-1", name="Demo", slug="demo"))
        sess.add(Project(id="p2", org_id="org-1", name="Second", slug="second"))
        sess.commit()
    engine.dispose()
    monkeypatch.setenv(cli_ml.DB_URL_ENV, db_url)
    # The CLI initialises redsim.db.session from REDSIM_DB_URL; start from a clean module state and restore it.
    monkeypatch.setattr(db_session, "_ENGINE", None)
    monkeypatch.setattr(db_session, "Session", None)

    def rows() -> tuple[list[Target], list[AuditEvent]]:
        with db_session.get_session() as sess:
            targets = list(sess.execute(select(Target).order_by(Target.created_at, Target.id)).scalars().all())
            events = list(sess.execute(select(AuditEvent).order_by(AuditEvent.chain_id, AuditEvent.seq)).scalars().all())
        return targets, events

    with patch("redsim.config.load_config", return_value=config):
        cli_main.main(["ml", "seed", "--project", "demo", "--actor", "cli:test"])
    out = capsys.readouterr().out
    assert "skipping cifar10_smallcnn" in out and "fixture-only" in out
    assert "seeding ['sms_tfidf_lr', 'url_trees', 'vehicles_cnn'] into project p1" in out, "sorted, fixture-only skipped"
    assert "registered: sms_tfidf_lr (target sms_tfidf_lr-" in out
    assert "registered: url_trees (target url_trees-" in out
    assert "registered: vehicles_cnn (target vehicles_cnn-" in out and ", status available)" in out
    assert "already present:" not in out and "3 registered, 0 already present, 0 refused" in out

    targets, events = rows()
    by_bundled = {t.detail["bundled_id"]: t for t in targets}
    assert set(by_bundled) == {"sms_tfidf_lr", "url_trees", "vehicles_cnn"} and len(targets) == 3
    digests = {"vehicles_cnn": sha256_bytes(SEED_WEIGHTS), "url_trees": sha256_bytes(SEED_JOBLIB),
               "sms_tfidf_lr": sha256_bytes(SEED_TEXT_JOBLIB)}
    for bundled_id, target in by_bundled.items():
        assert re.fullmatch(rf"{bundled_id}-[0-9a-f]{{8}}", target.id), "per-project Target.id <bundled_id>-<8 hex>"
        assert target.value == f"bundled:{bundled_id}" and target.kind == "ml_model_artifact" and target.verified
        assert target.project_id == "p1" and target.detail["status"] == "available"
        assert target.detail["source"] == "bundled" and target.detail["registered_by"] == "cli:test"
        assert target.detail["sha256"] == digests[bundled_id] == target.detail["blob"]["sha256"]
        assert (blob_root / digests[bundled_id][:2] / digests[bundled_id]).is_file(), "the weights blob was put"
    # One model.register row per registration on the project chain, hash-linked, written before the row it names.
    assert [(e.chain_id, e.seq, e.action, e.success) for e in events] == [
        ("project:p1", 1, "model.register", True), ("project:p1", 2, "model.register", True),
        ("project:p1", 3, "model.register", True)]
    assert [e.detail["bundled_id"] for e in events] == ["sms_tfidf_lr", "url_trees", "vehicles_cnn"]
    assert [e.detail["target_id"] for e in events] == [by_bundled["sms_tfidf_lr"].id, by_bundled["url_trees"].id,
                                                       by_bundled["vehicles_cnn"].id]
    assert [e.detail["modality"] for e in events] == ["text", "tabular", "image"]
    assert all(e.actor == "cli:test" and e.detail["source"] == "bundled" and e.project_id == "p1" for e in events)
    assert events[0].prev_hash is None and events[1].prev_hash == events[0].this_hash
    assert events[2].prev_hash == events[1].this_hash
    assert events[0].detail["blob_key"] == "ml/assets/bundled/sms_tfidf_lr/model.joblib"
    assert events[1].detail["blob_key"] == "ml/assets/bundled/url_trees/model.joblib"

    # 4. Seeding again: both are already present (found read-only, the service is not called), no new
    #    Target or blob, and the chain is untouched: a re-seed is idempotent, not a refused admission, so
    #    no success=False model.register row is written for a model the project already holds.
    with patch("redsim.config.load_config", return_value=config), \
            patch.object(ml_models, "register_bundled_model",
                         side_effect=AssertionError("the service must not be called for a present model")):
        cli_main.main(["ml", "seed", "--project", "demo", "--actor", "cli:test"])
    out = capsys.readouterr().out
    assert f"already present: sms_tfidf_lr (target {by_bundled['sms_tfidf_lr'].id}, status available)" in out
    assert f"already present: url_trees (target {by_bundled['url_trees'].id}, status available)" in out
    assert f"already present: vehicles_cnn (target {by_bundled['vehicles_cnn'].id}, status available)" in out
    assert "registered:" not in out and "0 registered, 3 already present, 0 refused" in out
    targets_again, events_again = rows()
    assert [t.id for t in targets_again] == [t.id for t in targets]
    assert len([p for p in blob_root.rglob("*") if p.is_file()]) == 3
    assert [(e.chain_id, e.seq, e.action, e.success) for e in events_again] == [
        ("project:p1", 1, "model.register", True), ("project:p1", 2, "model.register", True),
        ("project:p1", 3, "model.register", True)], \
        "a re-seed writes no refusal row"
    assert all(e.success for e in events_again)

    # 5. A genuine refusal: tampered url_trees weights fail verification into the second project, the command
    #    exits 1 after still registering sms_tfidf_lr and vehicles_cnn there, and the refusal is on p2's chain
    #    with no Target.
    (assets / "bundled" / "url_trees" / "model.joblib").write_bytes(SEED_JOBLIB + b" tampered")
    with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "seed", "--project", "p2", "--actor", "cli:test"])
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "url_trees: refused (model_load_refused)" in captured.err and "assets_unverified" in captured.err
    assert "sha256 mismatch" in captured.err
    assert "registered: vehicles_cnn (target vehicles_cnn-" in captured.out
    assert "registered: sms_tfidf_lr (target sms_tfidf_lr-" in captured.out
    assert "2 registered, 0 already present, 1 refused" in captured.out
    targets_p2 = [t for t in rows()[0] if t.project_id == "p2"]
    assert [t.detail["bundled_id"] for t in targets_p2] == ["sms_tfidf_lr", "vehicles_cnn"]
    p2_events = [e for e in rows()[1] if e.chain_id == "project:p2"]
    assert [(e.seq, e.success, e.detail["bundled_id"], e.detail.get("reason")) for e in p2_events] == [
        (1, True, "sms_tfidf_lr", None), (2, False, "url_trees", "model_load_refused"), (3, True, "vehicles_cnn", None)]
    assert p2_events[1].detail["refusal_reason"] == "assets_unverified"
    assert "tampered" not in json.dumps([e.detail for e in p2_events]), "audit detail never carries payload bytes"

    # 6. --only with an id the manifest lacks is a usage error, an unknown project a clear refusal, and a
    #    selection of fixture-only models seeds nothing without touching the database.
    with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "seed", "--project", "demo", "--only", "resnet_from_upload"])
    assert exc.value.code == 2 and "resnet_from_upload" in capsys.readouterr().err
    with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "seed", "--project", "nope"])
    assert exc.value.code == 1 and "project 'nope' not found" in capsys.readouterr().err
    with patch("redsim.config.load_config", return_value=config):
        cli_main.main(["ml", "seed", "--project", "demo", "--only", "cifar10_smallcnn"])
    assert "nothing to seed" in capsys.readouterr().out
    assert len(rows()[1]) == 6, ("no audit row for a usage error, an unknown project, a fixture-only selection "
                                 "or a re-seed: three registrations on p1, one refusal and two registrations on p2")
