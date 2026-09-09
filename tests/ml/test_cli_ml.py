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


# ---------------------------------------------------------------------------
# redsim ml attack / redsim ml seed (G-CLI-ATTACK, G-ASSET4)
# ---------------------------------------------------------------------------

from contextlib import contextmanager  # noqa: E402
from types import SimpleNamespace  # noqa: E402

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


class _FakeSeedSession:
    """Just enough of a SQLAlchemy session for the seed command: ``get`` and a ``select`` that finds nothing."""

    def __init__(self) -> None:
        self.projects = {"p1": SimpleNamespace(id="p1", slug="demo")}

    def get(self, model, key):
        return self.projects.get(key) if getattr(model, "__tablename__", "") == "projects" else None

    def execute(self, _stmt):
        return SimpleNamespace(scalar_one_or_none=lambda: None, scalars=lambda: SimpleNamespace(all=lambda: []))


def test_ml_seed_registers_or_explains(tmp_path, monkeypatch, capsys):
    import redsim.services.ml_models as ml_models
    from redsim.api.errors import ALREADY_REGISTERED, ApiError

    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "MANIFEST.json").write_text(json.dumps({
        "schema_version": 1,
        "datasets": {},
        "models": {
            "vehicles_cnn": {"id": "vehicles_cnn", "fixture_only": False},
            "url_trees": {"id": "url_trees", "fixture_only": False},
            "cifar10_smallcnn": {"id": "cifar10_smallcnn", "fixture_only": True},
        },
    }), encoding="utf-8")
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(assets))
    monkeypatch.delenv("REDSIM_DB_URL", raising=False)
    config = RedsimConfig(output_dir=str(tmp_path / "out"))

    # 1. The wave-2 service is absent in this build: say so, exit non-zero, register nothing.
    monkeypatch.delattr(ml_models, "register_bundled_model", raising=False)
    with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "seed", "--project", "p1"])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "register_bundled_model" in err and "nothing was registered" in err

    # 2. The service is present but the database is not configured: the env var is named.
    monkeypatch.setattr(ml_models, "register_bundled_model", lambda *a, **k: None, raising=False)
    with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "seed", "--project", "p1"])
    assert exc.value.code == 1 and "REDSIM_DB_URL" in capsys.readouterr().err

    # 3. Service present, session available: one call per bundled, non-fixture model, positional contract.
    calls: list[tuple] = []

    def fake_register(session, project_id, bundled_id, actor):
        calls.append((session, project_id, bundled_id, actor))
        if bundled_id == "url_trees":
            raise ApiError(ALREADY_REGISTERED)
        return {"id": f"tgt-{bundled_id}", "status": "available"}

    monkeypatch.setattr(ml_models, "register_bundled_model", fake_register, raising=False)
    sess = _FakeSeedSession()

    @contextmanager
    def fake_session():
        yield sess

    monkeypatch.setattr(cli_ml, "_seed_session", fake_session)
    with patch("redsim.config.load_config", return_value=config):
        cli_main.main(["ml", "seed", "--project", "p1", "--actor", "cli:test"])
    out = capsys.readouterr().out
    assert [c[2] for c in calls] == ["url_trees", "vehicles_cnn"], "sorted, fixture-only skipped"
    assert all(c[0] is sess and c[1] == "p1" and c[3] == "cli:test" for c in calls)
    assert "skipping cifar10_smallcnn" in out and "fixture-only" in out
    assert "registered: vehicles_cnn (target tgt-vehicles_cnn, status available)" in out
    assert "already present: url_trees" in out

    # 4. A model already present in the project is reported and the service is not called for it.
    calls.clear()
    existing = SimpleNamespace(id="tgt-existing", detail={"status": "available"})
    monkeypatch.setattr(cli_ml, "_existing_bundled_target",
                        lambda _s, _p, bundled_id: existing if bundled_id == "vehicles_cnn" else None)
    with patch("redsim.config.load_config", return_value=config):
        cli_main.main(["ml", "seed", "--project", "p1", "--only", "vehicles_cnn"])
    assert calls == [] and "already present: vehicles_cnn (target tgt-existing, status available)" in capsys.readouterr().out

    # 5. --only with an id the manifest lacks is a usage error; an unknown project is a clear refusal.
    with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "seed", "--project", "p1", "--only", "resnet_from_upload"])
    assert exc.value.code == 2 and "resnet_from_upload" in capsys.readouterr().err
    with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "seed", "--project", "nope"])
    assert exc.value.code == 1 and "project 'nope' not found" in capsys.readouterr().err
