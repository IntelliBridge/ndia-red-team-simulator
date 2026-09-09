"""``redsim ml attack`` over several targets or a ``--matrix`` file (BULK-17, -18; plan 12 wave B3).

Pure tests (no ML import): the parser accepts several ids and ``--matrix``,
``expand_matrix`` walks ``models x attack_sets x eps_grids x seeds`` in that
order with the file's scalars over the flag defaults, usage errors name the
key, and the summary table carries one row per cell and no cross-cell
aggregate word. One ``ml``-marked test builds two tiny bundled targets into
``tmp_path`` (an 8x8 CNN as ``vehicles_cnn`` and a tree ensemble on the
committed URL sample as ``url_trees``, both non-fixture entries of one asset
manifest; nothing they produce is evidence) and runs a three-cell matrix
through the CLI: two cells succeed, each with its own run directory and a
verified ``audit.jsonl`` chain, the third (a fixture-only target) is refused
and recorded, ``summary.json`` lists all three and the process exits 1.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from redsim.cli import ml as cli_ml
from redsim.cli.ml import (
    MATRIX_KEYS,
    MATRIX_SCHEMA_HELP,
    CellResult,
    MatrixCell,
    MatrixDefaults,
    MatrixError,
    cells_from_targets,
    expand_matrix,
    format_summary_table,
    load_matrix_file,
    resolve_cells,
)
from redsim.config import RedsimConfig

SAMPLE_URLS = Path(__file__).parent / "fixtures" / "malicious_urls_sample.csv"

# ``redsim.cli.main`` re-exports the ``main`` function through the package, so resolve the module by name.
cli_main = importlib.import_module("redsim.cli.main")


def _parse(argv: list[str]):  # type: ignore[no-untyped-def]
    return cli_main.build_parser().parse_args(argv)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parser_accepts_several_targets_a_matrix_file_and_fail_fast() -> None:
    args = _parse(["ml", "attack", "vehicles_cnn", "url_trees", "cifar10_smallcnn", "--fail-fast"])
    assert args.target_id == "vehicles_cnn" and args.targets == ["url_trees", "cifar10_smallcnn"]
    assert args.fail_fast is True and args.matrix is None
    only_matrix = _parse(["ml", "attack", "--matrix", "grid.yaml"])
    assert only_matrix.target_id is None and only_matrix.targets == [] and only_matrix.matrix == "grid.yaml"
    assert only_matrix.fail_fast is False
    both = _parse(["ml", "attack", "extra_model", "--matrix", "grid.yaml", "--n-samples", "20"])
    assert both.target_id == "extra_model" and both.matrix == "grid.yaml" and both.n_samples == 20
    with pytest.raises(SystemExit):
        _parse(["ml", "attack"])                # neither a target nor --matrix


def test_attack_help_documents_the_matrix_schema(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        _parse(["ml", "attack", "--help"])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    for needle in ("--matrix FILE", "--fail-fast", "models:", "attack_sets:", "eps_grids:", "seeds:", "summary.json",
                   "one offline run", "per cell"):
        assert needle in text, needle
    # Every documented key is an accepted key; every required/grid key is documented.
    documented = {line.split(":")[0].strip() for line in MATRIX_SCHEMA_HELP.splitlines()
                  if line.startswith("  ") and ":" in line and not line.strip().startswith(("-", "#"))}
    assert documented <= set(MATRIX_KEYS)
    assert {"models", "attack_sets", "eps_grids", "seeds", "norm", "reference_eps", "n_samples", "explain_k",
            "include_control"} <= documented


# ---------------------------------------------------------------------------
# Expansion (pure)
# ---------------------------------------------------------------------------


def test_expand_matrix_walks_models_attack_sets_grids_seeds_in_order() -> None:
    defaults = MatrixDefaults(n_samples=30, explain_k=2, norm="linf", include_control=False)
    document = {
        "name": "grid", "models": ["m1", "m2"], "attack_sets": [["fgsm", "pgd"], "hopskipjump"],
        "eps_grids": [[0.01, 0.03], None], "seeds": [0, 7], "n_samples": 40,
    }
    cells = expand_matrix(document, defaults)
    assert len(cells) == 2 * 2 * 2 * 2
    assert [c.index for c in cells] == list(range(16))
    first, second = cells[0], cells[1]
    assert (first.target_id, first.attack_ids, first.eps_grid, first.seed) == ("m1", ("fgsm", "pgd"), (0.01, 0.03), 0)
    assert (second.target_id, second.attack_ids, second.eps_grid, second.seed) == ("m1", ("fgsm", "pgd"), (0.01, 0.03), 7)
    assert cells[2].eps_grid is None and cells[4].attack_ids == ("hopskipjump",) and cells[8].target_id == "m2"
    # The file's scalars win over the flag defaults; omitted ones come from the flags.
    assert all(c.n_samples == 40 and c.explain_k == 2 and c.norm == "linf" and c.include_control is False
               for c in cells)
    assert cells[0].label == "m1 x [fgsm,pgd] eps=0.01,0.03 seed=0" and cells[2].label.endswith("eps=default seed=0")
    assert cells[0].as_dict()["attack_ids"] == ["fgsm", "pgd"] and cells[2].as_dict()["eps_grid"] is None
    # Minimal document: the flags supply attacks, grid and seed.
    minimal = expand_matrix({"models": "only_one"}, MatrixDefaults(attack_ids=("pgd",), eps_grid=(0.1,), seed=3))
    assert len(minimal) == 1 and minimal[0].attack_ids == ("pgd",) and minimal[0].eps_grid == (0.1,)
    assert minimal[0].seed == 3 and minimal[0].n_samples == 200 and minimal[0].explain_k == 8


@pytest.mark.parametrize(
    ("document", "needle"),
    [
        ({}, "models"),
        ({"models": []}, "must not be empty"),
        ({"models": ["m"], "bogus": 1}, "unknown matrix keys"),
        ({"models": ["m"], "attack_sets": []}, "attack_sets"),
        ({"models": ["m"], "eps_grids": [[]]}, "eps_grids[0]"),
        ({"models": ["m"], "eps_grids": [["x"]]}, "numbers"),
        ({"models": ["m"], "seeds": ["a"]}, "seeds[0]"),
        ({"models": ["m"], "norm": "l1"}, "norm"),
        ({"models": ["m"], "n_samples": 5}, "n_samples"),
        ({"models": ["m"], "explain_k": 99}, "explain_k"),
        ({"models": ["m"], "include_control": "yes"}, "include_control"),
        ({"models": ["m"], "reference_eps": "abc"}, "reference_eps"),
    ],
)
def test_expand_matrix_usage_errors_name_the_key(document: dict, needle: str) -> None:
    with pytest.raises(MatrixError) as info:
        expand_matrix(document, MatrixDefaults())
    assert needle in str(info.value)


def test_load_matrix_file_reads_yaml_and_accepts_a_matrix_wrapper(tmp_path: Path) -> None:
    plain = tmp_path / "plain.yaml"
    plain.write_text("models: [a, b]\nattack_sets:\n  - [fgsm]\nseeds: [1]\n", encoding="utf-8")
    assert load_matrix_file(plain) == {"models": ["a", "b"], "attack_sets": [["fgsm"]], "seeds": [1]}
    wrapped = tmp_path / "wrapped.yaml"
    wrapped.write_text("matrix:\n  models: [a]\n", encoding="utf-8")
    assert load_matrix_file(wrapped) == {"models": ["a"]}
    with pytest.raises(MatrixError, match="not found"):
        load_matrix_file(tmp_path / "absent.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(MatrixError, match="mapping"):
        load_matrix_file(bad)
    unknown = tmp_path / "unknown.yaml"
    unknown.write_text("models: [a]\nmean_of: everything\n", encoding="utf-8")
    with pytest.raises(MatrixError, match="unknown keys"):
        load_matrix_file(unknown)


def test_cells_from_targets_and_resolve_cells(tmp_path: Path) -> None:
    defaults = MatrixDefaults(attack_ids=("fgsm",), seed=2)
    cells = cells_from_targets(["a", "b", "a", " "], defaults)
    assert [c.target_id for c in cells] == ["a", "b"] and all(c.attack_ids == ("fgsm",) and c.seed == 2 for c in cells)
    with pytest.raises(MatrixError, match="target id"):
        cells_from_targets([], defaults)
    # resolve_cells from parsed args: positional ids alone, then a file plus an extra positional model.
    cells, source = resolve_cells(_parse(["ml", "attack", "x", "y", "--attacks", "pgd", "--seed", "4"]))
    assert [c.target_id for c in cells] == ["x", "y"] and source == {"targets": ["x", "y"]}
    assert all(c.attack_ids == ("pgd",) and c.seed == 4 for c in cells)
    grid = tmp_path / "grid.yaml"
    grid.write_text("name: t\nmodels: [m1]\nattack_sets: [[fgsm], [pgd]]\nseeds: [0, 1]\n", encoding="utf-8")
    cells, source = resolve_cells(_parse(["ml", "attack", "extra", "--matrix", str(grid)]))
    assert [(c.target_id, c.attack_ids, c.seed) for c in cells] == [
        ("m1", ("fgsm",), 0), ("m1", ("fgsm",), 1), ("m1", ("pgd",), 0), ("m1", ("pgd",), 1),
        ("extra", ("fgsm",), 0), ("extra", ("fgsm",), 1), ("extra", ("pgd",), 0), ("extra", ("pgd",), 1),
    ]
    assert [c.index for c in cells] == list(range(8))
    assert source["matrix_file"] == str(grid) and source["name"] == "t" and source["extra_targets"] == ["extra"]


def test_summary_table_has_one_row_per_cell_and_no_aggregate() -> None:
    cell_a = MatrixCell(0, "vehicles_cnn", ("fgsm", "pgd"), (0.01, 0.03), 0, "linf", None, 200, 8, True)
    cell_b = MatrixCell(1, "url_trees", ("pgd",), None, 1, "linf", None, 200, 8, True)
    cell_c = MatrixCell(2, "cifar10_smallcnn", ("pgd",), None, 0, "linf", None, 200, 8, True)
    results = [
        CellResult(0, cell_a, "succeeded", run_id="run-aaaaaaaaaaaa", mri=0.512, grade="C", audit_events=9,
                   chain_verified=True),
        CellResult(1, cell_b, "failed", run_id="run-bbbbbbbbbbbb", audit_events=4, chain_verified=False,
                   chain_error="broken at seq=2", reason="failed", message="child died"),
        CellResult(2, cell_c, "refused", reason="fixture_only", message="never served"),
    ]
    table = format_summary_table(results)
    lines = table.splitlines()
    assert len(lines) == 2 + 3 + 1, table
    assert lines[2].startswith("0    vehicles_cnn") and "succeeded" in lines[2] and "0.512" in lines[2]
    assert "verified" in lines[2] and "run-aaaaaaaaaaaa" in lines[2] and "0.01,0.03" in lines[2]
    assert "BROKEN" in lines[3] and "failed" in lines[3] and "default" in lines[3]
    assert "refused" in lines[4] and lines[4].count("-") >= 3
    assert lines[-1].startswith("3 cell(s): 1 succeeded, 1 refused, 1 failed")
    lowered = table.lower()
    for banned in ("mean", "average", "rank", "aggregate mri", "overall"):
        assert banned not in lowered.replace("nothing aggregated", ""), banned
    row = results[0].as_dict()
    assert row["cell"]["attack_ids"] == ["fgsm", "pgd"] and row["label"] == cell_a.label and row["chain_verified"]


# ---------------------------------------------------------------------------
# End to end through the CLI over two tiny bundled targets (ml extra)
# ---------------------------------------------------------------------------


def _two_target_tree(root: Path) -> Path:
    """One asset tree with ``vehicles_cnn`` (tiny CNN, synthetic 8x8 images) and ``url_trees`` (tree ensemble on
    the committed URL sample as a non-fixture entry). Test stand-ins only; nothing they produce is evidence."""
    import numpy as np

    from redsim.ml.assets import datasets as ds
    from redsim.ml.assets.build import build_cnn_asset, build_url_asset
    from redsim.ml.assets.manifest import MANIFEST_NAME, AssetManifest, DatasetEntry, write_manifest

    class_names = ["class_0", "class_1", "class_2"]
    n, size = 48, 8
    rng = np.random.default_rng(0)
    x = rng.integers(0, 256, size=(n, 3, size, size), dtype=np.uint8)
    y = (np.arange(n) % len(class_names)).astype(np.int64)
    image_entry = DatasetEntry(id="local:synthetic-images", source="local", revision="synthetic-v1", license="n/a",
                               class_names=list(class_names), fixture_only=False,
                               notes=["unit-test stand-in for a built asset tree; never a result"])
    train = ds.ImageSplit(name="train", x=x, y=y, indices=np.arange(n, dtype=np.int64), class_names=list(class_names))
    n_eval = n // 2
    evaluation = ds.ImageSplit(name="test", x=x[:n_eval], y=y[:n_eval], indices=np.arange(n_eval, dtype=np.int64),
                               class_names=list(class_names))
    img_ds, img_model = build_cnn_asset(ds.ImageDataset(dataset=image_entry, train=train, eval=evaluation),
                                        model_id="vehicles_cnn", root=root, epochs=1, seed=0, log=lambda _m: None)

    indices, urls, labels = ds.read_url_rows(SAMPLE_URLS)
    url_entry = DatasetEntry(id="local:synthetic-urls", source="local", revision="synthetic-v1", license="n/a",
                             class_names=list(ds.URL_CLASS_NAMES), fixture_only=False, n_rows=len(urls),
                             notes=["unit-test stand-in shaped like the Kaggle file; never a result"])
    table = ds.UrlTable(urls=urls, labels=labels, dataset=url_entry, source_path=SAMPLE_URLS, row_indices=indices)
    url_ds, url_model = build_url_asset(table, model_id="url_trees", root=root, seed=0, log=lambda _m: None)

    manifest = AssetManifest.new()
    manifest.datasets[img_ds.id] = img_ds
    manifest.datasets[url_ds.id] = url_ds
    manifest.models[img_model.id] = img_model
    manifest.models[url_model.id] = url_model
    write_manifest(manifest, root / MANIFEST_NAME)
    return root


@pytest.mark.ml
def test_matrix_runs_one_chain_per_cell_and_records_the_refused_cell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    pytest.importorskip("numpy")
    pytest.importorskip("torch")
    pytest.importorskip("art")
    pytest.importorskip("sklearn")
    from redsim.audit.chain import verify_chain
    from redsim.ml.schema import CampaignRecord

    assets = _two_target_tree(tmp_path / "assets")
    out = tmp_path / "runs"
    monkeypatch.setenv("REDSIM_ML_ASSETS_DIR", str(assets))
    monkeypatch.setenv("REDSIM_ML_WORK_DIR", str(tmp_path / "work"))
    for key in ("REDSIM_DB_URL", "REDSIM_TEST_AUDIT", "REDSIM_PLUGINS", "PYTHIA_BASE_URL", "PYTHIA_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    config = RedsimConfig(output_dir=str(tmp_path / "unused-output-dir"))
    matrix = tmp_path / "grid.yaml"
    matrix.write_text(
        "name: two-targets\nmodels: [vehicles_cnn, url_trees]\nattack_sets:\n  - [pgd]\n"
        "eps_grids:\n  - [0.03, 0.1]\nseeds: [0]\nn_samples: 12\nexplain_k: 0\n",
        encoding="utf-8",
    )

    # Two matrix cells plus one positional fixture-only target: 2 succeed, 1 refused, exit 1.
    with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "attack", "cifar10_smallcnn", "--matrix", str(matrix), "--out", str(out),
                       "--actor", "cli:matrix-test"])
    assert exc.value.code == cli_ml.EXIT_REFUSED
    captured = capsys.readouterr()
    text = captured.out
    assert "refused (fixture_only)" in captured.err or "refused (not_implemented)" in captured.err

    summaries = list(out.glob("matrix-*/summary.json"))
    assert len(summaries) == 1
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    assert (summary["n_cells"], summary["n_succeeded"], summary["n_refused"], summary["n_failed"]) == (3, 2, 1, 0)
    assert summary["source"]["name"] == "two-targets" and summary["source"]["extra_targets"] == ["cifar10_smallcnn"]
    cells = summary["cells"]
    assert [c["cell"]["target_id"] for c in cells] == ["vehicles_cnn", "url_trees", "cifar10_smallcnn"]
    refused = cells[2]
    assert refused["status"] == "refused" and refused["run_id"] is None
    assert refused["reason"] in {"fixture_only", "not_implemented"}

    run_dirs = sorted(p for p in out.iterdir() if p.is_dir() and p.name.startswith("run-"))
    assert len(run_dirs) == 2, "one run directory per succeeded cell, none for the refused one"
    for cell in cells[:2]:
        assert cell["status"] == "succeeded" and cell["chain_verified"] is True and cell["chain_error"] is None
        assert cell["narrative_source"] == "rules" and cell["settings_hash"]
        run_dir = Path(cell["run_dir"])
        assert run_dir.parent == out and run_dir.name == cell["run_id"]
        for name in ("audit.jsonl", "run_record.json", "report.md", "report.json", "report.html"):
            assert (run_dir / name).is_file(), name
        record = CampaignRecord.model_validate_json((run_dir / "run_record.json").read_text(encoding="utf-8"))
        assert record.status == "succeeded" and record.run_id == cell["run_id"]
        assert record.target.id == cell["cell"]["target_id"] and record.config.attack_ids == ["pgd"]
        assert record.config.eps_grid == [0.03, 0.1] and record.config.n_samples == 12 and record.config.explain_k == 0
        assert record.config.llm_narrative is False
        # Its own chain: attack.run first, job.complete last, every row on run:<run_id>, verified.
        lines = [json.loads(line) for line in (run_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
                 if line.strip()]
        assert lines[0]["action"] == "attack.run" and lines[-1]["action"] == "job.complete"
        assert {line["chain_id"] for line in lines} == {f"run:{cell['run_id']}"}
        assert all(line["actor"] == "cli:matrix-test" for line in lines)
        assert verify_chain(iter(lines)).verified and len(lines) == cell["audit_events"]
        assert lines[0]["detail"]["settings_hash"] == record.settings_hash
    assert {c["settings_hash"] for c in cells[:2]}.__len__() == 2, "different models, different settings hashes"

    # The table names every cell, each chain verdict, and no aggregate.
    assert "vehicles_cnn" in text and "url_trees" in text and "cifar10_smallcnn" in text
    assert text.count("verified") >= 2 and "3 cell(s): 2 succeeded, 1 refused, 0 failed" in text
    assert "summary" in text and str(summaries[0]) in text
    assert "mean" not in text.lower() and "rank" not in text.lower()

    # --fail-fast stops at the first non-succeeded cell: the fixture-only target first, nothing runs.
    out2 = tmp_path / "runs2"
    with patch("redsim.config.load_config", return_value=config), pytest.raises(SystemExit) as exc:
        cli_main.main(["ml", "attack", "cifar10_smallcnn", "vehicles_cnn", "--attacks", "pgd", "--eps", "0.03",
                       "--n-samples", "12", "--explain-k", "0", "--fail-fast", "--out", str(out2)])
    assert exc.value.code == cli_ml.EXIT_REFUSED
    text2 = capsys.readouterr().out
    assert "--fail-fast" in text2 and "1 cell(s) not run" in text2
    assert not [p for p in out2.iterdir() if p.name.startswith("run-")], "nothing ran after the refused cell"
    summary2 = json.loads(next(out2.glob("matrix-*/summary.json")).read_text(encoding="utf-8"))
    assert summary2["n_cells"] == 1 and summary2["source"]["n_cells_planned"] == 2 and summary2["source"]["fail_fast"]
