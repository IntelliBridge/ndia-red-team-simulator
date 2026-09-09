"""Orchestration for ``redsim ml build-assets`` (spec 11, 20.1 step 3, milestones M0 / M1 / M4).

Fetch each dataset by pinned revision, train the bundled models on CPU with a
fixed seed, write weights and evaluation slices under the assets root and
record everything in ``MANIFEST.json``. Each model entry is a
``redsim.ml.schema.MLModelManifest`` plus the build record. The two
``build_*_asset`` functions take in-memory data, so tests drive them with
synthetic inputs and never touch the network; only ``build_assets`` fetches.

The manifest shape the loaders (``redsim.ml.targets.bundled`` / ``tabular``)
read is the one written here: weights at ``models[id].file.path``, the
architecture kwargs at ``models[id].architecture``, the evaluation slice at
``datasets[models[id].dataset_id].splits[models[id].dataset_split].file`` and
the tabular surrogate at ``models[id].surrogate.file``. Model ids are the
registry ids (``vehicles_cnn``, ``cifar10_smallcnn``, ``url_trees``).

``build_cifar10_fixture`` writes the committed CI slice
``tests/ml/fixtures/cifar10_test_500.npz`` (``--fixture``) from a local copy of
the CIFAR-10 test split -- the bundled ``test.npz`` under the assets root or the
cached hub parquet -- and records its provenance in the sidecar
``tests/ml/fixtures/MANIFEST.json``. It downloads nothing.

Python HTTPS on the hackathon machines goes through a TLS-inspecting proxy, so
the entrypoint injects the OS trust store via ``truststore`` when available.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from redsim.ml.assets import (
    ARCH_CHOICES,
    ASSET_IDS,
    DATASET_CHOICES,
    LEGACY_MODEL_IDS,
    MODEL_IDS,
    MODEL_NAMES,
    canonical_model_id,
)
from redsim.ml.assets import datasets as ds
from redsim.ml.assets.manifest import (
    MANIFEST_NAME,
    AssetManifest,
    DatasetEntry,
    FileEntry,
    ModelEntry,
    SplitEntry,
    SurrogateEntry,
    file_entry,
    library_versions,
    load_manifest,
    load_or_new,
    sha256_file,
    stamp_manifest_sha256,
    write_manifest,
)
from redsim.ml.assets.train_cnn import save_state_dict, train_cnn
from redsim.ml.assets.train_url_classifier import SURROGATE_KIND, save_url_classifier, train_url_classifier
from redsim.ml.datasets import DatasetUnavailable as SliceUnavailable
from redsim.ml.datasets import cifar10
from redsim.ml.datasets.url_features import EXTRACTOR_VERSION, FEATURE_NAMES, N_FEATURES, featurize_array
from redsim.ml.schema import AccuracyPoint, CleanAccuracy
from redsim.ml.targets.architectures import canonical_architecture_id

Log = Callable[[str], None]

__all__ = [
    "ASSET_IDS", "DATASET_CHOICES", "DEFAULT_FIXTURE_PATH", "MODEL_IDS", "MODEL_NAMES", "BuildOptions",
    "FixtureBuild", "build_assets", "build_cifar10_fixture", "build_cnn_asset", "build_url_asset",
    "inject_truststore", "summarize", "write_url_eval_slice",
]

VEHICLES_LICENSE_NOTE = ("MIT on the dataset card covers the authors' compilation and labels, not the photographers' "
                         "copyright (sources per WEO_Data_Sheet.xlsx). Internal demo only; images are not redistributed "
                         "(spec 11.3.1, 11.5).")
VEHICLES_NOTES = (
    "Demo image dataset, coarse 7-class task (spec 11.3.1).",
    "Ground-level photographs, not aerial or overhead imagery.",
    "Card has no split protocol or de-duplication statement; near-duplicates across splits are possible.",
    "Images may incidentally contain people; no person or face labels exist or are derived.",
)

# ``--fixture`` destination: the committed CI slice and its sidecar (spec 11.3.5, 22.2).
FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "ml" / "fixtures"
DEFAULT_FIXTURE_PATH = FIXTURES_DIR / cifar10.FIXTURE_NAME
FIXTURE_SAMPLING_METHOD = ("redsim.ml.datasets.cifar10.fixture_indices: seeded stratified selection over the test "
                           "split (redsim.ml.datasets.sampling.stratified_indices, equal count per class), sorted by "
                           "source row")


def inject_truststore() -> bool:
    """Route Python TLS through the OS trust store when ``truststore`` is installed."""
    try:
        import truststore
    except ImportError:
        return False
    truststore.inject_into_ssl()
    return True


@dataclass
class BuildOptions:
    dataset: str = "all"
    only: tuple[str, ...] = ()           # model ids; when set, overrides ``dataset``
    epochs: int = 3
    out: Path = Path("assets")
    cache_dir: Path | None = None
    seed: int = 0
    image_size: int = 128
    image_repo: str = ds.VEHICLES_REPO
    image_revision: str = "main"
    cifar10_revision: str = "main"
    max_train: int | None = None
    max_eval: int | None = None
    workers: int = 8
    prefer_xgboost: bool = False         # sklearn_joblib is what every worker image can load (spec 9.2)
    holdout: float = 0.2
    arch: str = "small_cnn"              # image architecture for the CNN builds (``--arch``)
    build_models: bool = True            # False: ``--fixture`` alone, no training and no network
    fixture: bool = False                # also write the committed CIFAR-10 test slice
    fixture_out: Path = DEFAULT_FIXTURE_PATH
    fixture_sidecar: Path | None = None  # default: MANIFEST.json beside ``fixture_out``
    fixture_allow_synthetic: bool = False

    def __post_init__(self) -> None:
        if self.dataset not in DATASET_CHOICES:
            raise ValueError(f"dataset must be one of {DATASET_CHOICES}, got {self.dataset!r}")
        self.only = tuple(canonical_model_id(m) for m in self.only)
        unknown = [m for m in self.only if m not in ASSET_IDS]
        if unknown:
            raise ValueError(f"unknown model id(s) {unknown}; known: {sorted(ASSET_IDS)}")
        if self.epochs < 1:
            raise ValueError("epochs must be >= 1")
        self.arch = canonical_architecture_id(self.arch)
        if self.arch not in ARCH_CHOICES:
            raise ValueError(f"arch must be one of {ARCH_CHOICES}, got {self.arch!r}")
        self.out = Path(self.out)
        self.cache_dir = Path(self.cache_dir) if self.cache_dir is not None else self.out / "cache"
        self.fixture_out = Path(self.fixture_out)
        if self.fixture_sidecar is not None:
            self.fixture_sidecar = Path(self.fixture_sidecar)

    @property
    def selected(self) -> set[str]:
        if not self.build_models:
            return set()
        if self.only:
            return {ASSET_IDS[m] for m in self.only}
        return {"image", "cifar10", "tabular"} if self.dataset == "all" else {self.dataset}


# ---------------------------------------------------------------------------
# Pure build steps (no network)
# ---------------------------------------------------------------------------

def dataset_dir(root: Path, entry: DatasetEntry) -> Path:
    safe_id = entry.id.replace(":", "--").replace("/", "--")
    return Path(root) / "datasets" / safe_id / (entry.revision or "unpinned")


def write_image_eval_slice(split: ds.ImageSplit, root: Path, entry: DatasetEntry) -> FileEntry:
    """Bundle the evaluation split as a compressed npz (uint8 NCHW, labels, source indices)."""
    path = dataset_dir(root, entry) / f"{split.name}.npz"
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(path, x=split.x, y=split.y, indices=split.indices,
                        class_names=np.asarray(split.class_names))
    return file_entry(root, path)


def _clean_accuracy(metrics: dict[str, object], split: str) -> CleanAccuracy:
    """The measured eval-split accuracy as the manifest's ``CleanAccuracy`` (value, n, split)."""
    value = metrics["clean_accuracy"]
    n = metrics["n"]
    assert isinstance(value, (int, float)) and isinstance(n, int)
    return CleanAccuracy(value=float(value), n=n, split=split)


def build_cnn_asset(data: ds.ImageDataset, *, model_id: str, root: Path, epochs: int, seed: int,
                    arch: str = "small_cnn", fixture_only: bool = False, notes: Sequence[str] = (),
                    name: str | None = None, log: Log = print) -> tuple[DatasetEntry, ModelEntry]:
    """Train the catalog architecture ``arch`` on ``data``; write weights, eval slice and manifest entries."""
    root = Path(root).resolve()
    arch = canonical_architecture_id(arch)
    class_names = list(data.train.class_names)
    log(f"{model_id}: training {arch} for {epochs} epoch(s), seed {seed}, "
        f"n_train={data.train.n}, n_eval={data.eval.n}, image_size={data.train.x.shape[-1]}")
    result = train_cnn(data.train.x, data.train.y, data.eval.x, data.eval.y, class_names,
                       arch=arch, epochs=epochs, seed=seed, log=log)
    weights = file_entry(root, save_state_dict(result.model, root / "bundled" / model_id / "weights.pt"))

    entry = data.dataset.model_copy(deep=True)
    entry.fixture_only = entry.fixture_only or fixture_only
    entry.notes = list(entry.notes) + list(notes)
    eval_file = write_image_eval_slice(data.eval, root, entry)
    entry.splits[data.train.name] = ds.split_entry(data.train)
    entry.splits[data.eval.name] = ds.split_entry(data.eval, file=eval_file)

    init_note = str(result.training.get("backbone_init", "random (seeded)"))
    model = ModelEntry(
        id=model_id, name=name or MODEL_NAMES.get(model_id, model_id), modality="image", format="torch_state_dict",
        sha256=weights.sha256, size_bytes=weights.size_bytes, file=weights,
        architecture_id=result.model.architecture_id, architecture=result.model.architecture_config(),
        input_shape=list(result.model.input_shape), n_classes=len(class_names), class_names=class_names,
        dataset_id=entry.id, dataset_revision=entry.revision, dataset_split=data.eval.name, train_split=data.train.name,
        clean_accuracy=_clean_accuracy(result.metrics, data.eval.name), gradients=True,
        license=entry.license, source_url=entry.url,
        seed=seed, epochs=epochs, training=result.training, metrics=result.metrics,
        library_versions=library_versions(("torch", "torchvision", "numpy")),
        fixture_only=entry.fixture_only,
        notes=["Input contract: float32 [0, 1] NCHW; channel normalisation is inside the model.",
               "Clean accuracy is measured on the full bundled evaluation split at build time.",
               f"Initialisation: {init_note}."],
    )
    model = stamp_manifest_sha256(model)
    log(f"{model_id}: clean accuracy {model.clean_accuracy.value:.4f} on n={model.clean_accuracy.n}, "  # type: ignore[union-attr]
        f"weights sha256 {model.sha256[:12]}...")
    return entry, model


def _per_class(labels: np.ndarray, idx: np.ndarray, class_names: Sequence[str]) -> dict[str, int]:
    counts = np.bincount(labels[idx], minlength=len(class_names))
    return {name: int(counts[i]) for i, name in enumerate(class_names)}


def write_url_eval_slice(urls: Sequence[str], labels: np.ndarray, eval_idx: np.ndarray, class_names: Sequence[str],
                         root: Path, entry: DatasetEntry, *, x_eval: np.ndarray | None = None,
                         ) -> tuple[FileEntry, FileEntry]:
    """Bundle the held-out URL rows twice: ``eval.npz`` (featurized ``x``, ``y``, ``indices``) and ``eval.csv``.

    The ``.npz`` is the slice the tabular target and uploads bound to this dataset consume, so nothing
    featurizes at load; the CSV (``index,url,type``) is the human-readable listing beside it. URL strings
    are data; nothing here fetches them. Returns ``(npz entry, csv entry)``.
    """
    out_dir = dataset_dir(root, entry)
    out_dir.mkdir(parents=True, exist_ok=True)
    eval_idx = np.asarray(eval_idx, dtype=np.int64)
    eval_urls = [urls[int(i)] for i in eval_idx]
    x = np.asarray(x_eval if x_eval is not None else featurize_array(eval_urls), dtype=np.float32)
    if x.shape != (len(eval_idx), N_FEATURES):
        raise ValueError(f"featurized eval slice has shape {x.shape}, expected {(len(eval_idx), N_FEATURES)}")
    y = np.asarray(labels, dtype=np.int64)[eval_idx]
    npz_path = out_dir / "eval.npz"
    np.savez_compressed(npz_path, x=x, y=y, indices=eval_idx, feature_names=np.asarray(FEATURE_NAMES),
                        class_names=np.asarray(list(class_names)), extractor_version=np.asarray(EXTRACTOR_VERSION))
    csv_path = out_dir / "eval.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["index", "url", "type"])
        for i, url in zip(eval_idx, eval_urls, strict=True):
            writer.writerow([int(i), url, class_names[int(labels[int(i)])]])
    return file_entry(root, npz_path), file_entry(root, csv_path)


def build_url_asset(table: ds.UrlTable, *, model_id: str, root: Path, seed: int, holdout: float = 0.2,
                    prefer_xgboost: bool = False, name: str | None = None,
                    log: Log = print) -> tuple[DatasetEntry, ModelEntry]:
    """Train the URL classifier and its surrogate on ``table``; write both plus the eval slice under ``root``."""
    root = Path(root).resolve()
    class_names = list(table.dataset.class_names)
    result = train_url_classifier(table.urls, table.labels, seed=seed, holdout=holdout,
                                  prefer_xgboost=prefer_xgboost, class_names=class_names, log=log)
    model_file, surrogate_file = save_url_classifier(result, root / "bundled" / model_id, assets_root=root)

    entry = table.dataset.model_copy(deep=True)
    entry.n_duplicates_removed = result.n_duplicates_removed
    eval_npz, eval_csv = write_url_eval_slice(result.urls, result.labels, result.eval_idx, class_names, root, entry,
                                              x_eval=result.x_eval)
    entry.splits["train"] = SplitEntry(name="train", n=len(result.train_idx),
                                       per_class=_per_class(result.labels, result.train_idx, class_names),
                                       seed=seed, indices_sha256=ds.indices_sha256(result.train_idx))
    entry.splits["eval"] = SplitEntry(name="eval", n=len(result.eval_idx),
                                      per_class=_per_class(result.labels, result.eval_idx, class_names),
                                      seed=seed, indices_sha256=ds.indices_sha256(result.eval_idx), file=eval_npz,
                                      rows_csv=eval_csv)
    entry.preprocessing = {"features": list(FEATURE_NAMES), "extractor": "redsim.ml.datasets.url_features",
                           "extractor_version": EXTRACTOR_VERSION, "dedupe": "exact URL string, first occurrence kept",
                           "split": f"seeded stratified, holdout {holdout}",
                           "eval_slice": "eval.npz holds the featurized rows (x float32, y, indices); eval.csv lists them"}

    surrogate = SurrogateEntry(
        kind=SURROGATE_KIND, sha256=surrogate_file.sha256, file=surrogate_file,
        agreement_clean=AccuracyPoint(n=len(result.eval_idx), n_correct=result.surrogate_agree_count,
                                      accuracy=result.surrogate_agreement),
    )
    model = ModelEntry(
        id=model_id, name=name or MODEL_NAMES.get(model_id, model_id), modality="tabular", format=result.format,
        sha256=model_file.sha256, size_bytes=model_file.size_bytes, file=model_file,
        architecture_id="xgboost_classifier" if result.library == "xgboost" else "sklearn_hist_gradient_boosting",
        architecture={"library": result.library, "params": result.training["params"]},
        input_shape=[N_FEATURES], n_classes=len(class_names), class_names=class_names,
        dataset_id=entry.id, dataset_revision=entry.revision, dataset_split="eval", train_split="train",
        clean_accuracy=_clean_accuracy(result.metrics, "eval"),
        features=result.features, extractor_version=EXTRACTOR_VERSION, surrogate=surrogate,
        gradients=False,   # tree ensembles expose no loss gradient; PGD runs on the surrogate (spec 12.2)
        license=entry.license, source_url=entry.url,
        seed=seed, epochs=None, training=result.training, metrics=result.metrics,
        library_versions=library_versions(("scikit-learn", "xgboost", "numpy")),
        fixture_only=entry.fixture_only,
        notes=[("Feature-space perturbations are evidence about the decision surface; Phase A constructs no URLs "
                "(realizability gap, spec 12.9)."),
               "PGD runs on the surrogate and is scored on the ensemble; HopSkipJump runs on the ensemble."],
    )
    model = stamp_manifest_sha256(model)
    log(f"{model_id}: clean accuracy {model.clean_accuracy.value:.4f} on n={model.clean_accuracy.n}, "  # type: ignore[union-attr]
        f"model sha256 {model.sha256[:12]}..., surrogate agreement {result.surrogate_agreement:.4f}")
    return entry, model


# ---------------------------------------------------------------------------
# The committed CIFAR-10 fixture (``--fixture``; spec 11.3.5, 22.2). No network.
# ---------------------------------------------------------------------------

@dataclass
class FixtureBuild:
    """What ``build_cifar10_fixture`` wrote and where the rows came from."""

    path: Path
    sidecar: Path
    entry: dict[str, Any]

    @property
    def synthetic(self) -> bool:
        return bool(self.entry.get("synthetic"))

    @property
    def source_kind(self) -> str:
        return str(self.entry["source"]["kind"])


def _bundled_cifar10_test_split(assets_root: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, Any]] | None:
    """The test split bundled by an earlier ``build-assets --dataset cifar10`` under ``assets_root``, if present."""
    manifest_path = Path(assets_root) / MANIFEST_NAME
    if not manifest_path.is_file():
        return None
    try:
        manifest = load_manifest(manifest_path)
    except ValueError:
        return None
    entry = manifest.datasets.get(cifar10.DATASET_ID)
    if entry is None:
        return None
    split = entry.splits.get("test")
    if split is None or split.file is None:
        return None
    path = Path(assets_root) / split.file.path
    if not path.is_file():
        return None
    actual = sha256_file(path)
    if actual != split.file.sha256:
        raise SliceUnavailable(f"bundled CIFAR-10 test split {path} has sha256 {actual[:12]}..., the manifest says "
                               f"{split.file.sha256[:12]}...; refusing to draw the fixture from a tampered slice")
    with np.load(path, allow_pickle=False) as npz:
        x = np.asarray(npz["x"], dtype=np.uint8)
        y = np.asarray(npz["y"], dtype=np.int64)
        indices = np.asarray(npz["indices"], dtype=np.int64) if "indices" in npz else np.arange(len(y))
    source = {"kind": "bundled_split_npz", "path": split.file.path, "sha256": split.file.sha256,
              "revision": entry.revision}
    return x, y, indices, source


def _cached_cifar10_test_parquet(cache_dir: Path) -> tuple[Path, str] | None:
    """``(parquet path, revision)`` of a cached hub download under ``cache_dir`` (newest revision dir wins)."""
    repo_dir = Path(cache_dir) / f"hf--{cifar10.REPO_ID.replace('/', '--')}"
    if not repo_dir.is_dir():
        return None
    candidates = sorted((p for p in repo_dir.iterdir() if (p / cifar10.TEST_PARQUET).is_file()),
                        key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        return None
    return candidates[0] / cifar10.TEST_PARQUET, candidates[0].name


def _read_sidecar(path: Path) -> dict[str, Any]:
    sidecar: dict[str, Any] = {"schema_version": 1, "files": {}}
    if path.is_file():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            sidecar = loaded
            sidecar.setdefault("files", {})
    return sidecar


def build_cifar10_fixture(*, out: Path = DEFAULT_FIXTURE_PATH, sidecar: Path | None = None,
                          assets_root: Path | None = None, cache_dir: Path | None = None,
                          per_class: int = cifar10.FIXTURE_PER_CLASS, seed: int = cifar10.FIXTURE_SEED,
                          allow_synthetic: bool = False, log: Log = print, warn: Log | None = None) -> FixtureBuild:
    """Write the pinned CIFAR-10 test slice and its sidecar entry; return what was written.

    Source order: the test split an earlier build bundled under ``assets_root`` (digest-verified against
    that tree's manifest), then the hub parquet cached under ``cache_dir``. With neither present the build
    stops -- unless ``allow_synthetic`` is set, in which case a seeded synthetic stand-in of CIFAR-10's shape
    is written and the sidecar marks it ``synthetic: true``. A synthetic draw never overwrites a committed
    fixture the sidecar records as real. Nothing here touches the network.
    """
    warn = warn or log
    out = Path(out)
    sidecar_path = Path(sidecar) if sidecar is not None else out.parent / ds.FIXTURE_SIDECAR_NAME
    source: dict[str, Any]
    synthetic = False
    bundled = _bundled_cifar10_test_split(assets_root) if assets_root is not None else None
    if bundled is not None:
        x, y, indices, source = bundled
        revision = str(source.get("revision") or "unpinned")
        log(f"fixture: drawing from the bundled test split {source['path']} (revision {revision[:12]})")
    else:
        cached = _cached_cifar10_test_parquet(cache_dir) if cache_dir is not None else None
        if cached is not None:
            parquet, revision = cached
            log(f"fixture: decoding the cached hub parquet {parquet} (revision {revision[:12]})")
            x, y = cifar10.load_parquet(parquet)
            indices = np.arange(len(y), dtype=np.int64)
            source = {"kind": "hub_parquet_cache", "path": str(parquet), "sha256": sha256_file(parquet),
                      "revision": revision}
        else:
            looked = [str(Path(assets_root) / MANIFEST_NAME) if assets_root is not None else "(no assets root)",
                      str(Path(cache_dir) / f"hf--{cifar10.REPO_ID.replace('/', '--')}") if cache_dir is not None
                      else "(no cache dir)"]
            if not allow_synthetic:
                raise SliceUnavailable("no local copy of the CIFAR-10 test split: looked for a bundled test.npz via "
                                       f"{looked[0]} and a cached parquet under {looked[1]}. Run `redsim ml "
                                       "build-assets --dataset cifar10` first, or pass --fixture-synthetic-ok to "
                                       "write a seeded synthetic stand-in that is labelled as such")
            existing = _read_sidecar(sidecar_path)["files"].get(out.name)
            if isinstance(existing, dict) and existing.get("synthetic") is False and out.is_file():
                raise SliceUnavailable(f"{out} is recorded as a real CIFAR-10 draw in {sidecar_path}; refusing to "
                                       "overwrite it with a synthetic stand-in")
            warn("fixture: no local CIFAR-10 test split found; writing a SEEDED SYNTHETIC stand-in with CIFAR-10's "
                 "shape. It is not CIFAR-10 data and the sidecar records synthetic=true.")
            x, y = cifar10.synthetic_test_split(seed=seed)
            indices = np.arange(len(y), dtype=np.int64)
            revision = f"synthetic-seed-{seed}"
            synthetic = True
            source = {"kind": "synthetic", "path": None, "sha256": None, "revision": revision,
                      "generator": "redsim.ml.datasets.cifar10.synthetic_test_split"}

    chosen = cifar10.fixture_indices(y, per_class=per_class, seed=seed)
    source_rows = indices[chosen]
    dataset_id = cifar10.SYNTHETIC_DATASET_ID if synthetic else cifar10.DATASET_ID
    digest = cifar10.save_fixture_npz(out, x[chosen], y[chosen], source_rows, dataset_revision=revision,
                                      dataset_id=dataset_id)
    counts = np.bincount(y[chosen], minlength=len(cifar10.CLASS_NAMES))
    entry: dict[str, Any] = {
        "role": "CI / fixture image dataset (spec 11.2, 11.3.5, 22.2)",
        "synthetic": synthetic,
        "source_dataset_id": dataset_id,
        "source_revision": revision,
        "source_split": "test",
        "source": source,
        "n_source_rows": int(len(y)),
        "source_row_indices": [int(i) for i in source_rows],
        "source_row_indices_sha256": ds.indices_sha256(source_rows),
        "sampling": {"method": FIXTURE_SAMPLING_METHOD, "seed": seed, "per_class": per_class,
                     "drawn_at": datetime.now(UTC).isoformat(), "module": "redsim.ml.assets.build.build_cifar10_fixture"},
        "class_names": list(cifar10.CLASS_NAMES),
        "n_rows": int(len(chosen)),
        "per_class": {name: int(counts[i]) for i, name in enumerate(cifar10.CLASS_NAMES)},
        "shape": [int(d) for d in x[chosen].shape],
        "dtype": "uint8",
        "layout": "NCHW, RGB, pixel values 0-255; scaled to float32 [0, 1] at use",
        "npz_keys": ["x", "y", "indices", "class_names", "dataset_id", "dataset_revision"],
        "sha256": digest,
        "notes": [
            ("CI fixture only (spec 11.1): never a demo target, never a Finding, never evidence. The cifar10_smallcnn "
             "target is fixture_only and no API path serves this file as a result."),
            "source_row_indices are 0-based positions in the source test split, in the fixture's row order.",
            ("Synthetic stand-in: seeded noise with CIFAR-10's shape and class list, written because no local copy "
             "of the test split was available. Not CIFAR-10 data." if synthetic else
             "Rows are real CIFAR-10 test images (uoft-cs/cifar10 parquet mirror); the license note of the dataset "
             "card applies (no formal license statement; research redistribution)."),
        ],
    }
    sidecar_doc = _read_sidecar(sidecar_path)
    sidecar_doc["files"][out.name] = entry
    sidecar_path.parent.mkdir(parents=True, exist_ok=True)
    sidecar_path.write_text(json.dumps(sidecar_doc, indent=2) + "\n", encoding="utf-8")
    log(f"fixture: wrote {out} ({entry['n_rows']} rows, sha256 {digest[:12]}...) and its entry in {sidecar_path}")
    return FixtureBuild(path=out, sidecar=sidecar_path, entry=entry)


# ---------------------------------------------------------------------------
# Fetch + build
# ---------------------------------------------------------------------------

def resolve_url_table(opts: BuildOptions, log: Log, warn: Log) -> ds.UrlTable:
    assert opts.cache_dir is not None
    download = ds.fetch_kaggle_malicious_urls(opts.cache_dir, log=log)
    if download is not None:
        return ds.kaggle_url_table(download)
    warn(ds.kaggle_missing_message())
    sample = ds.committed_sample_path()
    if sample is None:
        raise ds.DatasetUnavailable("no Kaggle credentials are set and the committed sample is not present in this "
                                    f"installation; export {ds.KAGGLE_TOKEN_ENV} or run from a source checkout")
    return ds.sample_url_table(sample)


def build_assets(opts: BuildOptions, log: Log = print, warn: Log | None = None) -> AssetManifest:
    """Run the selected builds and write ``<out>/MANIFEST.json``.

    The manifest is read back right before it is written and only the entries
    this run built are replaced, so re-runs and two builds into the same root
    (say ``--dataset image`` beside ``--dataset tabular``) keep each other's
    entries. A legacy entry (``url_classifier``) is dropped once its current id
    (``url_trees``) has been built. With ``opts.fixture`` the committed CIFAR-10
    slice is written afterwards from local files only.
    """
    inject_truststore()
    warn = warn or log
    assert opts.cache_dir is not None
    root = opts.out.resolve()
    root.mkdir(parents=True, exist_ok=True)
    opts.cache_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = root / MANIFEST_NAME
    built_datasets: dict[str, DatasetEntry] = {}
    built_models: dict[str, ModelEntry] = {}
    cap_notes = []
    if opts.max_train is not None:
        cap_notes.append(f"training split capped to {opts.max_train} rows by --max-train (smoke build)")
    if opts.max_eval is not None:
        cap_notes.append(f"evaluation split capped to {opts.max_eval} rows by --max-eval (smoke build)")

    built: list[str] = []
    selected = opts.selected
    client = ds.make_client() if selected & {"image", "cifar10"} else None
    try:
        if "image" in selected and client is not None:
            data = ds.fetch_imagefolder(client, opts.cache_dir, opts.image_repo, split_dirs=ds.VEHICLES_SPLIT_DIRS,
                                        revision=opts.image_revision, image_size=opts.image_size,
                                        max_train=opts.max_train, max_eval=opts.max_eval, seed=opts.seed,
                                        workers=opts.workers, log=log, license_note=VEHICLES_LICENSE_NOTE,
                                        notes=VEHICLES_NOTES)
            entry, model = build_cnn_asset(data, model_id=MODEL_IDS["image"], root=root, epochs=opts.epochs,
                                           seed=opts.seed, arch=opts.arch, notes=cap_notes, log=log)
            built_datasets[entry.id] = entry
            built_models[model.id] = model
            built.append(model.id)
        if "cifar10" in selected and client is not None:
            data = ds.fetch_cifar10(client, opts.cache_dir, revision=opts.cifar10_revision, max_train=opts.max_train,
                                    max_eval=opts.max_eval, seed=opts.seed, log=log)
            entry, model = build_cnn_asset(data, model_id=MODEL_IDS["cifar10"], root=root, epochs=opts.epochs,
                                           seed=opts.seed, arch=opts.arch, fixture_only=True, notes=cap_notes, log=log)
            built_datasets[entry.id] = entry
            built_models[model.id] = model
            built.append(model.id)
        if "tabular" in selected:
            table = resolve_url_table(opts, log, warn)
            entry, model = build_url_asset(table, model_id=MODEL_IDS["tabular"], root=root, seed=opts.seed,
                                           holdout=opts.holdout, prefer_xgboost=opts.prefer_xgboost, log=log)
            built_datasets[entry.id] = entry
            built_models[model.id] = model
            built.append(model.id)
    finally:
        if client is not None:
            client.close()

    manifest = load_or_new(manifest_path)
    if built:
        manifest.datasets.update(built_datasets)
        manifest.models.update(built_models)
        for legacy, current in LEGACY_MODEL_IDS.items():
            if current in built_models and legacy in manifest.models:
                del manifest.models[legacy]
                log(f"dropped the legacy manifest entry {legacy!r}; {current!r} replaces it")
        manifest.touch()
        write_manifest(manifest, manifest_path)
        log(f"wrote {manifest_path} ({len(built)} model(s) built: {', '.join(built)})")
    else:
        log("no model selected for this run; the manifest is unchanged")
    if opts.fixture:
        build_cifar10_fixture(out=opts.fixture_out, sidecar=opts.fixture_sidecar, assets_root=root,
                              cache_dir=opts.cache_dir, seed=opts.seed, allow_synthetic=opts.fixture_allow_synthetic,
                              log=log, warn=warn)
    return manifest


def summarize(manifest: AssetManifest) -> str:
    """Human-readable manifest summary for the CLI."""
    lines = [f"MANIFEST built {manifest.built_at.isoformat()} by {manifest.builder} (redsim {manifest.redsim_version})"]
    for model in manifest.models.values():
        rev = (model.dataset_revision or "unpinned")[:12]
        acc = model.clean_accuracy
        acc_s = f"{acc.value:.4f} (n={acc.n}, {acc.split})" if acc is not None else "n/a"
        flag = "  [fixture only]" if model.fixture_only else ""
        lines.append(f"  {model.id}: {model.format} ({model.architecture_id}) on {model.dataset_id}@{rev}, "
                     f"clean accuracy {acc_s}, sha256 {model.sha256[:12]}...{flag}")
    return "\n".join(lines)
