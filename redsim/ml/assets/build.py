"""Orchestration for ``redsim ml build-assets`` (spec 11, 20.1 step 3, milestones M0 / M1 / M4).

Fetch each dataset by pinned revision, train the bundled models on CPU with a
fixed seed, write weights and evaluation slices under the assets root and
record everything in ``MANIFEST.json``. Each model entry is a
``redsim.ml.schema.MLModelManifest`` plus the build record. The two
``build_*_asset`` functions take in-memory data, so tests drive them with
synthetic inputs and never touch the network; only ``build_assets`` fetches.

Python HTTPS on the hackathon machines goes through a TLS-inspecting proxy, so
the entrypoint injects the OS trust store via ``truststore`` when available.
"""

from __future__ import annotations

import csv
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from redsim.ml.assets import ASSET_IDS, DATASET_CHOICES, MODEL_IDS, MODEL_NAMES
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
    load_or_new,
    stamp_manifest_sha256,
    write_manifest,
)
from redsim.ml.assets.train_cnn import save_state_dict, train_small_cnn
from redsim.ml.assets.train_url_classifier import SURROGATE_KIND, save_url_classifier, train_url_classifier
from redsim.ml.datasets.url_features import EXTRACTOR_VERSION, FEATURE_NAMES, N_FEATURES
from redsim.ml.schema import AccuracyPoint, CleanAccuracy

Log = Callable[[str], None]

__all__ = [
    "ASSET_IDS", "DATASET_CHOICES", "MODEL_IDS", "MODEL_NAMES", "BuildOptions", "build_assets",
    "build_cnn_asset", "build_url_asset", "inject_truststore", "summarize",
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
    prefer_xgboost: bool = True
    holdout: float = 0.2

    def __post_init__(self) -> None:
        if self.dataset not in DATASET_CHOICES:
            raise ValueError(f"dataset must be one of {DATASET_CHOICES}, got {self.dataset!r}")
        self.only = tuple(self.only)
        unknown = [m for m in self.only if m not in ASSET_IDS]
        if unknown:
            raise ValueError(f"unknown model id(s) {unknown}; known: {sorted(ASSET_IDS)}")
        if self.epochs < 1:
            raise ValueError("epochs must be >= 1")
        self.out = Path(self.out)
        self.cache_dir = Path(self.cache_dir) if self.cache_dir is not None else self.out / "cache"

    @property
    def selected(self) -> set[str]:
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
                    fixture_only: bool = False, notes: Sequence[str] = (), name: str | None = None,
                    log: Log = print) -> tuple[DatasetEntry, ModelEntry]:
    """Train ``SmallCNN`` on ``data`` and write weights, eval slice and manifest entries under ``root``."""
    root = Path(root).resolve()
    class_names = list(data.train.class_names)
    log(f"{model_id}: training SmallCNN for {epochs} epoch(s), seed {seed}, "
        f"n_train={data.train.n}, n_eval={data.eval.n}, image_size={data.train.x.shape[-1]}")
    result = train_small_cnn(data.train.x, data.train.y, data.eval.x, data.eval.y, class_names,
                             epochs=epochs, seed=seed, log=log)
    weights = file_entry(root, save_state_dict(result.model, root / "bundled" / model_id / "weights.pt"))

    entry = data.dataset.model_copy(deep=True)
    entry.fixture_only = entry.fixture_only or fixture_only
    entry.notes = list(entry.notes) + list(notes)
    eval_file = write_image_eval_slice(data.eval, root, entry)
    entry.splits[data.train.name] = ds.split_entry(data.train)
    entry.splits[data.eval.name] = ds.split_entry(data.eval, file=eval_file)

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
               "Clean accuracy is measured on the full bundled evaluation split at build time."],
    )
    model = stamp_manifest_sha256(model)
    log(f"{model_id}: clean accuracy {model.clean_accuracy.value:.4f} on n={model.clean_accuracy.n}, "  # type: ignore[union-attr]
        f"weights sha256 {model.sha256[:12]}...")
    return entry, model


def _per_class(labels: np.ndarray, idx: np.ndarray, class_names: Sequence[str]) -> dict[str, int]:
    counts = np.bincount(labels[idx], minlength=len(class_names))
    return {name: int(counts[i]) for i, name in enumerate(class_names)}


def write_url_eval_slice(urls: Sequence[str], labels: np.ndarray, eval_idx: np.ndarray, class_names: Sequence[str],
                         root: Path, entry: DatasetEntry) -> FileEntry:
    """Bundle the held-out URL rows (index, url, type). URL strings are data; nothing here fetches them."""
    path = dataset_dir(root, entry) / "eval.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["index", "url", "type"])
        for i in eval_idx:
            writer.writerow([int(i), urls[int(i)], class_names[int(labels[int(i)])]])
    return file_entry(root, path)


def build_url_asset(table: ds.UrlTable, *, model_id: str, root: Path, seed: int, holdout: float = 0.2,
                    prefer_xgboost: bool = True, name: str | None = None,
                    log: Log = print) -> tuple[DatasetEntry, ModelEntry]:
    """Train the URL classifier and its surrogate on ``table``; write both plus the eval slice under ``root``."""
    root = Path(root).resolve()
    class_names = list(table.dataset.class_names)
    result = train_url_classifier(table.urls, table.labels, seed=seed, holdout=holdout,
                                  prefer_xgboost=prefer_xgboost, class_names=class_names, log=log)
    model_file, surrogate_file = save_url_classifier(result, root / "bundled" / model_id, assets_root=root)

    entry = table.dataset.model_copy(deep=True)
    entry.n_duplicates_removed = result.n_duplicates_removed
    eval_file = write_url_eval_slice(result.urls, result.labels, result.eval_idx, class_names, root, entry)
    entry.splits["train"] = SplitEntry(name="train", n=len(result.train_idx),
                                       per_class=_per_class(result.labels, result.train_idx, class_names),
                                       seed=seed, indices_sha256=ds.indices_sha256(result.train_idx))
    entry.splits["eval"] = SplitEntry(name="eval", n=len(result.eval_idx),
                                      per_class=_per_class(result.labels, result.eval_idx, class_names),
                                      seed=seed, indices_sha256=ds.indices_sha256(result.eval_idx), file=eval_file)
    entry.preprocessing = {"features": list(FEATURE_NAMES), "extractor": "redsim.ml.datasets.url_features",
                           "extractor_version": EXTRACTOR_VERSION, "dedupe": "exact URL string, first occurrence kept",
                           "split": f"seeded stratified, holdout {holdout}"}

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
    entries.
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
                                           seed=opts.seed, notes=cap_notes, log=log)
            built_datasets[entry.id] = entry
            built_models[model.id] = model
            built.append(model.id)
        if "cifar10" in selected and client is not None:
            data = ds.fetch_cifar10(client, opts.cache_dir, revision=opts.cifar10_revision, max_train=opts.max_train,
                                    max_eval=opts.max_eval, seed=opts.seed, log=log)
            entry, model = build_cnn_asset(data, model_id=MODEL_IDS["cifar10"], root=root, epochs=opts.epochs,
                                           seed=opts.seed, fixture_only=True, notes=cap_notes, log=log)
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
    manifest.datasets.update(built_datasets)
    manifest.models.update(built_models)
    manifest.touch()
    write_manifest(manifest, manifest_path)
    log(f"wrote {manifest_path} ({len(built)} model(s) built: {', '.join(built)})")
    return manifest


def summarize(manifest: AssetManifest) -> str:
    """Human-readable manifest summary for the CLI."""
    lines = [f"MANIFEST built {manifest.built_at.isoformat()} by {manifest.builder} (redsim {manifest.redsim_version})"]
    for model in manifest.models.values():
        rev = (model.dataset_revision or "unpinned")[:12]
        acc = model.clean_accuracy
        acc_s = f"{acc.value:.4f} (n={acc.n}, {acc.split})" if acc is not None else "n/a"
        flag = "  [fixture only]" if model.fixture_only else ""
        lines.append(f"  {model.id}: {model.format} on {model.dataset_id}@{rev}, clean accuracy {acc_s}, "
                     f"sha256 {model.sha256[:12]}...{flag}")
    return "\n".join(lines)
