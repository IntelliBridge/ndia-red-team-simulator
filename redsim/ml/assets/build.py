"""Orchestration for ``redsim ml build-assets`` (spec 11, 20.1 step 3, milestones M0 / M1 / M4).

Fetch each dataset by pinned revision, train the bundled models on CPU with a
fixed seed, write weights and evaluation slices under the assets root and
record everything in ``MANIFEST.json``. Each model entry is a
``redsim.ml.schema.MLModelManifest`` plus the build record. The two
``build_*_asset`` functions take in-memory data, so tests drive them with
synthetic inputs and never touch the network; only ``build_assets`` fetches.

The manifest shape the loaders (``redsim.ml.targets.bundled`` / ``tabular`` /
``text`` / ``detection``) read is the one written here: weights at
``models[id].file.path``, the architecture kwargs at
``models[id].architecture``, the evaluation slice at
``datasets[models[id].dataset_id].splits[models[id].dataset_split].file`` and
the tabular surrogate at ``models[id].surrogate.file``. Model ids are the
registry ids (``vehicles_cnn``, ``cifar10_smallcnn``, ``url_trees``, and since
Phase B ``sms_tfidf_lr`` for ``--dataset text`` and ``assets_frcnn_mnv3`` for
``--dataset detection``; the vocabulary is ``manifest.BUILD_*``).

Phase B additions (plan 12): the image builds also write the bundled training
slice a training defense fine-tunes on (``bundled/<model>/train_slice.npz``,
recorded as a split of the dataset and named by ``models[id].train_slice_split``,
ATTACKS_HARDEN-11) with a sidecar ``train_slice.json``; ``attach_train_slice``
records a slice drawn out-of-band from that sidecar (``--attach-train-slice``)
without retraining. The text build (``build_text_asset`` in
``train_text_classifier``) reads the cached UCI corpus, falling back to the
committed fixture as the tabular build does; the detection build reads the
published capped subset under ``<assets>/cache/military_assets_subset`` and is
never part of ``--dataset all`` (it cannot fetch its own input).

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

import httpx
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
    BUILD_ASSET_IDS,
    BUILD_DATASET_CHOICES,
    BUILD_MODEL_IDS,
    BUILD_MODEL_NAMES,
    DETECTION_MODEL_ID,
    EXPLICIT_ONLY_DATASETS,
    MANIFEST_NAME,
    TEXT_MODEL_ID,
    AssetManifest,
    DatasetEntry,
    FileEntry,
    ModelEntry,
    SplitEntry,
    SurrogateEntry,
    all_build_datasets,
    file_entry,
    library_versions,
    load_manifest,
    load_or_new,
    manifest_digest,
    model_entry,
    sha256_file,
    stamp_manifest_sha256,
    with_dataset_caveats,
    write_manifest,
)
from redsim.ml.datasets import DatasetUnavailable as SliceUnavailable
from redsim.ml.datasets import cifar10
from redsim.ml.datasets.url_features import EXTRACTOR_VERSION, FEATURE_NAMES, N_FEATURES, featurize_array
from redsim.ml.schema import AccuracyPoint, CleanAccuracy

# torch-backed modules (train_cnn, train_url_classifier via classification_metrics, targets.architectures,
# train_text_classifier, train_detector) are imported inside the functions that train, so ``redsim ml
# build-assets`` parses and refuses bad options without the ``ml`` extra (tests/ml/test_cli_ml.py runs on the
# py3.13 lane).

Log = Callable[[str], None]

__all__ = [
    "ASSET_IDS", "BUILD_ASSET_IDS", "BUILD_DATASET_CHOICES", "BUILD_MODEL_IDS", "BUILD_MODEL_NAMES",
    "CIFAR10_CAVEATS", "DATASET_CAVEATS", "DATASET_CHOICES", "DEFAULT_FIXTURE_PATH", "DETECTION_MODEL_ID",
    "DETECTION_PIPELINE_CAVEATS", "EXPLICIT_ONLY_DATASETS", "FIXTURE_ONLY_CAVEAT", "KAGGLE_URL_CAVEATS", "MODEL_IDS",
    "MODEL_NAMES", "SUBJECT_CENTERED", "TEXT_MODEL_ID", "URL_PIPELINE_CAVEATS", "VEHICLES_CAVEATS",
    "VEHICLES_DATASET_ID", "BuildOptions", "FixtureBuild", "attach_train_slice", "build_assets",
    "build_cifar10_fixture", "build_cnn_asset", "build_detection_asset", "build_url_asset", "dataset_caveats",
    "inject_truststore", "resolve_detection_data", "resolve_detection_subset_root", "resolve_sms_table",
    "subject_centered_for", "summarize", "write_url_eval_slice",
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

# ---------------------------------------------------------------------------
# Dataset caveats (spec 11.3) and the subject_centered flag (spec 13.4)
#
# Written into ``DatasetEntry.caveats`` / ``DatasetEntry.subject_centered`` and copied onto every model entry bound
# to the dataset. ``redsim.ml.campaign`` appends each caveat to the limitations of every campaign on that dataset
# as "Dataset caveat (<dataset id>): <text>" (spec 14.5) and reads ``subject_centered`` for the centre-mass caveat.
# Wording here is the spec's; it never grades, never speaks of readiness or certification.
# ---------------------------------------------------------------------------

VEHICLES_DATASET_ID = f"hf:{ds.VEHICLES_REPO}"
KAGGLE_URL_DATASET_ID = f"kaggle:{ds.MALICIOUS_URLS_SLUG}"

# The D3 bounds statement with its open / unclassified / public framing (spec 11.1), then the 11.3.1 caveats 1-5.
VEHICLES_CAVEATS: tuple[str, ...] = (
    (f"{ds.VEHICLES_REPO} is an open, unclassified, publicly available dataset whose license (MIT) is stated on its "
     "distribution page (D3, spec 11.1). D3's choice of military-vehicle imagery knowingly diverges from the "
     "non-operational wording of the brief; its bounds are these: the tool evaluates and hardens the robustness of a "
     "classifier on this public benchmark, it never trains, optimises or deploys a targeting or weapons model, and it "
     "connects to no operational, sensitive or mission data source. The team decision is recorded in decision D001 "
     "pending named approval."),
    ("Ground-level photographs, not aerial or overhead imagery: D3's 'aerial-target / military-vehicle' phrase is "
     "satisfied on the vehicle side only (spec 11.3.1 caveat 1)."),
    ("Photo copyright is not cleared by the dataset's MIT tag, which covers the authors' compilation and labels; the "
     "images were collected from Roboflow, armyrecognition.com and other web sources. Internal, non-commercial demo; "
     "images are not redistributed in public releases or reports without further review (spec 11.3.1 caveat 2, 11.5)."),
    ("The dataset card states no split protocol and no de-duplication step; train/test are taken as given and "
     "near-duplicates across splits are possible (spec 11.3.1 caveat 3)."),
    ("Images may incidentally contain people. No person or face recognition is performed, no such labels exist in the "
     "data and none are derived (spec 11.3.1 caveat 4)."),
    ("Subjects are not reliably centred or tightly framed (web-thumbnail framing), so the centre-mass heuristic of "
     "spec 13.4 is weaker evidence on this dataset than on a centred fixture; it stays labelled heuristic "
     "(spec 11.3.1 caveat 5)."),
)

# CIFAR-10 is a CI / fixture dataset only (spec 11.1, 11.3.5).
CIFAR10_CAVEATS: tuple[str, ...] = (
    (f"{cifar10.REPO_ID} is a CI / fixture image dataset only (spec 11.1, 11.3.5): it is never a demo target, never "
     "populates a Finding and is never presented as evidence; results on it are test outputs, not results about any "
     "operational domain."),
    ("CIFAR-10 carries no formal license statement ('unknown' on the dataset card); it is used as a test fixture that "
     "is never presented as results (spec 11.5)."),
)

# Properties of the lexical-feature URL pipeline (spec 11.3.3 caveats 1-2, 12.9): true for every table the URL builder
# processes, the Kaggle file and the committed CI sample alike.
URL_PIPELINE_CAVEATS: tuple[str, ...] = (
    ("URL strings are inert data (spec 11.3.3 caveat 1): the pipeline never fetches, resolves (DNS) or renders any URL "
     "from the dataset, in the worker, the sandbox child, the UI or the reports; only lexical features are computed, "
     "and a displayed URL is escaped, non-clickable text labelled as dataset content."),
    ("Realizability gap (spec 11.3.3 caveat 2, 12.9): feature-space perturbations of the lexical URL features (PGD "
     "with rounding, HopSkipJump) are evidence about the classifier's decision surface. They count as a realizable "
     "attack only if the perturbed feature vector maps back to a constructible URL that yields exactly those features; "
     "Phase A constructs no URLs and does not check this, so no tabular row is presented as demonstrated URL evasion."),
)

# The Kaggle file itself (spec 11.3.3 caveats 3-6).
KAGGLE_URL_CAVEATS: tuple[str, ...] = (
    ("Label noise (spec 11.3.3 caveat 3): labels come from several blacklists and feeds merged by the uploader without a "
     "documented adjudication step; disagreement between sources cannot be recovered from the file."),
    ("Dataset age (spec 11.3.3 caveat 4): compiled in 2021; phishing and malware-distribution URL patterns drift, so "
     "results describe this snapshot, not current traffic."),
    ("Class imbalance (spec 11.3.3 caveat 5): benign is about two thirds of the rows, so minority-class per-class counts "
     "are small at the default n_samples; per-class n is always shown."),
    ("Access (spec 11.3.3 caveat 6): the download needs a personal Kaggle token, used once by the asset build and never "
     "present on the API, web or steady-state worker containers."),
)

# Every fixture_only dataset (spec 11.1): the committed URL sample, CIFAR-10, synthetic doubles.
FIXTURE_ONLY_CAVEAT = ("CI / fixture dataset (spec 11.1): never a demo target, never populates a Finding and never "
                       "appears as evidence; campaign output on it is a test result, not a result about any dataset.")

# Properties of the detector build (MODALITIES-29): true for every subset it processes, the published one and a
# synthetic double alike. The corpus caveats of the subset itself travel on the dataset entry
# (``ds.MILITARY_ASSETS_CAVEATS``, also the table row below).
DETECTION_PIPELINE_CAVEATS: tuple[str, ...] = (
    ("Detection clean_accuracy is recall at IoU >= 0.5 over the evaluation split's ground-truth boxes (n counts "
     "boxes, not images), measured at build time; it is not a classification accuracy. mAP@0.5 and per-class box "
     "counts sit beside it in the model entry's metrics (MODALITIES-29)."),
    ("Images are stretched to a square input at load time and boxes are scaled with the same factors, so aspect "
     "ratios differ from the source photographs."),
    ("A few-hundred-image CPU fine-tune of a COCO-initialised detector yields modest mAP; the figures describe this "
     "build on this capped subset and no other detector or dataset."),
)

DATASET_CAVEATS: dict[str, tuple[str, ...]] = {
    VEHICLES_DATASET_ID: VEHICLES_CAVEATS,
    cifar10.DATASET_ID: CIFAR10_CAVEATS,
    KAGGLE_URL_DATASET_ID: KAGGLE_URL_CAVEATS,
    ds.MILITARY_ASSETS_DATASET_ID: ds.MILITARY_ASSETS_CAVEATS,
}

# Spec 13.4 / 11.3.1 caveat 5: the vehicle photographs are not reliably centred; CIFAR-10 thumbnails are object-centred
# (the spec's own comparison point). Any dataset not listed stays ``None``: the flag is recorded, never assumed.
SUBJECT_CENTERED: dict[str, bool] = {
    VEHICLES_DATASET_ID: False,
    cifar10.DATASET_ID: True,
}


def _uniq(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = item.strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def dataset_caveats(entry: DatasetEntry, *, pipeline: Sequence[str] = (), extra: Sequence[str] = ()) -> list[str]:
    """The spec 11.3 caveats for ``entry``, deduplicated, in this order: what it already carries, the ``pipeline``
    caveats of the build that processes it, the table row for its id, ``FIXTURE_ONLY_CAVEAT`` when it is
    fixture-only, then ``extra``."""
    out: list[str] = list(entry.caveats)
    out.extend(pipeline)
    out.extend(DATASET_CAVEATS.get(entry.id, ()))
    if entry.fixture_only:
        out.append(FIXTURE_ONLY_CAVEAT)
    out.extend(extra)
    return _uniq(out)


def subject_centered_for(entry: DatasetEntry) -> bool | None:
    """``entry.subject_centered`` when declared, else the table value for its id, else ``None`` (unknown)."""
    if entry.subject_centered is not None:
        return entry.subject_centered
    return SUBJECT_CENTERED.get(entry.id)

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


# Dataset selections whose model is trained on an image split and so carries a training slice.
_IMAGE_DATASETS: frozenset[str] = frozenset({"image", "cifar10"})


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
    build_models: bool = True            # False: ``--fixture`` / ``--attach-train-slice`` alone, no training
    fixture: bool = False                # also write the committed CIFAR-10 test slice
    fixture_out: Path = DEFAULT_FIXTURE_PATH
    fixture_sidecar: Path | None = None  # default: MANIFEST.json beside ``fixture_out``
    fixture_allow_synthetic: bool = False
    # ATTACKS_HARDEN-11: the image builds write ``bundled/<model>/train_slice.npz`` (``--no-train-slice`` skips it).
    train_slice: bool = True
    train_slice_n: int = ds.DEFAULT_TRAIN_SLICE_N
    # Image model ids whose out-of-band slice (``train_slice.json`` sidecar) is recorded in the manifest.
    attach_train_slice: tuple[str, ...] = ()
    # MODALITIES-29: the detector build reads the published subset (default: ``<cache>/military_assets_subset``,
    # else ``<out>/cache/military_assets_subset``) at this square input size.
    detection_image_size: int = 320
    detection_subset: Path | None = None

    def __post_init__(self) -> None:
        if self.dataset not in BUILD_DATASET_CHOICES:
            raise ValueError(f"dataset must be one of {BUILD_DATASET_CHOICES}, got {self.dataset!r}")
        self.only = tuple(canonical_model_id(m) for m in self.only)
        unknown = [m for m in self.only if m not in BUILD_ASSET_IDS]
        if unknown:
            raise ValueError(f"unknown model id(s) {unknown}; known: {sorted(BUILD_ASSET_IDS)}")
        self.attach_train_slice = tuple(canonical_model_id(m) for m in self.attach_train_slice)
        not_image = [m for m in self.attach_train_slice
                     if BUILD_ASSET_IDS.get(m) not in _IMAGE_DATASETS]
        if not_image:
            raise ValueError(f"attach_train_slice names non-image model id(s) {not_image}; a training slice belongs "
                             f"to an image model: {sorted(m for m, d in BUILD_ASSET_IDS.items() if d in _IMAGE_DATASETS)}")
        if self.epochs < 1:
            raise ValueError("epochs must be >= 1")
        if self.train_slice_n < 1:
            raise ValueError("train_slice_n must be >= 1")
        if self.detection_image_size < 8:
            raise ValueError("detection_image_size must be >= 8")
        if not 0.0 < self.holdout < 1.0:
            raise ValueError("holdout must be in (0, 1)")
        try:
            from redsim.ml.targets.architectures import canonical_architecture_id
        except ImportError:  # no ``ml`` extra: aliases cannot be resolved, canonical ids still validate below
            pass
        else:
            self.arch = canonical_architecture_id(self.arch)
        if self.arch not in ARCH_CHOICES:
            raise ValueError(f"arch must be one of {ARCH_CHOICES}, got {self.arch!r}")
        self.out = Path(self.out)
        self.cache_dir = Path(self.cache_dir) if self.cache_dir is not None else self.out / "cache"
        self.fixture_out = Path(self.fixture_out)
        if self.fixture_sidecar is not None:
            self.fixture_sidecar = Path(self.fixture_sidecar)
        if self.detection_subset is not None:
            self.detection_subset = Path(self.detection_subset)

    @property
    def selected(self) -> set[str]:
        """Dataset selections to build: ``--only`` ids win; ``all`` leaves out ``EXPLICIT_ONLY_DATASETS``."""
        if not self.build_models:
            return set()
        if self.only:
            return {BUILD_ASSET_IDS[m] for m in self.only}
        return all_build_datasets() if self.dataset == "all" else {self.dataset}

    @property
    def train_slice_options(self) -> ds.TrainSliceOptions:
        return ds.TrainSliceOptions(n=self.train_slice_n, seed=self.seed, enabled=self.train_slice)


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


def write_image_train_slice(data: ds.ImageDataset, root: Path, entry: DatasetEntry, model_id: str, *,
                            options: ds.TrainSliceOptions) -> SplitEntry:
    """Draw the bundled training slice of ``model_id`` from ``data.train`` and record it on ``entry`` (ATTACKS_HARDEN-11).

    The slice goes to ``bundled/<model_id>/train_slice.npz`` with its ``train_slice.json`` sidecar and the
    ``SplitEntry`` (named ``<train split>_slice``) under ``entry.splits``. When train and eval come from one
    pool (same split name) the evaluation rows are excluded so the slice never overlaps what is measured.
    """
    same_pool = data.train.name == data.eval.name
    dest = Path(root) / "bundled" / model_id / ds.TRAIN_SLICE_NAME
    _sub, slice_entry = ds.write_train_slice(data.train, dest, root, n=options.n, seed=options.seed,
                                             exclude_indices=data.eval.indices if same_pool else None)
    entry.splits[slice_entry.name] = slice_entry
    ds.write_train_slice_sidecar(dest.parent / ds.TRAIN_SLICE_SIDECAR_NAME, ds.TrainSliceSidecar(
        model_id=model_id, dataset_id=entry.id, revision=entry.revision, source_split=data.train.name,
        split_entry=slice_entry, n_requested=options.n, seed=options.seed,
        note=(f"seeded stratified draw over the {data.train.name} split (redsim.ml.assets.datasets.write_train_slice); "
              + ("disjoint from the evaluation rows by construction" if same_pool
                 else f"train and evaluation ({data.eval.name}) are distinct source splits")),
    ))
    return slice_entry


def build_cnn_asset(data: ds.ImageDataset, *, model_id: str, root: Path, epochs: int, seed: int,
                    arch: str = "small_cnn", fixture_only: bool = False, notes: Sequence[str] = (),
                    caveats: Sequence[str] = (), subject_centered: bool | None = None,
                    name: str | None = None, train_slice: ds.TrainSliceOptions | None = None,
                    log: Log = print) -> tuple[DatasetEntry, ModelEntry]:
    """Train the catalog architecture ``arch`` on ``data``; write weights, eval slice and manifest entries.

    The dataset entry gets its spec 11.3 caveats (``dataset_caveats``: the table row for its id, the fixture-only
    statement, then ``caveats``) and its ``subject_centered`` flag (``subject_centered`` when given, else the table
    value, else ``None``); both are copied onto the model entry (spec 13.4, 14.5). The bundled training slice
    (``train_slice``; the defaults when ``None``, ``TrainSliceOptions(enabled=False)`` to skip) is written beside
    the weights and named by the model entry's ``train_slice_split`` (ATTACKS_HARDEN-11).
    """
    from redsim.ml.assets.train_cnn import save_state_dict, train_cnn
    from redsim.ml.targets.architectures import canonical_architecture_id

    root = Path(root).resolve()
    arch = canonical_architecture_id(arch)
    slice_options = train_slice if train_slice is not None else ds.TrainSliceOptions(seed=seed)
    class_names = list(data.train.class_names)
    log(f"{model_id}: training {arch} for {epochs} epoch(s), seed {seed}, "
        f"n_train={data.train.n}, n_eval={data.eval.n}, image_size={data.train.x.shape[-1]}")
    result = train_cnn(data.train.x, data.train.y, data.eval.x, data.eval.y, class_names,
                       arch=arch, epochs=epochs, seed=seed, log=log)
    weights = file_entry(root, save_state_dict(result.model, root / "bundled" / model_id / "weights.pt"))

    entry = data.dataset.model_copy(deep=True)
    entry.fixture_only = entry.fixture_only or fixture_only
    entry.notes = list(entry.notes) + list(notes)
    entry.caveats = dataset_caveats(entry, extra=caveats)
    entry.subject_centered = subject_centered if subject_centered is not None else subject_centered_for(entry)
    eval_file = write_image_eval_slice(data.eval, root, entry)
    entry.splits[data.train.name] = ds.split_entry(data.train)
    entry.splits[data.eval.name] = ds.split_entry(data.eval, file=eval_file)
    slice_name: str | None = None
    if slice_options.enabled:
        slice_entry = write_image_train_slice(data, root, entry, model_id, options=slice_options)
        slice_name = slice_entry.name
        log(f"{model_id}: training slice {slice_entry.name} n={slice_entry.n} (requested {slice_options.n}, seed "
            f"{slice_options.seed}) at {slice_entry.file.path}")  # type: ignore[union-attr]

    init_note = str(result.training.get("backbone_init", "random (seeded)"))
    model = ModelEntry(
        id=model_id, name=name or BUILD_MODEL_NAMES.get(model_id, model_id), modality="image",
        format="torch_state_dict", sha256=weights.sha256, size_bytes=weights.size_bytes, file=weights,
        architecture_id=result.model.architecture_id, architecture=result.model.architecture_config(),
        input_shape=list(result.model.input_shape), n_classes=len(class_names), class_names=class_names,
        dataset_id=entry.id, dataset_revision=entry.revision, dataset_split=data.eval.name, train_split=data.train.name,
        clean_accuracy=_clean_accuracy(result.metrics, data.eval.name), gradients=True,
        license=entry.license, source_url=entry.url,
        seed=seed, epochs=epochs, training=result.training, metrics=result.metrics,
        library_versions=library_versions(("torch", "torchvision", "numpy")),
        fixture_only=entry.fixture_only, train_slice_split=slice_name,
        notes=["Input contract: float32 [0, 1] NCHW; channel normalisation is inside the model.",
               "Clean accuracy is measured on the full bundled evaluation split at build time.",
               f"Initialisation: {init_note}."],
    )
    model = stamp_manifest_sha256(with_dataset_caveats(model, entry))
    log(f"{model_id}: clean accuracy {model.clean_accuracy.value:.4f} on n={model.clean_accuracy.n}, "  # type: ignore[union-attr]
        f"weights sha256 {model.sha256[:12]}..., {len(entry.caveats)} dataset caveat(s), "
        f"subject_centered={entry.subject_centered}")
    return entry, model


def attach_train_slice(manifest: AssetManifest, root: Path, model_id: str, *, sidecar: Path | None = None,
                       log: Log = print) -> SplitEntry:
    """Record a training slice drawn out-of-band in ``manifest`` from its ``train_slice.json`` sidecar.

    For a model the manifest already holds (``vehicles_cnn`` built before the slice existed): the sidecar must
    name this model, its dataset, revision and training split; the slice file must be where the sidecar says
    and hash to its recorded digest. The ``SplitEntry`` then joins the dataset's ``splits`` and the model entry
    gets ``train_slice_split``, which sits outside the frozen projection, so ``manifest_sha256`` is unchanged
    and nothing is retrained. Returns the split entry recorded.
    """
    root = Path(root).resolve()
    model_id = canonical_model_id(model_id)
    entry = model_entry(manifest, model_id)
    if entry is None:
        raise SliceUnavailable(f"{model_id!r} has no entry in the manifest; build it before attaching a training slice")
    sidecar_path = Path(sidecar) if sidecar is not None else root / "bundled" / model_id / ds.TRAIN_SLICE_SIDECAR_NAME
    record = ds.read_train_slice_sidecar(sidecar_path)
    if record.model_id != model_id:
        raise SliceUnavailable(f"{sidecar_path} describes {record.model_id!r}, not {model_id!r}")
    if record.dataset_id != entry.dataset_id:
        raise SliceUnavailable(f"{sidecar_path}: the slice was drawn from {record.dataset_id!r}; {model_id!r} is bound "
                               f"to {entry.dataset_id!r}")
    if record.revision is not None and entry.dataset_revision is not None and record.revision != entry.dataset_revision:
        raise SliceUnavailable(f"{sidecar_path}: the slice was drawn from revision {record.revision!r}; the model was "
                               f"trained on {entry.dataset_revision!r}")
    if record.source_split != entry.train_split:
        raise SliceUnavailable(f"{sidecar_path}: the slice was drawn from split {record.source_split!r}; the model's "
                               f"training split is {entry.train_split!r}")
    split = record.split_entry
    if split.file is None:
        raise SliceUnavailable(f"{sidecar_path}: the split entry names no file")
    path = root / split.file.path
    if not path.is_file():
        raise SliceUnavailable(f"training slice {path} is missing (named by {sidecar_path})")
    actual = sha256_file(path)
    if actual != split.file.sha256 or path.stat().st_size != split.file.size_bytes:
        raise SliceUnavailable(f"training slice {path} has sha256 {actual[:12]}... and {path.stat().st_size} bytes; "
                               f"{sidecar_path} records {split.file.sha256[:12]}... and {split.file.size_bytes}; "
                               "refusing to record a slice the sidecar does not vouch for")
    dataset = manifest.datasets.get(entry.dataset_id)
    if dataset is None:
        raise SliceUnavailable(f"dataset {entry.dataset_id!r} of {model_id!r} is not in the manifest")
    dataset.splits[split.name] = split
    updated = entry.model_copy(update={"train_slice_split": split.name})
    if manifest_digest(updated) != manifest_digest(entry):  # pragma: no cover - the field is outside the projection
        raise RuntimeError("train_slice_split changed the frozen projection; refusing to write")
    key = model_id if model_id in manifest.models else next(k for k, v in manifest.models.items() if v is entry)
    manifest.models[key] = updated
    log(f"{model_id}: recorded training slice {split.name} (n={split.n}, seed {split.seed}) at {split.file.path}; "
        f"manifest_sha256 unchanged")
    return split


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
                    prefer_xgboost: bool = False, caveats: Sequence[str] = (), name: str | None = None,
                    log: Log = print) -> tuple[DatasetEntry, ModelEntry]:
    """Train the URL classifier and its surrogate on ``table``; write both plus the eval slice under ``root``.

    The dataset entry gets the lexical-feature pipeline caveats (``URL_PIPELINE_CAVEATS``: URL strings are inert
    data; realizability gap), the table row for its id (the Kaggle file's caveats), the fixture-only statement when
    it is fixture-only, then ``caveats``; the model entry carries a copy (spec 11.3.3, 12.9, 14.5).
    ``subject_centered`` has no tabular meaning and stays ``None``.
    """
    from redsim.ml.assets.train_url_classifier import (
        SURROGATE_KIND,
        save_url_classifier,
        train_url_classifier,
    )

    root = Path(root).resolve()
    class_names = list(table.dataset.class_names)
    result = train_url_classifier(table.urls, table.labels, seed=seed, holdout=holdout,
                                  prefer_xgboost=prefer_xgboost, class_names=class_names, log=log)
    model_file, surrogate_file = save_url_classifier(result, root / "bundled" / model_id, assets_root=root)

    entry = table.dataset.model_copy(deep=True)
    entry.n_duplicates_removed = result.n_duplicates_removed
    entry.caveats = dataset_caveats(entry, pipeline=URL_PIPELINE_CAVEATS, extra=caveats)
    entry.subject_centered = None
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
        id=model_id, name=name or BUILD_MODEL_NAMES.get(model_id, model_id), modality="tabular", format=result.format,
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
    model = stamp_manifest_sha256(with_dataset_caveats(model, entry))
    log(f"{model_id}: clean accuracy {model.clean_accuracy.value:.4f} on n={model.clean_accuracy.n}, "  # type: ignore[union-attr]
        f"model sha256 {model.sha256[:12]}..., surrogate agreement {result.surrogate_agreement:.4f}, "
        f"{len(entry.caveats)} dataset caveat(s)")
    return entry, model


# ---------------------------------------------------------------------------
# The detector (MODALITIES-29): the published subset, a seeded holdout, a bounded CPU fine-tune
# ---------------------------------------------------------------------------

def _detection_spec(result_block: dict[str, Any], *, class_names: Sequence[str], image_size: int,
                    excluded_classes: Sequence[str]) -> dict[str, Any]:
    """The frozen ``MLModelManifest.detection`` block (``schema.DetectionModelSpec``) from the trainer's record.

    The trainer's block names ``class_names`` and a ``[C, H, W]`` size; the schema wants ``classes``,
    ``[H, W]`` and the excluded dataset classes. Thresholds are copied as measured.
    """
    return {
        "box_format": "xyxy",
        "input_size": [int(image_size), int(image_size)],
        "iou_threshold": float(result_block.get("iou_threshold", 0.5)),
        "score_threshold": float(result_block.get("score_threshold", 0.5)),
        "classes": [str(c) for c in class_names],
        "excluded_classes": [str(c) for c in excluded_classes],
    }


def build_detection_asset(train: Any, eval_split: Any, dataset: DatasetEntry, *, model_id: str, root: Path,
                          epochs: int, seed: int, anchor_sizes: Sequence[int] | None = None,
                          pretrained: bool = True, batch_size: int | None = None, threads: int | None = None,
                          caveats: Sequence[str] = (), notes: Sequence[str] = (), name: str | None = None,
                          log: Log = print) -> tuple[DatasetEntry, ModelEntry]:
    """Fine-tune the bundled detector on ``train``, measure it on ``eval_split``; write weights, slice and entries.

    ``train`` / ``eval_split`` are ``redsim.ml.datasets.military_assets.DetectionSplit`` rows (uint8 NCHW at
    one square size, xyxy boxes) and ``dataset`` the entry for what they were drawn from. ``clean_accuracy``
    is recall at IoU >= 0.5 over the evaluation split's ground-truth boxes (``n`` counts boxes) and is
    labelled so in the model notes and ``DETECTION_PIPELINE_CAVEATS``; mAP@0.5 and the per-class counts
    stay in ``metrics``. ``anchor_sizes`` / ``pretrained`` / ``batch_size`` / ``threads`` pass through to
    ``train_detector`` (tests use small anchors on 16 px synthetic rectangles). No network here.
    """
    from redsim.ml.assets.train_detector import save_state_dict, train_detector, write_eval_slice
    from redsim.ml.datasets.military_assets import EVAL_SLICE_NAME

    root = Path(root).resolve()
    class_names = list(train.class_names)
    image_size = int(train.x.shape[-1])
    log(f"{model_id}: fine-tuning the detector for {epochs} epoch(s), seed {seed}, n_train={train.n} "
        f"({train.n_boxes} boxes), n_eval={eval_split.n} ({eval_split.n_boxes} boxes), image_size={image_size}")
    extra: dict[str, Any] = {}
    if batch_size is not None:
        extra["batch_size"] = int(batch_size)
    result = train_detector(train, eval_split, epochs=epochs, seed=seed, anchor_sizes=anchor_sizes,
                            pretrained=pretrained, threads=threads, log=log, **extra)
    weights = file_entry(root, save_state_dict(result.model, root / "bundled" / model_id / "weights.pt"))

    entry = dataset.model_copy(deep=True)
    entry.notes = list(entry.notes) + list(notes)
    entry.caveats = dataset_caveats(entry, pipeline=DETECTION_PIPELINE_CAVEATS, extra=caveats)
    entry.subject_centered = None          # boxes locate the subjects; the centre-mass heuristic does not apply
    eval_path = dataset_dir(root, entry) / EVAL_SLICE_NAME
    write_eval_slice(eval_split, eval_path, dataset_id=entry.id, dataset_revision=entry.revision)
    eval_file = file_entry(root, eval_path)
    entry.splits[train.name] = SplitEntry(name=train.name, n=train.n, per_class=train.per_class_boxes(), seed=seed,
                                          indices_sha256=ds.indices_sha256(train.indices))
    entry.splits[eval_split.name] = SplitEntry(name=eval_split.name, n=eval_split.n,
                                               per_class=eval_split.per_class_boxes(), seed=seed,
                                               indices_sha256=ds.indices_sha256(eval_split.indices), file=eval_file)
    entry.preprocessing = {
        **entry.preprocessing,
        "image_size": image_size, "layout": "uint8 NCHW RGB; boxes xyxy in pixels at image_size",
        "split": f"seeded stratified holdout by primary class, seed {seed} (the subset has no official split)",
        "per_class": "SplitEntry.per_class counts ground-truth boxes per class, not images",
        "eval_slice": f"{EVAL_SLICE_NAME} packs x, boxes, labels, offsets, indices and class_names "
                      "(redsim.ml.datasets.military_assets.save_detection_npz)",
    }

    metrics = dict(result.metrics)
    recall = metrics.get("recall")
    n_gt = metrics.get("n_gt_boxes")
    if recall is None or not n_gt:
        raise SliceUnavailable("the detection evaluation split has no ground-truth boxes; recall is undefined and "
                               "the model entry would record no clean accuracy")
    init_note = str(result.training.get("backbone_init", "random (seeded)"))
    model = ModelEntry(
        id=model_id, name=name or BUILD_MODEL_NAMES.get(model_id, model_id), modality="detection",
        format="torch_state_dict", sha256=weights.sha256, size_bytes=weights.size_bytes, file=weights,
        architecture_id=str(result.architecture["architecture_id"]), architecture=dict(result.architecture),
        input_shape=[3, image_size, image_size], n_classes=len(class_names), class_names=class_names,
        dataset_id=entry.id, dataset_revision=entry.revision, dataset_split=eval_split.name, train_split=train.name,
        clean_accuracy=CleanAccuracy(value=float(recall), n=int(n_gt), split=eval_split.name), gradients=True,
        license=entry.license, source_url=entry.url,
        seed=seed, epochs=epochs, training=result.training, metrics=metrics,
        detection=_detection_spec(result.detection, class_names=class_names, image_size=image_size,
                                  excluded_classes=list(train.excluded_classes)),
        library_versions=library_versions(("torch", "torchvision", "numpy")),
        fixture_only=entry.fixture_only,
        notes=[("clean_accuracy is recall at IoU >= 0.5 over the evaluation split's ground-truth boxes (n counts "
                "boxes), measured at build time; it is not a classification accuracy. metrics carries map50, "
                "n_matched, n_predictions and the per-class counts."),
               "Input contract: float32 [0, 1] NCHW at input_shape (uint8 slices are scaled at load); predictions "
               "are xyxy boxes in pixels with 0-based labels into class_names.",
               f"Initialisation: {init_note}."],
    )
    model = stamp_manifest_sha256(with_dataset_caveats(model, entry))
    map50 = metrics.get("map50")
    map_s = f"{float(map50):.4f}" if map50 is not None else "n/a"
    log(f"{model_id}: recall@0.5 {float(recall):.4f} over n={int(n_gt)} boxes, mAP@0.5 {map_s}, "
        f"weights sha256 {model.sha256[:12]}..., {len(entry.caveats)} dataset caveat(s)")
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


def resolve_sms_table(opts: BuildOptions, client: httpx.Client, log: Log, warn: Log) -> Any:
    """The ``SmsSpamTable`` the text build trains on: the UCI corpus, else the committed CI sample.

    ``ds.fetch_sms_spam`` reuses a cached corpus whose digest still matches without a request and otherwise
    downloads the pinned zip; the rows are read with ``redsim.ml.datasets.sms_spam.load_sms_spam`` against
    the pinned digest. When neither is possible (offline, a digest that no longer matches) the build falls
    back to ``tests/ml/fixtures/sms_spam_sample.tsv`` exactly as the tabular build falls back to its committed
    sample: the model is then ``fixture_only`` and carries ``FIXTURE_ONLY_CAVEAT``, never a demo target. The
    committed sample is in the ``write_sms_tsv`` layout (``index``, ``label``, ``text``; the index cites the
    corpus row) and is read with ``ds.read_sms_tsv``; the corpus itself is ``<label>\t<text>``. Nothing is
    faked: the warning names the reason and the entry names the file it was trained on.
    """
    from redsim.ml.datasets import sms_spam

    assert opts.cache_dir is not None
    try:
        corpus = ds.fetch_sms_spam(client, opts.cache_dir, log=log)
        return sms_spam.load_sms_spam(corpus, expected_sha256=ds.SMS_SPAM_FILE_SHA256)
    except (ds.DatasetUnavailable, SliceUnavailable, httpx.HTTPError) as exc:
        warn(f"sms_spam: the UCI SMS Spam Collection is not available ({type(exc).__name__}: {exc}); falling back to "
             "the committed CI sample. The text model of this build is fixture-only, never a demo target.")
    sample = ds.committed_sms_sample_path()
    if sample is None:
        raise ds.DatasetUnavailable("the UCI SMS corpus could not be fetched and the committed sample "
                                    f"tests/ml/fixtures/{ds.SMS_SAMPLE_NAME} is not present in this installation; "
                                    "run from a source checkout or retry with network access")
    _indices, texts, label_names = ds.read_sms_tsv(sample)      # (source_indices, texts, labels)
    return sms_spam.SmsSpamTable(texts=list(texts), labels=sms_spam.encode_labels(label_names),
                                 label_names=list(label_names), source_path=sample, source_sha256=sha256_file(sample),
                                 fixture_only=True)


def resolve_detection_subset_root(opts: BuildOptions) -> Path:
    """Where the published military-assets subset sits: ``opts.detection_subset``, else the cache, else ``<out>``.

    Raises ``DatasetUnavailable`` naming every location looked at when no ``manifest.json`` is found, so a
    detection build refuses before anything is trained rather than after the other selections.
    """
    assert opts.cache_dir is not None
    candidates: list[Path] = []
    if opts.detection_subset is not None:
        candidates.append(Path(opts.detection_subset))
    else:
        for candidate in (Path(opts.cache_dir) / ds.MILITARY_ASSETS_SUBSET_NAME, ds.detection_subset_root(opts.out)):
            if candidate not in candidates:         # the default cache is <out>/cache: one location, named once
                candidates.append(candidate)
    for candidate in candidates:
        if (candidate / ds.MILITARY_ASSETS_SUBSET_MANIFEST).is_file():
            return candidate
    looked = ", ".join(str(c / ds.MILITARY_ASSETS_SUBSET_MANIFEST) for c in candidates)
    raise ds.DatasetUnavailable(f"no published detection subset: looked for {looked}. The capped subset of "
                                f"{ds.MILITARY_ASSETS_SLUG} (MODALITIES-27) is written by the B0 datasets step with a "
                                "Kaggle token; pass --detection-subset to name where it lives")


def resolve_detection_data(opts: BuildOptions, log: Log) -> tuple[Any, Any, DatasetEntry]:
    """``(train, eval, dataset entry)`` for the detector build from the published subset (no network)."""
    subset_root = resolve_detection_subset_root(opts)
    log(f"detection: reading the published subset at {subset_root} (image_size={opts.detection_image_size})")
    subset = ds.load_detection_subset(subset_root, image_size=opts.detection_image_size)
    train, evaluation = ds.detection_holdout(subset.split, holdout=opts.holdout, seed=opts.seed)
    entry = ds.military_assets_dataset_entry(subset.manifest, index_sha256=subset.manifest_sha256)
    log(f"detection: {subset.split.n} images / {subset.split.n_boxes} boxes verified against manifest.json "
        f"(sha256 {subset.manifest_sha256[:12]}...); holdout {opts.holdout} -> train {train.n}, eval {evaluation.n}")
    return train, evaluation, entry


def build_assets(opts: BuildOptions, log: Log = print, warn: Log | None = None) -> AssetManifest:
    """Run the selected builds and write ``<out>/MANIFEST.json``.

    The manifest is read back right before it is written and only the entries
    this run built are replaced, so re-runs and two builds into the same root
    (say ``--dataset image`` beside ``--dataset tabular``) keep each other's
    entries. A legacy entry (``url_classifier``) is dropped once its current id
    (``url_trees``) has been built. ``opts.attach_train_slice`` records the
    named models' out-of-band training slices in the manifest after the builds
    (``attach_train_slice``; no training). With ``opts.fixture`` the committed
    CIFAR-10 slice is written afterwards from local files only. A detection
    selection checks that the published subset is present before any model is
    trained.
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
    if "detection" in selected:
        resolve_detection_subset_root(opts)      # refuse now, before hours of CPU go into the other selections
    slice_options = opts.train_slice_options
    client = ds.make_client() if selected & {"image", "cifar10", "text"} else None
    try:
        if "image" in selected and client is not None:
            data = ds.fetch_imagefolder(client, opts.cache_dir, opts.image_repo, split_dirs=ds.VEHICLES_SPLIT_DIRS,
                                        revision=opts.image_revision, image_size=opts.image_size,
                                        max_train=opts.max_train, max_eval=opts.max_eval, seed=opts.seed,
                                        workers=opts.workers, log=log, license_note=VEHICLES_LICENSE_NOTE,
                                        notes=VEHICLES_NOTES)
            entry, model = build_cnn_asset(data, model_id=BUILD_MODEL_IDS["image"], root=root, epochs=opts.epochs,
                                           seed=opts.seed, arch=opts.arch, notes=cap_notes, train_slice=slice_options,
                                           log=log)
            built_datasets[entry.id] = entry
            built_models[model.id] = model
            built.append(model.id)
        if "cifar10" in selected and client is not None:
            data = ds.fetch_cifar10(client, opts.cache_dir, revision=opts.cifar10_revision, max_train=opts.max_train,
                                    max_eval=opts.max_eval, seed=opts.seed, log=log)
            entry, model = build_cnn_asset(data, model_id=BUILD_MODEL_IDS["cifar10"], root=root, epochs=opts.epochs,
                                           seed=opts.seed, arch=opts.arch, fixture_only=True, notes=cap_notes,
                                           train_slice=slice_options, log=log)
            built_datasets[entry.id] = entry
            built_models[model.id] = model
            built.append(model.id)
        if "tabular" in selected:
            table = resolve_url_table(opts, log, warn)
            entry, model = build_url_asset(table, model_id=BUILD_MODEL_IDS["tabular"], root=root, seed=opts.seed,
                                           holdout=opts.holdout, prefer_xgboost=opts.prefer_xgboost, log=log)
            built_datasets[entry.id] = entry
            built_models[model.id] = model
            built.append(model.id)
        if "text" in selected and client is not None:
            from redsim.ml.assets.train_text_classifier import build_text_asset

            table = resolve_sms_table(opts, client, log, warn)
            entry, model = build_text_asset(root, table=table, model_id=BUILD_MODEL_IDS["text"], seed=opts.seed,
                                            holdout=opts.holdout, log=log)
            built_datasets[entry.id] = entry
            built_models[model.id] = model
            built.append(model.id)
        if "detection" in selected:
            train, evaluation, dataset = resolve_detection_data(opts, log)
            entry, model = build_detection_asset(train, evaluation, dataset, model_id=BUILD_MODEL_IDS["detection"],
                                                 root=root, epochs=opts.epochs, seed=opts.seed, notes=cap_notes,
                                                 log=log)
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
    attached: list[str] = []
    for model_id in opts.attach_train_slice:
        split = attach_train_slice(manifest, root, model_id, log=log)
        attached.append(f"{model_id} ({split.name})")
    if built or attached:
        manifest.touch()
        write_manifest(manifest, manifest_path)
        what = []
        if built:
            what.append(f"{len(built)} model(s) built: {', '.join(built)}")
        if attached:
            what.append(f"training slice(s) recorded: {', '.join(attached)}")
        log(f"wrote {manifest_path} ({'; '.join(what)})")
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
        acc_label = "recall@0.5 over boxes" if model.modality == "detection" else "clean accuracy"
        acc_s = f"{acc.value:.4f} (n={acc.n}, {acc.split})" if acc is not None else "n/a"
        flag = "  [fixture only]" if model.fixture_only else ""
        caveats = f", {len(model.dataset_caveats)} dataset caveat(s)" if model.dataset_caveats else ""
        train_slice = f", train slice {model.train_slice_split}" if model.train_slice_split else ""
        lines.append(f"  {model.id}: {model.format} ({model.architecture_id}, {model.modality}) on "
                     f"{model.dataset_id}@{rev}, {acc_label} {acc_s}, sha256 {model.sha256[:12]}..."
                     f"{caveats}{train_slice}{flag}")
    return "\n".join(lines)
