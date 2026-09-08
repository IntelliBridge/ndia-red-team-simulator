"""Dataset fetchers for ``redsim ml build-assets`` (spec section 11).

Every fetch pins what it got: the HuggingFace commit sha for hub datasets and
the sha256 of ``malicious_phish.csv`` for the Kaggle tabular dataset. Nothing
here runs outside the asset build; the worker and the tests never import the
network paths. ``huggingface_hub`` and ``datasets`` are not dependencies: the
hub is spoken to with ``httpx`` through its public API and ``resolve`` URLs,
and CIFAR-10 comes from the ``uoft-cs/cifar10`` parquet files, never from
torchvision's Toronto mirror (unreachable through the corporate proxy).
"""

from __future__ import annotations

import csv
import hashlib
import io
import os
import zipfile
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import numpy as np

from redsim.ml.assets.manifest import (
    DatasetEntry,
    FileEntry,
    SplitEntry,
    redsim_version,
    sha256_file,
)

HF_API_DATASET = "https://huggingface.co/api/datasets/{repo}"
HF_RESOLVE = "https://huggingface.co/datasets/{repo}/resolve/{revision}/{path}"
KAGGLE_DOWNLOAD = "https://www.kaggle.com/api/v1/datasets/download/{slug}"
KAGGLE_VIEW = "https://www.kaggle.com/api/v1/datasets/view/{slug}"

CIFAR10_REPO = "uoft-cs/cifar10"
CIFAR10_FILES = {"train": "plain_text/train-00000-of-00001.parquet",
                 "test": "plain_text/test-00000-of-00001.parquet"}
CIFAR10_CLASS_NAMES = ["airplane", "automobile", "bird", "cat", "deer", "dog", "frog", "horse", "ship", "truck"]

VEHICLES_REPO = "leibnitz-lab/military_vehicles"
VEHICLES_SPLIT_DIRS = {"train": "train_coarse", "test": "test_coarse"}

MALICIOUS_URLS_SLUG = "sid321axn/malicious-urls-dataset"
MALICIOUS_URLS_FILE = "malicious_phish.csv"
URL_CLASS_NAMES = ["benign", "defacement", "phishing", "malware"]
URL_LICENSE = "CC0: Public Domain"
URL_LICENSE_NOTE = ("Kaggle metadata API licenseName; the uploader's statement over the compilation. "
                    "Upstream feeds (ISCX-URL-2016, PhishTank, Malware Domain Blacklist, faizann24) carry "
                    "their own terms and are never re-fetched (spec 11.5).")

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}

Log = Callable[[str], None]


class DatasetUnavailable(RuntimeError):
    """A dataset could not be fetched or fails its integrity check."""


# ---------------------------------------------------------------------------
# Shared containers
# ---------------------------------------------------------------------------

@dataclass
class ImageSplit:
    """One split as uint8 NCHW pixels; ``indices`` index the source split."""

    name: str
    x: np.ndarray
    y: np.ndarray
    indices: np.ndarray
    class_names: list[str]

    @property
    def n(self) -> int:
        return int(self.x.shape[0])

    def per_class(self) -> dict[str, int]:
        counts = np.bincount(self.y, minlength=len(self.class_names))
        return {name: int(counts[i]) for i, name in enumerate(self.class_names)}


@dataclass
class ImageDataset:
    dataset: DatasetEntry
    train: ImageSplit
    eval: ImageSplit


@dataclass
class HubDatasetInfo:
    repo_id: str
    sha: str
    license: str | None
    files: list[str] = field(default_factory=list)

    @property
    def dataset_id(self) -> str:
        return f"hf:{self.repo_id}"

    @property
    def url(self) -> str:
        return f"https://huggingface.co/datasets/{self.repo_id}"


# ---------------------------------------------------------------------------
# Seeded, stratified selection
# ---------------------------------------------------------------------------

def stratified_indices(y: np.ndarray, n: int, seed: int) -> np.ndarray:
    """Seeded stratified subset of size ``min(n, len(y))``.

    Equal allocation per class; when a class is exhausted the remainder is
    redistributed proportionally over the classes that still have members
    (spec section 11.5). Returned sorted for stable downstream order.
    """
    y = np.asarray(y)
    total = int(y.shape[0])
    if n >= total:
        return np.arange(total, dtype=np.int64)
    rng = np.random.default_rng(seed)
    classes = np.unique(y)
    pools = {int(c): rng.permutation(np.flatnonzero(y == c)) for c in classes}
    take = {c: 0 for c in pools}
    remaining = n
    while remaining > 0:
        open_classes = [c for c in pools if take[c] < len(pools[c])]
        if not open_classes:
            break
        share = max(remaining // len(open_classes), 1)
        for c in open_classes:
            if remaining <= 0:
                break
            room = len(pools[c]) - take[c]
            grab = min(share, room, remaining)
            take[c] += grab
            remaining -= grab
    chosen = np.concatenate([pools[c][: take[c]] for c in pools])
    return np.sort(chosen.astype(np.int64))


def stratified_split(y: np.ndarray | Sequence[int], holdout: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Seeded stratified ``(train_idx, eval_idx)`` for data without an official split."""
    if not 0.0 < holdout < 1.0:
        raise ValueError("holdout must be in (0, 1)")
    y_arr = np.asarray(y)
    rng = np.random.default_rng(seed)
    train_parts: list[np.ndarray] = []
    eval_parts: list[np.ndarray] = []
    for c in np.unique(y_arr):
        members = rng.permutation(np.flatnonzero(y_arr == c))
        n_eval = round(len(members) * holdout)
        if len(members) >= 2:
            n_eval = min(max(n_eval, 1), len(members) - 1)
        else:
            n_eval = 0
        eval_parts.append(members[:n_eval])
        train_parts.append(members[n_eval:])
    train_idx = np.sort(np.concatenate(train_parts).astype(np.int64))
    eval_idx = np.sort(np.concatenate(eval_parts).astype(np.int64))
    return train_idx, eval_idx


def indices_sha256(indices: np.ndarray) -> str:
    return hashlib.sha256(np.ascontiguousarray(np.asarray(indices, dtype=np.int64)).tobytes()).hexdigest()


def split_entry(split: ImageSplit, *, seed: int | None = None, file: FileEntry | None = None) -> SplitEntry:
    return SplitEntry(name=split.name, n=split.n, per_class=split.per_class(), seed=seed,
                      indices_sha256=indices_sha256(split.indices), file=file)


# ---------------------------------------------------------------------------
# HTTP client and HuggingFace hub
# ---------------------------------------------------------------------------

def make_client(timeout: float = 120.0) -> httpx.Client:
    """An httpx client for the build. ``HF_TOKEN`` is honoured when present (never logged)."""
    headers = {"User-Agent": f"redsim-build-assets/{redsim_version()}"}
    token = os.environ.get("HF_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(timeout=timeout, follow_redirects=True, headers=headers)


def _license_string(card: Any) -> str | None:
    if not isinstance(card, dict):
        return None
    value = card.get("license")
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def resolve_hub_dataset(client: httpx.Client, repo_id: str, revision: str = "main") -> HubDatasetInfo:
    """Resolve ``revision`` to a commit sha and list the repo's files."""
    url = HF_API_DATASET.format(repo=repo_id)
    resp = client.get(url, params={"revision": revision} if revision != "main" else None)
    if resp.status_code != 200:
        raise DatasetUnavailable(f"hub API {url} returned HTTP {resp.status_code}")
    data = resp.json()
    sha = data.get("sha")
    if not sha:
        raise DatasetUnavailable(f"hub API response for {repo_id} carries no commit sha")
    files = [s["rfilename"] for s in data.get("siblings", []) if "rfilename" in s]
    return HubDatasetInfo(repo_id=repo_id, sha=str(sha), license=_license_string(data.get("cardData")), files=files)


def repo_cache_dir(cache_dir: Path, repo_id: str, sha: str) -> Path:
    return Path(cache_dir) / f"hf--{repo_id.replace('/', '--')}" / sha


def download_hub_file(client: httpx.Client, repo_id: str, sha: str, rfilename: str, dest: Path) -> Path:
    """Stream one repo file at a pinned sha to ``dest`` (skipped when already cached)."""
    dest = Path(dest)
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = HF_RESOLVE.format(repo=repo_id, revision=sha, path=httpx.URL(rfilename).path)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with client.stream("GET", url) as resp:
        if resp.status_code != 200:
            raise DatasetUnavailable(f"{url} returned HTTP {resp.status_code}")
        with open(tmp, "wb") as fh:
            fh.writelines(resp.iter_bytes(1 << 20))
    os.replace(tmp, dest)
    return dest


def hub_dataset_entry(info: HubDatasetInfo, files: Iterable[FileEntry] = (), *, license_note: str | None = None,
                      class_names: Sequence[str] = (), fixture_only: bool = False, notes: Sequence[str] = ()) -> DatasetEntry:
    file_list = list(files)
    return DatasetEntry(
        id=info.dataset_id, source="huggingface", revision=info.sha, url=info.url, license=info.license,
        license_note=license_note, class_names=list(class_names), source_files=file_list,
        size_bytes=sum(f.size_bytes for f in file_list) or None, fixture_only=fixture_only, notes=list(notes),
    )


# ---------------------------------------------------------------------------
# Image preprocessing
# ---------------------------------------------------------------------------

def preprocess_image(img: Any, image_size: int) -> np.ndarray:
    """Resize the shorter side to ``image_size``, center-crop square, return uint8 CHW.

    No mean / std normalisation here: that lives inside the model (spec 11.3.1).
    """
    from PIL import Image

    rgb = img.convert("RGB")
    w, h = rgb.size
    scale = image_size / min(w, h)
    new_w, new_h = max(image_size, round(w * scale)), max(image_size, round(h * scale))
    if (new_w, new_h) != (w, h):
        rgb = rgb.resize((new_w, new_h), Image.Resampling.BILINEAR)
    left = (new_w - image_size) // 2
    top = (new_h - image_size) // 2
    rgb = rgb.crop((left, top, left + image_size, top + image_size))
    arr = np.asarray(rgb, dtype=np.uint8)
    return np.ascontiguousarray(arr.transpose(2, 0, 1))


def _subsample(split: ImageSplit, limit: int | None, seed: int) -> ImageSplit:
    if limit is None or limit >= split.n:
        return split
    keep = stratified_indices(split.y, limit, seed)
    return ImageSplit(name=split.name, x=split.x[keep], y=split.y[keep],
                      indices=split.indices[keep], class_names=split.class_names)


# ---------------------------------------------------------------------------
# CIFAR-10 from the uoft-cs/cifar10 parquet files (CI fixture, spec 11.3.5)
# ---------------------------------------------------------------------------

def _decode_parquet_images(path: Path, image_size: int | None) -> tuple[np.ndarray, np.ndarray]:
    import pyarrow.parquet as pq
    from PIL import Image

    table = pq.read_table(path, columns=["img", "label"])
    imgs = table.column("img").to_pylist()
    labels = np.asarray(table.column("label").to_pylist(), dtype=np.int64)
    out: list[np.ndarray] = []
    for item in imgs:
        raw = item["bytes"] if isinstance(item, dict) else item
        with Image.open(io.BytesIO(raw)) as im:
            if image_size is None:
                arr = np.asarray(im.convert("RGB"), dtype=np.uint8).transpose(2, 0, 1)
                out.append(np.ascontiguousarray(arr))
            else:
                out.append(preprocess_image(im, image_size))
    return np.stack(out), labels


def fetch_cifar10(client: httpx.Client, cache_dir: Path, *, revision: str = "main", max_train: int | None = None,
                  max_eval: int | None = None, seed: int = 0, log: Log = print) -> ImageDataset:
    info = resolve_hub_dataset(client, CIFAR10_REPO, revision)
    log(f"cifar10: {info.repo_id} @ {info.sha[:12]} (license {info.license})")
    root = repo_cache_dir(cache_dir, info.repo_id, info.sha)
    files: list[FileEntry] = []
    splits: dict[str, ImageSplit] = {}
    for split_name, rfilename in CIFAR10_FILES.items():
        dest = download_hub_file(client, info.repo_id, info.sha, rfilename, root / rfilename)
        files.append(FileEntry(path=rfilename, sha256=sha256_file(dest), size_bytes=dest.stat().st_size))
        x, y = _decode_parquet_images(dest, None)
        splits[split_name] = ImageSplit(name=split_name, x=x, y=y, indices=np.arange(len(y), dtype=np.int64),
                                        class_names=list(CIFAR10_CLASS_NAMES))
        log(f"cifar10: {split_name} split decoded, n={len(y)}")
    entry = hub_dataset_entry(
        info, files, class_names=CIFAR10_CLASS_NAMES, fixture_only=True,
        license_note="No formal license statement exists for CIFAR-10; test fixture only, never presented as results.",
        notes=["CI / fixture image dataset (spec 11.3.5). Never a demo target.",
               "Fetched from the HuggingFace parquet mirror, not torchvision's Toronto host."],
    )
    entry.preprocessing = {"resolution": 32, "channel_order": "RGB", "layout": "NCHW", "value_range": "[0, 1] float32 at use",
                           "normalization": "inside the model (buffers)"}
    return ImageDataset(dataset=entry, train=_subsample(splits["train"], max_train, seed),
                        eval=_subsample(splits["test"], max_eval, seed))


# ---------------------------------------------------------------------------
# imagefolder layouts on the hub (leibnitz-lab/military_vehicles, spec 11.3.1)
# ---------------------------------------------------------------------------

def _imagefolder_listing(info: HubDatasetInfo, split_dir: str) -> tuple[list[str], list[str]]:
    """Return (files, class_of_file) for one ``<split_dir>/<class>/<file>`` directory."""
    prefix = split_dir.rstrip("/") + "/"
    files: list[str] = []
    classes: list[str] = []
    for path in sorted(info.files):
        if not path.startswith(prefix):
            continue
        parts = path.split("/")
        if len(parts) != 3 or Path(parts[2]).suffix.lower() not in IMAGE_EXTENSIONS:
            continue
        files.append(path)
        classes.append(parts[1])
    return files, classes


def fetch_imagefolder(client: httpx.Client, cache_dir: Path, repo_id: str, *, split_dirs: dict[str, str],
                      revision: str = "main", image_size: int = 128, max_train: int | None = None,
                      max_eval: int | None = None, seed: int = 0, workers: int = 8, log: Log = print,
                      license_note: str | None = None, notes: Sequence[str] = ()) -> ImageDataset:
    """Fetch an imagefolder dataset (``<split>/<class>/<image>``) at a pinned sha and preprocess it."""
    from PIL import Image

    info = resolve_hub_dataset(client, repo_id, revision)
    log(f"{repo_id}: @ {info.sha[:12]} (license {info.license}), {len(info.files)} files in repo")
    root = repo_cache_dir(cache_dir, info.repo_id, info.sha)

    listings = {name: _imagefolder_listing(info, d) for name, d in split_dirs.items()}
    class_names = sorted({c for _, classes in listings.values() for c in classes})
    if not class_names:
        raise DatasetUnavailable(f"{repo_id}: no images found under {sorted(split_dirs.values())}")
    class_index = {c: i for i, c in enumerate(class_names)}

    def _get(rfilename: str) -> Path:
        return download_hub_file(client, info.repo_id, info.sha, rfilename, root / rfilename)

    splits: dict[str, ImageSplit] = {}
    for split_name, (files, classes) in listings.items():
        if not files:
            raise DatasetUnavailable(f"{repo_id}: split directory {split_dirs[split_name]!r} is empty")
        indices = np.arange(len(files), dtype=np.int64)
        y = np.asarray([class_index[c] for c in classes], dtype=np.int64)
        limit = max_train if split_name == "train" else max_eval
        if limit is not None and limit < len(files):
            indices = stratified_indices(y, limit, seed)
        log(f"{repo_id}: fetching {len(indices)} of {len(files)} images for split {split_name!r}")
        selected = [files[i] for i in indices]
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            paths = list(pool.map(_get, selected))
        pixels = np.empty((len(paths), 3, image_size, image_size), dtype=np.uint8)
        for k, path in enumerate(paths):
            with Image.open(path) as im:
                pixels[k] = preprocess_image(im, image_size)
        splits[split_name] = ImageSplit(name=split_dirs[split_name], x=pixels, y=y[indices], indices=indices,
                                        class_names=class_names)

    entry = hub_dataset_entry(info, class_names=class_names, license_note=license_note, notes=notes)
    entry.preprocessing = {"resize": "shorter side to resolution, then center crop", "resolution": image_size,
                           "channel_order": "RGB", "layout": "NCHW", "value_range": "[0, 1] float32 at use",
                           "normalization": "inside the model (buffers)", "split_dirs": dict(split_dirs)}
    return ImageDataset(dataset=entry, train=splits["train"], eval=splits["eval"] if "eval" in splits else splits["test"])


# ---------------------------------------------------------------------------
# Kaggle malicious-URLs dataset (spec 11.3.3) and the committed sample
# ---------------------------------------------------------------------------

@dataclass
class UrlTable:
    urls: list[str]
    labels: list[str]
    dataset: DatasetEntry
    source_path: Path


def kaggle_credentials() -> tuple[str, str] | None:
    user = os.environ.get("KAGGLE_USERNAME", "").strip()
    key = os.environ.get("KAGGLE_KEY", "").strip()
    if user and key:
        return user, key
    return None


def kaggle_missing_message() -> str:
    return ("KAGGLE_USERNAME / KAGGLE_KEY are not set, so the full malicious-URLs dataset "
            f"({MALICIOUS_URLS_SLUG}, {MALICIOUS_URLS_FILE}) was not downloaded. Falling back to the committed "
            "CI sample tests/ml/fixtures/malicious_urls_sample.csv. Export a Kaggle API token for this one-off "
            "run to build the demo tabular asset (spec 11.3.3, 20.3).")


def fetch_kaggle_malicious_urls(cache_dir: Path, *, timeout: float = 300.0, log: Log = print) -> Path | None:
    """Download ``malicious_phish.csv`` with the operator's Kaggle token; ``None`` when no token is set.

    The token is read from the environment for this call only and never logged
    or written anywhere.
    """
    creds = kaggle_credentials()
    if creds is None:
        return None
    dest_dir = Path(cache_dir) / f"kaggle--{MALICIOUS_URLS_SLUG.replace('/', '--')}"
    dest = dest_dir / MALICIOUS_URLS_FILE
    if dest.exists() and dest.stat().st_size > 0:
        log(f"kaggle: using cached {dest}")
        return dest
    dest_dir.mkdir(parents=True, exist_ok=True)
    url = KAGGLE_DOWNLOAD.format(slug=MALICIOUS_URLS_SLUG)
    log(f"kaggle: downloading {MALICIOUS_URLS_SLUG} (authenticated)")
    archive = dest_dir / "download.bin"
    headers = {"User-Agent": f"redsim-build-assets/{redsim_version()}"}
    with (httpx.Client(timeout=timeout, follow_redirects=True, auth=creds, headers=headers) as client,
          client.stream("GET", url) as resp):
        if resp.status_code != 200:
            raise DatasetUnavailable(f"Kaggle download returned HTTP {resp.status_code} for {MALICIOUS_URLS_SLUG}")
        with open(archive, "wb") as fh:
            fh.writelines(resp.iter_bytes(1 << 20))
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            names = zf.namelist()
            member = next((n for n in names if n.endswith(MALICIOUS_URLS_FILE)), None)
            if member is None:
                raise DatasetUnavailable(f"Kaggle archive holds {names}, not {MALICIOUS_URLS_FILE}")
            with zf.open(member) as src, open(dest, "wb") as out:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
        archive.unlink()
    else:
        os.replace(archive, dest)
    return dest


def load_url_csv(path: Path) -> tuple[list[str], list[str]]:
    """Read ``url,type`` rows; labels are lower-cased, blank rows skipped."""
    urls: list[str] = []
    labels: list[str] = []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or "url" not in reader.fieldnames or "type" not in reader.fieldnames:
            raise DatasetUnavailable(f"{path}: expected columns url,type, found {reader.fieldnames}")
        for row in reader:
            url = (row.get("url") or "").strip()
            label = (row.get("type") or "").strip().lower()
            if not url or not label:
                continue
            urls.append(url)
            labels.append(label)
    return urls, labels


def dedupe_urls(urls: Sequence[str], labels: Sequence[str]) -> tuple[list[str], list[str], int]:
    """Drop exact-duplicate URL strings, keeping the first occurrence; returns the removed count."""
    seen: set[str] = set()
    out_u: list[str] = []
    out_l: list[str] = []
    for u, label in zip(urls, labels, strict=True):
        if u in seen:
            continue
        seen.add(u)
        out_u.append(u)
        out_l.append(label)
    return out_u, out_l, len(urls) - len(out_u)


def committed_sample_path() -> Path | None:
    """The CI sample committed with the repository, when this is a source checkout."""
    candidate = Path(__file__).resolve().parents[3] / "tests" / "ml" / "fixtures" / "malicious_urls_sample.csv"
    return candidate if candidate.exists() else None


def kaggle_url_table(csv_path: Path) -> UrlTable:
    urls, labels = load_url_csv(csv_path)
    digest = sha256_file(csv_path)
    entry = DatasetEntry(
        id=f"kaggle:{MALICIOUS_URLS_SLUG}", source="kaggle", revision=digest,
        url=f"https://www.kaggle.com/datasets/{MALICIOUS_URLS_SLUG}", license=URL_LICENSE, license_note=URL_LICENSE_NOTE,
        class_names=list(URL_CLASS_NAMES),
        source_files=[FileEntry(path=MALICIOUS_URLS_FILE, sha256=digest, size_bytes=csv_path.stat().st_size)],
        size_bytes=csv_path.stat().st_size,
        notes=["Demo tabular dataset (spec 11.3.3). URL strings are data: never fetched, resolved or rendered."],
    )
    return UrlTable(urls=urls, labels=labels, dataset=entry, source_path=csv_path)


def sample_url_table(csv_path: Path) -> UrlTable:
    urls, labels = load_url_csv(csv_path)
    digest = sha256_file(csv_path)
    entry = DatasetEntry(
        id="local:tests/ml/fixtures/malicious_urls_sample.csv", source="local", revision=digest,
        license=URL_LICENSE, license_note="Synthetic CI sample shaped like the Kaggle file; not the Kaggle data.",
        class_names=list(URL_CLASS_NAMES),
        source_files=[FileEntry(path=csv_path.name, sha256=digest, size_bytes=csv_path.stat().st_size)],
        size_bytes=csv_path.stat().st_size, fixture_only=True,
        notes=["CI fixture only (spec 11.1): never a demo target, never evidence.",
               kaggle_missing_message()],
    )
    return UrlTable(urls=urls, labels=labels, dataset=entry, source_path=csv_path)
