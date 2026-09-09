"""Dataset fetchers for ``redsim ml build-assets`` (spec section 11).

Every fetch pins what it got: the HuggingFace commit sha for hub datasets and
the sha256 of ``malicious_phish.csv`` (plus the zip it came in) for the Kaggle
tabular dataset. Nothing
here runs outside the asset build; the worker and the tests never import the
network paths. ``huggingface_hub`` and ``datasets`` are not dependencies: the
hub is spoken to with ``httpx`` through its public API and ``resolve`` URLs,
and CIFAR-10 comes from the ``uoft-cs/cifar10`` parquet files, never from
torchvision's Toronto mirror (unreachable through the corporate proxy).

Phase B (plan 12, wave B0 ``datasets`` track) adds, each behind a pinned digest
and with its licence recorded next to the bytes:

* the UCI SMS Spam Collection for the text modality (MODALITIES-11 / -12);
* WordNet 3.0 from ``nltk/nltk_data`` for the word-substitution attack
  (cached under ``<cache>/wordnet``, never republished);
* the capped, seeded detection subset of the Kaggle military-assets set
  (MODALITIES-27, person and weapon classes excluded at selection time);
* the bundled training slice writer for the image dataset (ATTACKS_HARDEN-11);
* the public data repository index mapping every dataset the code names to
  its ``INDEX.csv`` row (TESTS_DOCS-35), so tests can check the snapshot
  ``tests/ml/fixtures/public_index.csv`` offline.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import random
import shutil
import time
import zipfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast, get_args
from urllib.parse import quote

import httpx
import numpy as np
from pydantic import BaseModel, ConfigDict

from redsim.llm.pythia import env_file_path, resolve_env
from redsim.ml.assets.manifest import (
    DatasetEntry,
    DatasetSource,
    FileEntry,
    SplitEntry,
    file_entry,
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


RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
HUB_RETRIES = 8
MAX_RETRY_DELAY_S = 120.0


def retry_delay(retry_after: str | None, attempt: int, *, rng: random.Random | None = None) -> float:
    """Seconds to wait before retry ``attempt`` (0-based): ``Retry-After`` when given, else capped exponential backoff."""
    if retry_after:
        try:
            return min(max(float(retry_after), 0.0), MAX_RETRY_DELAY_S)
        except ValueError:
            pass
    base = min(2.0 ** attempt, MAX_RETRY_DELAY_S)
    return base + (rng or random).uniform(0.0, base / 2)


def download_hub_file(client: httpx.Client, repo_id: str, sha: str, rfilename: str, dest: Path, *,
                      retries: int = HUB_RETRIES, sleep: Callable[[float], None] = time.sleep) -> Path:
    """Stream one repo file at a pinned sha to ``dest`` (skipped when already cached).

    The hub rate-limits anonymous ``resolve`` requests; a 429 (or a 5xx) is
    retried with the server's ``Retry-After`` or exponential backoff, up to
    ``retries`` times, before ``DatasetUnavailable`` is raised.
    """
    dest = Path(dest)
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = HF_RESOLVE.format(repo=repo_id, revision=sha, path=httpx.URL(rfilename).path)
    tmp = dest.with_suffix(dest.suffix + ".part")
    for attempt in range(retries + 1):
        with client.stream("GET", url) as resp:
            if resp.status_code == 200:
                with open(tmp, "wb") as fh:
                    fh.writelines(resp.iter_bytes(1 << 20))
                os.replace(tmp, dest)
                return dest
            status = resp.status_code
            retry_after = resp.headers.get("retry-after")
        if status in RETRYABLE_STATUS and attempt < retries:
            sleep(retry_delay(retry_after, attempt))
            continue
        raise DatasetUnavailable(f"{url} returned HTTP {status}" + (f" after {attempt} retries" if attempt else ""))
    raise AssertionError("unreachable")


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

KAGGLE_TOKEN_ENV = "KAGGLE_API_TOKEN"       # what the current kaggle client reads; sent as a bearer token
KAGGLE_USERNAME_ENV = "KAGGLE_USERNAME"     # the older pair, sent as HTTP basic auth
KAGGLE_KEY_ENV = "KAGGLE_KEY"
KAGGLE_ARCHIVE_NAME = "malicious-urls-dataset.zip"
KAGGLE_DOWNLOAD_RECORD = "download.json"
FIXTURE_SIDECAR_NAME = "MANIFEST.json"
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


@dataclass
class UrlTable:
    urls: list[str]
    labels: list[str]
    dataset: DatasetEntry
    source_path: Path
    row_indices: list[int] = field(default_factory=list)   # 0-based data-row index of each row in source_path


@dataclass(frozen=True, repr=False)
class KaggleAuth:
    """Kaggle API credentials for one build run. ``repr`` and ``str`` never contain the secret."""

    kind: Literal["bearer", "basic"]
    source: str                     # the variable name and where it was read from, never the value
    secret: str = field(repr=False)
    username: str | None = None

    def headers(self) -> dict[str, str]:
        if self.kind == "bearer":
            return {"Authorization": f"Bearer {self.secret}"}
        raw = f"{self.username}:{self.secret}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}

    def __repr__(self) -> str:
        return f"KaggleAuth(kind={self.kind!r}, source={self.source!r})"

    __str__ = __repr__


def kaggle_credentials(environ: Mapping[str, str] | None = None) -> KaggleAuth | None:
    """Resolve the operator's Kaggle credentials for this call; ``None`` when there are none.

    ``KAGGLE_API_TOKEN`` wins and is sent as a bearer token. The older
    ``KAGGLE_USERNAME`` / ``KAGGLE_KEY`` pair is the basic-auth fallback. Both
    are read from the process environment first, then from the ``.env`` file
    ``redsim.llm.pythia`` discovers (``REDSIM_ENV_FILE``, else ``./.env``, else
    the repo-root ``.env``). The environment wins over the file. The values are
    never logged or written anywhere.
    """
    env = os.environ if environ is None else environ
    merged = resolve_env(env)
    env_file = env_file_path(env)

    def _source(name: str) -> str:
        if env.get(name, "").strip():
            return f"{name} in the environment"
        return f"{name} in {env_file}" if env_file is not None else f"{name} in a .env file"

    token = merged.get(KAGGLE_TOKEN_ENV, "").strip()
    if token:
        return KaggleAuth(kind="bearer", source=_source(KAGGLE_TOKEN_ENV), secret=token)
    username = merged.get(KAGGLE_USERNAME_ENV, "").strip()
    key = merged.get(KAGGLE_KEY_ENV, "").strip()
    if username and key:
        return KaggleAuth(kind="basic", source=_source(KAGGLE_KEY_ENV), secret=key, username=username)
    return None


def kaggle_missing_message() -> str:
    return (f"{KAGGLE_TOKEN_ENV} is not set (nor the older {KAGGLE_USERNAME_ENV} / {KAGGLE_KEY_ENV} pair), in the "
            f"environment or a .env file, so the full malicious-URLs dataset ({MALICIOUS_URLS_SLUG}, "
            f"{MALICIOUS_URLS_FILE}) was not downloaded. Falling back to the committed CI sample "
            "tests/ml/fixtures/malicious_urls_sample.csv. Export a Kaggle API token for this one-off run to build "
            "the demo tabular asset (spec 11.3.3, 20.3).")


@dataclass
class KaggleDownload:
    """One authenticated fetch, as recorded in ``download.json`` beside the extracted file."""

    slug: str
    url: str
    fetched_at: str
    auth_kind: str
    archive: FileEntry | None       # the zip as served; None when Kaggle answered with the bare CSV
    file: FileEntry                 # malicious_phish.csv; paths are relative to the download directory
    csv_path: Path

    def record(self) -> dict[str, Any]:
        return {"slug": self.slug, "url": self.url, "fetched_at": self.fetched_at, "auth_kind": self.auth_kind,
                "archive": self.archive.model_dump() if self.archive is not None else None,
                "file": self.file.model_dump()}


def kaggle_cache_dir(cache_dir: Path) -> Path:
    return Path(cache_dir) / f"kaggle--{MALICIOUS_URLS_SLUG.replace('/', '--')}"


def _cached_kaggle_download(dest_dir: Path) -> KaggleDownload | None:
    """The previous download, when its record is present and the CSV still hashes to what it says."""
    record_path = dest_dir / KAGGLE_DOWNLOAD_RECORD
    csv_path = dest_dir / MALICIOUS_URLS_FILE
    if not (record_path.is_file() and csv_path.is_file()):
        return None
    try:
        data = json.loads(record_path.read_text(encoding="utf-8"))
        file = FileEntry.model_validate(data["file"])
        archive = FileEntry.model_validate(data["archive"]) if data.get("archive") else None
    except (ValueError, KeyError, TypeError):
        return None
    if sha256_file(csv_path) != file.sha256:
        return None
    return KaggleDownload(slug=str(data.get("slug", MALICIOUS_URLS_SLUG)), url=str(data.get("url", "")),
                          fetched_at=str(data.get("fetched_at", "")), auth_kind=str(data.get("auth_kind", "")),
                          archive=archive, file=file, csv_path=csv_path)


def _stream_to(resp: httpx.Response, path: Path) -> None:
    with open(path, "wb") as fh:
        fh.writelines(resp.iter_bytes(1 << 20))


def kaggle_fetch_archive(auth: KaggleAuth, url: str, dest: Path, *, timeout: float = 300.0,
                         transport: httpx.BaseTransport | None = None) -> None:
    """One authenticated GET of ``url`` into ``dest``.

    Kaggle answers the download endpoint with a 302 to a signed Google Cloud
    Storage URL. That redirect is followed by a second client that carries no
    ``Authorization`` header: the storage host rejects the bearer token, and
    the credential must not leave Kaggle's origin in any case.
    """
    ua = {"User-Agent": f"redsim-build-assets/{redsim_version()}"}
    tmp = dest.with_suffix(dest.suffix + ".part")
    with (httpx.Client(timeout=timeout, follow_redirects=False, headers=ua, transport=transport) as client,
          client.stream("GET", url, headers=auth.headers()) as resp):
        if resp.status_code == 200:
            _stream_to(resp, tmp)
            os.replace(tmp, dest)
            return
        if resp.status_code in (401, 403):
            raise DatasetUnavailable(f"Kaggle refused the credentials read from {auth.source} (HTTP {resp.status_code})")
        if resp.status_code not in _REDIRECT_CODES:
            raise DatasetUnavailable(f"Kaggle download returned HTTP {resp.status_code} for {MALICIOUS_URLS_SLUG}")
        location = resp.headers.get("location")
        if not location:
            raise DatasetUnavailable(f"Kaggle answered HTTP {resp.status_code} without a Location header")
        target = resp.url.join(location)
    with (httpx.Client(timeout=timeout, follow_redirects=True, headers=ua, transport=transport) as anonymous,
          anonymous.stream("GET", target) as resp):
        if resp.status_code != 200:
            raise DatasetUnavailable(f"{target.host} returned HTTP {resp.status_code} for the Kaggle archive")
        _stream_to(resp, tmp)
    os.replace(tmp, dest)


def fetch_kaggle_malicious_urls(cache_dir: Path, *, auth: KaggleAuth | None = None, timeout: float = 300.0,
                                log: Log = print, transport: httpx.BaseTransport | None = None) -> KaggleDownload | None:
    """Download ``malicious_phish.csv`` with the operator's Kaggle credentials; ``None`` when there are none.

    A cached file that still hashes to what ``download.json`` recorded is
    reused without credentials. Otherwise the credentials are resolved for
    this call only and never logged or written anywhere. The zip Kaggle serves
    is hashed before extraction and both digests land in ``download.json``
    beside the CSV.
    """
    dest_dir = kaggle_cache_dir(cache_dir)
    cached = _cached_kaggle_download(dest_dir)
    if cached is not None:
        log(f"kaggle: using cached {cached.csv_path} (sha256 {cached.file.sha256[:12]}...)")
        return cached
    auth = auth if auth is not None else kaggle_credentials()
    if auth is None:
        return None
    dest_dir.mkdir(parents=True, exist_ok=True)
    url = KAGGLE_DOWNLOAD.format(slug=MALICIOUS_URLS_SLUG)
    log(f"kaggle: downloading {MALICIOUS_URLS_SLUG} ({auth.kind} auth, {auth.source})")
    archive_path = dest_dir / KAGGLE_ARCHIVE_NAME
    kaggle_fetch_archive(auth, url, archive_path, timeout=timeout, transport=transport)
    csv_path = dest_dir / MALICIOUS_URLS_FILE
    archive: FileEntry | None = None
    if zipfile.is_zipfile(archive_path):
        archive = FileEntry(path=KAGGLE_ARCHIVE_NAME, sha256=sha256_file(archive_path),
                            size_bytes=archive_path.stat().st_size)
        with zipfile.ZipFile(archive_path) as zf:
            names = zf.namelist()
            member = next((n for n in names if n.endswith(MALICIOUS_URLS_FILE)), None)
            if member is None:
                raise DatasetUnavailable(f"Kaggle archive holds {names}, not {MALICIOUS_URLS_FILE}")
            tmp = csv_path.with_suffix(csv_path.suffix + ".part")
            with zf.open(member) as src, open(tmp, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
        os.replace(tmp, csv_path)
    else:
        os.replace(archive_path, csv_path)      # the endpoint answered with the bare CSV
    file = FileEntry(path=MALICIOUS_URLS_FILE, sha256=sha256_file(csv_path), size_bytes=csv_path.stat().st_size)
    download = KaggleDownload(slug=MALICIOUS_URLS_SLUG, url=url, fetched_at=datetime.now(UTC).isoformat(),
                              auth_kind=auth.kind, archive=archive, file=file, csv_path=csv_path)
    (dest_dir / KAGGLE_DOWNLOAD_RECORD).write_text(json.dumps(download.record(), indent=2, sort_keys=True) + "\n",
                                                    encoding="utf-8")
    archive_note = f", archive sha256 {archive.sha256[:12]}..." if archive is not None else ""
    log(f"kaggle: {MALICIOUS_URLS_FILE} sha256 {file.sha256[:12]}... ({file.size_bytes} bytes{archive_note})")
    return download


def read_url_rows(path: Path) -> tuple[list[int], list[str], list[str]]:
    """Read ``url,type`` rows as ``(row_indices, urls, labels)``.

    ``row_indices`` are 0-based data-row positions (header excluded) so a row
    can be cited back to the source file. Labels are lower-cased, and rows with
    an empty url or type are skipped, which is why the indices are kept.
    """
    indices: list[int] = []
    urls: list[str] = []
    labels: list[str] = []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or "url" not in reader.fieldnames or "type" not in reader.fieldnames:
            raise DatasetUnavailable(f"{path}: expected columns url,type, found {reader.fieldnames}")
        for index, row in enumerate(reader):
            url = (row.get("url") or "").strip()
            label = (row.get("type") or "").strip().lower()
            if not url or not label:
                continue
            indices.append(index)
            urls.append(url)
            labels.append(label)
    return indices, urls, labels


def load_url_csv(path: Path) -> tuple[list[str], list[str]]:
    """Read ``url,type`` rows; labels are lower-cased, blank rows skipped."""
    _, urls, labels = read_url_rows(path)
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


def fixture_sidecar_entry(csv_path: Path, sidecar_path: Path | None = None) -> dict[str, Any] | None:
    """The committed sample's sidecar record (``tests/ml/fixtures/MANIFEST.json``), when present."""
    csv_path = Path(csv_path)
    path = Path(sidecar_path) if sidecar_path is not None else csv_path.parent / FIXTURE_SIDECAR_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    entry = data.get("files", {}).get(csv_path.name) if isinstance(data, dict) else None
    return entry if isinstance(entry, dict) else None


def kaggle_url_table(source: KaggleDownload | Path) -> UrlTable:
    """The full Kaggle file as a ``UrlTable`` whose dataset entry pins the file (and archive) digests."""
    csv_path = source.csv_path if isinstance(source, KaggleDownload) else Path(source)
    indices, urls, labels = read_url_rows(csv_path)
    digest = sha256_file(csv_path)
    size = csv_path.stat().st_size
    source_files = [FileEntry(path=MALICIOUS_URLS_FILE, sha256=digest, size_bytes=size)]
    archive_sha256: str | None = None
    if isinstance(source, KaggleDownload) and source.archive is not None:
        source_files.insert(0, source.archive)
        archive_sha256 = source.archive.sha256
    entry = DatasetEntry(
        id=f"kaggle:{MALICIOUS_URLS_SLUG}", source="kaggle", revision=digest,
        url=f"https://www.kaggle.com/datasets/{MALICIOUS_URLS_SLUG}", license=URL_LICENSE, license_note=URL_LICENSE_NOTE,
        class_names=list(URL_CLASS_NAMES), source_files=source_files, size_bytes=size,
        source_file_sha256=digest, archive_sha256=archive_sha256, n_rows=len(urls),
        notes=["Demo tabular dataset (spec 11.3.3). URL strings are data: never fetched, resolved or rendered."],
    )
    return UrlTable(urls=urls, labels=labels, dataset=entry, source_path=csv_path, row_indices=indices)


SAMPLE_SIDECAR_KEYS: tuple[str, ...] = (
    "source_dataset_id", "source_file", "source_file_sha256", "source_archive_sha256", "n_source_rows",
    "source_row_indices_sha256", "sampling",
)


def sample_url_table(csv_path: Path, sidecar_path: Path | None = None) -> UrlTable:
    """The committed CI sample as a ``UrlTable``; its sidecar says which Kaggle rows it was drawn from."""
    csv_path = Path(csv_path)
    indices, urls, labels = read_url_rows(csv_path)
    digest = sha256_file(csv_path)
    sidecar = fixture_sidecar_entry(csv_path, sidecar_path) or {}
    synthetic = bool(sidecar.get("synthetic", True))
    sampled_from = None if synthetic else {key: sidecar.get(key) for key in SAMPLE_SIDECAR_KEYS}
    license_note = ("Synthetic CI sample shaped like the Kaggle file; not the Kaggle data." if synthetic else
                    "Seeded stratified sample of the Kaggle file; the source digest and row indices are in "
                    "sampled_from. A CI fixture, not the demo dataset.")
    entry = DatasetEntry(
        id="local:tests/ml/fixtures/malicious_urls_sample.csv", source="local", revision=digest,
        license=URL_LICENSE, license_note=license_note, class_names=list(URL_CLASS_NAMES),
        source_files=[FileEntry(path=csv_path.name, sha256=digest, size_bytes=csv_path.stat().st_size)],
        size_bytes=csv_path.stat().st_size, source_file_sha256=digest, n_rows=len(urls), sampled_from=sampled_from,
        fixture_only=True,
        notes=["CI fixture only (spec 11.1): never a demo target, never evidence.", kaggle_missing_message()],
    )
    return UrlTable(urls=urls, labels=labels, dataset=entry, source_path=csv_path, row_indices=indices)


# ---------------------------------------------------------------------------
# Phase B shared helpers
# ---------------------------------------------------------------------------

def dataset_source(preferred: str) -> DatasetSource:
    """``preferred`` when ``manifest.DatasetSource`` admits it, else ``"local"``.

    ``manifest.DatasetSource`` carries ``uci`` (the SMS corpus) and ``github``
    (the nltk_data WordNet zip) since Phase B, so the entries below record
    their real source; the fallback stays for a manifest schema without a
    member (the entry then says so in its notes, with the origin in ``url``
    and ``source_files``).
    """
    if preferred in get_args(DatasetSource):
        return cast(DatasetSource, preferred)
    return "local"


def _source_fallback_note(preferred: str) -> list[str]:
    if dataset_source(preferred) == preferred:
        return []
    return [f"source is recorded as 'local' because manifest.DatasetSource has no {preferred!r} member yet; the "
            "bytes were fetched from the url and source_files recorded on this entry."]


def _stream_download(client: httpx.Client, url: str, dest: Path, *, expected_sha256: str | None,
                     what: str) -> FileEntry:
    """GET ``url`` to ``dest`` via a ``.part`` file; verify the digest before the rename; return a ``FileEntry``.

    The ``FileEntry.path`` is ``dest.name`` (source-relative, like every other
    ``source_files`` entry: these live in the download cache, not the assets root).
    """
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    digest = hashlib.sha256()
    with client.stream("GET", url) as resp:
        if resp.status_code != 200:
            raise DatasetUnavailable(f"{what}: {url} returned HTTP {resp.status_code}")
        with open(tmp, "wb") as fh:
            for chunk in resp.iter_bytes(1 << 20):
                digest.update(chunk)
                fh.write(chunk)
    actual = digest.hexdigest()
    if expected_sha256 and actual != expected_sha256.lower():
        tmp.unlink(missing_ok=True)
        raise DatasetUnavailable(f"{what}: sha256 mismatch for {url}: expected {expected_sha256}, got {actual}")
    os.replace(tmp, dest)
    return FileEntry(path=dest.name, sha256=actual, size_bytes=dest.stat().st_size)


def _safe_zip_member(name: str) -> str:
    """Refuse archive members that would escape the extraction directory."""
    parts = Path(name).parts
    if not parts or name.startswith(("/", "\\")) or any(p in ("..", "") for p in parts) or ":" in parts[0]:
        raise DatasetUnavailable(f"refusing archive member {name!r}")
    return name


# ---------------------------------------------------------------------------
# UCI SMS Spam Collection (MODALITIES-11 / -12): the bundled text dataset
# ---------------------------------------------------------------------------

SMS_SPAM_DATASET_ID = "uci:sms-spam-collection"
SMS_SPAM_UCI_ID = 228
SMS_SPAM_PAGE_URL = "https://archive.ics.uci.edu/dataset/228/sms+spam+collection"
SMS_SPAM_DOI = "10.24432/C5CC84"
SMS_SPAM_ARCHIVE_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
SMS_SPAM_ARCHIVE_NAME = "sms+spam+collection.zip"
SMS_SPAM_ARCHIVE_SHA256 = "1587ea43e58e82b14ff1f5425c88e17f8496bfcdb67a583dbff9eefaf9963ce3"
SMS_SPAM_ARCHIVE_SIZE = 203415
SMS_SPAM_FILE = "SMSSpamCollection"                       # ``label<TAB>text``, one message per line, UTF-8
SMS_SPAM_FILE_SHA256 = "7d039a24a6083ed9ef0f806ebad56bbb976e3aeb8de05669173bfdc4996c239d"
SMS_SPAM_FILE_SIZE = 477907
SMS_SPAM_README = "readme"
SMS_SPAM_README_SHA256 = "8753cd2d3cab68f80c8257851b8c2037778c267f55accb6fd1b5a2e32d36a84e"
SMS_SPAM_N_ROWS = 5574
SMS_SPAM_PER_CLASS = {"ham": 4827, "spam": 747}
SMS_CLASS_NAMES = ["ham", "spam"]
SMS_SPAM_LICENSE = "CC BY 4.0"
SMS_SPAM_LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/legalcode"
# The licence statement as it appears on the UCI page (read 2026-09-09 through the hackathon proxy).
SMS_SPAM_LICENSE_TEXT = ("This dataset is licensed under a Creative Commons Attribution 4.0 International (CC BY 4.0) "
                         "license. This allows for the sharing and adaptation of the datasets for any purpose, "
                         "provided that the appropriate credit is given.")
SMS_SPAM_LICENSE_NOTE = (f"UCI Machine Learning Repository page {SMS_SPAM_PAGE_URL} states: \"{SMS_SPAM_LICENSE_TEXT}\" "
                         f"({SMS_SPAM_LICENSE_URL}). The corpus readme inside the zip adds the authors' own "
                         "as-is / no-warranty terms and asks for a citation of the 2011 DocEng paper. Original "
                         "message sources: Grumbletext (UK spam reports), the NUS SMS Corpus, Caroline Tagg's PhD "
                         "thesis corpus and the SMS Spam Corpus v.0.1 Big.")
SMS_SPAM_ATTRIBUTION = ("Almeida, T. A. and Gómez Hidalgo, J. M. (2011). SMS Spam Collection [Dataset]. UCI Machine "
                        f"Learning Repository. https://doi.org/{SMS_SPAM_DOI}. Paper: Almeida, Gómez Hidalgo, Yamakami, "
                        "\"Contributions to the study of SMS spam filtering: new collection and results\", ACM DocEng 2011.")
SMS_SPAM_CAVEATS: tuple[str, ...] = (
    (f"{SMS_SPAM_DATASET_ID} is an open, unclassified, publicly available dataset whose licence (CC BY 4.0) is stated "
     "on its distribution page (spec 11.1). Demo text dataset for the text modality; never operational data."),
    ("Collected in 2011 or earlier from UK and Singapore sources: English only, 2003-2011 marketing and personal "
     "messages. Results describe SMS spam of that era, not current smishing or any other language."),
    ("Class imbalance: 747 of 5,574 messages (13.4%) are spam, so spam per-class counts are small at the default "
     "n_samples; per-class n is always shown."),
    ("Message texts contain phone numbers, SMS short codes and first names as published by the authors and UCI; the "
     "public copy is verbatim (no redaction), so results and exports quote the corpus as distributed."),
    ("Ham messages come largely from the NUS SMS Corpus (Singapore students, Singlish) and spam from UK reports; "
     "the two classes differ in dialect and source, which a lexical classifier can exploit."),
)
SMS_SPAM_PREPROCESSING: dict[str, Any] = {
    "format": "label<TAB>text, one message per line, UTF-8, LF line endings, no header",
    "labels": {"ham": 0, "spam": 1},
    "split": "seeded stratified holdout 0.2 (redsim.ml.assets.datasets.stratified_split), seed 0",
    "tokenizer": "decided by the text-modality build (redsim.ml.assets.train_text_classifier)",
}
SMS_EVAL_HOLDOUT = 0.2
SMS_EVAL_SEED = 0
SMS_DOWNLOAD_RECORD = "download.json"
SMS_TSV_COLUMNS = ("index", "label", "text")


@dataclass
class TextTable:
    """Labelled texts with the dataset entry that pins where they came from."""

    texts: list[str]
    labels: list[str]
    dataset: DatasetEntry
    source_path: Path
    row_indices: list[int] = field(default_factory=list)   # 0-based line index of each row in source_path

    @property
    def n(self) -> int:
        return len(self.texts)

    def per_class(self) -> dict[str, int]:
        return {name: sum(1 for label in self.labels if label == name) for name in self.dataset.class_names}


def sms_cache_dir(cache_dir: Path) -> Path:
    return Path(cache_dir) / "uci--sms-spam-collection"


def read_sms_rows(path: Path) -> tuple[list[int], list[str], list[str]]:
    """Read ``label<TAB>text`` lines as ``(row_indices, texts, labels)``.

    ``row_indices`` are 0-based line positions so a row can be cited back to
    the source file; blank lines and lines without a tab or with a label
    outside ``SMS_CLASS_NAMES`` are skipped, which is why the indices are kept.
    Only the first tab splits the line (the corpus has none inside a message).
    """
    indices: list[int] = []
    texts: list[str] = []
    labels: list[str] = []
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        for index, line in enumerate(fh):
            line = line.rstrip("\r\n")
            if "\t" not in line:
                continue
            label, text = line.split("\t", 1)
            label = label.strip().lower()
            if label not in SMS_CLASS_NAMES or not text.strip():
                continue
            indices.append(index)
            texts.append(text)
            labels.append(label)
    return indices, texts, labels


def fetch_sms_spam(client: httpx.Client, cache_dir: Path, *, expected_archive_sha256: str | None = SMS_SPAM_ARCHIVE_SHA256,
                   expected_file_sha256: str | None = SMS_SPAM_FILE_SHA256, log: Log = print) -> Path:
    """Download the UCI zip once, verify both digests, extract the corpus and readme; return the corpus path.

    A cached corpus that still hashes to ``expected_file_sha256`` is reused
    without a request. The zip streams to ``.part`` and is renamed only after
    its digest matches, then ``SMSSpamCollection`` and ``readme`` are extracted
    beside it and ``download.json`` records url, digests, licence and time.
    """
    dest_dir = sms_cache_dir(cache_dir)
    corpus = dest_dir / SMS_SPAM_FILE
    if corpus.is_file() and (not expected_file_sha256 or sha256_file(corpus) == expected_file_sha256):
        log(f"sms_spam: using cached {corpus}")
        return corpus
    log(f"sms_spam: downloading {SMS_SPAM_ARCHIVE_URL}")
    archive = _stream_download(client, SMS_SPAM_ARCHIVE_URL, dest_dir / SMS_SPAM_ARCHIVE_NAME,
                               expected_sha256=expected_archive_sha256, what="sms_spam")
    members: dict[str, FileEntry] = {}
    with zipfile.ZipFile(dest_dir / SMS_SPAM_ARCHIVE_NAME) as zf:
        names = zf.namelist()
        for member in (SMS_SPAM_FILE, SMS_SPAM_README):
            if member not in names:
                raise DatasetUnavailable(f"sms_spam: archive holds {names}, not {member}")
            out = dest_dir / _safe_zip_member(member)
            tmp = out.with_suffix(out.suffix + ".part")
            with zf.open(member) as src, open(tmp, "wb") as fh:
                shutil.copyfileobj(src, fh, 1 << 20)
            os.replace(tmp, out)
            members[member] = FileEntry(path=member, sha256=sha256_file(out), size_bytes=out.stat().st_size)
    if expected_file_sha256 and members[SMS_SPAM_FILE].sha256 != expected_file_sha256:
        corpus.unlink(missing_ok=True)
        raise DatasetUnavailable(f"sms_spam: {SMS_SPAM_FILE} sha256 {members[SMS_SPAM_FILE].sha256} is not the "
                                 f"pinned {expected_file_sha256}")
    record = {"dataset_id": SMS_SPAM_DATASET_ID, "url": SMS_SPAM_ARCHIVE_URL, "page_url": SMS_SPAM_PAGE_URL,
              "doi": SMS_SPAM_DOI, "fetched_at": datetime.now(UTC).isoformat(),
              "archive": archive.model_dump(), "file": members[SMS_SPAM_FILE].model_dump(),
              "readme": members[SMS_SPAM_README].model_dump(), "license": SMS_SPAM_LICENSE,
              "license_url": SMS_SPAM_LICENSE_URL, "license_text": SMS_SPAM_LICENSE_TEXT,
              "attribution": SMS_SPAM_ATTRIBUTION}
    (dest_dir / SMS_DOWNLOAD_RECORD).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log(f"sms_spam: {SMS_SPAM_FILE} sha256 {members[SMS_SPAM_FILE].sha256[:12]}... "
        f"({members[SMS_SPAM_FILE].size_bytes} bytes, archive sha256 {archive.sha256[:12]}...)")
    return corpus


def sms_spam_table(path: Path, *, pinned_sha256: str | None = SMS_SPAM_FILE_SHA256,
                   archive_sha256: str | None = SMS_SPAM_ARCHIVE_SHA256) -> TextTable:
    """The full corpus as a ``TextTable`` whose dataset entry pins the file digest as ``revision``.

    ``pinned_sha256`` is the loader's guard: a file that does not hash to the
    pinned digest is refused (``DatasetUnavailable``) rather than silently
    treated as the UCI corpus. Pass ``None`` only for a deliberately different
    revision, which the entry then records.
    """
    path = Path(path)
    digest = sha256_file(path)
    if pinned_sha256 and digest != pinned_sha256:
        raise DatasetUnavailable(f"{path}: sha256 {digest[:12]}... is not the pinned SMS Spam Collection digest "
                                 f"{pinned_sha256[:12]}... (MODALITIES-11)")
    indices, texts, labels = read_sms_rows(path)
    size = path.stat().st_size
    source_files = [FileEntry(path=SMS_SPAM_FILE, sha256=digest, size_bytes=size)]
    if archive_sha256:
        source_files.insert(0, FileEntry(path=SMS_SPAM_ARCHIVE_NAME, sha256=archive_sha256,
                                         size_bytes=SMS_SPAM_ARCHIVE_SIZE))
    entry = DatasetEntry(
        id=SMS_SPAM_DATASET_ID, source=dataset_source("uci"), revision=digest, url=SMS_SPAM_PAGE_URL,
        license=SMS_SPAM_LICENSE, license_note=SMS_SPAM_LICENSE_NOTE, class_names=list(SMS_CLASS_NAMES),
        source_files=source_files, size_bytes=size, source_file_sha256=digest, archive_sha256=archive_sha256,
        n_rows=len(texts), preprocessing=dict(SMS_SPAM_PREPROCESSING), caveats=list(SMS_SPAM_CAVEATS),
        notes=["Demo text dataset (MODALITIES-11). Message texts are data: never sent anywhere, never dialled.",
               f"Attribution: {SMS_SPAM_ATTRIBUTION}", *_source_fallback_note("uci")],
    )
    return TextTable(texts=texts, labels=labels, dataset=entry, source_path=path, row_indices=indices)


def sms_labels_to_ids(labels: Sequence[str]) -> np.ndarray:
    index = {name: i for i, name in enumerate(SMS_CLASS_NAMES)}
    return np.asarray([index[label] for label in labels], dtype=np.int64)


def sms_eval_split(labels: Sequence[str], *, holdout: float = SMS_EVAL_HOLDOUT,
                   seed: int = SMS_EVAL_SEED) -> tuple[np.ndarray, np.ndarray]:
    """Seeded stratified ``(train_positions, eval_positions)`` over the table rows (the corpus has no official split)."""
    return stratified_split(sms_labels_to_ids(labels), holdout, seed)


def write_sms_tsv(path: Path, table: TextTable, positions: Sequence[int] | np.ndarray) -> FileEntry:
    """Write ``index<TAB>label<TAB>text`` rows for ``positions`` (header row first; LF endings).

    ``index`` is the 0-based line position in the source corpus so every row
    cites back to ``SMSSpamCollection``. Returns a ``FileEntry`` whose path is
    the file name.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\t".join(SMS_TSV_COLUMNS) + "\n")
        for pos in positions:
            p = int(pos)
            text = table.texts[p]
            if "\t" in text or "\n" in text or "\r" in text:
                raise ValueError(f"row {table.row_indices[p]} contains a tab or newline; the TSV would break")
            fh.write(f"{table.row_indices[p]}\t{table.labels[p]}\t{text}\n")
    return FileEntry(path=path.name, sha256=sha256_file(path), size_bytes=path.stat().st_size)


def read_sms_tsv(path: Path) -> tuple[list[int], list[str], list[str]]:
    """Read a ``write_sms_tsv`` file back as ``(source_indices, texts, labels)``."""
    indices: list[int] = []
    texts: list[str] = []
    labels: list[str] = []
    with open(path, encoding="utf-8", newline="") as fh:
        header = fh.readline().rstrip("\r\n").split("\t")
        if tuple(header) != SMS_TSV_COLUMNS:
            raise DatasetUnavailable(f"{path}: expected columns {SMS_TSV_COLUMNS}, found {header}")
        for line in fh:
            line = line.rstrip("\r\n")
            if not line:
                continue
            parts = line.split("\t", 2)
            if len(parts) != 3 or parts[1] not in SMS_CLASS_NAMES:
                raise DatasetUnavailable(f"{path}: malformed row {line[:60]!r}")
            indices.append(int(parts[0]))
            labels.append(parts[1])
            texts.append(parts[2])
    return indices, texts, labels


SMS_SAMPLE_NAME = "sms_spam_sample.tsv"


def committed_sms_sample_path() -> Path | None:
    """The committed SMS CI sample, when this is a source checkout."""
    candidate = Path(__file__).resolve().parents[3] / "tests" / "ml" / "fixtures" / SMS_SAMPLE_NAME
    return candidate if candidate.exists() else None


def sms_sample_table(tsv_path: Path, sidecar_path: Path | None = None) -> TextTable:
    """The committed SMS sample (``write_sms_tsv`` layout) as a fixture-only ``TextTable``.

    The sidecar entry in ``tests/ml/fixtures/MANIFEST.json`` says which corpus
    rows it was drawn from; ``row_indices`` are those source line positions.
    """
    tsv_path = Path(tsv_path)
    indices, texts, labels = read_sms_tsv(tsv_path)
    digest = sha256_file(tsv_path)
    sidecar = fixture_sidecar_entry(tsv_path, sidecar_path) or {}
    synthetic = bool(sidecar.get("synthetic", True))
    sampled_from = None if synthetic else {key: sidecar.get(key) for key in SAMPLE_SIDECAR_KEYS}
    entry = DatasetEntry(
        id=f"local:tests/ml/fixtures/{tsv_path.name}", source="local", revision=digest, url=SMS_SPAM_PAGE_URL,
        license=SMS_SPAM_LICENSE, class_names=list(SMS_CLASS_NAMES),
        license_note=("Synthetic CI sample shaped like the UCI corpus; not the UCI data." if synthetic else
                      "Seeded stratified sample of the UCI SMS Spam Collection (CC BY 4.0); the source digest and "
                      "row indices are in sampled_from. A CI fixture, not the demo dataset."),
        source_files=[FileEntry(path=tsv_path.name, sha256=digest, size_bytes=tsv_path.stat().st_size)],
        size_bytes=tsv_path.stat().st_size, source_file_sha256=digest, n_rows=len(texts), sampled_from=sampled_from,
        fixture_only=True, caveats=list(SMS_SPAM_CAVEATS),
        notes=["CI fixture only (spec 11.1): never a demo target, never evidence.",
               f"Attribution: {SMS_SPAM_ATTRIBUTION}"],
    )
    return TextTable(texts=texts, labels=labels, dataset=entry, source_path=tsv_path, row_indices=indices)


# ---------------------------------------------------------------------------
# WordNet 3.0 from nltk/nltk_data (word-substitution synonyms; cached, never republished)
# ---------------------------------------------------------------------------

WORDNET_DATASET_ID = "nltk_data:wordnet"
WORDNET_VERSION = "3.0"
WORDNET_REPO = "nltk/nltk_data"
WORDNET_BRANCH = "gh-pages"
WORDNET_REVISION = "550b6625bcef1f2abff2ff770a5a0d272c9c6b2a"     # gh-pages commit the zip was fetched at (2026-09-09)
WORDNET_ZIP_PATH = "packages/corpora/wordnet.zip"
WORDNET_URL_TEMPLATE = "https://raw.githubusercontent.com/nltk/nltk_data/{revision}/packages/corpora/wordnet.zip"
WORDNET_ZIP_NAME = "wordnet.zip"
WORDNET_ZIP_SHA256 = "cbda5ea6eef7f36a97a43d4a75f85e07fccbb4f23657d27b4ccbc93e2646ab59"
WORDNET_ZIP_SIZE = 10775600
WORDNET_LICENSE_MEMBER = "wordnet/LICENSE"
WORDNET_LICENSE_SHA256 = "7731175a77952e259390b496fab905e57118b8d19ad3a8383c67eee724ff443f"
WORDNET_README_MEMBER = "wordnet/README"
WORDNET_README_SHA256 = "adad8d28ddea1db05b67ba1ac23506b025d29e0bcbf23bb35dde346089d8808d"
WORDNET_HOMEPAGE = "https://wordnet.princeton.edu/"
WORDNET_LICENSE = "WordNet 3.0 License"
WORDNET_COPYRIGHT = "WordNet 3.0 Copyright 2006 by Princeton University.  All rights reserved."
WORDNET_LICENSE_NOTE = ("Princeton WordNet 3.0 licence (BSD-style, from wordnet/LICENSE in the zip): permission to use, "
                        "copy, modify and distribute the software and database for any purpose and without fee is "
                        "granted provided the copyright notice, statements and disclaimer appear on all copies; "
                        "Princeton's name may not be used in advertising or publicity; title stays with Princeton. "
                        f"{WORDNET_COPYRIGHT} redsim caches the zip at build time and never republishes it.")
WORDNET_CACHE_SUBDIR = "wordnet"
WORDNET_DOWNLOAD_RECORD = "download.json"


def wordnet_cache_dir(cache_dir: Path) -> Path:
    return Path(cache_dir) / WORDNET_CACHE_SUBDIR


def wordnet_nltk_data_dir(cache_dir: Path) -> Path:
    """The directory to hand the sandbox child as ``NLTK_DATA`` (``corpora/wordnet/`` lives under it)."""
    return wordnet_cache_dir(cache_dir) / "nltk_data"


def wordnet_url(revision: str = WORDNET_REVISION) -> str:
    return WORDNET_URL_TEMPLATE.format(revision=revision)


@dataclass
class WordNetDownload:
    """One fetch of the nltk_data WordNet zip, as recorded in ``download.json`` beside it."""

    revision: str
    url: str
    fetched_at: str
    zip: FileEntry
    license: FileEntry
    readme: FileEntry | None
    nltk_data_dir: Path

    def record(self) -> dict[str, Any]:
        return {"dataset_id": WORDNET_DATASET_ID, "version": WORDNET_VERSION, "repo": WORDNET_REPO,
                "branch": WORDNET_BRANCH, "revision": self.revision, "url": self.url, "fetched_at": self.fetched_at,
                "zip": self.zip.model_dump(), "license_file": self.license.model_dump(),
                "readme": self.readme.model_dump() if self.readme is not None else None,
                "license": WORDNET_LICENSE, "license_note": WORDNET_LICENSE_NOTE, "homepage": WORDNET_HOMEPAGE,
                "nltk_data_dir": str(self.nltk_data_dir), "republished": False}


def _cached_wordnet(dest_dir: Path) -> WordNetDownload | None:
    record_path = dest_dir / WORDNET_DOWNLOAD_RECORD
    zip_path = dest_dir / WORDNET_ZIP_NAME
    if not (record_path.is_file() and zip_path.is_file()):
        return None
    try:
        data = json.loads(record_path.read_text(encoding="utf-8"))
        zip_entry = FileEntry.model_validate(data["zip"])
        lic = FileEntry.model_validate(data["license_file"])
        readme = FileEntry.model_validate(data["readme"]) if data.get("readme") else None
    except (ValueError, KeyError, TypeError):
        return None
    nltk_dir = dest_dir / "nltk_data"
    lic_path = nltk_dir / "corpora" / WORDNET_LICENSE_MEMBER
    if sha256_file(zip_path) != zip_entry.sha256 or not lic_path.is_file() or sha256_file(lic_path) != lic.sha256:
        return None
    return WordNetDownload(revision=str(data.get("revision", "")), url=str(data.get("url", "")),
                           fetched_at=str(data.get("fetched_at", "")), zip=zip_entry, license=lic, readme=readme,
                           nltk_data_dir=nltk_dir)


def fetch_wordnet(client: httpx.Client, cache_dir: Path, *, revision: str = WORDNET_REVISION,
                  expected_sha256: str | None = WORDNET_ZIP_SHA256, log: Log = print) -> WordNetDownload:
    """Fetch ``wordnet.zip`` at a pinned nltk_data commit, verify it, unpack it as an ``NLTK_DATA`` tree.

    Layout after the call: ``<cache>/wordnet/wordnet.zip``, ``<cache>/wordnet/download.json`` and
    ``<cache>/wordnet/nltk_data/corpora/wordnet/{LICENSE,README,data.*,index.*,...}`` so the child
    runs with ``NLTK_DATA=<cache>/wordnet/nltk_data`` and no network. Nothing here is committed or
    republished; the digests are what the asset manifest records.
    """
    dest_dir = wordnet_cache_dir(cache_dir)
    cached = _cached_wordnet(dest_dir)
    if cached is not None:
        log(f"wordnet: using cached {dest_dir / WORDNET_ZIP_NAME} (sha256 {cached.zip.sha256[:12]}...)")
        return cached
    url = wordnet_url(revision)
    log(f"wordnet: downloading {url}")
    zip_entry = _stream_download(client, url, dest_dir / WORDNET_ZIP_NAME, expected_sha256=expected_sha256,
                                 what="wordnet")
    corpora = dest_dir / "nltk_data" / "corpora"
    corpora.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest_dir / WORDNET_ZIP_NAME) as zf:
        names = zf.namelist()
        if WORDNET_LICENSE_MEMBER not in names:
            raise DatasetUnavailable(f"wordnet: {WORDNET_LICENSE_MEMBER} is missing from the zip; refusing an "
                                     "unlicensed copy")
        for member in names:
            rel = _safe_zip_member(member)
            if not rel.startswith("wordnet/"):
                raise DatasetUnavailable(f"wordnet: unexpected member {member!r}")
            out = corpora / rel
            if member.endswith("/"):
                out.mkdir(parents=True, exist_ok=True)
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            tmp = out.with_suffix(out.suffix + ".part")
            with zf.open(member) as src, open(tmp, "wb") as fh:
                shutil.copyfileobj(src, fh, 1 << 20)
            os.replace(tmp, out)
    lic_path = corpora / WORDNET_LICENSE_MEMBER
    lic = FileEntry(path=WORDNET_LICENSE_MEMBER, sha256=sha256_file(lic_path), size_bytes=lic_path.stat().st_size)
    readme_path = corpora / WORDNET_README_MEMBER
    readme = (FileEntry(path=WORDNET_README_MEMBER, sha256=sha256_file(readme_path),
                        size_bytes=readme_path.stat().st_size) if readme_path.is_file() else None)
    download = WordNetDownload(revision=revision, url=url, fetched_at=datetime.now(UTC).isoformat(), zip=zip_entry,
                               license=lic, readme=readme, nltk_data_dir=dest_dir / "nltk_data")
    (dest_dir / WORDNET_DOWNLOAD_RECORD).write_text(json.dumps(download.record(), indent=2, sort_keys=True) + "\n",
                                                     encoding="utf-8")
    log(f"wordnet: {WORDNET_ZIP_NAME} sha256 {zip_entry.sha256[:12]}... ({zip_entry.size_bytes} bytes); licence "
        f"sha256 {lic.sha256[:12]}...")
    return download


def wordnet_dataset_entry(download: WordNetDownload) -> DatasetEntry:
    """The asset-manifest entry for the cached WordNet copy (digests, licence, no bundled split)."""
    return DatasetEntry(
        id=WORDNET_DATASET_ID, source=dataset_source("github"), revision=download.revision, url=WORDNET_HOMEPAGE,
        license=WORDNET_LICENSE, license_note=WORDNET_LICENSE_NOTE, source_files=[download.zip, download.license],
        size_bytes=download.zip.size_bytes, source_file_sha256=download.zip.sha256, archive_sha256=download.zip.sha256,
        preprocessing={"version": WORDNET_VERSION, "repo": WORDNET_REPO, "branch": WORDNET_BRANCH,
                       "path": WORDNET_ZIP_PATH, "nltk_data_layout": "corpora/wordnet/", "use": "synonym sets for the "
                       "word-substitution attack (redsim.ml.attacks.word_substitution), read offline via NLTK_DATA"},
        notes=["Lexical resource, not a labelled dataset: no splits, no classes, never a target.",
               "Cached under the gitignored assets cache; never republished (plan 12 section 4).",
               *_source_fallback_note("github")],
    )


# ---------------------------------------------------------------------------
# Kaggle military-assets detection set (MODALITIES-27): capped, seeded subset, person and weapon classes excluded
# ---------------------------------------------------------------------------

MILITARY_ASSETS_SLUG = "rawsi18/military-assets-dataset-12-classes-yolo8-format"
MILITARY_ASSETS_DATASET_ID = f"kaggle:{MILITARY_ASSETS_SLUG}"
MILITARY_ASSETS_URL = f"https://www.kaggle.com/datasets/{MILITARY_ASSETS_SLUG}"
MILITARY_ASSETS_VERSION = 5                          # Kaggle currentVersionNumber, lastUpdated 2024-11-23 (read 2026-09-09)
MILITARY_ASSETS_TOTAL_BYTES = 4185478976            # Kaggle totalBytes (uncompressed listing)
# The archive Kaggle served for version 5 on 2026-09-09 (the whole set; only the subset below is kept or published).
MILITARY_ASSETS_ARCHIVE_SHA256 = "49a6b339ea4f666015683bc5d801368030243139bcec1e3a88f2af31f9e9a268"
MILITARY_ASSETS_ARCHIVE_SIZE = 4113622610
# sha256 of data/military_assets_subset/manifest.json as published (the subset's ``revision``).
MILITARY_ASSETS_SUBSET_MANIFEST_SHA256 = "749611b4676ab10a4cd586f64b31b2a49a6245f121cee66d0d474dbddb85a001"
MILITARY_ASSETS_ROOT = "military_object_dataset"
MILITARY_ASSETS_SPLITS = ("train", "val", "test")    # 21,978 / 2,941 / 1,396 images (file listing, 2026-09-09)
MILITARY_ASSETS_LICENSE = "CC BY 4.0"
MILITARY_ASSETS_LICENSE_KAGGLE = "Attribution 4.0 International (CC BY 4.0)"
MILITARY_ASSETS_LICENSE_NOTE = (f"Kaggle metadata API licenseName \"{MILITARY_ASSETS_LICENSE_KAGGLE}\" (read 2026-09-09): "
                                "the uploader's statement over the compilation and labels. The photographs were "
                                "collected from the web; their copyright is not cleared by the CC BY tag (same caveat "
                                "as the vehicle imagery, spec 11.3.1 caveat 2).")
MILITARY_ASSETS_ATTRIBUTION = ("RAWx18 (Ryan Madhuwala), \"Military Assets Dataset (12 Classes - Yolo8 Format)\", Kaggle, "
                               f"version {MILITARY_ASSETS_VERSION} (2024-11-23), CC BY 4.0, {MILITARY_ASSETS_URL}")
# ``names`` from military_object_dataset/military_dataset.yaml (fetched 2026-09-09); index = YOLO class id.
MILITARY_ASSETS_CLASS_NAMES: tuple[str, ...] = (
    "camouflage_soldier", "weapon", "military_tank", "military_truck", "military_vehicle", "civilian", "soldier",
    "civilian_vehicle", "military_artillery", "trench", "military_aircraft", "military_warship",
)
# D3 bound (spec 3.3, 11.3.1 caveat 4): no person recognition, no weapon detection. An image with any box of these
# classes is dropped from the subset; the labels of kept images are copied verbatim, so no box is edited.
MILITARY_ASSETS_EXCLUDED_CLASSES: tuple[str, ...] = ("camouflage_soldier", "weapon", "civilian", "soldier")
# The subset task: four vehicle-type classes (owner confirms before wave B1, plan 12 section 2).
MILITARY_ASSETS_SUBSET_CLASSES: tuple[str, ...] = ("military_tank", "military_truck", "military_vehicle",
                                                   "military_aircraft")
MILITARY_ASSETS_SUBSET_N = 300
MILITARY_ASSETS_SUBSET_SEED = 0
MILITARY_ASSETS_SUBSET_NAME = "military_assets_subset"
MILITARY_ASSETS_SUBSET_MANIFEST = "manifest.json"
MILITARY_ASSETS_CAVEATS: tuple[str, ...] = (
    (f"{MILITARY_ASSETS_DATASET_ID} is an open, publicly available dataset whose licence (CC BY 4.0) is stated in its "
     "Kaggle metadata (spec 11.1). Only a capped, seeded subset is used; the D3 bounds apply as for the vehicle "
     "imagery: robustness evaluation of a detector on a public benchmark, never a targeting or weapons model."),
    ("Person and weapon classes (camouflage_soldier, soldier, civilian, weapon) are excluded by construction: images "
     "carrying any such box are dropped before selection, no person or face label exists in the subset and none is "
     "derived. Images may still incidentally show people without a box."),
    ("Web-scraped photographs of varying provenance; the uploader's CC BY covers the compilation and labels, not the "
     "photographs' copyright. Label quality is undocumented; 2024 snapshot (version 5)."),
    ("Detection is scored with mAP and matched-box counts with denominators; no MRI is computed for detection "
     "(plan 12, MODALITIES-36)."),
)


def military_assets_class_id(name: str) -> int:
    try:
        return MILITARY_ASSETS_CLASS_NAMES.index(name)
    except ValueError as exc:
        raise ValueError(f"unknown military-assets class {name!r}") from exc


def kaggle_file_url(slug: str, rel_path: str) -> str:
    """The per-file download endpoint; the path is percent-encoded as one segment (slashes as ``%2F``)."""
    return KAGGLE_DOWNLOAD.format(slug=slug) + "/" + quote(rel_path, safe="")


def military_assets_cache_dir(cache_dir: Path) -> Path:
    return Path(cache_dir) / f"kaggle--{MILITARY_ASSETS_SLUG.replace('/', '--')}"


def fetch_kaggle_file(auth: KaggleAuth, slug: str, rel_path: str, dest: Path, *, timeout: float = 120.0,
                      transport: httpx.BaseTransport | None = None, force: bool = False) -> Path:
    """One dataset file by path (``kaggle_fetch_archive`` semantics: bearer to Kaggle, anonymous to storage)."""
    dest = Path(dest)
    if dest.is_file() and not force and (dest.stat().st_size > 0 or rel_path.endswith(".txt")):
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    kaggle_fetch_archive(auth, kaggle_file_url(slug, rel_path), dest, timeout=timeout, transport=transport)
    return dest


@dataclass(frozen=True)
class YoloBox:
    """One ``class cx cy w h`` line (normalised centre / size in [0, 1])."""

    class_id: int
    cx: float
    cy: float
    w: float
    h: float


def parse_yolo_labels(text: str, *, n_classes: int = len(MILITARY_ASSETS_CLASS_NAMES)) -> list[YoloBox]:
    """Parse a YOLO label file; malformed lines raise ``DatasetUnavailable`` (a label is never guessed)."""
    boxes: list[YoloBox] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5:
            raise DatasetUnavailable(f"YOLO label line {lineno} has {len(parts)} fields, expected 5: {line!r}")
        try:
            cid = int(parts[0])
            cx, cy, w, h = (float(v) for v in parts[1:5])
        except ValueError as exc:
            raise DatasetUnavailable(f"YOLO label line {lineno} is not numeric: {line!r}") from exc
        if not 0 <= cid < n_classes:
            raise DatasetUnavailable(f"YOLO label line {lineno} names class {cid}, outside 0..{n_classes - 1}")
        if not all(0.0 <= v <= 1.0 for v in (cx, cy, w, h)):
            raise DatasetUnavailable(f"YOLO label line {lineno} has coordinates outside [0, 1]: {line!r}")
        boxes.append(YoloBox(cid, cx, cy, w, h))
    return boxes


def yolo_to_xyxy(box: YoloBox, width: int, height: int) -> tuple[float, float, float, float]:
    """Pixel ``(x_min, y_min, x_max, y_max)`` of a normalised YOLO box, clipped to the image."""
    x0 = max(0.0, (box.cx - box.w / 2) * width)
    y0 = max(0.0, (box.cy - box.h / 2) * height)
    x1 = min(float(width), (box.cx + box.w / 2) * width)
    y1 = min(float(height), (box.cy + box.h / 2) * height)
    return x0, y0, x1, y1


def primary_class(boxes: Sequence[YoloBox]) -> int | None:
    """The most frequent class id in the image (ties -> the smallest id); ``None`` for an empty label."""
    if not boxes:
        return None
    counts: dict[int, int] = {}
    for b in boxes:
        counts[b.class_id] = counts.get(b.class_id, 0) + 1
    best = max(counts.values())
    return min(c for c, n in counts.items() if n == best)


def select_detection_subset(labels: Mapping[str, Sequence[YoloBox]], *, keep_classes: Sequence[int],
                            exclude_classes: Sequence[int], n: int, seed: int) -> list[str]:
    """Seeded, stratified image keys for the subset.

    Eligible images have at least one box and every box in ``keep_classes``
    (so none in ``exclude_classes`` and none of the other, unmodelled
    classes: labels are copied verbatim, never edited). Stratification is by
    the image's primary class through ``stratified_indices``; the result is
    sorted by key for a stable file order.
    """
    keep = set(keep_classes)
    if keep & set(exclude_classes):
        raise ValueError("keep_classes and exclude_classes overlap")
    keys = sorted(labels)
    eligible: list[str] = []
    strata: list[int] = []
    for key in keys:
        boxes = labels[key]
        if not boxes or any(b.class_id not in keep for b in boxes):
            continue
        prim = primary_class(boxes)
        assert prim is not None
        eligible.append(key)
        strata.append(sorted(keep).index(prim))
    if not eligible:
        return []
    chosen = stratified_indices(np.asarray(strata, dtype=np.int64), n, seed)
    return [eligible[int(i)] for i in chosen]


def detection_subset_manifest(chosen: Sequence[str], labels: Mapping[str, Sequence[YoloBox]], files: Mapping[str, FileEntry],
                              *, keep_classes: Sequence[str] = MILITARY_ASSETS_SUBSET_CLASSES,
                              exclude_classes: Sequence[str] = MILITARY_ASSETS_EXCLUDED_CLASSES, n_requested: int,
                              seed: int, n_candidates: int, splits_scanned: Sequence[str],
                              image_sizes: Mapping[str, tuple[int, int]] | None = None) -> dict[str, Any]:
    """The subset's own manifest: provenance, selection rule, per-class box and image counts, per-file digests.

    ``files`` maps ``<split>/<stem>`` to the ``FileEntry`` of its image and
    ``<split>/<stem>.txt`` to its label (paths relative to the subset root).
    """
    keep_ids = [military_assets_class_id(c) for c in keep_classes]
    per_class_boxes = {c: 0 for c in keep_classes}
    per_class_images = {c: 0 for c in keep_classes}
    images: list[dict[str, Any]] = []
    for key in chosen:
        boxes = labels[key]
        prim = primary_class(boxes)
        for b in boxes:
            per_class_boxes[MILITARY_ASSETS_CLASS_NAMES[b.class_id]] += 1
        per_class_images[MILITARY_ASSETS_CLASS_NAMES[prim]] += 1   # type: ignore[index]
        split, stem = key.split("/", 1)
        item: dict[str, Any] = {"key": key, "source_split": split, "stem": stem, "n_boxes": len(boxes),
                                "primary_class": MILITARY_ASSETS_CLASS_NAMES[prim],   # type: ignore[index]
                                "image": files[key].model_dump(), "label": files[key + ".txt"].model_dump()}
        if image_sizes and key in image_sizes:
            item["width"], item["height"] = image_sizes[key]
        images.append(item)
    return {
        "schema_version": 1,
        "dataset_id": MILITARY_ASSETS_DATASET_ID,
        "source": {"kaggle_slug": MILITARY_ASSETS_SLUG, "url": MILITARY_ASSETS_URL, "version": MILITARY_ASSETS_VERSION,
                   "total_bytes_upstream": MILITARY_ASSETS_TOTAL_BYTES, "fetched_per_file": True,
                   "splits_scanned": list(splits_scanned)},
        "license": MILITARY_ASSETS_LICENSE, "license_kaggle": MILITARY_ASSETS_LICENSE_KAGGLE,
        "license_note": MILITARY_ASSETS_LICENSE_NOTE, "attribution": MILITARY_ASSETS_ATTRIBUTION,
        "class_names": list(MILITARY_ASSETS_CLASS_NAMES), "keep_classes": list(keep_classes),
        "keep_class_ids": keep_ids, "excluded_classes": list(exclude_classes),
        "selection": {"rule": "an image is eligible when it has at least one box and every box is a keep class (so "
                              "no person, weapon or other class appears); stratified by primary class (most boxes, "
                              "ties to the smallest id) with redsim.ml.assets.datasets.stratified_indices",
                      "n_requested": n_requested, "n_selected": len(chosen), "n_candidates": n_candidates,
                      "seed": seed, "labels": "YOLO txt copied verbatim (class cx cy w h, original class ids)"},
        "per_class_images": per_class_images, "per_class_boxes": per_class_boxes,
        "n_images": len(chosen), "n_boxes": sum(len(labels[k]) for k in chosen),
        "caveats": list(MILITARY_ASSETS_CAVEATS),
        "images": images,
        "built_at": datetime.now(UTC).isoformat(),
    }


def military_assets_dataset_entry(manifest: Mapping[str, Any], *, index_sha256: str) -> DatasetEntry:
    """The asset-manifest entry for the subset; ``revision`` is the sha256 of the subset manifest file."""
    return DatasetEntry(
        id=MILITARY_ASSETS_DATASET_ID, source="kaggle", revision=index_sha256, url=MILITARY_ASSETS_URL,
        license=MILITARY_ASSETS_LICENSE, license_note=MILITARY_ASSETS_LICENSE_NOTE,
        class_names=[str(c) for c in manifest.get("keep_classes", MILITARY_ASSETS_SUBSET_CLASSES)],
        n_rows=int(manifest.get("n_images", 0)), caveats=list(MILITARY_ASSETS_CAVEATS),
        preprocessing={"layout": "YOLOv8 (images/ + labels/), class ids as upstream", "subset_manifest": "manifest.json",
                       "excluded_classes": list(manifest.get("excluded_classes", MILITARY_ASSETS_EXCLUDED_CLASSES)),
                       "selection": dict(manifest.get("selection", {}))},
        notes=[f"Capped, seeded subset of Kaggle {MILITARY_ASSETS_SLUG} version {MILITARY_ASSETS_VERSION} (MODALITIES-27). "
               "Owner confirmation of the dataset choice is pending (plan 12 section 2).",
               f"Attribution: {MILITARY_ASSETS_ATTRIBUTION}"],
    )


# ---------------------------------------------------------------------------
# The published detection subset, read back for the detector build (MODALITIES-27 / -29)
#
# B0 publishes the capped subset under ``<assets>/cache/military_assets_subset`` in a flat layout keyed by
# upstream split (``images/<split>/<stem>.jpg`` beside ``labels/<split>/<stem>.txt``) with ``manifest.json``
# (``detection_subset_manifest``) listing every file and its digest. ``redsim.ml.datasets.military_assets``
# reads the ``<split>/images`` YOLO layout; this reader follows the subset manifest instead and checks each
# file against it, so the detector is trained on exactly the bytes the subset manifest vouches for.
# ---------------------------------------------------------------------------


@dataclass
class DetectionSubset:
    """The subset as one ``DetectionSplit`` plus the manifest it was verified against."""

    split: Any                      # redsim.ml.datasets.military_assets.DetectionSplit (imported lazily)
    manifest: dict[str, Any]
    manifest_sha256: str            # the dataset revision the asset manifest records
    root: Path


def detection_subset_root(assets_root: Path) -> Path:
    """Where B0 publishes the subset under an assets root (``military_assets.SUBSET_RELATIVE_DIR``)."""
    return Path(assets_root) / "cache" / MILITARY_ASSETS_SUBSET_NAME


def load_detection_subset(subset_root: Path, *, image_size: int = 320, verify: bool = True) -> DetectionSubset:
    """Decode every image ``manifest.json`` lists at ``image_size`` (square; boxes scaled), digest-checked.

    Boxes carry the manifest's ``keep_classes`` remapped to a contiguous 0-based list in that order; the
    selection rule promises no other class appears, so a label outside them is refused rather than edited
    away. ``indices`` are positions in the manifest's image list sorted by key and ``filenames`` the keys
    (``<upstream split>/<stem>``), so every row traces back to the subset manifest.
    """
    from PIL import Image

    from redsim.ml.datasets.military_assets import DetectionSplit, parse_yolo_label

    root = Path(subset_root)
    manifest_path = root / MILITARY_ASSETS_SUBSET_MANIFEST
    if not manifest_path.is_file():
        raise DatasetUnavailable(f"detection subset manifest not found: {manifest_path}; the capped military-assets "
                                 "subset (MODALITIES-27) is published there by the B0 datasets step and needs a "
                                 "Kaggle token to reproduce")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise DatasetUnavailable(f"{manifest_path}: not JSON ({exc})") from exc
    if not isinstance(manifest, dict) or manifest.get("dataset_id") != MILITARY_ASSETS_DATASET_ID:
        raise DatasetUnavailable(f"{manifest_path}: not a {MILITARY_ASSETS_DATASET_ID!r} subset manifest")
    images = manifest.get("images")
    if not isinstance(images, list) or not images:
        raise DatasetUnavailable(f"{manifest_path}: lists no images")
    all_names = [str(c) for c in (manifest.get("class_names") or MILITARY_ASSETS_CLASS_NAMES)]
    keep = [str(c) for c in (manifest.get("keep_classes") or MILITARY_ASSETS_SUBSET_CLASSES)]
    raw_ids = manifest.get("keep_class_ids")
    keep_ids = [int(i) for i in raw_ids] if isinstance(raw_ids, list) and raw_ids else [all_names.index(c) for c in keep]
    if len(keep_ids) != len(keep):
        raise DatasetUnavailable(f"{manifest_path}: keep_class_ids and keep_classes disagree")
    remap = {old: new for new, old in enumerate(keep_ids)}
    excluded = [str(c) for c in (manifest.get("excluded_classes") or MILITARY_ASSETS_EXCLUDED_CLASSES)]
    raw_selection = manifest.get("selection")
    selection: dict[str, Any] = dict(raw_selection) if isinstance(raw_selection, dict) else {}
    seed = selection.get("seed")

    xs: list[np.ndarray] = []
    boxes: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    keys: list[str] = []
    for item in sorted(images, key=lambda it: str(it.get("key", ""))):
        if not isinstance(item, dict) or not isinstance(item.get("image"), dict) or not isinstance(item.get("label"), dict):
            raise DatasetUnavailable(f"{manifest_path}: malformed image record {item!r}")
        image_ref = FileEntry.model_validate(item["image"])
        label_ref = FileEntry.model_validate(item["label"])
        image_path = root / image_ref.path
        label_path = root / label_ref.path
        for ref, path in ((image_ref, image_path), (label_ref, label_path)):
            if not path.is_file():
                raise DatasetUnavailable(f"detection subset file missing: {path}")
            if verify and sha256_file(path) != ref.sha256:
                raise DatasetUnavailable(f"detection subset file {path} does not match the digest in {manifest_path}")
        try:
            with Image.open(image_path) as im:
                rgb = im.convert("RGB")
                width, height = rgb.size
                if (width, height) != (image_size, image_size):
                    rgb = rgb.resize((image_size, image_size), Image.Resampling.BILINEAR)
                arr = np.ascontiguousarray(np.asarray(rgb, dtype=np.uint8).transpose(2, 0, 1))
        except OSError as exc:
            raise DatasetUnavailable(f"cannot decode {image_path}: {exc}") from exc
        raw_boxes, raw_labels = parse_yolo_label(label_path.read_text(encoding="utf-8"), width, height)
        if raw_labels.size == 0:
            raise DatasetUnavailable(f"{label_path}: no boxes; the subset rule requires at least one per image")
        outside = sorted({all_names[int(c)] if 0 <= int(c) < len(all_names) else str(int(c))
                          for c in raw_labels if int(c) not in remap})
        if outside:
            raise DatasetUnavailable(f"{label_path}: class(es) {outside} are outside keep_classes {keep}; the subset "
                                     "manifest promises none, so the file is refused rather than edited")
        scale = np.asarray([image_size / float(width), image_size / float(height)] * 2, dtype=np.float32)
        xs.append(arr)
        boxes.append(np.clip(raw_boxes * scale, 0.0, float(image_size)).astype(np.float32))
        labels.append(np.asarray([remap[int(c)] for c in raw_labels], dtype=np.int64))
        keys.append(str(item.get("key") or image_path.stem))
    split = DetectionSplit(
        name="subset", x=np.stack(xs), boxes=boxes, labels=labels,
        indices=np.arange(len(xs), dtype=np.int64), class_names=keep, filenames=keys, excluded_classes=excluded,
        seed=int(seed) if isinstance(seed, int) else None,
    )
    return DetectionSubset(split=split, manifest=manifest, manifest_sha256=sha256_file(manifest_path), root=root)


def detection_holdout(split: Any, *, holdout: float, seed: int) -> tuple[Any, Any]:
    """Seeded stratified ``(train, eval)`` of a ``DetectionSplit`` by primary class (the subset has no split).

    ``round(n * holdout)`` images, at least one and at most ``n - 1``, go to ``eval`` (named ``eval``); the
    rest are ``train``. Both keep their positions in the source ``indices`` so the draw is reproducible.
    """
    from redsim.ml.datasets.military_assets import stratified_detection_indices

    if not 0.0 < holdout < 1.0:
        raise ValueError("holdout must be in (0, 1)")
    n = int(split.n)
    if n < 2:
        raise DatasetUnavailable(f"the detection subset holds {n} image(s); a holdout needs at least two")
    n_eval = min(max(int(round(n * holdout)), 1), n - 1)
    eval_pos = np.sort(stratified_detection_indices(split, n_eval, seed))
    mask = np.ones(n, dtype=bool)
    mask[eval_pos] = False
    train = split.subset(np.flatnonzero(mask))
    evaluation = split.subset(eval_pos)
    train.name, evaluation.name = "train", "eval"
    train.seed = evaluation.seed = int(seed)
    return train, evaluation


# ---------------------------------------------------------------------------
# Bundled training slice for the image dataset (ATTACKS_HARDEN-11)
# ---------------------------------------------------------------------------

TRAIN_SLICE_NAME = "train_slice.npz"
DEFAULT_TRAIN_SLICE_N = 1536


@dataclass
class TrainSliceOptions:
    """``build-assets`` option for the training slice (wiring into ``build.py`` is a follow-up in that file)."""

    n: int = DEFAULT_TRAIN_SLICE_N
    seed: int = 0
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.n < 1:
            raise ValueError("train slice n must be >= 1")


def train_slice_indices(y: np.ndarray, n: int, seed: int, *, exclude: np.ndarray | Sequence[int] | None = None
                        ) -> np.ndarray:
    """Positions into ``y`` of a seeded stratified slice of ``min(n, available)`` rows, disjoint from ``exclude``."""
    y = np.asarray(y).reshape(-1)
    mask = np.ones(y.shape[0], dtype=bool)
    if exclude is not None:
        ex = np.asarray(exclude, dtype=np.int64)
        if ex.size:
            mask[ex] = False
    available = np.flatnonzero(mask)
    if available.size == 0:
        return np.empty(0, dtype=np.int64)
    picked = stratified_indices(y[available], n, seed)
    return np.sort(available[picked].astype(np.int64))


def write_train_slice(split: ImageSplit, dest: Path, root: Path, *, n: int = DEFAULT_TRAIN_SLICE_N, seed: int = 0,
                      exclude_indices: np.ndarray | Sequence[int] | None = None) -> tuple[ImageSplit, SplitEntry]:
    """Write ``dest`` (``train_slice.npz``: uint8 NCHW ``x``, ``y``, source ``indices``, ``class_names``, ``seed``,
    ``source_split``) from a seeded stratified draw of ``split`` and return the slice with its ``SplitEntry``.

    ``exclude_indices`` are source-split indices that must not appear (the
    evaluation rows when train and eval come from one pool); the slice is
    disjoint from them by construction. ``SplitEntry.file`` is relative to the
    assets ``root`` so ``verify_manifest`` checks the digest like any bundled
    file, and ``indices_sha256`` pins the draw.
    """
    dest = Path(dest)
    positions = train_slice_indices(split.y, n, seed, exclude=(
        None if exclude_indices is None else np.flatnonzero(np.isin(split.indices, np.asarray(exclude_indices)))))
    sub = ImageSplit(name=f"{split.name}_slice", x=split.x[positions], y=split.y[positions],
                     indices=split.indices[positions], class_names=list(split.class_names))
    dest.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(dest, x=sub.x, y=sub.y, indices=sub.indices, class_names=np.asarray(sub.class_names),
                        seed=np.asarray(seed), n_requested=np.asarray(n), source_split=np.asarray(split.name))
    entry = SplitEntry(name=sub.name, n=sub.n, per_class=sub.per_class(), seed=seed,
                       indices_sha256=indices_sha256(sub.indices), file=file_entry(Path(root), dest))
    return sub, entry


TRAIN_SLICE_SIDECAR_NAME = "train_slice.json"


class TrainSliceSidecar(BaseModel):
    """``bundled/<model>/train_slice.json``: what a training slice was drawn from and the ``SplitEntry`` it makes.

    Written beside the slice by ``build_cnn_asset`` and read back by ``build.attach_train_slice`` when a slice
    drawn out-of-band (the B0 draw for ``vehicles_cnn``) is recorded in an existing manifest: the model and
    dataset it belongs to, the dataset revision and source split it was drawn from, the requested size and
    seed, and the split entry (``file`` relative to the assets root) that goes under the dataset's ``splits``.
    """

    model_config = ConfigDict(extra="ignore", protected_namespaces=())

    model_id: str
    dataset_id: str
    revision: str | None = None
    source_split: str
    split_entry: SplitEntry
    n_requested: int
    seed: int
    note: str = ""


def write_train_slice_sidecar(path: Path, sidecar: TrainSliceSidecar) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sidecar.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    return path


def read_train_slice_sidecar(path: Path) -> TrainSliceSidecar:
    path = Path(path)
    if not path.is_file():
        raise DatasetUnavailable(f"training slice sidecar {path} is missing")
    try:
        return TrainSliceSidecar.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise DatasetUnavailable(f"training slice sidecar {path} is not readable: {exc}") from exc


def load_train_slice(path: Path, *, expected_sha256: str | None = None) -> ImageSplit:
    """Read a ``write_train_slice`` file back (digest-checked when ``expected_sha256`` is given)."""
    path = Path(path)
    if not path.is_file():
        raise DatasetUnavailable(f"training slice {path} is missing")
    if expected_sha256 and sha256_file(path) != expected_sha256:
        raise DatasetUnavailable(f"training slice {path} does not match its recorded sha256")
    with np.load(path, allow_pickle=False) as data:
        try:
            x = np.asarray(data["x"], dtype=np.uint8)
            y = np.asarray(data["y"], dtype=np.int64)
            indices = np.asarray(data["indices"], dtype=np.int64)
            class_names = [str(c) for c in data["class_names"].tolist()]
            source_split = str(data["source_split"]) if "source_split" in data else "train"
        except KeyError as exc:
            raise DatasetUnavailable(f"training slice {path} lacks key {exc}") from exc
    if x.ndim != 4 or x.shape[0] != y.shape[0] or y.shape[0] != indices.shape[0]:
        raise DatasetUnavailable(f"training slice {path} has inconsistent shapes {x.shape}, {y.shape}, {indices.shape}")
    return ImageSplit(name=f"{source_split}_slice", x=x, y=y, indices=indices, class_names=class_names)


def cached_imagefolder_split(cache_root: Path, split_dir: str, *, class_names: Sequence[str] | None = None,
                             image_size: int = 128, positions: Sequence[int] | np.ndarray | None = None,
                             ) -> ImageSplit:
    """Decode one imagefolder split from the local hub cache (no network), in the hub's sorted file order.

    Indices match ``fetch_imagefolder`` for the same repo revision because
    both sort the repo-relative paths. ``positions`` restricts decoding to a
    subset of that order (the training-slice draw) so a 7,000-image split need
    not be decoded to write a 1,536-image slice.
    """
    from PIL import Image

    root = Path(cache_root) / split_dir
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS
                   and p.parent.parent == root)
    if not files:
        raise DatasetUnavailable(f"{root}: no cached images")
    classes = [p.parent.name for p in files]
    names = list(class_names) if class_names is not None else sorted(set(classes))
    index = {c: i for i, c in enumerate(names)}
    unknown = sorted({c for c in classes if c not in index})
    if unknown:
        raise DatasetUnavailable(f"{root}: classes {unknown} are not in the declared class list")
    y = np.asarray([index[c] for c in classes], dtype=np.int64)
    pos = np.arange(len(files), dtype=np.int64) if positions is None else np.asarray(positions, dtype=np.int64)
    pixels = np.empty((len(pos), 3, image_size, image_size), dtype=np.uint8)
    for k, i in enumerate(pos):
        with Image.open(files[int(i)]) as im:
            pixels[k] = preprocess_image(im, image_size)
    return ImageSplit(name=split_dir, x=pixels, y=y[pos], indices=pos, class_names=names)


# ---------------------------------------------------------------------------
# The public data repository (TESTS_DOCS-35, LLM-27): every dataset the code names has an INDEX.csv row
# ---------------------------------------------------------------------------

PUBLIC_DATA_REPO = "IntelliBridge/ai-red-teaming-data"
PUBLIC_DATA_URL = f"https://github.com/{PUBLIC_DATA_REPO}"
PUBLIC_INDEX_URL = f"https://raw.githubusercontent.com/{PUBLIC_DATA_REPO}/main/INDEX.csv"
PUBLIC_INDEX_COLUMNS = ("file", "bytes", "sha256", "source", "license", "note")
PUBLIC_INDEX_SNAPSHOT = Path(__file__).resolve().parents[3] / "tests" / "ml" / "fixtures" / "public_index.csv"

GARAK_VERSION = "0.16.0"
GARAK_CORPORA_ID = f"pypi:garak=={GARAK_VERSION}/data"
GARAK_WHEEL = f"garak-{GARAK_VERSION}-py3-none-any.whl"
GARAK_WHEEL_SHA256 = "871100d78e2bc5a7ee6de58ff8301bdd3de3a41236032690d1a6da21a05e9f06"   # pypi.org JSON, 2026-09-09
GARAK_SDIST_SHA256 = "71962ecf7c3a09d27f0cee0b9cf26f7ecbceb122264fcfd487ddbf9a72b4a750"
GARAK_UPSTREAM = "https://github.com/NVIDIA/garak"
GARAK_LICENSE = "Apache-2.0"
# The garak/data files behind the planned offline ``redsim-core`` probe set (LLM-27), licence per subset as recorded
# in the public repository's data/garak/PROVENANCE.csv. garak loads these itself from the installed package; redsim
# never re-packages them.
GARAK_DATA_FILES_USED: tuple[tuple[str, str], ...] = (
    ("inthewild_jailbreak_llms.json", "Apache-2.0 (garak packaging); upstream terms of Shen et al. / Yu et al. "
                                      "unconfirmed, so no redistribution outside the garak copy"),
    ("dan/*.json", "Apache-2.0 (garak packaging)"),
    ("donotanswer/*.jsonl", "MIT upstream (Libr-AI/do-not-answer); Apache-2.0 packaging"),
    ("harmbench/harmbench_prompts.txt (+ harmbench/LICENSE)", "MIT (harmbench/LICENSE)"),
    ("realtoxicityprompts/*.txt", "Apache-2.0 upstream and packaging"),
    ("payloads/*.json", "Apache-2.0"),
)

# Every dataset id this module names, with its publication status in the public repository (spec 11.1, plan 12
# section 4). ``PUBLIC_DATA_FILES`` maps an id to the INDEX.csv ``file`` values that publish or reference it;
# ``PUBLIC_DATA_PENDING`` names ids whose publication waits on something recorded here (never silently absent);
# ``FIXTURE_ONLY_DATASET_IDS`` are never published (CI fixtures, spec 11.1). ``tests/ml/test_datasets.py`` checks
# that the three sets partition ``CODE_NAMED_DATASET_IDS``.
PUBLIC_DATA_FILES: dict[str, tuple[str, ...]] = {
    f"hf:{VEHICLES_REPO}": ("data/military_vehicles.parquet",),
    f"kaggle:{MALICIOUS_URLS_SLUG}": ("data/malicious_urls.csv", "data/malicious_urls_eval_split.csv"),
    SMS_SPAM_DATASET_ID: ("data/sms_spam_collection.tsv", "data/sms_spam_eval_split.tsv"),
    MILITARY_ASSETS_DATASET_ID: ("data/military_assets_subset/",),
    GARAK_CORPORA_ID: ("data/garak/", "external/garak-probe-corpora.md"),
    WORDNET_DATASET_ID: ("external/wordnet-3.0.md",),
}
# Nothing is pending today; the map stays so a future dataset can be named before its publication without hiding it.
PUBLIC_DATA_PENDING: dict[str, str] = {}
FIXTURE_ONLY_DATASET_IDS: frozenset[str] = frozenset({f"hf:{CIFAR10_REPO}"})
CODE_NAMED_DATASET_IDS: frozenset[str] = frozenset({
    f"hf:{VEHICLES_REPO}", f"kaggle:{MALICIOUS_URLS_SLUG}", f"hf:{CIFAR10_REPO}", SMS_SPAM_DATASET_ID,
    MILITARY_ASSETS_DATASET_ID, GARAK_CORPORA_ID, WORDNET_DATASET_ID,
})
# Published digests the code pins: the public copy of a verbatim file must hash to what the loader expects.
PUBLIC_DATA_PINNED_SHA256: dict[str, str] = {
    "data/sms_spam_collection.tsv": SMS_SPAM_FILE_SHA256,
}
# Directory rows carry their manifest digest in the sha256 column ("see <dir>/manifest.json (manifest sha256 ...)").
PUBLIC_DATA_DIRECTORY_MANIFEST_SHA256: dict[str, str] = {
    "data/military_assets_subset/": MILITARY_ASSETS_SUBSET_MANIFEST_SHA256,
}


def read_public_index(path: Path | None = None) -> list[dict[str, str]]:
    """Rows of ``INDEX.csv`` (the committed snapshot by default); the header must be ``PUBLIC_INDEX_COLUMNS``."""
    path = Path(path) if path is not None else PUBLIC_INDEX_SNAPSHOT
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if tuple(reader.fieldnames or ()) != PUBLIC_INDEX_COLUMNS:
            raise DatasetUnavailable(f"{path}: expected columns {PUBLIC_INDEX_COLUMNS}, found {reader.fieldnames}")
        return [dict(row) for row in reader]


def public_index_rows_for(dataset_id: str, rows: Sequence[Mapping[str, str]]) -> dict[str, Mapping[str, str]]:
    """``{file: row}`` for every ``PUBLIC_DATA_FILES[dataset_id]`` entry present in ``rows``."""
    by_file = {row["file"]: row for row in rows}
    return {f: by_file[f] for f in PUBLIC_DATA_FILES.get(dataset_id, ()) if f in by_file}


def missing_public_index_rows(rows: Sequence[Mapping[str, str]]) -> dict[str, list[str]]:
    """``{dataset_id: [missing files]}`` for every code-named dataset without all its rows."""
    by_file = {row["file"] for row in rows}
    out: dict[str, list[str]] = {}
    for dataset_id, files in PUBLIC_DATA_FILES.items():
        missing = [f for f in files if f not in by_file]
        if missing:
            out[dataset_id] = missing
    return out


def fetch_public_index(client: httpx.Client, *, url: str = PUBLIC_INDEX_URL) -> list[dict[str, str]]:
    """The live ``INDEX.csv`` (only the ``REDSIM_PUBLIC_DATA_CHECK=1`` slow test calls this)."""
    resp = client.get(url)
    if resp.status_code != 200:
        raise DatasetUnavailable(f"{url} returned HTTP {resp.status_code}")
    reader = csv.DictReader(io.StringIO(resp.text))
    if tuple(reader.fieldnames or ()) != PUBLIC_INDEX_COLUMNS:
        raise DatasetUnavailable(f"{url}: expected columns {PUBLIC_INDEX_COLUMNS}, found {reader.fieldnames}")
    return [dict(row) for row in reader]
