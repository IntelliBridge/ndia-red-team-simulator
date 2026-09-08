"""HuggingFace hub helpers for the image datasets (spec sections 11.3.1, 11.3.5).

Plain ``httpx`` against the hub's public REST surface, so the worker image
needs neither ``huggingface_hub`` nor ``datasets``:

* ``resolve_revision``  ``GET /api/datasets/{repo}/revision/{rev}`` -> commit sha
* ``repo_files``        the ``siblings`` list of that same response
* ``download_file``     ``GET /datasets/{repo}/resolve/{sha}/{path}`` streamed to the
                        local cache (``REDSIM_ML_WORK_DIR``), digest-checked, atomic rename
* ``fetch_imagefolder_split`` every image under ``<split_dir>/<class>/`` of an imagefolder repo
* ``imagefolder_to_arrays`` resize shorter side + center crop -> uint8 NCHW

TLS trust goes through ``truststore`` when it is importable so corporate
proxies with a private root CA work without extra configuration. Nothing here
is called from a test: tests exercise the helpers with ``httpx.MockTransport``.
"""

from __future__ import annotations

import hashlib
import io
import os
import ssl
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import numpy as np

from redsim.ml.datasets import DatasetUnavailable, work_dir

HF_ENDPOINT_ENV = "HF_ENDPOINT"
DEFAULT_ENDPOINT = "https://huggingface.co"
IMAGE_SUFFIXES = (".jpg", ".jpeg", ".png", ".bmp", ".webp")
USER_AGENT = "redsim-ml/0.13 (+https://github.com/IntelliBridge/ndia-red-team-simulator)"
_CHUNK = 1 << 20


def hub_endpoint() -> str:
    return (os.environ.get(HF_ENDPOINT_ENV, "").strip() or DEFAULT_ENDPOINT).rstrip("/")


def dataset_cache_dir(repo_id: str, revision: str) -> Path:
    """``<work_dir>/datasets/<owner>--<name>/<revision>``."""
    return work_dir() / "datasets" / repo_id.replace("/", "--") / revision


def _ssl_verify() -> ssl.SSLContext | bool:
    try:
        import truststore
    except ImportError:  # pragma: no cover - depends on the environment
        return True
    context: ssl.SSLContext = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    return context


def make_client(*, timeout: float = 60.0, transport: httpx.BaseTransport | None = None) -> httpx.Client:
    """An ``httpx.Client`` for the hub. ``HF_TOKEN`` is sent only when set (gated repos are not used)."""
    headers = {"User-Agent": USER_AGENT}
    token = os.environ.get("HF_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(headers=headers, timeout=timeout, follow_redirects=True,
                        verify=_ssl_verify(), transport=transport)


def _get_json(client: httpx.Client, url: str) -> dict[str, Any]:
    try:
        resp = client.get(url)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:
        raise DatasetUnavailable(f"hub request failed: {url}: {exc}") from exc
    except ValueError as exc:
        raise DatasetUnavailable(f"hub response is not JSON: {url}") from exc
    if not isinstance(data, dict):
        raise DatasetUnavailable(f"unexpected hub response shape: {url}")
    return data


def repo_info(repo_id: str, revision: str = "main", *, client: httpx.Client | None = None) -> dict[str, Any]:
    """The hub's dataset-info document for ``repo_id`` at ``revision`` (contains ``sha`` and ``siblings``)."""
    url = f"{hub_endpoint()}/api/datasets/{repo_id}/revision/{quote(revision, safe='')}"
    own = client is None
    c = client or make_client()
    try:
        return _get_json(c, url)
    finally:
        if own:
            c.close()


def resolve_revision(repo_id: str, revision: str = "main", *, client: httpx.Client | None = None) -> str:
    """Resolve a branch/tag/sha to the commit sha the run records as ``dataset_revision``."""
    info = repo_info(repo_id, revision, client=client)
    sha = info.get("sha")
    if not isinstance(sha, str) or not sha:
        raise DatasetUnavailable(f"hub did not return a commit sha for {repo_id}@{revision}")
    return sha


def repo_files(repo_id: str, revision: str = "main", *, client: httpx.Client | None = None) -> list[str]:
    info = repo_info(repo_id, revision, client=client)
    siblings = info.get("siblings") or []
    names = [s.get("rfilename") for s in siblings if isinstance(s, dict)]
    return sorted(n for n in names if isinstance(n, str))


def resolve_url(repo_id: str, path: str, revision: str) -> str:
    return f"{hub_endpoint()}/datasets/{repo_id}/resolve/{quote(revision, safe='')}/{quote(path)}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_dest(root: Path, rel: str) -> Path:
    dest = (root / rel).resolve()
    if root.resolve() != dest and root.resolve() not in dest.parents:
        raise DatasetUnavailable(f"refusing repo path that escapes the cache dir: {rel!r}")
    return dest


def download_file(
    repo_id: str,
    path: str,
    revision: str,
    *,
    dest_dir: Path | None = None,
    client: httpx.Client | None = None,
    expected_sha256: str | None = None,
    force: bool = False,
) -> Path:
    """Fetch one repo file into the cache and return its local path.

    A cached copy is reused (after the digest check when ``expected_sha256``
    is given). Bytes stream to ``<name>.part`` and are renamed into place only
    after the digest is verified, so a partial download never masquerades as
    the file.
    """
    root = dest_dir if dest_dir is not None else dataset_cache_dir(repo_id, revision)
    dest = _safe_dest(root, path)
    if dest.exists() and not force:
        if expected_sha256 and sha256_file(dest) != expected_sha256.lower():
            dest.unlink()
        else:
            return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    url = resolve_url(repo_id, path, revision)
    own = client is None
    c = client or make_client()
    h = hashlib.sha256()
    try:
        with c.stream("GET", url) as resp:
            resp.raise_for_status()
            with part.open("wb") as fh:
                for chunk in resp.iter_bytes(_CHUNK):
                    h.update(chunk)
                    fh.write(chunk)
    except httpx.HTTPError as exc:
        part.unlink(missing_ok=True)
        raise DatasetUnavailable(f"download failed: {url}: {exc}") from exc
    finally:
        if own:
            c.close()
    digest = h.hexdigest()
    if expected_sha256 and digest != expected_sha256.lower():
        part.unlink(missing_ok=True)
        raise DatasetUnavailable(f"sha256 mismatch for {repo_id}/{path}@{revision}: "
                                 f"expected {expected_sha256}, got {digest}")
    os.replace(part, dest)
    return dest


def imagefolder_files(files: Iterable[str], split_dir: str) -> list[tuple[str, str]]:
    """``(repo_path, class_name)`` for every image under ``<split_dir>/<class>/`` in an imagefolder listing."""
    prefix = split_dir.strip("/") + "/"
    out: list[tuple[str, str]] = []
    for f in files:
        if not f.startswith(prefix) or not f.lower().endswith(IMAGE_SUFFIXES):
            continue
        parts = f[len(prefix):].split("/")
        if len(parts) != 2:
            continue
        out.append((f, parts[0]))
    return sorted(out)


def fetch_imagefolder_split(
    repo_id: str,
    revision: str,
    split_dir: str,
    *,
    client: httpx.Client | None = None,
    limit_per_class: int | None = None,
) -> list[tuple[Path, str]]:
    """Download every image of one imagefolder split; returns ``(local_path, class_name)`` pairs."""
    own = client is None
    c = client or make_client()
    try:
        listing = imagefolder_files(repo_files(repo_id, revision, client=c), split_dir)
        if limit_per_class is not None:
            seen: dict[str, int] = {}
            trimmed = []
            for f, cls in listing:
                if seen.get(cls, 0) < limit_per_class:
                    trimmed.append((f, cls))
                    seen[cls] = seen.get(cls, 0) + 1
            listing = trimmed
        return [(download_file(repo_id, f, revision, client=c), cls) for f, cls in listing]
    finally:
        if own:
            c.close()


def preprocess_image(img: Any, image_size: int | None) -> np.ndarray:
    """RGB, resize the shorter side to ``image_size`` (bilinear), center-crop square -> uint8 (3, S, S).

    ``image_size=None`` keeps the native size (used for fixed-size sources such as CIFAR-10).
    """
    from PIL import Image

    im = img.convert("RGB")
    if image_size is not None:
        w, h = im.size
        scale = image_size / min(w, h)
        new_w, new_h = max(image_size, round(w * scale)), max(image_size, round(h * scale))
        im = im.resize((new_w, new_h), Image.Resampling.BILINEAR)
        left, top = (new_w - image_size) // 2, (new_h - image_size) // 2
        im = im.crop((left, top, left + image_size, top + image_size))
    arr = np.asarray(im, dtype=np.uint8)
    return np.ascontiguousarray(arr.transpose(2, 0, 1))


def image_bytes_to_array(data: bytes, image_size: int | None) -> np.ndarray:
    from PIL import Image

    with Image.open(io.BytesIO(data)) as im:
        return preprocess_image(im, image_size)


def imagefolder_to_arrays(
    items: Sequence[tuple[Path, str]],
    class_names: Sequence[str],
    image_size: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Decode ``(path, class_name)`` pairs into uint8 NCHW ``x`` and int64 ``y`` (index into ``class_names``)."""
    from PIL import Image

    index = {name: i for i, name in enumerate(class_names)}
    xs: list[np.ndarray] = []
    ys: list[int] = []
    for path, cls in items:
        if cls not in index:
            raise DatasetUnavailable(f"class {cls!r} is not in the declared class list")
        with Image.open(path) as im:
            xs.append(preprocess_image(im, image_size))
        ys.append(index[cls])
    if not xs:
        return np.empty((0, 3, image_size, image_size), dtype=np.uint8), np.empty(0, dtype=np.int64)
    return np.stack(xs), np.asarray(ys, dtype=np.int64)


__all__ = [
    "DEFAULT_ENDPOINT", "IMAGE_SUFFIXES", "dataset_cache_dir", "download_file", "fetch_imagefolder_split",
    "hub_endpoint", "image_bytes_to_array", "imagefolder_files", "imagefolder_to_arrays", "make_client",
    "preprocess_image", "repo_files", "repo_info", "resolve_revision", "resolve_url", "sha256_file",
]
