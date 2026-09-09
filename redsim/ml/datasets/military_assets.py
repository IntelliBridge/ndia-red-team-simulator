"""Capped military-assets detection subset (spec 11.1, 11.5; register MODALITIES-27, -28).

Source: Kaggle ``rawsi18/military-assets-dataset-12-classes-yolo8-format`` (CC BY 4.0 declared by the
uploader over the compilation; the photographs' copyright is not cleared by that tag). The owner
approved a capped, seeded subset on 2026-09-09. Wave B0 publishes that subset in YOLOv8 layout under
``<assets>/cache/military_assets_subset`` (``{train,valid,test}/images/*.jpg`` with a ``labels/*.txt``
line ``<class> <cx> <cy> <w> <h>`` per box, all normalised to the image, plus a ``*.yaml`` with the class
``names``). This module only reads that layout; nothing here fetches, and nothing here imports torch.

D3 bound (spec 3.3, 11.3.1 caveat 4): the person and weapon classes of the source
(``EXCLUDED_CLASSES``) are dropped at load time. Their boxes are removed, an image whose only boxes
were excluded is dropped, and the remaining class ids are remapped to a contiguous list. The exclusion
and the subset seed are recorded on the split so the manifest can state them.

Bundled evaluation slices are ``.npz`` files with packed boxes (``boxes`` (K, 4) xyxy float32 in pixel
units at the stored size, ``labels`` (K,) int64 0-based, ``offsets`` (n + 1,) int64 so image ``i`` owns
``boxes[offsets[i]:offsets[i + 1]]``). ``synthetic_detection_split`` draws coloured rectangles for
tests; whatever it produces is a test double, never evidence about the dataset.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from redsim.ml.datasets import DatasetUnavailable
from redsim.ml.datasets.sampling import stratified_indices

KAGGLE_SLUG = "rawsi18/military-assets-dataset-12-classes-yolo8-format"
DATASET_ID = f"kaggle:{KAGGLE_SLUG}"
SUBSET_DATASET_ID = f"{DATASET_ID}#subset"
LICENSE = "CC BY 4.0"
LICENSE_NOTE = ("Kaggle metadata API licenseName 'Attribution 4.0 International (CC BY 4.0)'; the uploader's "
                "statement over the compilation and labels, not the photographers' copyright (spec 11.5). "
                "Attribution: RAWx18 (Kaggle).")
SOURCE_URL = f"https://www.kaggle.com/datasets/{KAGGLE_SLUG}"
SUBSET_DIRNAME = "military_assets_subset"
SUBSET_RELATIVE_DIR = f"cache/{SUBSET_DIRNAME}"          # under the assets root, as B0 publishes it
SPLIT_DIRS: tuple[str, ...] = ("train", "valid", "test")
YAML_CANDIDATES: tuple[str, ...] = ("military_dataset.yaml", "data.yaml", "dataset.yaml")
IMAGE_EXTENSIONS: frozenset[str] = frozenset({".jpg", ".jpeg", ".png", ".bmp", ".webp"})
# D3 bound: no person recognition, no weapons model. Confirmed against the source yaml at load time.
EXCLUDED_CLASSES: tuple[str, ...] = ("soldier", "civilian", "camouflage_soldier", "weapon")
DEFAULT_IMAGE_SIZE = 320
EVAL_SLICE_NAME = "eval_det.npz"
CAVEATS: tuple[str, ...] = (
    (f"{KAGGLE_SLUG} is an open, unclassified, publicly available dataset whose licence (CC BY 4.0) is declared "
     "by the uploader over the compilation; the photographs were collected from the web and their copyright is "
     "not cleared by that tag. Internal demo; images are not redistributed without review (spec 11.5)."),
    ("Only a capped, seeded subset is bundled; person and weapon classes are excluded at load time under the D3 "
     "bound (no person recognition, no targeting or weapons model). The exclusion is recorded on the split."),
    ("Label quality of the source is unknown (no adjudication statement on the dataset page); the 2024 snapshot "
     "is a compilation of web photographs, not operational, aerial or sensor imagery."),
    ("Images are stretched to a square at load time; boxes are scaled with the same factors, so aspect ratios "
     "differ from the source photographs."),
)


@dataclass
class DetectionSplit:
    """One split as uint8 NCHW pixels with per-image boxes (xyxy pixel units at the stored size).

    ``labels`` are 0-based indices into ``class_names``; ``indices`` index the source listing (sorted file
    order) so a slice can be traced back; ``filenames`` are recorded for the same reason.
    """

    name: str
    x: np.ndarray
    boxes: list[np.ndarray]
    labels: list[np.ndarray]
    indices: np.ndarray
    class_names: list[str]
    filenames: list[str] = field(default_factory=list)
    excluded_classes: list[str] = field(default_factory=list)
    n_boxes_excluded: int = 0
    n_images_dropped: int = 0
    seed: int | None = None

    @property
    def n(self) -> int:
        return int(self.x.shape[0])

    @property
    def n_boxes(self) -> int:
        return int(sum(int(b.shape[0]) for b in self.boxes))

    def per_class_boxes(self) -> dict[str, int]:
        counts = Counter(int(v) for lab in self.labels for v in lab.tolist())
        return {name: int(counts.get(i, 0)) for i, name in enumerate(self.class_names)}

    def targets(self) -> list[dict[str, np.ndarray]]:
        """``[{"boxes": (k, 4) float32, "labels": (k,) int64}, ...]`` per image."""
        return [{"boxes": np.asarray(b, dtype=np.float32).reshape(-1, 4), "labels": np.asarray(lab, dtype=np.int64)}
                for b, lab in zip(self.boxes, self.labels, strict=True)]

    def subset(self, idx: np.ndarray) -> DetectionSplit:
        idx = np.asarray(idx, dtype=np.int64)
        return DetectionSplit(
            name=self.name, x=self.x[idx], boxes=[self.boxes[i] for i in idx], labels=[self.labels[i] for i in idx],
            indices=self.indices[idx], class_names=list(self.class_names),
            filenames=[self.filenames[i] for i in idx] if self.filenames else [],
            excluded_classes=list(self.excluded_classes), n_boxes_excluded=self.n_boxes_excluded,
            n_images_dropped=self.n_images_dropped, seed=self.seed,
        )


def primary_labels(labels: Sequence[np.ndarray], n_classes: int) -> np.ndarray:
    """One label per image for stratification: the most frequent class in the image (ties -> smallest id).

    An image without boxes gets ``n_classes`` (an "empty" stratum) so it never counts toward a class."""
    out = np.empty(len(labels), dtype=np.int64)
    for i, lab in enumerate(labels):
        arr = np.asarray(lab, dtype=np.int64).ravel()
        if arr.size == 0:
            out[i] = n_classes
            continue
        counts = np.bincount(arr, minlength=n_classes)
        out[i] = int(np.argmax(counts))
    return out


def stratified_detection_indices(split: DetectionSplit, n: int, seed: int) -> np.ndarray:
    """Seeded stratified image selection by primary class (``redsim.ml.datasets.sampling`` rules)."""
    return stratified_indices(primary_labels(split.labels, len(split.class_names)), n, seed)


# ---------------------------------------------------------------------------
# YOLO layout
# ---------------------------------------------------------------------------

def parse_yolo_label(text: str, width: int, height: int) -> tuple[np.ndarray, np.ndarray]:
    """``<class> <cx> <cy> <w> <h>`` (normalised) lines -> ``(boxes xyxy float32 in pixels, labels int64)``.

    Malformed lines raise ``DatasetUnavailable``; boxes are clipped to the image and degenerate ones dropped.
    """
    boxes: list[list[float]] = []
    labels: list[int] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5:
            raise DatasetUnavailable(f"YOLO label line {lineno} has {len(parts)} fields, expected 5: {line!r}")
        try:
            cls = int(float(parts[0]))
            cx, cy, w, h = (float(v) for v in parts[1:5])
        except ValueError as exc:
            raise DatasetUnavailable(f"YOLO label line {lineno} is not numeric: {line!r}") from exc
        if cls < 0:
            raise DatasetUnavailable(f"YOLO label line {lineno} has a negative class id: {line!r}")
        x0 = max(0.0, (cx - w / 2.0) * width)
        y0 = max(0.0, (cy - h / 2.0) * height)
        x1 = min(float(width), (cx + w / 2.0) * width)
        y1 = min(float(height), (cy + h / 2.0) * height)
        if x1 - x0 < 1.0 or y1 - y0 < 1.0:
            continue
        boxes.append([x0, y0, x1, y1])
        labels.append(cls)
    if not boxes:
        return np.zeros((0, 4), dtype=np.float32), np.zeros((0,), dtype=np.int64)
    return np.asarray(boxes, dtype=np.float32), np.asarray(labels, dtype=np.int64)


def read_class_names(root: Path) -> list[str] | None:
    """Class names from the dataset yaml (``names`` as a list or an ``{id: name}`` mapping); ``None`` when absent."""
    root = Path(root)
    for name in YAML_CANDIDATES:
        path = root / name
        if path.is_file():
            break
    else:
        candidates = sorted(root.glob("*.yaml")) + sorted(root.glob("*.yml"))
        if not candidates:
            return None
        path = candidates[0]
    import yaml

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise DatasetUnavailable(f"cannot read class names from {path}: {exc}") from exc
    names = data.get("names") if isinstance(data, dict) else None
    if isinstance(names, dict):
        try:
            ordered = sorted(((int(k), str(v)) for k, v in names.items()), key=lambda kv: kv[0])
        except (TypeError, ValueError) as exc:
            raise DatasetUnavailable(f"{path}: 'names' mapping keys must be class ids") from exc
        return [v for _, v in ordered]
    if isinstance(names, list):
        return [str(v) for v in names]
    raise DatasetUnavailable(f"{path} carries no 'names' list")


def list_images(split_dir: Path) -> list[Path]:
    images_dir = Path(split_dir) / "images"
    if not images_dir.is_dir():
        raise DatasetUnavailable(f"YOLO split has no images directory: {images_dir}")
    return sorted(p for p in images_dir.iterdir() if p.suffix.lower() in IMAGE_EXTENSIONS and p.is_file())


def _label_path(image_path: Path) -> Path:
    return image_path.parent.parent / "labels" / (image_path.stem + ".txt")


def _load_image(path: Path, image_size: int) -> tuple[np.ndarray, int, int]:
    """uint8 CHW stretched to ``image_size`` square, with the source ``(width, height)``."""
    from PIL import Image

    try:
        with Image.open(path) as im:
            rgb = im.convert("RGB")
            width, height = rgb.size
            if (width, height) != (image_size, image_size):
                rgb = rgb.resize((image_size, image_size), Image.Resampling.BILINEAR)
            arr = np.asarray(rgb, dtype=np.uint8)
    except OSError as exc:
        raise DatasetUnavailable(f"cannot decode image {path}: {exc}") from exc
    return np.ascontiguousarray(arr.transpose(2, 0, 1)), width, height


def load_yolo_split(root: Path, split: str, *, image_size: int = DEFAULT_IMAGE_SIZE,
                    class_names: Sequence[str] | None = None,
                    excluded_classes: Sequence[str] = EXCLUDED_CLASSES,
                    max_images: int | None = None, seed: int = 0) -> DetectionSplit:
    """Read ``<root>/<split>/{images,labels}`` into a ``DetectionSplit`` at ``image_size``.

    Boxes of ``excluded_classes`` are dropped and images left without boxes are dropped; the kept classes
    are remapped to a contiguous 0-based list. ``max_images`` applies a seeded stratified cap by primary
    class. ``class_names`` defaults to the dataset yaml under ``root``.
    """
    root = Path(root)
    names = list(class_names) if class_names is not None else read_class_names(root)
    if not names:
        raise DatasetUnavailable(f"no class names: pass class_names or provide a yaml with 'names' under {root}")
    excluded = [c for c in excluded_classes if c in names]
    kept_ids = [i for i, c in enumerate(names) if c not in excluded]
    remap = {old: new for new, old in enumerate(kept_ids)}
    kept_names = [names[i] for i in kept_ids]
    if not kept_names:
        raise DatasetUnavailable("every class is excluded; nothing to load")

    split_dir = root / split
    images = list_images(split_dir)
    if not images:
        raise DatasetUnavailable(f"YOLO split {split!r} under {root} has no images")
    xs: list[np.ndarray] = []
    boxes: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    indices: list[int] = []
    filenames: list[str] = []
    n_excluded_boxes = 0
    n_dropped = 0
    for src_index, image_path in enumerate(images):
        label_path = _label_path(image_path)
        text = label_path.read_text(encoding="utf-8") if label_path.is_file() else ""
        arr, width, height = _load_image(image_path, image_size)
        raw_boxes, raw_labels = parse_yolo_label(text, width, height)
        if raw_labels.size and int(raw_labels.max()) >= len(names):
            raise DatasetUnavailable(f"{label_path}: class id {int(raw_labels.max())} outside {len(names)} names")
        keep = np.asarray([int(c) in remap for c in raw_labels], dtype=bool)
        n_excluded_boxes += int((~keep).sum())
        if not keep.any():
            n_dropped += 1
            continue
        sx, sy = image_size / float(width), image_size / float(height)
        scaled = raw_boxes[keep] * np.asarray([sx, sy, sx, sy], dtype=np.float32)
        xs.append(arr)
        boxes.append(np.clip(scaled, 0.0, float(image_size)).astype(np.float32))
        labels.append(np.asarray([remap[int(c)] for c in raw_labels[keep]], dtype=np.int64))
        indices.append(src_index)
        filenames.append(image_path.name)
    if not xs:
        raise DatasetUnavailable(f"YOLO split {split!r}: every image was dropped after excluding {excluded}")
    out = DetectionSplit(
        name=split, x=np.stack(xs), boxes=boxes, labels=labels, indices=np.asarray(indices, dtype=np.int64),
        class_names=kept_names, filenames=filenames, excluded_classes=excluded, n_boxes_excluded=n_excluded_boxes,
        n_images_dropped=n_dropped, seed=seed,
    )
    if max_images is not None and max_images < out.n:
        out = out.subset(np.sort(stratified_detection_indices(out, max_images, seed)))
    return out


def subset_root(assets_root: Path) -> Path:
    """Where B0 publishes the capped subset under the assets root."""
    return Path(assets_root) / SUBSET_RELATIVE_DIR


# ---------------------------------------------------------------------------
# Packed .npz slices
# ---------------------------------------------------------------------------

def pack_targets(boxes: Sequence[np.ndarray], labels: Sequence[np.ndarray]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """``(boxes (K, 4) float32, labels (K,) int64, offsets (n + 1,) int64)``."""
    if len(boxes) != len(labels):
        raise ValueError("boxes and labels disagree on the number of images")
    offsets = np.zeros(len(boxes) + 1, dtype=np.int64)
    flat_boxes: list[np.ndarray] = []
    flat_labels: list[np.ndarray] = []
    for i, (b, lab) in enumerate(zip(boxes, labels, strict=True)):
        b_arr = np.asarray(b, dtype=np.float32).reshape(-1, 4)
        l_arr = np.asarray(lab, dtype=np.int64).ravel()
        if b_arr.shape[0] != l_arr.shape[0]:
            raise ValueError(f"image {i}: {b_arr.shape[0]} boxes but {l_arr.shape[0]} labels")
        offsets[i + 1] = offsets[i] + b_arr.shape[0]
        flat_boxes.append(b_arr)
        flat_labels.append(l_arr)
    packed_boxes = np.concatenate(flat_boxes) if flat_boxes else np.zeros((0, 4), dtype=np.float32)
    packed_labels = np.concatenate(flat_labels) if flat_labels else np.zeros((0,), dtype=np.int64)
    return packed_boxes, packed_labels, offsets


def unpack_targets(boxes: np.ndarray, labels: np.ndarray, offsets: np.ndarray) -> tuple[list[np.ndarray], list[np.ndarray]]:
    offsets = np.asarray(offsets, dtype=np.int64)
    out_b: list[np.ndarray] = []
    out_l: list[np.ndarray] = []
    for i in range(offsets.shape[0] - 1):
        a, b = int(offsets[i]), int(offsets[i + 1])
        out_b.append(np.asarray(boxes[a:b], dtype=np.float32).reshape(-1, 4))
        out_l.append(np.asarray(labels[a:b], dtype=np.int64))
    return out_b, out_l


def save_detection_npz(path: Path, split: DetectionSplit, *, dataset_id: str = SUBSET_DATASET_ID,
                       dataset_revision: str | None = None) -> str:
    """Write a packed detection slice and return its sha256."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    boxes, labels, offsets = pack_targets(split.boxes, split.labels)
    payload: dict[str, Any] = {
        "x": np.asarray(split.x, dtype=np.uint8), "boxes": boxes, "labels": labels, "offsets": offsets,
        "indices": np.asarray(split.indices, dtype=np.int64), "class_names": np.asarray(split.class_names),
        "dataset_id": np.asarray(dataset_id), "excluded_classes": np.asarray(list(split.excluded_classes)),
        "split": np.asarray(split.name),
    }
    if split.filenames:
        payload["filenames"] = np.asarray(split.filenames)
    if dataset_revision is not None:
        payload["dataset_revision"] = np.asarray(dataset_revision)
    if split.seed is not None:
        payload["seed"] = np.asarray(int(split.seed))
    np.savez_compressed(path, **payload)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_detection_npz(path: Path) -> DetectionSplit:
    """Read a slice written by ``save_detection_npz``; malformed files raise ``DatasetUnavailable``."""
    path = Path(path)
    if not path.is_file():
        raise DatasetUnavailable(f"detection slice not found: {path}")
    try:
        with np.load(path, allow_pickle=False) as npz:
            x = np.asarray(npz["x"])
            boxes, labels = unpack_targets(np.asarray(npz["boxes"]), np.asarray(npz["labels"]),
                                           np.asarray(npz["offsets"]))
            indices = (np.asarray(npz["indices"], dtype=np.int64) if "indices" in npz
                       else np.arange(x.shape[0], dtype=np.int64))
            names = [str(s) for s in np.asarray(npz["class_names"]).tolist()]
            filenames = [str(s) for s in np.asarray(npz["filenames"]).tolist()] if "filenames" in npz else []
            excluded = ([str(s) for s in np.asarray(npz["excluded_classes"]).tolist()]
                        if "excluded_classes" in npz else [])
            split_name = str(np.asarray(npz["split"]).item()) if "split" in npz else "eval"
            seed = int(np.asarray(npz["seed"]).item()) if "seed" in npz else None
    except (OSError, KeyError, ValueError) as exc:
        raise DatasetUnavailable(f"cannot read detection slice {path}: {exc}") from exc
    if x.ndim != 4 or x.shape[1] != 3:
        raise DatasetUnavailable(f"detection slice {path} is not NCHW RGB: shape {x.shape}")
    if len(boxes) != x.shape[0]:
        raise DatasetUnavailable(f"detection slice {path}: {len(boxes)} box lists for {x.shape[0]} images")
    if any(lab.size and int(lab.max()) >= len(names) for lab in labels):
        raise DatasetUnavailable(f"detection slice {path}: a label falls outside the {len(names)} class names")
    return DetectionSplit(name=split_name, x=x, boxes=boxes, labels=labels, indices=indices, class_names=names,
                          filenames=filenames, excluded_classes=excluded, seed=seed)


def slice_provenance(path: Path) -> dict[str, str]:
    """``dataset_id`` / ``dataset_revision`` strings stored in a slice (empty when absent)."""
    out: dict[str, str] = {}
    try:
        with np.load(Path(path), allow_pickle=False) as npz:
            for key in ("dataset_id", "dataset_revision"):
                if key in npz:
                    out[key] = str(np.asarray(npz[key]).item())
    except (OSError, KeyError, ValueError) as exc:
        raise DatasetUnavailable(f"cannot read detection slice {path}: {exc}") from exc
    return out


# ---------------------------------------------------------------------------
# Synthetic split for tests (a test double, never evidence)
# ---------------------------------------------------------------------------

SYNTHETIC_DATASET_ID = "local:synthetic-detection-rectangles"
SYNTHETIC_CLASS_NAMES: tuple[str, ...] = ("red_block", "blue_block")
# Class colours in [0, 1] RGB. Deliberately far apart so a colour-evidence detector separates them.
_SYNTHETIC_COLOURS: tuple[tuple[float, float, float], ...] = ((0.90, 0.15, 0.15), (0.15, 0.25, 0.95))


def synthetic_detection_split(n: int, image_size: int = 16, *, seed: int = 0,
                              class_names: Sequence[str] = SYNTHETIC_CLASS_NAMES,
                              max_boxes: int = 2, name: str = "synthetic") -> DetectionSplit:
    """``n`` uint8 images of dark noise with one or two coloured rectangles as ground truth.

    Rectangles are between 35 and 55 percent of the side, never overlapping each other; each class has a
    fixed colour (``_SYNTHETIC_COLOURS``, cycled). Labelled ``synthetic``: a seeded stand-in for tests.
    """
    if n < 1:
        raise ValueError("n must be >= 1")
    if image_size < 8:
        raise ValueError("image_size must be >= 8")
    names = list(class_names)
    rng = np.random.default_rng(seed)
    x = np.zeros((n, 3, image_size, image_size), dtype=np.float32)
    boxes: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    lo, hi = max(3, int(round(image_size * 0.35))), max(4, int(round(image_size * 0.55)))
    for i in range(n):
        base = rng.uniform(0.02, 0.12, size=(3, 1, 1)).astype(np.float32)
        x[i] = base + rng.uniform(0.0, 0.04, size=(3, image_size, image_size)).astype(np.float32)
        k = int(rng.integers(1, max_boxes + 1))
        placed: list[list[float]] = []
        cls: list[int] = []
        for _ in range(k):
            for _attempt in range(20):
                w = int(rng.integers(lo, hi + 1))
                h = int(rng.integers(lo, hi + 1))
                x0 = int(rng.integers(0, image_size - w + 1))
                y0 = int(rng.integers(0, image_size - h + 1))
                cand = [float(x0), float(y0), float(x0 + w), float(y0 + h)]
                if all(cand[2] <= p[0] or cand[0] >= p[2] or cand[3] <= p[1] or cand[1] >= p[3] for p in placed):
                    break
            else:
                continue
            c = int(rng.integers(0, len(names)))
            colour = np.asarray(_SYNTHETIC_COLOURS[c % len(_SYNTHETIC_COLOURS)], dtype=np.float32)
            x[i, :, y0:y0 + h, x0:x0 + w] = colour[:, None, None]
            placed.append(cand)
            cls.append(c)
        if not placed:  # pragma: no cover - the first attempt always fits on an empty image
            raise RuntimeError("synthetic split could not place a rectangle")
        boxes.append(np.asarray(placed, dtype=np.float32))
        labels.append(np.asarray(cls, dtype=np.int64))
    x_uint8 = np.clip(np.rint(x * 255.0), 0, 255).astype(np.uint8)
    return DetectionSplit(name=name, x=x_uint8, boxes=boxes, labels=labels, indices=np.arange(n, dtype=np.int64),
                          class_names=names, seed=seed)


__all__ = [
    "CAVEATS", "DATASET_ID", "DEFAULT_IMAGE_SIZE", "EVAL_SLICE_NAME", "EXCLUDED_CLASSES", "IMAGE_EXTENSIONS",
    "KAGGLE_SLUG", "LICENSE", "LICENSE_NOTE", "SOURCE_URL", "SPLIT_DIRS", "SUBSET_DATASET_ID", "SUBSET_DIRNAME",
    "SUBSET_RELATIVE_DIR", "SYNTHETIC_CLASS_NAMES", "SYNTHETIC_DATASET_ID", "YAML_CANDIDATES", "DetectionSplit",
    "list_images", "load_detection_npz", "load_yolo_split", "pack_targets", "parse_yolo_label", "primary_labels",
    "read_class_names", "save_detection_npz", "slice_provenance", "stratified_detection_indices", "subset_root",
    "synthetic_detection_split", "unpack_targets",
]
