"""Deterministic Parquet shards for an adversarial-dataset export (INTEROP-05, -07).

One Parquet file per ``(attack, eps)`` adversarial slice, per-eps control slice
and the single clean slice, built with pyarrow from the slices a campaign run
persisted (``ml.adv_slice`` / ``ml.clean_slice`` / ``ml.control_slice``). Every
shard shares one fixed, nullable Arrow schema so a Croissant ``RecordSet`` can
type it once per family; rows are sorted by ``sample_index`` and the file is
written with a pinned writer configuration so two builds of the same slice are
byte-identical (``sha256`` is the shard's content id). ``pyarrow`` is imported
inside the functions only, so importing this module never pulls an ML/parse
library into the API process (``tests/test_api_process_has_no_ml.py``).

The input column is always a numeric feature vector or a flattened tensor,
never a raw string: a tabular export carries feature vectors, never the URL
string (spec 11.5, the D9 bound). A text-modality slice has no numeric input
tensor (the model consumes the message itself), so its rows leave ``input``
null and carry the message in the nullable ``text`` column; every other
modality leaves ``text`` null. Per-sample clean/adversarial predictions and
confidences are carried when the slice retained them and left null otherwise;
``flipped`` is computed from the retained predictions when present and taken
from the run's ``flip_matrix`` oracle otherwise (the projection guard in
``croissant.py`` checks either against that oracle).

A slice a modality runner writes is **self-describing**: besides the arrays it
carries the descriptor keys :data:`SLICE_META_KEYS` (``family``, ``attack``,
``eps``) so the export can label it whatever the blob backend did with its
name (the filesystem store keeps a pure digest path). The classification, text
and detection runners all write them (``redsim.ml.runners.base.slice_bytes``).
The storage location is only a fallback for slices written before the
descriptor existed.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from redsim.ml.schema import CampaignRecord

# The families a shard can belong to and the order they sort in.
FAMILY_CLEAN = "clean"
FAMILY_ADVERSARIAL = "adversarial"
FAMILY_CONTROL = "control"
_FAMILY_RANK = {FAMILY_CLEAN: 0, FAMILY_ADVERSARIAL: 1, FAMILY_CONTROL: 2}
CONTROL_ATTACK_LABEL = "control"

# The fixed column order of every shard. Integer/float/boolean columns are
# nullable so one schema fits clean, adversarial and control rows.
COLUMNS: tuple[str, ...] = (
    "family", "attack", "eps", "norm", "sample_index", "true_label", "flipped",
    "y_pred_clean", "y_pred_adv", "conf_clean", "conf_adv", "input", "text",
    "dataset_id", "dataset_revision", "run_id",
)

# Croissant field ``dataType`` per column (croissant.py reads this).
COLUMN_DATATYPES: dict[str, str] = {
    "family": "sc:Text", "attack": "sc:Text", "eps": "sc:Float", "norm": "sc:Text",
    "sample_index": "sc:Integer", "true_label": "sc:Integer", "flipped": "sc:Boolean",
    "y_pred_clean": "sc:Integer", "y_pred_adv": "sc:Integer",
    "conf_clean": "sc:Float", "conf_adv": "sc:Float", "input": "sc:Float", "text": "sc:Text",
    "dataset_id": "sc:Text", "dataset_revision": "sc:Text", "run_id": "sc:Text",
}


#: Descriptor keys the runner embeds in every slice ``.npz`` (INTEROP-04): ``family`` is one of the
#: three families above, ``attack`` the attack id (``""`` for the clean slice, ``"control"`` for the
#: control), ``eps`` the grid budget (absent on the clean slice). Zero-dimensional arrays; the strings
#: are unicode arrays, so ``allow_pickle=False`` loads them.
SLICE_META_KEYS: tuple[str, ...] = ("family", "attack", "eps")
#: Per-sample array keys of a slice, in the order the runner writes them (``text`` / ``text_adv`` are the
#: text runner's message columns; a detection slice adds its packed ``boxes`` / ``labels`` / ``offsets``).
SLICE_ARRAY_KEYS: tuple[str, ...] = (
    "x", "x_adv", "text", "text_adv", "indices", "y", "y_pred_clean", "y_pred_adv", "conf_clean", "conf_adv",
)


def eps_tag(eps: float) -> str:
    """``0.03 -> "eps0.03"`` — the tag the runner keys ``flip_matrix`` and slice names by."""
    return f"eps{float(eps):g}"


@dataclass
class LoadedSlice:
    """One retained slice: its family, the attack/eps it belongs to, and its arrays.

    ``arrays`` carries numpy arrays keyed ``x``/``x_adv`` (the input tensor), ``indices``,
    ``y`` (true label) and, when the slice retained them, ``y_pred_clean`` / ``y_pred_adv``
    / ``conf_clean`` / ``conf_adv``.
    """

    family: str
    attack: str
    eps: float | None
    arrays: dict[str, Any]


@dataclass
class Shard:
    """One Parquet file of the export."""

    name: str                 # e.g. "adversarial/fgsm_eps0.03.parquet"
    family: str
    attack: str
    eps: float | None
    n_rows: int
    data: bytes
    sha256: str
    size: int
    columns: list[str] = field(default_factory=lambda: list(COLUMNS))


def _slice_sort_key(sl: LoadedSlice) -> tuple[int, str, float]:
    return (_FAMILY_RANK.get(sl.family, 9), sl.attack or "", -1.0 if sl.eps is None else float(sl.eps))


def _shard_name(sl: LoadedSlice) -> str:
    if sl.family == FAMILY_CLEAN:
        return "clean/clean.parquet"
    tag = eps_tag(sl.eps) if sl.eps is not None else "all"
    if sl.family == FAMILY_CONTROL:
        return f"control/{tag}.parquet"
    return f"adversarial/{sl.attack}_{tag}.parquet"


def parse_npz(data: bytes) -> dict[str, Any]:
    """Load an ``.npz`` slice into a dict of arrays (no pickle)."""
    import numpy as np

    with np.load(io.BytesIO(data), allow_pickle=False) as npz:
        return {key: npz[key] for key in npz.files}


def _opt_int(value: Any, n: int) -> Any:
    import numpy as np

    if value is None:
        return None
    arr = np.asarray(value).astype("int64")
    return arr if arr.shape[0] == n else None


def _opt_float(value: Any, n: int) -> Any:
    import numpy as np

    if value is None:
        return None
    arr = np.asarray(value).astype("float64")
    return arr if arr.shape[0] == n else None


def _flip_oracle(flip_matrix: dict[str, Any] | None, attack: str, eps: float | None) -> dict[int, bool]:
    if not flip_matrix or eps is None:
        return {}
    indices = [int(i) for i in flip_matrix.get("indices", [])]
    flags = (flip_matrix.get("flipped", {}) or {}).get(attack, {}).get(eps_tag(eps))
    if flags is None:
        return {}
    return {idx: bool(flag) for idx, flag in zip(indices, flags)}


def _pa_schema() -> Any:
    import pyarrow as pa

    return pa.schema([
        ("family", pa.string()), ("attack", pa.string()), ("eps", pa.float64()),
        ("norm", pa.string()), ("sample_index", pa.int64()), ("true_label", pa.int64()),
        ("flipped", pa.bool_()), ("y_pred_clean", pa.int64()), ("y_pred_adv", pa.int64()),
        ("conf_clean", pa.float64()), ("conf_adv", pa.float64()), ("input", pa.list_(pa.float64())),
        ("text", pa.string()),
        ("dataset_id", pa.string()), ("dataset_revision", pa.string()), ("run_id", pa.string()),
    ])


def _write_parquet(columns: dict[str, list[Any]]) -> bytes:
    import pyarrow as pa
    import pyarrow.parquet as pq

    table = pa.Table.from_pydict(columns, schema=_pa_schema())
    buf = pa.BufferOutputStream()
    # Pinned writer configuration: zstd, the stable 2.6 format, no timestamps in
    # the data, statistics on (deterministic min/max). Given one pyarrow version
    # the ``created_by`` footer string is constant, so two writes of identical
    # rows are byte-identical and the shard sha256 is the content id.
    pq.write_table(table, buf, compression="zstd", version="2.6",
                   use_dictionary=False, write_statistics=True, store_schema=True)
    return bytes(buf.getvalue().to_pybytes())


def build_shards(record: CampaignRecord, loaded: list[LoadedSlice], *,
                 flip_matrix: dict[str, Any] | None) -> list[Shard]:
    """Build one deterministic Parquet shard per retained slice.

    Rows are a projection of the slice arrays: ``flipped`` is computed from the
    retained per-sample predictions when present, else taken from ``flip_matrix``.
    Every ``input`` is a numeric feature vector / flattened tensor — never a string;
    a text slice (``text`` / ``text_adv`` unicode arrays, no tensor) fills the
    ``text`` column instead and leaves ``input`` null.
    """
    import numpy as np

    norm = record.config.norm
    dataset_id = record.config.dataset_id
    dataset_rev = record.config.dataset_revision
    run_id = record.run_id
    shards: list[Shard] = []
    for sl in sorted(loaded, key=_slice_sort_key):
        arrays = sl.arrays
        x = arrays.get("x_adv")
        if x is None:
            x = arrays.get("x")
        text = _text_column(arrays) if x is None else None
        if (x is None and text is None) or "indices" not in arrays or "y" not in arrays:
            continue
        indices = np.asarray(arrays["indices"]).astype("int64")
        y = np.asarray(arrays["y"]).astype("int64")
        n = int(indices.shape[0])
        xf: Any = None
        if x is not None:
            xf = np.asarray(x, dtype="float64").reshape(n, -1) if n else np.zeros((0, 0), dtype="float64")
        elif text is not None and len(text) != n:
            continue
        ypc = _opt_int(arrays.get("y_pred_clean"), n)
        ypa = _opt_int(arrays.get("y_pred_adv"), n)
        conf_clean = _opt_float(arrays.get("conf_clean"), n)
        conf_adv = _opt_float(arrays.get("conf_adv"), n)

        if sl.family == FAMILY_ADVERSARIAL and ypc is not None and ypa is not None:
            flipped_col: list[Any] = [bool(int(ypc[i]) == int(y[i]) and int(ypa[i]) != int(y[i]))
                                      for i in range(n)]
        elif sl.family == FAMILY_ADVERSARIAL:
            oracle = _flip_oracle(flip_matrix, sl.attack, sl.eps)
            flipped_col = [oracle.get(int(indices[i])) for i in range(n)]
        else:
            flipped_col = [None] * n

        order = sorted(range(n), key=lambda i: int(indices[i]))
        eps_val = None if sl.eps is None else float(sl.eps)
        attack_val = "" if sl.family == FAMILY_CLEAN else sl.attack
        columns: dict[str, list[Any]] = {
            "family": [sl.family] * n,
            "attack": [attack_val] * n,
            "eps": [eps_val] * n,
            "norm": [norm] * n,
            "sample_index": [int(indices[i]) for i in order],
            "true_label": [int(y[i]) for i in order],
            "flipped": [flipped_col[i] for i in order],
            "y_pred_clean": [None if ypc is None else int(ypc[i]) for i in order],
            "y_pred_adv": [None if ypa is None else int(ypa[i]) for i in order],
            "conf_clean": [None if conf_clean is None else float(conf_clean[i]) for i in order],
            "conf_adv": [None if conf_adv is None else float(conf_adv[i]) for i in order],
            "input": [None if xf is None else [float(v) for v in xf[i]] for i in order],
            "text": [None if text is None else text[i] for i in order],
            "dataset_id": [dataset_id] * n,
            "dataset_revision": [dataset_rev] * n,
            "run_id": [run_id] * n,
        }
        data = _write_parquet(columns)
        shards.append(Shard(
            name=_shard_name(sl), family=sl.family, attack=attack_val, eps=eps_val,
            n_rows=n, data=data, sha256=hashlib.sha256(data).hexdigest(), size=len(data),
        ))
    return shards


def _text_column(arrays: dict[str, Any]) -> list[str] | None:
    """The per-sample message strings of a text slice (``text_adv`` first, else ``text``), or ``None``."""
    import numpy as np

    for key in ("text_adv", "text"):
        value = arrays.get(key)
        if value is None:
            continue
        arr = np.asarray(value)
        if arr.dtype.kind not in ("U", "S") or arr.ndim != 1:
            return None
        return [item.decode("utf-8") if isinstance(item, bytes) else str(item) for item in arr.tolist()]
    return None


def read_table(data: bytes) -> Any:
    """Read a shard's bytes back into a pyarrow ``Table`` (tests and the projection guard)."""
    import pyarrow.parquet as pq

    return pq.read_table(io.BytesIO(data))


# --------------------------------------------------------------------------- slice discovery

_SLICE_KINDS: dict[str, str] = {
    "ml.adv_slice": FAMILY_ADVERSARIAL,
    "ml.control_slice": FAMILY_CONTROL,
    "ml.clean_slice": FAMILY_CLEAN,
}


def _scalar_str(value: Any) -> str | None:
    import numpy as np

    arr = np.asarray(value)
    if arr.dtype.kind not in ("U", "S") or arr.size != 1:
        return None
    item = arr.reshape(-1)[0]
    return item.decode("utf-8") if isinstance(item, bytes) else str(item)


def slice_descriptor_from_arrays(arrays: dict[str, Any]) -> tuple[str, str, float | None] | None:
    """``(family, attack, eps)`` from the descriptor keys a self-describing slice carries, or ``None``.

    The runner writes ``family`` / ``attack`` as zero-dimensional unicode arrays and ``eps`` as a
    float scalar (absent on the clean slice). A slice without a recognised ``family`` yields ``None``
    so the caller falls back to :func:`slice_descriptor_from_location`.
    """
    import numpy as np

    family = _scalar_str(arrays.get("family"))
    if family not in _FAMILY_RANK:
        return None
    if family == FAMILY_CLEAN:
        return (FAMILY_CLEAN, "", None)
    eps: float | None = None
    raw_eps = arrays.get("eps")
    if raw_eps is not None:
        eps_arr = np.asarray(raw_eps)
        if eps_arr.size == 1 and eps_arr.dtype.kind in ("f", "i", "u"):
            value = float(eps_arr.reshape(-1)[0])
            eps = value if value == value else None   # NaN means "no budget"
    if family == FAMILY_CONTROL:
        return (FAMILY_CONTROL, CONTROL_ATTACK_LABEL, eps)
    attack = _scalar_str(arrays.get("attack"))
    if not attack or eps is None:
        return None
    return (FAMILY_ADVERSARIAL, attack, eps)


def slice_descriptor_from_location(location: str) -> tuple[str, str, float | None] | None:
    """``(family, attack, eps)`` parsed from a content-addressed blob location, or ``None``.

    The campaign sink keys a slice blob as ``<project>/<run>/<name>/<digest>`` and the
    S3 backend keeps that name in the object URI, so the runner's slice name
    (``adv_slice/<attack>_<eps_tag>.npz``, ``control_slice/<eps_tag>.npz``,
    ``clean_slice.npz``) is recoverable from the location. A pure-digest filesystem
    path carries no name and yields ``None`` — the export then states the slice could
    not be labelled rather than guessing.
    """
    text = str(location)
    if "adv_slice/" in text and "clean_slice" not in text and "control_slice" not in text:
        tail = text.split("adv_slice/", 1)[1].split("/", 1)[0]
        stem = tail[:-4] if tail.endswith(".npz") else tail
        if "_eps" in stem:
            attack, eps_str = stem.rsplit("_eps", 1)
            try:
                return (FAMILY_ADVERSARIAL, attack, float(eps_str))
            except ValueError:
                return None
        return None
    if "control_slice/" in text:
        tail = text.split("control_slice/", 1)[1].split("/", 1)[0]
        stem = tail[:-4] if tail.endswith(".npz") else tail
        eps_str = stem[3:] if stem.startswith("eps") else stem
        try:
            return (FAMILY_CONTROL, CONTROL_ATTACK_LABEL, float(eps_str))
        except ValueError:
            return (FAMILY_CONTROL, CONTROL_ATTACK_LABEL, None)
    if "clean_slice" in text:
        return (FAMILY_CLEAN, "", None)
    return None


__all__ = [
    "COLUMNS", "COLUMN_DATATYPES", "CONTROL_ATTACK_LABEL",
    "FAMILY_ADVERSARIAL", "FAMILY_CLEAN", "FAMILY_CONTROL",
    "SLICE_ARRAY_KEYS", "SLICE_META_KEYS",
    "LoadedSlice", "Shard", "build_shards", "eps_tag", "parse_npz",
    "read_table", "slice_descriptor_from_arrays", "slice_descriptor_from_location",
]
