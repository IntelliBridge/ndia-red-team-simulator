"""The input contract an uploaded model declares (spec 11.3.1: normalisation lives inside the model).

Pure Python, no numpy or torch, so the API process can validate the multipart fields of
``POST /v1/models`` (``input_scale``, ``input_mean``, ``input_std``, ``input_resize``,
``input_layout``) before a byte is stored, and the worker's loader
(``redsim.ml.targets.artifact``) applies the same block inside the sandbox child.

The campaign always perturbs [0, 1] NCHW pixels at the evaluation slice's resolution. An
open-weights model trained on another contract (raw 0-255 pixels, ImageNet mean / std,
upsampled inputs, a channels-last graph) declares it here. The loader folds the block into the
estimator in this order: resize, scale, ``(x - mean) / std``, layout. Epsilon keeps its meaning,
the graph is never edited, and every value is recorded in the manifest.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

INPUT_LAYOUTS: tuple[str, ...] = ("NCHW", "NHWC")
MIN_INPUT_RESIZE = 8
MAX_INPUT_RESIZE = 1024

#: Multipart field -> block key.
FORM_FIELDS: dict[str, str] = {
    "input_scale": "scale",
    "input_mean": "mean",
    "input_std": "std",
    "input_resize": "resize",
    "input_layout": "layout",
}

_KEYS: frozenset[str] = frozenset(FORM_FIELDS.values())


class InputPreprocessingError(ValueError):
    """A block that does not describe a valid contract; ``field`` names the offending key."""

    code = "params_out_of_range"

    def __init__(self, message: str, *, field: str = "input_preprocessing") -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class InputPreprocessing:
    """What the uploaded model consumes, applied in this order: resize, scale, (x - mean) / std, layout."""

    scale: float = 1.0
    mean: tuple[float, ...] | None = None
    std: tuple[float, ...] | None = None
    resize: int | None = None
    layout: str | None = None      # ``None``: NCHW for a state_dict; sniffed from the graph for ONNX

    @property
    def is_identity(self) -> bool:
        return self.scale == 1.0 and self.mean is None and self.resize is None

    def record(self) -> dict[str, Any]:
        return {"scale": self.scale, "mean": list(self.mean) if self.mean else None,
                "std": list(self.std) if self.std else None, "resize": self.resize, "layout": self.layout}


def _floats(value: Any, key: str) -> tuple[float, ...]:
    items = list(value) if isinstance(value, (list, tuple)) else [value]
    try:
        out = tuple(float(v) for v in items)
    except (TypeError, ValueError) as exc:
        raise InputPreprocessingError(f"input_preprocessing.{key} must be numbers", field=key) from exc
    if not out or any(not math.isfinite(v) for v in out):
        raise InputPreprocessingError(f"input_preprocessing.{key} must be finite numbers", field=key)
    return out


def parse_input_preprocessing(block: Mapping[str, Any] | None) -> InputPreprocessing:
    """Validate the manifest's ``input_preprocessing`` block; ``{}`` or ``None`` is the identity."""
    if not block:
        return InputPreprocessing()
    if not isinstance(block, Mapping):
        raise InputPreprocessingError("input_preprocessing must be an object")
    unknown = sorted(set(block) - _KEYS)
    if unknown:
        raise InputPreprocessingError(f"input_preprocessing has unknown keys {unknown}")
    scale = _floats(block["scale"], "scale")[0] if block.get("scale") is not None else 1.0
    if scale <= 0:
        raise InputPreprocessingError("input_preprocessing.scale must be > 0", field="scale")
    mean = _floats(block["mean"], "mean") if block.get("mean") is not None else None
    std = _floats(block["std"], "std") if block.get("std") is not None else None
    if (mean is None) != (std is None):
        raise InputPreprocessingError("input_preprocessing.mean and .std come together",
                                      field="std" if std is None else "mean")
    if mean is not None and std is not None:
        if len(mean) != len(std) or len(mean) not in (1, 3):
            raise InputPreprocessingError("input_preprocessing.mean and .std need 1 or 3 matching per-channel "
                                          "values", field="mean")
        if any(v <= 0 for v in std):
            raise InputPreprocessingError("input_preprocessing.std must be > 0 on every channel", field="std")
    resize: int | None = None
    if block.get("resize") is not None:
        raw = block["resize"]
        try:
            resize = int(raw)
        except (TypeError, ValueError) as exc:
            raise InputPreprocessingError("input_preprocessing.resize must be an integer", field="resize") from exc
        if isinstance(raw, float) and raw != resize:
            raise InputPreprocessingError("input_preprocessing.resize must be an integer", field="resize")
        if not MIN_INPUT_RESIZE <= resize <= MAX_INPUT_RESIZE:
            raise InputPreprocessingError(f"input_preprocessing.resize must be within "
                                          f"[{MIN_INPUT_RESIZE}, {MAX_INPUT_RESIZE}]", field="resize")
    layout: str | None = None
    if block.get("layout") is not None:
        layout = str(block["layout"]).strip().upper()
        if layout not in INPUT_LAYOUTS:
            raise InputPreprocessingError(f"input_preprocessing.layout must be one of {list(INPUT_LAYOUTS)}",
                                          field="layout")
    return InputPreprocessing(scale=scale, mean=mean, std=std, resize=resize, layout=layout)


def _form_value(raw: Any, key: str) -> Any:
    """A multipart field: a JSON array, a comma or space separated list, or one scalar."""
    text = str(raw).strip()
    if not text:
        return None
    if key in {"mean", "std"}:
        if text.startswith("["):
            try:
                value = json.loads(text)
            except json.JSONDecodeError as exc:
                raise InputPreprocessingError(f"input_{key} is not a JSON array", field=key) from exc
            if not isinstance(value, list):
                raise InputPreprocessingError(f"input_{key} must be a list of numbers", field=key)
            return value
        return [part for part in text.replace(",", " ").split() if part]
    if key == "layout":
        return text
    return text


def preprocessing_from_fields(fields: Mapping[str, Any]) -> dict[str, Any] | None:
    """The block the API stores in the upload manifest from the multipart fields, or ``None`` when absent.

    Raises :class:`InputPreprocessingError` (``params_out_of_range``) naming the form field.
    """
    block: dict[str, Any] = {}
    try:
        for form_key, key in FORM_FIELDS.items():
            raw = fields.get(form_key)
            if raw is None:
                continue
            value = _form_value(raw, key)
            if value is not None:
                block[key] = value
        if not block:
            return None
        parsed = parse_input_preprocessing(block)
    except InputPreprocessingError as exc:
        form_field = next((form for form, key in FORM_FIELDS.items() if key == exc.field), exc.field)
        raise InputPreprocessingError(str(exc), field=form_field) from exc
    return parsed.record()


def sniff_input_layout(dims: tuple[int | None, ...]) -> str:
    """``NHWC`` when a rank-3 signature ends in 1 or 3 channels and does not start with them, else ``NCHW``."""
    if len(dims) == 3 and dims[2] in (1, 3) and dims[0] not in (1, 3):
        return "NHWC"
    return "NCHW"


__all__ = [
    "FORM_FIELDS",
    "INPUT_LAYOUTS",
    "MAX_INPUT_RESIZE",
    "MIN_INPUT_RESIZE",
    "InputPreprocessing",
    "InputPreprocessingError",
    "parse_input_preprocessing",
    "preprocessing_from_fields",
    "sniff_input_layout",
]
