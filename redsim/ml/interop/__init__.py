"""Adversarial-dataset interoperability: Croissant + Parquet export of a run (INTEROP-05..12).

The export is a projection of a terminal campaign or verify record: one Parquet
shard per (attack, ε) plus the control family and the clean slice
(:mod:`redsim.ml.interop.parquet`), a Croissant JSON-LD manifest whose own sha256
is the dataset version with a projection-equality guard against the run's
``flip_matrix`` (:mod:`redsim.ml.interop.croissant`), and a template-rendered
dataset card (:mod:`redsim.ml.interop.card`). Every submodule keeps pyarrow
imports inside the functions, so importing this package never drags an ML/parse
library into the API process.
"""

from __future__ import annotations

from redsim.ml.interop.card import render_card
from redsim.ml.interop.croissant import (
    CROISSANT_1_0,
    CROISSANT_CONTEXT,
    CroissantValidationError,
    ExportMismatch,
    build_manifest,
    check_projection,
    croissant_validate,
    manifest_digest,
)
from redsim.ml.interop.parquet import (
    COLUMNS,
    FAMILY_ADVERSARIAL,
    FAMILY_CLEAN,
    FAMILY_CONTROL,
    LoadedSlice,
    Shard,
    build_shards,
    eps_tag,
    parse_npz,
    read_table,
    slice_descriptor_from_location,
)

__all__ = [
    "COLUMNS",
    "CROISSANT_1_0",
    "CROISSANT_CONTEXT",
    "CroissantValidationError",
    "ExportMismatch",
    "FAMILY_ADVERSARIAL",
    "FAMILY_CLEAN",
    "FAMILY_CONTROL",
    "LoadedSlice",
    "Shard",
    "build_manifest",
    "build_shards",
    "check_projection",
    "croissant_validate",
    "eps_tag",
    "manifest_digest",
    "parse_npz",
    "read_table",
    "render_card",
    "slice_descriptor_from_location",
]
