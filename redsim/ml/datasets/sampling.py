"""Seeded, stratified evaluation slices (spec section 11.5).

``Target.sample(n, seed)`` returns a slice with equal allocation per class
where the class has enough members. When a class is exhausted the remainder
is redistributed over the classes that still have members. The same
``(labels, n, seed)`` always yields the same indices, so a rerun with the same
``(dataset_revision, split, n, seed)`` sees the same rows.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np

from redsim.ml.targets.base import Sample


def per_class_counts(y: np.ndarray, class_names: Sequence[str]) -> dict[str, int]:
    """``{class_name: n}`` for every declared class (zero when absent)."""
    labels = np.asarray(y).reshape(-1)
    return {name: int(np.count_nonzero(labels == i)) for i, name in enumerate(class_names)}


def stratified_indices(y: np.ndarray, n: int, seed: int) -> np.ndarray:
    """Indices into ``y`` for a seeded, stratified slice of size ``min(n, len(y))``.

    Allocation: each round hands every class that still has members an equal
    share of what remains (the remainder of the division goes to a seeded
    subset of classes). A class that cannot fill its share is exhausted and
    drops out, so its shortfall flows to the others in the next round. Rows
    inside a class are chosen by a seeded permutation.
    """
    labels = np.asarray(y).reshape(-1)
    if n <= 0:
        raise ValueError("n must be positive")
    total = int(labels.shape[0])
    if total == 0:
        raise ValueError("cannot sample from an empty split")
    n = min(int(n), total)

    rng = np.random.default_rng(seed)
    classes = np.unique(labels)
    pools: dict[int, np.ndarray] = {}
    for c in classes:
        members = np.flatnonzero(labels == c)
        pools[int(c)] = members[rng.permutation(members.shape[0])]
    cap = {c: int(pool.shape[0]) for c, pool in pools.items()}
    alloc = {c: 0 for c in pools}

    active = sorted(pools)
    remaining = n
    while remaining > 0 and active:
        base, extra = divmod(remaining, len(active))
        # Which active classes receive one of the ``extra`` leftover rows is seeded, not positional.
        bonus = set(rng.permutation(len(active))[:extra].tolist())
        exhausted: list[int] = []
        for pos, c in enumerate(active):
            want = base + (1 if pos in bonus else 0)
            give = min(want, cap[c] - alloc[c])
            alloc[c] += give
            remaining -= give
            if alloc[c] >= cap[c]:
                exhausted.append(c)
        active = [c for c in active if c not in exhausted]

    chosen = np.concatenate([pools[c][: alloc[c]] for c in sorted(pools)]) if pools else np.empty(0, dtype=np.int64)
    chosen = chosen[rng.permutation(chosen.shape[0])]
    return chosen.astype(np.int64)


def as_model_input(x: np.ndarray) -> np.ndarray:
    """float32 view of ``x``. uint8 images are scaled to [0, 1]; floats pass through unchanged."""
    arr = np.asarray(x)
    if arr.dtype == np.uint8:
        return (arr.astype(np.float32) / 255.0).astype(np.float32)
    return arr.astype(np.float32, copy=False)


def stratified_sample(
    x: np.ndarray,
    y: np.ndarray,
    n: int,
    seed: int,
    class_names: Sequence[str],
    *,
    source_indices: np.ndarray | None = None,
) -> Sample:
    """Build a ``Sample`` from a full evaluation split held in memory.

    ``source_indices`` maps rows of ``x`` back to the source split when ``x``
    is itself a subset (for example a committed fixture slice), so
    ``Sample.indices`` always refers to the source split.
    """
    labels = np.asarray(y).reshape(-1)
    if labels.shape[0] != np.asarray(x).shape[0]:
        raise ValueError("x and y disagree on the number of rows")
    idx = stratified_indices(labels, n, seed)
    indices = np.asarray(source_indices)[idx] if source_indices is not None else idx
    return Sample(
        x=as_model_input(np.asarray(x)[idx]),
        y=labels[idx].astype(np.int64),
        indices=np.asarray(indices, dtype=np.int64),
        class_names=list(class_names),
    )


__all__ = ["as_model_input", "per_class_counts", "stratified_indices", "stratified_sample"]
