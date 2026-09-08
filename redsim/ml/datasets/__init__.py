"""Dataset access for the ML vertical (spec section 11).

Every dataset here is open, unclassified and publicly available. Bytes are
fetched once at build time into the local work directory and read by the
worker afterwards. Nothing in this package fetches inside a test, and no
module here imports torch, ART or SHAP at import time.

Submodules (import them explicitly, this package stays light):

* ``sampling``   seeded, stratified evaluation slices -> ``Sample``
* ``image_hub``  HuggingFace hub helpers (revision lookup, file download, imagefolder decode)
* ``cifar10``    the ``uoft-cs/cifar10`` parquet loader (CI fixture dataset, never a demo target)
* ``url_features`` lexical URL features (written by the assets branch, imported lazily)
"""

from __future__ import annotations

import os
from pathlib import Path

from redsim.ml.errors import TargetUnavailable

WORK_DIR_ENV = "REDSIM_ML_WORK_DIR"
DEFAULT_WORK_DIR = "./redsim_output/ml"


class DatasetUnavailable(TargetUnavailable):
    """A dataset file or revision could not be fetched or failed its digest check."""


def work_dir() -> Path:
    """Local cache root for datasets and per-job work (``REDSIM_ML_WORK_DIR``)."""
    raw = os.environ.get(WORK_DIR_ENV, "").strip() or DEFAULT_WORK_DIR
    return Path(raw).expanduser()


__all__ = ["DEFAULT_WORK_DIR", "WORK_DIR_ENV", "DatasetUnavailable", "work_dir"]
