"""SHAP explanations as supporting evidence (spec section 13).

``shap_image.explain`` / ``shap_tabular.explain`` return an ``ExplainOutput``:
per-sample ``Observation`` rows (each with its own ``expl_shift``) plus the
reference-row ``Measurement`` fields (``expl_shift_mean`` and its denominators,
the benign-noise floor and its denominator). ``stability.expl_shift`` is the
cosine-based explanation-shift metric that feeds ``S_expl``.
``summary.text_summary`` renders the deterministic text the LLM writer is
allowed to see. ``ExplanationCache`` is the digest-keyed on-disk cache of spec
13.10 and ``artifact_path`` reads the tabular per-sample artifacts by their spec
5.8 names or their pre-rename names. Heavy imports (torch, shap, matplotlib)
happen inside the functions so importing this package stays cheap.
"""

from redsim.ml.explain.base import (
    CACHE_DIR_ENV,
    CACHE_KEY_FIELDS,
    FEATURE_DIFF_NAME,
    LEGACY_ARTIFACT_NAMES,
    MEASUREMENT_FIELDS,
    SHAP_LIMITATION,
    ExplainOutput,
    ExplanationCache,
    artifact_path,
    force_plot_name,
    resolve_cache_dir,
)

__all__ = [
    "CACHE_DIR_ENV",
    "CACHE_KEY_FIELDS",
    "FEATURE_DIFF_NAME",
    "LEGACY_ARTIFACT_NAMES",
    "MEASUREMENT_FIELDS",
    "SHAP_LIMITATION",
    "ExplainOutput",
    "ExplanationCache",
    "artifact_path",
    "force_plot_name",
    "resolve_cache_dir",
]
