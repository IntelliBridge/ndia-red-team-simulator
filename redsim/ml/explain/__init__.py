"""SHAP explanations as supporting evidence (spec section 13).

``shap_image.explain`` / ``shap_tabular.explain`` return an ``ExplainOutput``;
``stability.expl_shift`` is the cosine-based explanation-shift metric that
feeds ``S_expl``; ``summary.text_summary`` renders the deterministic text the
LLM writer is allowed to see. Heavy imports (torch, shap, matplotlib) happen
inside the functions so importing this package stays cheap.
"""

from redsim.ml.explain.base import ExplainOutput

__all__ = ["ExplainOutput"]
