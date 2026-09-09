"""LLM red-teaming through garak and the Pythia gateway (spec 11.6, 12.2, 17.4; plan 12 wave B2, llm-core).

The package is imported only by the worker and the tests. The API process
never imports it at module level (``tests/test_api_process_has_no_ml.py``
blocks ``garak``, ``openai`` and ``litellm``), and the modules split along that
boundary:

* ``catalog``        the committed probe catalog (``catalog.json``), pydantic and
                     json only; no garak import.
* ``scorecard``      ``LLMProbeScorecard`` with ``k / n`` denominators per probe
                     and detector, the validator that forbids every MRI, grade
                     or subscore key, and the standing LLM limitations (D9).
* ``rules``          deterministic interpretation and candidate recommendations
                     for probe hits; rule text only, never a narrative.
* ``report_section`` the Markdown / HTML fragment ``redsim.ml.reporting`` hooks in
                     (``reporting`` re-exports it as ``render_probe_reports``).
* ``schema``         re-exports the record models under the register's name and
                     carries ``LLM_STANDING_LIMITATIONS``.
* ``generator``      ``PythiaGenerator(garak.generators.openai.OpenAICompatible)``;
                     imports garak and the OpenAI client, so worker-child only.
* ``probe_child``    ``python -m redsim.ml.llm.probe_child --spec <json>``: one
                     garak run in a fresh, credential-minimised subprocess.
* ``runner``         the worker-parent side: work directory, 0600 key file,
                     allowlisted child environment, rlimits, wall clock,
                     process-group kill, secret scrubbing.

Nothing here computes an MRI, a grade or a subscore; LLM probe results never
enter ``redsim.ml.scoring`` (D9, spec 15.8).
"""

from __future__ import annotations

__all__ = [
    "catalog",
    "generator",
    "probe_child",
    "report_section",
    "reporting",
    "rules",
    "runner",
    "schema",
    "scorecard",
]
