"""Report entry points of the LLM track under the name the register uses (LLM-17).

The renderers live in :mod:`redsim.ml.llm.report_section`; this module
re-exports them so ``redsim.ml.llm.reporting.render_probe_reports(scorecard,
findings, recommendations, artifacts=...)`` is the worker task's call and
``render_llm_section`` the hook ``redsim.ml.reporting`` embeds.
"""

from __future__ import annotations

from redsim.ml.llm.report_section import (
    LLM_SECTION_HEADING,
    SECTION_HEADINGS,
    LLMSectionFragments,
    check_llm_report_text,
    extract_scorecard,
    render_llm_html,
    render_llm_markdown,
    render_llm_reports,
    render_llm_section,
    render_probe_reports,
)

render_reports = render_probe_reports

__all__ = [
    "LLM_SECTION_HEADING",
    "SECTION_HEADINGS",
    "LLMSectionFragments",
    "check_llm_report_text",
    "extract_scorecard",
    "render_llm_html",
    "render_llm_markdown",
    "render_llm_reports",
    "render_llm_section",
    "render_probe_reports",
    "render_reports",
]
