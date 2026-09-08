"""Report-rendering orchestration service."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aegis.schema import AegisFinding

if TYPE_CHECKING:
    from aegis.state import RunStateAPI

logger = logging.getLogger(__name__)


@dataclass
class ReportOutcome:
    markdown_path: str
    json_path: str
    html_path: str | None


def render_reports(
    *,
    run_state: RunStateAPI,
    findings: list[AegisFinding],
    html: bool = True,
) -> ReportOutcome:
    from aegis.report import save_reports

    logger.info("render_reports start run_id=%s findings=%d html=%s",
                run_state.run_id, len(findings), html)
    md_path, json_path = save_reports(run_state, findings, html=html)
    html_path = str(run_state.run_path / "report.html") if html else None
    logger.info("render_reports finished run_id=%s markdown=%s json=%s",
                run_state.run_id, md_path, json_path)
    return ReportOutcome(
        markdown_path=md_path,
        json_path=json_path,
        html_path=html_path,
    )
