"""Report-rendering orchestration service."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.schema import AegisFinding
from aegis.state import RunState


@dataclass
class ReportOutcome:
    markdown_path: str
    json_path: str
    html_path: str | None


def render_reports(
    *,
    run_state: RunState,
    findings: list[AegisFinding],
    html: bool = True,
) -> ReportOutcome:
    from aegis.report import save_reports

    md_path, json_path = save_reports(run_state, findings, html=html)
    html_path = str(run_state.run_path / "report.html") if html else None
    return ReportOutcome(
        markdown_path=md_path,
        json_path=json_path,
        html_path=html_path,
    )
