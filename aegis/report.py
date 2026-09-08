"""Aegis report generation — markdown and JSON outputs from scan findings."""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from aegis.schema import AegisFinding

if TYPE_CHECKING:
    from aegis.state import RunStateAPI

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _sort_findings(findings: list[AegisFinding]) -> list[AegisFinding]:
    """Sort findings by severity (critical first) then by title."""
    rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: (rank.get(f.severity.lower(), 99), f.title))


def _resolve_target(findings: list[AegisFinding]) -> str:
    """Determine target label from findings list."""
    targets = {f.target for f in findings if f.target}
    if len(targets) == 1:
        return targets.pop()
    if len(targets) > 1:
        return "Multiple targets"
    return "Unknown"


def _load_remediation_log(run_state: RunStateAPI) -> list[dict] | None:
    """Load remediation log if it exists, otherwise return None."""
    path = run_state.remediation_log_path
    if not path.exists():
        return None
    with open(path) as fh:
        data = json.load(fh)
    return data if data else None


def _load_stage_table(run_state: RunStateAPI) -> list[dict] | None:
    path = run_state.run_path / "stage_table.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    return data.get("stages") or None


def _load_verify_results(run_state: RunStateAPI) -> dict[str, dict]:
    verify_dir = run_state.run_path / "verify"
    if not verify_dir.exists():
        return {}
    out: dict[str, dict] = {}
    for f in verify_dir.glob("*.json"):
        out[f.stem] = json.loads(f.read_text())
    return out


def _load_evidence(run_state: RunStateAPI, finding_id: str) -> dict[str, dict] | None:
    evidence_dir = run_state.run_path / "artifacts" / "evidence" / finding_id
    if not evidence_dir.exists():
        return None
    out: dict[str, dict] = {}
    for name in ("before.json", "after.json"):
        path = evidence_dir / name
        if path.exists():
            out[name.removesuffix(".json")] = json.loads(path.read_text())
    return out or None


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def generate_markdown_report(run_state: RunStateAPI, findings: list[AegisFinding]) -> str:
    """Produce a full markdown security assessment report."""
    target = _resolve_target(findings)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    severity_counts = Counter(f.severity.lower() for f in findings)
    stages = _load_stage_table(run_state)
    verify_results = _load_verify_results(run_state)

    lines: list[str] = []
    _a = lines.append

    # Header
    _a("# Aegis Security Assessment Report")
    _a("")
    _a(f"**Run ID:** {run_state.run_id}")
    _a(f"**Date:** {date}")
    _a(f"**Target:** {target}")
    _a(f"**Total Findings:** {len(findings)}")
    _a("")

    # Stage table — live vs fixture provenance
    if stages:
        _a("## Stage Provenance")
        _a("")
        _a("| Stage | Mode | Success | Detail |")
        _a("|-------|------|---------|--------|")
        for s in stages:
            ok = "✓" if s.get("success") else "✗"
            _a(f"| {s.get('name','')} | {s.get('mode','')} | {ok} | {s.get('detail','')} |")
        _a("")

    # Summary table
    _a("## Summary")
    _a("")
    _a("| Severity | Count |")
    _a("|----------|-------|")
    for sev in _SEVERITY_ORDER:
        _a(f"| {sev.capitalize():<8} | {severity_counts.get(sev, 0):<5} |")
    _a("")

    # Findings
    _a("## Findings")
    _a("")

    sorted_findings = _sort_findings(findings)
    for finding in sorted_findings:
        tag = finding.severity.upper()
        _a(f"### [{tag}] {finding.title}")
        _a("")

        # Metadata line
        meta_parts = [f"**ID:** {finding.id}"]
        if finding.cwe:
            meta_parts.append(f"**CWE:** {finding.cwe}")
        if finding.cvss is not None:
            meta_parts.append(f"**CVSS:** {finding.cvss}")
        _a(" | ".join(meta_parts))

        if finding.affected_component:
            _a(f"**Component:** {finding.affected_component}")
        _a(f"**Status:** {finding.status}")
        _a("")

        # Description
        if finding.description:
            _a("#### Description")
            _a(finding.description)
            _a("")

        # Impact
        if finding.impact:
            _a("#### Impact")
            _a(finding.impact)
            _a("")

        # Proof of Concept
        if finding.poc_script_code:
            _a("#### Proof of Concept")
            _a("```")
            _a(finding.poc_script_code)
            _a("```")
            _a("")

        # Code locations
        if finding.code_locations:
            for loc in finding.code_locations:
                if loc.snippet:
                    _a("#### Vulnerable Code")
                    _a(f"**File:** {loc.file} (lines {loc.start_line}-{loc.end_line})")
                    _a("```")
                    _a(loc.snippet)
                    _a("```")
                    _a("")
                if loc.fix_after:
                    _a("#### Suggested Fix")
                    _a("```")
                    _a(loc.fix_after)
                    _a("```")
                    _a("")

        # Remediation steps
        if finding.remediation_steps:
            _a("#### Remediation Steps")
            _a(finding.remediation_steps)
            _a("")

        # Before/After verify panel
        verify = verify_results.get(finding.id)
        if verify:
            badge = {"verified": "✓ Verified", "still_vulnerable": "✗ Still vulnerable",
                     "inconclusive": "~ Inconclusive"}.get(verify.get("status", ""), verify.get("status", ""))
            _a(f"#### Verification — {badge}")
            _a(f"**Strategy:** {verify.get('strategy','')}")
            if verify.get("notes"):
                _a(f"**Notes:** {verify['notes']}")
            evidence = _load_evidence(run_state, finding.id)
            if evidence:
                if "after" in evidence:
                    after = evidence["after"]
                    _a("")
                    _a("**After (post-patch replay)**")
                    _a(f"- Status: `{after.get('status')}`")
                    if after.get("body_excerpt"):
                        excerpt = after["body_excerpt"][:200].replace("\n", " ")
                        _a(f"- Body excerpt: `{excerpt}`")
            _a("")

        _a("---")
        _a("")

    # Remediation actions section
    remediation_log = _load_remediation_log(run_state)
    if remediation_log:
        _a("## Remediation Actions")
        _a("")
        _a("| Finding ID | Action | Result | Success | Timestamp |")
        _a("|------------|--------|--------|---------|-----------|")
        for entry in remediation_log:
            success_str = "Yes" if entry.get("success") else "No"
            _a(
                f"| {entry.get('finding_id', '')} "
                f"| {entry.get('action', '')} "
                f"| {entry.get('result', '')} "
                f"| {success_str} "
                f"| {entry.get('timestamp', '')} |"
            )
        _a("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def generate_json_report(run_state: RunStateAPI, findings: list[AegisFinding]) -> dict[str, Any]:
    """Produce a structured JSON-serialisable report dict."""
    target = _resolve_target(findings)
    severity_counts = Counter(f.severity.lower() for f in findings)
    status_counts = Counter(f.status.lower() for f in findings)

    sorted_findings = _sort_findings(findings)

    report: dict = {
        "run_id": run_state.run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "summary": {
            "total": len(findings),
            "severity": {sev: severity_counts.get(sev, 0) for sev in _SEVERITY_ORDER},
            "statuses": dict(status_counts),
        },
        "findings": [f.to_dict() for f in sorted_findings],
    }

    remediation_log = _load_remediation_log(run_state)
    report["remediation_actions"] = remediation_log if remediation_log else []

    return report


# ---------------------------------------------------------------------------
# Save helpers
# ---------------------------------------------------------------------------

_HTML_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #222; }
h1, h2, h3, h4 { color: #1a1a2e; }
h2 { border-bottom: 1px solid #ddd; padding-bottom: .25rem; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
pre { background: #f4f4f6; padding: .75rem; border-radius: 6px; overflow-x: auto; }
code { background: #f4f4f6; padding: 0 .25rem; border-radius: 3px; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }
th, td { border: 1px solid #ddd; padding: .35rem .6rem; text-align: left; }
th { background: #f8f8fb; }
.severity-critical { color: #b00020; font-weight: 700; }
.severity-high     { color: #c25e00; font-weight: 700; }
.severity-medium   { color: #b08900; font-weight: 600; }
.severity-low      { color: #5a5a5a; }
.badge-verified         { color: #0a7f33; font-weight: 700; }
.badge-still_vulnerable { color: #b00020; font-weight: 700; }
.badge-inconclusive     { color: #8a6d00; font-weight: 600; }
hr { border: none; border-top: 1px dashed #ccc; margin: 1.5rem 0; }
"""


def html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;"))


def render_inline_markdown(s: str) -> str:
    s = html_escape(s)
    # bold **x**
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    # inline code `x`
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s


def _md_to_html_min(md: str) -> str:
    """Minimal Markdown → HTML so we don't introduce a heavy dependency.

    Handles headings, paragraphs, code fences, inline backticks, tables, and
    horizontal rules — enough for the report shape we generate. Not a general
    Markdown engine.
    """
    out: list[str] = []
    in_code = False
    code_buf: list[str] = []
    in_table = False
    table_rows: list[list[str]] = []

    def flush_table() -> None:
        nonlocal in_table, table_rows
        if not table_rows:
            in_table = False
            return
        out.append("<table>")
        for i, row in enumerate(table_rows):
            cells = [c.strip() for c in row]
            tag = "th" if i == 0 else "td"
            out.append("<tr>" + "".join(f"<{tag}>{html_escape(c)}</{tag}>" for c in cells) + "</tr>")
        out.append("</table>")
        table_rows = []
        in_table = False

    for raw in md.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            if in_code:
                out.append("<pre><code>" + html_escape("\n".join(code_buf)) + "</code></pre>")
                code_buf = []
                in_code = False
            else:
                if in_table:
                    flush_table()
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue
        if line.startswith("|") and line.endswith("|"):
            if not in_table:
                in_table = True
                table_rows = []
            cells = line.strip("|").split("|")
            # skip the markdown separator row like |---|---|
            if all(set(c.strip()) <= set("-:") for c in cells):
                continue
            table_rows.append(cells)
            continue
        elif in_table:
            flush_table()

        if line.startswith("# "):
            out.append(f"<h1>{render_inline_markdown(line[2:])}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{render_inline_markdown(line[3:])}</h2>")
        elif line.startswith("### "):
            out.append(f"<h3>{render_inline_markdown(line[4:])}</h3>")
        elif line.startswith("#### "):
            out.append(f"<h4>{render_inline_markdown(line[5:])}</h4>")
        elif line.strip() == "---":
            out.append("<hr/>")
        elif line.strip() == "":
            out.append("")
        else:
            out.append(f"<p>{render_inline_markdown(line)}</p>")
    if in_table:
        flush_table()
    if in_code:
        out.append("<pre><code>" + "\n".join(code_buf) + "</code></pre>")
    return "\n".join(out)


def generate_html_report(run_state: RunStateAPI, findings: list[AegisFinding]) -> str:
    md = generate_markdown_report(run_state, findings)
    body = _md_to_html_min(md)
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>Aegis Report — {run_state.run_id}</title>"
        f"<style>{_HTML_CSS}</style></head><body>{body}</body></html>"
    )


def save_reports(run_state: RunStateAPI, findings: list[AegisFinding],
                 *, html: bool = True) -> tuple[str, str]:
    """Generate and persist markdown + JSON (+ optional HTML) reports.

    Returns (markdown_path, json_path) as strings.
    """
    md_content = generate_markdown_report(run_state, findings)
    json_content = generate_json_report(run_state, findings)

    md_path = run_state.run_path / "report.md"
    json_path = run_state.run_path / "report.json"

    md_path.write_text(md_content)
    json_path.write_text(json.dumps(json_content, indent=2))

    if html:
        html_content = generate_html_report(run_state, findings)
        (run_state.run_path / "report.html").write_text(html_content)

    return str(md_path), str(json_path)
