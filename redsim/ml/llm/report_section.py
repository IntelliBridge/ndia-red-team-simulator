"""Report fragments for LLM probe runs (LLM-14, -17, -18).

:func:`render_llm_section` renders one :class:`LLMProbeScorecard` (with its
rule outputs) as the Markdown and HTML fragment ``redsim.ml.reporting`` hooks
into the report route, and :func:`render_llm_reports` produces the full
``report.{md,json,html}`` triple in the same shape as
``redsim.ml.reporting.render_campaign_reports`` so ``GET /v1/runs/{id}/report.*``
serves probe runs unchanged.

Seven sections in this order: configuration and provenance; probe scorecard
(per family, per probe, per detector, ``k / n`` beside every rate, status and
reason for rows that did not run, garak's CI when present); findings (ids,
severity labelled as derived from the hit rate, ``k / n``); interpretation;
candidate recommendations (``candidate``); limitations;
stored artifacts (ids, kinds, digests; "prompts and responses are stored, not
displayed"). The D9 sentence appears exactly once, in the scorecard header.

``render_llm_section`` accepts the scorecard itself, its JSON dump, or any
record that carries one (``.scorecard``, ``.llm_scorecard`` or
``provenance.model_manifest["llm_scorecard"]``); a record without one renders
an honest one-line note instead of a scorecard. The returned fragment iterates
as Markdown lines, which is how ``redsim.ml.reporting._llm_section`` embeds it.

No prompt or response text ever reaches these fragments: the scorecard has
none, and every user-derived string (model id, persona, reasons) is one-line
text in the Markdown and escaped once at the HTML boundary through
``redsim.report``'s helpers. :func:`check_llm_report_text` is the guard the
tests run: no banned score word, and the words ``MRI`` or ``grade`` only in the
D9 sentence.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from redsim.ml.llm.rules import NARRATIVE_NOT_OFFERED_REASON, interpret, recommend
from redsim.ml.llm.scorecard import D9_SENTENCE, LLMProbeScorecard, assert_no_mri
from redsim.ml.schema import CandidateRecommendation, Interpretation, contains_banned_score_word
from redsim.report import _HTML_CSS, _md_to_html_min, html_escape

REPORT_TITLE = "# Redsim LLM probe report (garak through Pythia)"
SECTION_HEADINGS: tuple[str, ...] = (
    "## 1. Configuration and provenance",
    "## 2. Probe scorecard",
    "## 3. Findings",
    "## 4. Interpretation",
    "## 5. Candidate recommendations",
    "## 6. Limitations",
    "## 7. Stored artifacts",
)
LLM_SECTION_HEADING = "## LLM probe scorecard (garak through Pythia)"
NO_SCORECARD_NOTE = ("No LLM probe scorecard is attached to this record; `GET /v1/runs/{id}/llm-scorecard` serves "
                     "the k / n table once the run has written one. Nothing is shown in its place.")
INVALID_SCORECARD_NOTE = "An LLM scorecard is attached but does not validate against llm-probe-scorecard-1 ({error}); it is not shown."
SEVERITY_BASIS_NOTE = "Severity is derived from the hit rate of one probe row (its own bands); it is not a score of the model."
NOT_EVALUATED = "Not evaluated on this model: redsim does not measure mitigations on an LLM target"
ARTIFACT_NOTE = "Prompts and responses are stored in garak's report.jsonl and hitlog.jsonl artifacts, not displayed."
UNAVAILABLE = "—"
_MRI_WORDS = re.compile(r"\b(MRI|grade|graded|grading)\b")


def _text(value: Any) -> str:
    return " ".join(str(value).split())


def _cell(value: Any) -> str:
    if value is None:
        return UNAVAILABLE
    text = _text(value).replace("|", "¦")
    return text or UNAVAILABLE


def _code(value: Any) -> str:
    return "`" + (_text(value).replace("`", "") or UNAVAILABLE) + "`"


def _when(value: datetime | None) -> str:
    return UNAVAILABLE if value is None else value.isoformat()


def _table(header: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    cells = [_cell(h) for h in header]
    lines = ["| " + " | ".join(cells) + " |", "|" + "|".join("---" for _ in cells) + "|"]
    lines.extend("| " + " | ".join(_cell(c) for c in row) + " |" for row in rows)
    return lines


def _ci(row: Any) -> str:
    if row.ci_lower is None or row.ci_upper is None:
        return UNAVAILABLE
    level = f"{row.ci_confidence:g}" if row.ci_confidence is not None else "?"
    return f"[{row.ci_lower:.4f}, {row.ci_upper:.4f}] ({row.ci_method or 'ci'}, {level})"


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def _section_configuration(card: LLMProbeScorecard, generated_at: datetime) -> list[str]:
    totals = card.totals()
    lines = [SECTION_HEADINGS[0], "",
             f"- **Run:** {_code(card.run_id)} (kind {_code(card.kind)}, status {_code(card.status)}, "
             f"completeness {_code(card.completeness)}); generated {generated_at.isoformat()}",
             f"- **Target:** {_code(card.target_id)}; model id {_code(card.model_id)}; gateway host "
             f"{_code(card.gateway_host)}; persona {_code(card.persona)}; guardrail_mode {_code(card.guardrail_mode)}",
             f"- **Versions:** garak {_code(card.garak_version)} (catalog built from {_code(card.catalog_garak_version)}"
             + (f", catalog sha256 {_code(card.catalog_sha256)}" if card.catalog_sha256 else "")
             + f"); redsim {_code(card.redsim_version)}",
             f"- **Probe set:** {_code(card.probe_set) if card.probe_set else 'explicit probe ids'}; probes requested "
             f"{totals['n_probes_requested']}, run "
             f"{totals['n_probes_run']}, not run {totals['n_probes_not_run']}, failed {totals['n_probes_failed']}",
             f"- **Settings:** max_prompts_per_probe {card.max_prompts_per_probe}, seed {card.seed}, generations "
             f"{card.generations}, detector_mode {_code(card.detector_mode)}, extended detectors "
             f"{'on' if card.extended_detectors else 'off'}, eval threshold {card.eval_threshold:g}",
             f"- **Timestamps:** started {_when(card.started_at)}, finished {_when(card.finished_at)}",
             f"- **Gateway usage:** {card.usage.requests} requests ({card.usage.responses_ok} ok, "
             f"{card.usage.retries} retries), prompt tokens {card.usage.prompt_tokens}, completion tokens "
             f"{card.usage.completion_tokens}, wall time {card.usage.wall_time_s:.2f} s, TLS {_code(card.usage.tls_mode)}"
             + (f", cost {card.usage.cost_cents} cents" if card.usage.cost_cents is not None else "")
             + (", model not priced" if card.usage.unpriced_model else ""),
             ]
    if card.usage.models_seen:
        seen = ", ".join(f"{_text(m)} ({n})" for m, n in sorted(card.usage.models_seen.items()))
        lines.append(f"- **Model ids the gateway answered with:** {seen}")
    if card.probe_ids_requested:
        lines.append("- **Probes requested:** " + ", ".join(_code(p) for p in card.probe_ids_requested))
    if card.error:
        lines.append(f"- **Run error:** {_text(card.error)}")
    return lines


def _section_scorecard(card: LLMProbeScorecard) -> list[str]:
    lines = [SECTION_HEADINGS[1], "", D9_SENTENCE,
             "Each row is k hits / n evaluated outputs for one probe and one detector; a hit is the detector "
             "firing on the model's output. Rows are read one by one: there is no pooled rate across probes or families.",
             ""]
    if not card.families:
        lines.append("No probe rows were recorded.")
        return lines
    for family in card.families:
        lines += [f"### Family {_code(family.family)} ({family.n_probes_run} run, {family.n_probes_not_run} not run, "
                  f"{family.n_probes_failed} failed)", ""]
        rows: list[list[Any]] = []
        for probe in family.probes:
            if probe.status != "run":
                rows.append([probe.probe_id, probe.short_id, probe.tier_name, probe.status, probe.reason,
                             UNAVAILABLE, UNAVAILABLE, UNAVAILABLE, UNAVAILABLE, UNAVAILABLE])
                continue
            if not probe.detectors:
                rows.append([probe.probe_id, probe.short_id, probe.tier_name, "run", "no detector row recorded",
                             UNAVAILABLE, probe.n_prompts_sent, UNAVAILABLE, UNAVAILABLE, UNAVAILABLE])
            for row in probe.detectors:
                rows.append([probe.probe_id, probe.short_id, probe.tier_name, row.status,
                             row.reason or (probe.goal or UNAVAILABLE), row.detector, probe.n_prompts_sent,
                             row.fraction() if row.status == "run" else UNAVAILABLE,
                             row.n_none if row.status == "run" else UNAVAILABLE, _ci(row)])
        lines += _table(["probe", "short id", "tier", "status", "goal / reason", "detector", "prompts sent",
                         "hits k/n (rate)", "unscored", "CI"], rows)
        lines.append("")
    return lines


def _field(item: Any, *names: str) -> Any:
    for name in names:
        if isinstance(item, Mapping):
            if name in item and item[name] is not None:
                return item[name]
        else:
            value = getattr(item, name, None)
            if value is not None:
                return value
    return None


def _section_findings(findings: Sequence[Any] | None) -> list[str]:
    lines = [SECTION_HEADINGS[2], "", SEVERITY_BASIS_NOTE, ""]
    if not findings:
        lines.append("No findings were projected for this run (no row crossed the finding threshold, or the "
                     "projection did not run).")
        return lines
    rows: list[list[Any]] = []
    for item in findings:
        detail = _field(item, "llm", "detail") or {}
        k = _field(item, "n_hits") if _field(item, "n_hits") is not None else _field(detail, "n_hits")
        n = _field(item, "n_evaluated") if _field(item, "n_evaluated") is not None else _field(detail, "n_evaluated")
        fraction = f"{int(k)}/{int(n)}" if isinstance(k, (int, float)) and isinstance(n, (int, float)) else UNAVAILABLE
        rows.append([
            _field(item, "id", "finding_id"), _field(item, "title"), _field(item, "severity"),
            _field(item, "probe_id") or _field(detail, "probe_id"), _field(item, "detector") or _field(detail, "detector"),
            fraction, _field(item, "status"),
        ])
    lines += _table(["finding", "title", "severity (derived from hit rate)", "probe", "detector", "hits k/n",
                     "status"], rows)
    return lines


def _section_interpretation(interpretations: Sequence[Interpretation]) -> list[str]:
    lines = [SECTION_HEADINGS[3], "", "Statements are inferred from the rows they cite; the threshold is printed in each.", ""]
    if not interpretations:
        lines.append("No interpretation: no row was evaluated.")
        return lines
    for item in interpretations:
        lines.append(f"- {_code(item.id)} ({item.kind}; basis {', '.join(_code(b) for b in item.basis)}): {_text(item.statement)}")
    return lines


def _section_recommendations(recommendations: Sequence[CandidateRecommendation]) -> list[str]:
    lines = [SECTION_HEADINGS[4], "", f"Narrative: {NARRATIVE_NOT_OFFERED_REASON}", ""]
    if not recommendations:
        lines.append("No candidate recommendation: no row crossed the threshold and no probe ran.")
        return lines
    for rec in recommendations:
        lines += [f"### {_code(rec.id)} {_text(rec.title)} ({rec.status})", "",
                  f"- **Rationale:** {_text(rec.rationale)}",
                  f"- **{NOT_EVALUATED}**",
                  f"- **Triggered by:** {', '.join(_code(t) for t in rec.triggered_by)}",
                  f"- **References:** {', '.join(_code(r) for r in rec.references) or UNAVAILABLE}",
                  f"- **Source:** {rec.narrative_source}", ""]
    return lines


def _section_limitations(card: LLMProbeScorecard) -> list[str]:
    lines = [SECTION_HEADINGS[5], ""]
    lines += [f"- {_text(item)}" for item in card.limitations if item != D9_SENTENCE]
    return lines


def _section_artifacts(card: LLMProbeScorecard, artifacts: Mapping[str, Mapping[str, Any]] | None) -> list[str]:
    lines = [SECTION_HEADINGS[6], "", ARTIFACT_NOTE, ""]
    rows: list[list[Any]] = []
    if artifacts:
        for name, meta in sorted(artifacts.items()):
            rows.append([name, meta.get("kind"), meta.get("id"), meta.get("sha256"), meta.get("size_bytes")])
    elif card.artifacts:
        for name, digest in sorted(card.artifacts.items()):
            rows.append([name, UNAVAILABLE, UNAVAILABLE, digest, UNAVAILABLE])
    if rows:
        lines += _table(["artifact", "kind", "id", "sha256", "bytes"], rows)
    else:
        lines.append("No artifacts recorded.")
    return lines


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LLMSectionFragments:
    """Markdown and HTML of the LLM block; iterating yields the Markdown lines."""

    markdown: str
    html: str
    scorecard: LLMProbeScorecard | None = None

    def __iter__(self) -> Iterator[str]:
        return iter(self.markdown.splitlines())

    def __str__(self) -> str:
        return self.markdown

    @property
    def lines(self) -> list[str]:
        return self.markdown.splitlines()


def extract_scorecard(record: Any) -> LLMProbeScorecard | None:
    """The scorecard in ``record``, or ``None``: the model, its dump, or a record that carries one."""
    if isinstance(record, LLMProbeScorecard):
        return record
    if isinstance(record, Mapping):
        if "families" in record or "schema_version" in record:
            return LLMProbeScorecard.model_validate(dict(record))
        for key in ("llm_scorecard", "scorecard"):
            if key in record:
                return extract_scorecard(record[key])
        return None
    for attr in ("llm_scorecard", "scorecard"):
        value = getattr(record, attr, None)
        if value is not None:
            return extract_scorecard(value)
    manifest = getattr(getattr(record, "provenance", None), "model_manifest", None)
    if isinstance(manifest, Mapping):
        for key in ("llm_scorecard", "scorecard"):
            if key in manifest:
                return extract_scorecard(manifest[key])
    return None


def _coerce(record: Any) -> LLMProbeScorecard:
    card = extract_scorecard(record)
    if card is None:
        raise TypeError("no LLM probe scorecard in the record")
    assert_no_mri(card)
    return card


def _coerce_recommendations(items: Sequence[Any] | None) -> list[CandidateRecommendation]:
    return [i if isinstance(i, CandidateRecommendation) else CandidateRecommendation.model_validate(i) for i in items or ()]


def _coerce_interpretations(items: Sequence[Any] | None) -> list[Interpretation]:
    return [i if isinstance(i, Interpretation) else Interpretation.model_validate(i) for i in items or ()]


def render_llm_markdown(
    record: Any,
    *,
    findings: Sequence[Any] | None = None,
    interpretations: Sequence[Any] | None = None,
    recommendations: Sequence[Any] | None = None,
    artifacts: Mapping[str, Mapping[str, Any]] | None = None,
    hit_threshold: float | None = None,
    generated_at: datetime | None = None,
    title: bool = True,
) -> str:
    """The seven sections in order; user strings unescaped (the HTML boundary escapes once)."""
    card = _coerce(record)
    stamp = generated_at if generated_at is not None else datetime.now(UTC)
    kwargs = {"hit_threshold": hit_threshold} if hit_threshold is not None else {}
    interp = _coerce_interpretations(interpretations) if interpretations is not None else interpret(card, **kwargs)
    recs = _coerce_recommendations(recommendations) if recommendations is not None else recommend(card, **kwargs)
    parts: list[str] = [REPORT_TITLE, ""] if title else []
    for section in (
        _section_configuration(card, stamp),
        _section_scorecard(card),
        _section_findings(findings),
        _section_interpretation(interp),
        _section_recommendations(recs),
        _section_limitations(card),
        _section_artifacts(card, artifacts),
    ):
        parts.extend(section)
        parts.append("")
    return "\n".join(parts).rstrip("\n") + "\n"


def render_llm_html_fragment(markdown: str) -> str:
    """The Markdown as an HTML fragment (no document wrapper), escaped by ``redsim.report``."""
    return _md_to_html_min(markdown)


def render_llm_html(markdown: str, record: Any) -> str:
    card = _coerce(record)
    title = html_escape(f"Redsim LLM probe report — {card.run_id}")
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{title}</title><style>{_HTML_CSS}</style></head><body>{_md_to_html_min(markdown)}</body></html>"
    )


def render_llm_section(
    record: Any,
    *,
    findings: Sequence[Any] | None = None,
    interpretations: Sequence[Any] | None = None,
    recommendations: Sequence[Any] | None = None,
    artifacts: Mapping[str, Mapping[str, Any]] | None = None,
    hit_threshold: float | None = None,
    generated_at: datetime | None = None,
) -> LLMSectionFragments:
    """The fragment ``redsim.ml.reporting`` embeds: headed by :data:`LLM_SECTION_HEADING`, no H1.

    A record without a scorecard, or with one that does not validate, yields the
    heading plus an honest one-line note; nothing is invented in its place.
    """
    try:
        card = extract_scorecard(record)
    except (ValidationError, ValueError) as exc:
        markdown = f"{LLM_SECTION_HEADING}\n\n{INVALID_SCORECARD_NOTE.format(error=type(exc).__name__)}\n"
        return LLMSectionFragments(markdown=markdown, html=render_llm_html_fragment(markdown))
    if card is None:
        markdown = f"{LLM_SECTION_HEADING}\n\n{NO_SCORECARD_NOTE}\n"
        return LLMSectionFragments(markdown=markdown, html=render_llm_html_fragment(markdown))
    body = render_llm_markdown(card, findings=findings, interpretations=interpretations,
                               recommendations=recommendations, artifacts=artifacts, hit_threshold=hit_threshold,
                               generated_at=generated_at, title=False)
    markdown = f"{LLM_SECTION_HEADING}\n\n{body}"
    return LLMSectionFragments(markdown=markdown, html=render_llm_html_fragment(markdown), scorecard=card)


def render_llm_reports(
    record: Any,
    *,
    findings: Sequence[Any] | None = None,
    interpretations: Sequence[Any] | None = None,
    recommendations: Sequence[Any] | None = None,
    artifacts: Mapping[str, Mapping[str, Any]] | None = None,
    hit_threshold: float | None = None,
    generated_at: datetime | None = None,
) -> list[tuple[str, bytes, str]]:
    """``report.md`` / ``report.json`` / ``report.html`` for a probe run, the shape the report route stores."""
    card = _coerce(record)
    kwargs = {"hit_threshold": hit_threshold} if hit_threshold is not None else {}
    interp = _coerce_interpretations(interpretations) if interpretations is not None else interpret(card, **kwargs)
    recs = _coerce_recommendations(recommendations) if recommendations is not None else recommend(card, **kwargs)
    markdown = render_llm_markdown(card, findings=findings, interpretations=interp, recommendations=recs,
                                   artifacts=artifacts, generated_at=generated_at)
    payload = {
        "kind": "llm_probe",
        "scorecard": card.model_dump(mode="json"),
        "findings": [_dump_any(f) for f in (findings or ())],
        "interpretation": [i.model_dump(mode="json") for i in interp],
        "recommendations": [r.model_dump(mode="json") for r in recs],
        "narrative_source": "rules",
        "narrative_reason": NARRATIVE_NOT_OFFERED_REASON,
        "artifacts": {k: dict(v) for k, v in (artifacts or {}).items()},
    }
    assert_no_mri(payload)
    json_bytes = (json.dumps(payload, sort_keys=True, indent=2, separators=(",", ": "), default=str) + "\n").encode()
    return [
        ("report.md", markdown.encode(), "text/markdown"),
        ("report.json", json_bytes, "application/json"),
        ("report.html", render_llm_html(markdown, card).encode(), "text/html"),
    ]


def _dump_any(value: Any) -> Any:
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    if isinstance(value, Mapping):
        return {str(k): _dump_any(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_dump_any(v) for v in value]
    return value


def render_probe_reports(
    scorecard: Any,
    findings: Sequence[Any] | None = None,
    recommendations: Sequence[Any] | None = None,
    *,
    artifacts: Mapping[str, Mapping[str, Any]] | None = None,
    interpretations: Sequence[Any] | None = None,
    hit_threshold: float | None = None,
    generated_at: datetime | None = None,
) -> list[tuple[str, bytes, str]]:
    """Positional form of :func:`render_llm_reports` for the worker task (scorecard, findings, recommendations)."""
    return render_llm_reports(scorecard, findings=findings, interpretations=interpretations,
                              recommendations=recommendations, artifacts=artifacts, hit_threshold=hit_threshold,
                              generated_at=generated_at)


def check_llm_report_text(text: str) -> list[str]:
    """Problems with a rendered LLM report: banned score words, or MRI / grade wording outside the D9 sentence."""
    problems: list[str] = []
    if contains_banned_score_word(text):
        problems.append("banned score word present")
    stripped = text.replace(D9_SENTENCE, "").replace(html_escape(D9_SENTENCE), "")
    for match in _MRI_WORDS.finditer(stripped):
        problems.append(f"{match.group(0)!r} outside the D9 sentence")
    if text.count(D9_SENTENCE) + text.count(html_escape(D9_SENTENCE)) == 0:
        problems.append("D9 sentence missing")
    return problems


__all__ = [
    "ARTIFACT_NOTE",
    "INVALID_SCORECARD_NOTE",
    "LLM_SECTION_HEADING",
    "NOT_EVALUATED",
    "NO_SCORECARD_NOTE",
    "REPORT_TITLE",
    "SECTION_HEADINGS",
    "SEVERITY_BASIS_NOTE",
    "LLMSectionFragments",
    "check_llm_report_text",
    "extract_scorecard",
    "render_llm_html",
    "render_llm_html_fragment",
    "render_llm_markdown",
    "render_llm_reports",
    "render_llm_section",
    "render_probe_reports",
]
