"""Report rendering for persisted adversarial-ML campaign records (spec 14.8).

``render_campaign_reports`` turns a ``CampaignRecord`` into three inert
artifacts:

* ``report.md`` — six sections in the fixed order of spec 14.8: configuration
  and provenance; measurements (the family table with denominators, the
  reference-budget aggregates, the per-class table, and the MRI scorecard as a
  derived-summary sub-block carrying the five subscores with denominators, the
  scoring inputs, the robustness curve, the attack-scoped reading and the
  standing grade statement, plus the ΔMRI block on verify runs); observations
  labelled with their heuristic metric kind; interpretation labelled inferred
  with its basis ids; candidate recommendations with their validation state;
  and limitations followed by reviewer notes.
* ``report.json`` — ``CampaignRecord.model_dump(mode="json")``: the RunRecord
  dump plus its queryable projections, with the ``MRIRecord`` under ``score``.
* ``report.html`` — built from the Markdown through the escaping helpers in
  ``redsim.report`` so every user-derived string (class names, model names,
  dataset names, notes) is escaped exactly once, at the HTML boundary. The
  Markdown itself carries the raw strings; no user string ever starts a
  Markdown line, so none can open a heading, table row or code fence.
* ``report.pdf`` (Phase B, REVIEW_REPORTS-16; opt-in through ``formats``) — the
  same Markdown projection typeset by ``redsim.ml.pdf`` with reportlab and the
  bundled DejaVu faces. It is a third projection of the record, never a
  recomputation, and the renderer is imported only when the format is asked for
  so the API process never loads reportlab.

Phase B additions (REVIEW_REPORTS-18, -30; ATTACKS_HARDEN-13; MODALITIES-43):
section 1 prints ``schema_version`` and labels the budget axis from the norm
literal; the scorecard carries a "non-default weights" line whenever the vector
differs from ``MRIWeights()``; the ΔMRI block prints the derived-model lineage a
training defense recorded in provenance; section 2 adds the text edit-budget
table (``Measurement.edit_fraction_mean``) and the detection scorecard
(``Measurement.detection``, every rate with its box denominator) when a record
carries them, and section 3 the per-modality observation evidence
(``Observation.text`` word positions, ``Observation.detection`` box counts); an
LLM probe record gets its own sub-block through a lazy hook on
``redsim.ml.llm.report_section`` (the fragment's headings nested under it).

Nothing is invented: a value that was not measured renders as ``—``, "no
evidence recorded" or "not computed (denominator 0)"; a rate never appears
without its fraction; the MRI never renders without its subscores, inputs and
curve; URL strings are inert text and never become anchors.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from redsim.ml.compare import is_default_weights
from redsim.ml.schema import (
    GRADE_STATEMENT,
    AccuracyPoint,
    CampaignRecord,
    CandidateRecommendation,
    Measurement,
    MRIRecord,
    RobustnessCurve,
)
from redsim.report import _HTML_CSS, _md_to_html_min, html_escape

#: The report formats a render produces without asking for the PDF (the Phase A
#: set; ``report.json`` stays exactly the record dump).
REPORT_FORMATS_TEXT: tuple[str, ...] = ("md", "json", "html")
#: Every format ``render_campaign_reports`` can produce (Phase B adds ``pdf``).
REPORT_FORMATS_ALL: tuple[str, ...] = ("md", "json", "html", "pdf")
REPORT_CONTENT_TYPES: dict[str, str] = {
    "md": "text/markdown", "json": "application/json", "html": "text/html", "pdf": "application/pdf",
}

REPORT_TITLE = "# Redsim adversarial-ML campaign report"

# Spec 14.8: six sections, this order. ``tests/ml/test_report.py`` asserts it.
SECTION_HEADINGS: tuple[str, ...] = (
    "## 1. Configuration and provenance",
    "## 2. Measurements",
    "## 3. Observations",
    "## 4. Interpretation",
    "## 5. Candidate recommendations",
    "## 6. Limitations",
)
SCORECARD_HEADING = "### MRI scorecard (derived summary)"
DELTA_HEADING = "### ΔMRI (verify run against its baseline)"
REVIEWER_NOTES_HEADING = "### Reviewer notes"
LLM_HEADING = "### LLM probe results"
LLM_EMBED_NOTE = ("The block below is the LLM track's probe scorecard fragment (`redsim.ml.llm.report_section`), "
                  "embedded as rendered with its headings nested under this sub-section: k/n per probe row, "
                  "never an MRI.")
#: Phase B modality blocks (MODALITIES-43): text and detection rows carry their own budget and counts.
TEXT_BUDGET_HEADING = "**Text edit budget** (realised share of words substituted per row; the `edit` norm)"
DETECTION_SCORECARD_HEADING = ("**Detection scorecard** (box-level counts per row, every rate with its denominator; "
                               "a detection run carries this scorecard, never an MRI)")
TEXT_EVIDENCE_HEADING = ("**Text evidence** (word positions of the clean input; the message text is an artifact, "
                         "never printed here)")
DETECTION_EVIDENCE_HEADING = ("**Detection evidence** (boxes matched per image; the per-box tables are the "
                              "`ml.detection.boxes` artifact)")
#: What the budget axis of each ``Norm`` literal measures; the report labels ε from the literal, never guesses.
BUDGET_LABELS: dict[str, str] = {
    "linf": "L-inf perturbation (fraction of the [0, 1] input range)",
    "l2": "L2 perturbation radius",
    "edit": "edit budget (share of words substituted)",
    "patch_area": "patch area (share of the image area)",
}
#: Spec 15.3: the badge text when the weight vector is not the default one.
NON_DEFAULT_WEIGHTS_BADGE = "**Non-default weights**"
DEFAULT_WEIGHTS_NOTE = "Weights: the default vector"
DERIVED_MODEL_HEADING = "**Derived model** (training defense; the verify run measures it)"
#: F007 FR-005 while decision D006 is open (REVIEW_REPORTS-19): said in every rendered format.
EXPORT_REDACTION_NOTE = ("No export-redaction policy was applied to this report (decision D006 is open); "
                         "it carries the record as measured.")
LICENCE_UNRECORDED = "not recorded in the model or dataset manifest"

# Spec 16.4 (3): the only wording for a gain that has not been measured.
NOT_MEASURED = "Expected gain: not measured — run Verify"
# Spec 14.2: never ``0%`` and never ``100%`` for a missing or zero denominator.
NOT_COMPUTED_ZERO = "not computed (denominator 0)"
NO_EVIDENCE = "no evidence recorded"
UNAVAILABLE = "—"
# Spec 14.4: what the reproducibility claim is and is not.
REPRODUCIBILITY_NOTE = (
    "Reproducibility: with the same settings hash, model sha256, dataset revision, sample-indices "
    "sha256, library versions and seed, measurements are expected to match to within float "
    "tolerance. Bit-for-bit repeatability is not promised; the nondeterminism sources are listed above."
)

SUBSCORE_KEYS: tuple[str, ...] = ("S_acc", "S_asr", "S_eps", "S_conf", "S_expl")
_WEIGHT_FIELD: dict[str, str] = {
    "S_acc": "acc", "S_asr": "asr", "S_eps": "eps", "S_conf": "conf", "S_expl": "expl",
}
_EPS_TOLERANCE = 1e-9


# ---------------------------------------------------------------------------
# Inert text helpers
# ---------------------------------------------------------------------------


def _text(value: Any) -> str:
    """One-line text: whitespace collapsed so a user string can never start a Markdown line."""
    return " ".join(str(value).split())


def _cell(value: Any) -> str:
    """Table-cell text: one line, the column separator replaced so the table shape holds."""
    if value is None:
        return UNAVAILABLE
    text = _text(value).replace("|", "¦")
    return text or UNAVAILABLE


def _code(value: Any) -> str:
    """An inline code span; backticks inside the value are dropped so the span stays closed."""
    return "`" + (_text(value).replace("`", "") or UNAVAILABLE) + "`"


def _fmt(value: float | None, nd: int = 4) -> str:
    return UNAVAILABLE if value is None else f"{value:.{nd}f}"


def _g(value: float | int | None) -> str:
    return UNAVAILABLE if value is None else f"{value:g}"


def _signed(value: float | int | None, nd: int = 1) -> str:
    if value is None:
        return UNAVAILABLE
    if isinstance(value, int):
        return f"{value:+d}"
    return f"{value:+.{nd}f}"


def _when(value: datetime | None) -> str:
    return UNAVAILABLE if value is None else value.isoformat()


def _json_text(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _fraction(numerator: int | None, denominator: int | None, rate: float | None = None) -> str:
    """``k/n (rate)`` — a rate never appears without its fraction (spec 14.2)."""
    if numerator is None or denominator is None:
        return NO_EVIDENCE
    if denominator <= 0:
        return f"{numerator}/{denominator} — {NOT_COMPUTED_ZERO}"
    value = rate if rate is not None else numerator / denominator
    return f"{numerator}/{denominator} ({value:.4f})"


def _point(point: AccuracyPoint | None) -> str:
    if point is None:
        return NO_EVIDENCE
    return _fraction(point.n_correct, point.n, point.accuracy)


def _eps_of(measurement: Measurement) -> float | None:
    eps = measurement.params.get("eps")
    if isinstance(eps, bool) or not isinstance(eps, (int, float)):
        return None
    return float(eps)


def _eps_close(a: float, b: float) -> bool:
    return abs(a - b) <= _EPS_TOLERANCE


def _table(header: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    cells = [_cell(h) for h in header]
    lines = ["| " + " | ".join(cells) + " |", "|" + "|".join("---" for _ in cells) + "|"]
    lines.extend("| " + " | ".join(_cell(c) for c in row) + " |" for row in rows)
    return lines


def _quoted(text: str, indent: str = "") -> list[str]:
    """Multi-line free text as a block quote; every line keeps a non-user prefix."""
    lines = text.splitlines() or [""]
    return [f"{indent}> {line.rstrip()}" for line in lines]


def _is_verify(record: CampaignRecord) -> bool:
    return record.kind == "verify" or record.baseline_run_id is not None


def _budget_label(norm: Any) -> str:
    return BUDGET_LABELS.get(str(norm), f"budget in norm {_text(norm)}")


def _nest_heading(line: str) -> str:
    """A line of an embedded fragment, its headings nested under an H3 sub-block of this report.

    The fragment's own top and section headings (``#``, ``##``) become ``####`` so the
    report keeps exactly six ``##`` sections; its deeper headings (``###`` and below,
    the converters stop at four levels) become bold lines. Everything else is verbatim.
    """
    stripped = line.lstrip("#")
    level = len(line) - len(stripped)
    if level == 0 or not stripped.startswith(" "):
        return line
    text = stripped.strip()
    if level <= 2:
        return f"#### {text}"
    return f"**{text.replace('**', '')}**"


# ---------------------------------------------------------------------------
# 1. Configuration and provenance
# ---------------------------------------------------------------------------


def _section_configuration(record: CampaignRecord, generated_at: datetime) -> list[str]:
    config = record.config
    lines = [SECTION_HEADINGS[0], ""]
    status: str = record.status
    if record.completeness != "complete":
        status = f"{record.status} (**{record.completeness}**)"
    lines += [
        f"- **Run ID:** {_code(record.run_id)}",
        f"- **Schema version:** {_code(record.schema_version)}",
        f"- **Kind:** {record.kind}",
        f"- **Status:** {status}",
        f"- **Stage:** {_text(record.stage) if record.stage else UNAVAILABLE}",
        f"- **Stages done:** {', '.join(_text(s) for s in record.stages_done) or UNAVAILABLE}",
        f"- **Error:** {_text(record.error) if record.error else 'none'}",
        f"- **Created:** {_when(record.created_at)}",
        f"- **Completed:** {_when(record.completed_at)}",
        f"- **Generated at:** {generated_at.isoformat()}",
        f"- **Settings hash:** {_code(record.settings_hash) if record.settings_hash else UNAVAILABLE}",
        (f"- **Baseline run:** {_code(record.baseline_run_id)}" if record.baseline_run_id
         else "- **Baseline run:** none (not a verify run)"),
        (f"- **Parent run:** {_code(record.parent_run_id)}" if record.parent_run_id
         else "- **Parent run:** none (not a rerun)"),
    ]
    if record.missing:
        lines.append("- **Missing:** " + "; ".join(_text(m) for m in record.missing))
    lines += ["", "**Target**", ""]
    target = record.target
    lines += [
        f"- **Name:** {_text(target.name)}",
        f"- **Id:** {_code(target.id)}",
        f"- **Domain:** {target.domain}",
        f"- **Status:** {target.status}" + (f" — {_text(target.reason)}" if target.reason else ""),
    ]
    if target.metadata:
        lines.append(f"- **Metadata:** {_code(_json_text(target.metadata))}")
    lines += ["", "**Configuration** (immutable after admission)", ""]
    by_id = {a.id: a for a in [*config.attacks, *record.attacks]}
    attack_lines: list[str] = []
    for attack_id in config.attack_ids:
        info = by_id.get(attack_id)
        params = config.attack_params.get(attack_id, {})
        describe = _code(attack_id)
        if info is not None:
            describe += f" — {_text(info.name)} ({info.family}, {info.access}, phase {info.phase})"
        describe += f"; params {_code(_json_text(params))}" if params else "; params: defaults"
        attack_lines.append(f"  - {describe}")
    weights = config.scoring.weights.as_dict()
    lines += [
        f"- **Modality:** {config.modality}",
        "- **Attack set:**",
        *attack_lines,
        f"- **Norm:** {config.norm}; budget axis: {_budget_label(config.norm)}",
        f"- **ε grid:** {', '.join(f'{e:g}' for e in config.eps_grid)}",
        f"- **Reference ε:** {config.reference_eps:g}",
        f"- **Finding ASR threshold:** {config.finding_asr_threshold:g}",
        f"- **n_samples:** {config.n_samples}; **seed:** {config.seed}",
        f"- **Benign-noise control:** {'yes' if config.include_control else 'no'}",
        f"- **explain_k:** {config.explain_k}",
        (f"- **Dataset:** {_text(config.dataset_id)} (revision "
         f"{_text(config.dataset_revision) if config.dataset_revision else 'unrecorded'}, "
         f"split {_text(config.dataset_split)})"),
        f"- **Licence (model and dataset manifests):** {_licence_of(record) or LICENCE_UNRECORDED}",
        (f"- **Scoring:** version {_text(config.scoring.version)}; weights "
         + ", ".join(f"{k} = {v:g}" for k, v in weights.items())
         + (" (default vector)" if is_default_weights(config.scoring.weights) else " (**non-default weights**)")
         + f"; severity thresholds asr_high = {config.scoring.severity.asr_high:g}, "
           f"asr_mid = {config.scoring.severity.asr_mid:g}; confidence n_high = "
           f"{config.scoring.confidence.n_high}, n_medium = {config.scoring.confidence.n_medium}"),
    ]
    if config.defense is not None:
        lines.append(
            "- **Defense (the changed variable of a verify run):** "
            f"{_code(config.defense.id)} — {_code(config.defense.art_class or 'ART class unrecorded')}, "
            f"params {_code(_json_text(config.defense.params))}"
        )
    else:
        lines.append("- **Defense:** none")
    lines += [
        f"- **LLM narrative:** {'requested' if config.llm_narrative else 'off'}",
        f"- **Auto-recommend:** {'on' if config.auto_recommend else 'off'}",
        "",
        "**Provenance**",
        "",
    ]
    provenance = record.provenance
    if provenance is None:
        lines.append("- No provenance was recorded for this run.")
    else:
        versions = {
            "redsim": provenance.redsim_version, "python": provenance.python, "torch": provenance.torch,
            "art": provenance.art, "shap": provenance.shap, "numpy": provenance.numpy,
            "onnxruntime": provenance.onnxruntime, "sklearn": provenance.sklearn,
            "xgboost": provenance.xgboost,
        }
        lines += [
            "- **Versions:** " + ", ".join(
                f"{name} {_text(version) if version else 'not used'}" for name, version in versions.items()
            ),
            f"- **Model sha256:** {_code(provenance.model_sha256) if provenance.model_sha256 else UNAVAILABLE}",
            (f"- **Dataset:** {_text(provenance.dataset) if provenance.dataset else UNAVAILABLE} (revision "
             f"{_text(provenance.dataset_revision) if provenance.dataset_revision else 'unrecorded'}, split "
             f"{_text(provenance.dataset_split) if provenance.dataset_split else 'unrecorded'})"),
            ("- **Sample indices sha256:** "
             + (_code(provenance.sample_indices_sha256) if provenance.sample_indices_sha256 else UNAVAILABLE)),
            f"- **Settings hash:** {_code(provenance.settings_hash) if provenance.settings_hash else UNAVAILABLE}",
            f"- **Baseline run:** {_code(provenance.baseline_run_id) if provenance.baseline_run_id else 'none'}",
            f"- **Parent run:** {_code(provenance.parent_run_id) if provenance.parent_run_id else 'none'}",
            ("- **Defense (verify runs):** "
             + (_code(_json_text(provenance.defense)) if provenance.defense is not None else "none")),
            ("- **LLM (redacted settings and hashes, never the key):** "
             + (_code(_json_text(provenance.llm)) if provenance.llm is not None else "no narrative generated")),
            f"- **Thread environment:** {_code(_json_text(provenance.thread_env)) if provenance.thread_env else UNAVAILABLE}",
            ("- **Model manifest:** "
             + (_code(_json_text(provenance.model_manifest)) if provenance.model_manifest else UNAVAILABLE)),
            f"- **Started:** {_when(provenance.started_at)}; **finished:** {_when(provenance.finished_at)}",
            f"- **Host:** {_text(provenance.hostname)}; **device:** {_text(provenance.device)}",
            "",
            "**Nondeterminism sources**",
            "",
        ]
        if provenance.nondeterminism:
            lines.extend(f"- {_text(item)}" for item in provenance.nondeterminism)
        else:
            lines.append("- none recorded")
    lines += ["", REPRODUCIBILITY_NOTE]
    return lines


# ---------------------------------------------------------------------------
# 2. Measurements (with the scorecard sub-block and the ΔMRI block)
# ---------------------------------------------------------------------------


def _asr_text(measurement: Measurement, clean: Measurement | None) -> str:
    if measurement.family == "clean":
        return "n/a (baseline row)"
    if measurement.n_flipped_from_clean is None:
        return NO_EVIDENCE
    denominator = measurement.n_clean_correct
    if denominator is None and clean is not None:
        denominator = clean.n_correct
    if denominator is None:
        return f"{measurement.n_flipped_from_clean} flipped; ASR {NO_EVIDENCE} (denominator unknown)"
    return _fraction(measurement.n_flipped_from_clean, denominator, measurement.attack_success_rate)


def _family_row(measurement: Measurement, clean: Measurement | None) -> list[Any]:
    clean_correct = measurement.n_clean_correct
    if clean_correct is None and clean is not None:
        clean_correct = clean.n_correct
    return [
        measurement.attack_id or measurement.family,
        _g(_eps_of(measurement)),
        measurement.n,
        clean_correct,
        _fraction(measurement.n_correct, measurement.n, measurement.accuracy),
        _asr_text(measurement, clean),
        _fmt(measurement.linf_norm_mean),
        _fmt(measurement.l2_norm_mean),
        f"{measurement.wall_time_s:g}",
        measurement.family,
        measurement.id,
        _json_text(measurement.params) if measurement.params else UNAVAILABLE,
        "; ".join(_text(n) for n in measurement.notes) or UNAVAILABLE,
    ]


def _with_n(value: float | None, n: int | None, nd: int = 4) -> str:
    if value is None:
        return UNAVAILABLE
    return f"{value:.{nd}f} (n={n if n is not None else UNAVAILABLE})"


def _aggregate_rows(measurements: Sequence[Measurement]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for m in measurements:
        if all(v is None for v in (m.pert_first_success_mean, m.conf_gap_mean, m.expl_shift_mean,
                                   m.expl_shift_noise_floor, m.queries_mean)):
            continue
        shift = _with_n(m.expl_shift_mean, m.expl_shift_n)
        if m.expl_shift_mean is not None and m.expl_shift_n_excluded:
            shift += f", {m.expl_shift_n_excluded} excluded"
        rows.append([
            m.id,
            _with_n(m.pert_first_success_mean, m.pert_first_success_n),
            _with_n(m.conf_gap_mean, m.conf_gap_n),
            shift,
            _with_n(m.expl_shift_noise_floor, m.expl_shift_noise_floor_n),
            _g(m.queries_mean),
        ])
    return rows


def _per_class_block(measurements: Sequence[Measurement]) -> list[str]:
    lines = ["**Per-class counts** (correct / n per class; wide uncertainty on a small slice)", ""]
    with_classes = [m for m in measurements if m.per_class]
    if not with_classes:
        lines.append("No per-class counts were recorded.")
        return lines
    classes: list[str] = []
    for m in with_classes:
        for name in m.per_class:
            if name not in classes:
                classes.append(name)
    rows = []
    for m in with_classes:
        row: list[Any] = [m.id]
        for name in classes:
            counts = m.per_class.get(name)
            row.append(NO_EVIDENCE if counts is None
                       else _fraction(counts.get("n_correct"), counts.get("n")))
        rows.append(row)
    lines.extend(_table(["Measurement", *classes], rows))
    return lines


def _text_budget_block(measurements: Sequence[Measurement], clean: Measurement | None) -> list[str]:
    """MODALITIES-43: the realised edit share per text row (``Measurement.edit_fraction_mean``), or nothing."""
    rows = [m for m in measurements if m.edit_fraction_mean is not None]
    if not rows:
        return []
    lines = ["", TEXT_BUDGET_HEADING, ""]
    lines.extend(_table(
        ["Measurement", "Attack", "Edit budget ε", "Edit fraction mean (realised)", "Correct / N (accuracy)",
         "Flipped / clean correct (ASR)"],
        [[m.id, m.attack_id or m.family, _g(_eps_of(m)), _fmt(m.edit_fraction_mean),
          _fraction(m.n_correct, m.n, m.accuracy), _asr_text(m, clean)] for m in rows],
    ))
    lines += ["", "The edit fraction is the share of words the attack actually replaced, averaged over the "
                  "messages with a defined fraction; the budget ε is the share it was allowed."]
    return lines


def _detection_scorecard_block(measurements: Sequence[Measurement]) -> list[str]:
    """MODALITIES-43: the box-level scorecard of a detection record (``Measurement.detection``), or nothing.

    On a detection row ``n`` counts ground-truth boxes and ``n_correct`` the boxes matched
    at the manifest's IoU threshold; recall is ``n_matched / n_boxes`` and the suppression
    rate ``n_flipped_from_clean / n_clean_correct`` (clean-matched boxes lost under the
    patch). No MRI is derived from these counts.
    """
    rows = [m for m in measurements if m.detection is not None]
    if not rows:
        return []
    table: list[list[Any]] = []
    for m in rows:
        det = m.detection
        assert det is not None
        if m.family == "clean":
            suppression = "n/a (clean row)"
        elif m.n_flipped_from_clean is None:
            suppression = NO_EVIDENCE
        else:
            suppression = _fraction(m.n_flipped_from_clean, m.n_clean_correct, det.suppression_rate)
        table.append([
            m.id, m.attack_id or m.family, _g(_eps_of(m)), _fraction(det.n_matched, det.n_boxes, det.recall),
            _fmt(det.map50), suppression, f"{m.wall_time_s:g}",
        ])
    lines = ["", DETECTION_SCORECARD_HEADING, ""]
    lines.extend(_table(
        ["Measurement", "Attack", "Patch area ε", "Matched / boxes (recall)", "mAP@0.5",
         "Suppressed / clean matched (suppression rate)", "Wall time (s)"],
        table,
    ))
    return lines


def _text_evidence_block(observations: Sequence[Any]) -> list[str]:
    """MODALITIES-43: ``Observation.text`` per explained message, positions only, or nothing."""
    rows: list[list[Any]] = []
    for o in observations:
        block = o.text
        if block is None:
            continue
        changed = ", ".join(str(p) for p in block.changed_positions[:8])
        if len(block.changed_positions) > 8:
            changed += f", … ({len(block.changed_positions)} in all)"
        top = ((", ".join(str(p) for p in block.top_tokens_clean[:5]) or UNAVAILABLE) + " → "
               + (", ".join(str(p) for p in block.top_tokens_adv[:5]) or UNAVAILABLE))
        attributions = "; ".join(f"{_text(k)}: {_text(v)}" for k, v in block.attribution_artifacts.items())
        rows.append([o.id, _fraction(block.n_changed, block.n_tokens, block.edit_fraction), changed or UNAVAILABLE,
                     top, attributions or UNAVAILABLE])
    if not rows:
        return []
    lines = ["", TEXT_EVIDENCE_HEADING, ""]
    lines.extend(_table(
        ["Observation", "Words changed / words (edit fraction)", "Changed positions",
         "Top tokens by |attribution| clean → adv (positions)", "Attribution artifacts"],
        rows,
    ))
    return lines


def _detection_evidence_block(observations: Sequence[Any]) -> list[str]:
    """MODALITIES-43: ``Observation.detection`` per explained image, counts and the patch box, or nothing."""
    rows: list[list[Any]] = []
    for o in observations:
        block = o.detection
        if block is None:
            continue
        bbox = ("[" + ", ".join(f"{v:g}" for v in block.patch_bbox) + "] (x_min, y_min, x_max, y_max px)"
                if block.patch_bbox else "none (control row, or no patch recorded)")
        rows.append([o.id, _fraction(block.n_matched_clean, block.n_gt), _fraction(block.n_matched_adv, block.n_gt),
                     bbox])
    if not rows:
        return []
    lines = ["", DETECTION_EVIDENCE_HEADING, ""]
    lines.extend(_table(
        ["Observation", "Matched clean / ground truth", "Matched adversarial / ground truth", "Patch box"], rows,
    ))
    return lines


def _curve_block(curves: Sequence[RobustnessCurve]) -> list[str]:
    lines = ["**Robustness curve** (evasion and benign-noise control per attack; every point with its denominator)",
             ""]
    if not curves:
        lines.append(f"No robustness curve was recorded ({NO_EVIDENCE}).")
        return lines
    for curve in curves:
        lines.append(
            f"Attack {_code(curve.attack_id)} (norm {curve.norm}; budget axis: {_budget_label(curve.norm)}); "
            f"clean accuracy {_point(curve.clean)}; reference ε = {curve.reference_eps:g}."
        )
        lines.append("")
        eps_values: list[float] = []
        for point in [*curve.points, *curve.control]:
            if not any(_eps_close(point.eps, e) for e in eps_values):
                eps_values.append(point.eps)
        rows: list[list[Any]] = []
        for eps in sorted(eps_values):
            evasion = next((p for p in curve.points if _eps_close(p.eps, eps)), None)
            control = next((p for p in curve.control if _eps_close(p.eps, eps)), None)
            evasion_text = _fraction(evasion.n_correct, evasion.n, evasion.accuracy) if evasion else NO_EVIDENCE
            asr_text = (
                _fraction(evasion.n_flipped_from_clean, evasion.n_clean_correct, evasion.asr)
                if evasion is not None and evasion.n_flipped_from_clean is not None else NO_EVIDENCE
            )
            control_text = _fraction(control.n_correct, control.n, control.accuracy) if control else NO_EVIDENCE
            marker = " (reference)" if _eps_close(eps, curve.reference_eps) else ""
            rows.append([f"{eps:g}{marker}", evasion_text, asr_text, control_text])
        lines.extend(_table(
            ["ε", "Evasion correct / n (accuracy)", "Flipped / clean correct (ASR)", "Control correct / n (accuracy)"],
            rows,
        ))
        lines.append("")
    return lines


def _subscore_rows(score: MRIRecord) -> list[list[Any]]:
    weights = score.weights.as_dict()
    attack_ids = [*score.attack_ids, *(a for a in score.per_attack if a not in score.attack_ids)]
    rows: list[list[Any]] = []
    for key in SUBSCORE_KEYS:
        value = getattr(score.subscores, key)
        row: list[Any] = [key, f"{weights[_WEIGHT_FIELD[key]]:g}",
                          "unavailable" if value is None else f"{float(value):.1f}"]
        for attack_id in attack_ids:
            per_attack = score.per_attack.get(attack_id)
            if per_attack is None:
                row.append(NO_EVIDENCE)
                continue
            scored = getattr(per_attack, key)
            if scored.value is None:
                row.append(f"unavailable ({_text(scored.reason) if scored.reason else 'no reason recorded'})")
            else:
                row.append(f"{float(scored.value):.1f} (n={scored.n if scored.n is not None else UNAVAILABLE})")
        rows.append(row)
    return rows


def _weights_line(weights: dict[str, float]) -> str:
    """Spec 15.3: the scorecard says which vector scored it; a non-default one gets the badge."""
    vector = ", ".join(f"{k} = {v:g}" for k, v in weights.items())
    if is_default_weights(weights):
        return f"{DEFAULT_WEIGHTS_NOTE} ({vector}); a run scored with a different vector is not comparable to this one."
    return (f"{NON_DEFAULT_WEIGHTS_BADGE} — this run was scored with {vector} (sum 1, never renormalised); "
            "it is comparable only to runs scored with the same vector.")


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _derived_model_lines(record: CampaignRecord) -> list[str]:
    """ATTACKS_HARDEN-13: the lineage a training defense recorded on the verify run.

    Read from ``provenance.defense`` (``kind: training`` with the parent and derived
    digests and the training report the worker recorded) and from
    ``provenance.model_manifest["derived_from"]`` (the ``DerivedFrom`` block of the
    registered derived target). Nothing is inferred: a key that was not recorded
    renders as unrecorded.
    """
    provenance = record.provenance
    if provenance is None:
        return []
    defense = _mapping(provenance.defense)
    derived_from = _mapping(provenance.model_manifest.get("derived_from"))
    if defense.get("kind") != "training" and not derived_from:
        return []
    lines = ["", DERIVED_MODEL_HEADING, ""]
    if defense.get("kind") == "training":
        lines.append(
            f"- Parent weights sha256: {_code(defense.get('parent_sha256') or 'unrecorded')}; derived weights sha256: "
            f"{_code(defense.get('derived_sha256') or 'unrecorded')}; defense {_code(defense.get('id') or 'unrecorded')}."
        )
        report = _mapping(defense.get("training_report"))
        if report:
            epochs = f"{_g(report.get('epochs_run'))} of {_g(report.get('epochs_requested'))} epochs"
            wall = f"wall time {_g(report.get('wall_time_s'))} s of a {_g(report.get('wall_budget_s'))} s budget"
            changed = report.get("weights_changed")
            changed_text = "unrecorded" if changed is None else ("yes" if changed else "no")
            frozen = report.get("backbone_frozen")
            frozen_text = "unrecorded" if frozen is None else ("yes" if frozen else "no")
            lines.append(
                f"- Training budget as run: {epochs}; {wall}; budget exhausted: "
                f"{'yes' if report.get('budget_exhausted') else 'no'}; weights changed: {changed_text}; "
                f"backbone frozen: {frozen_text}; n_train = {_g(report.get('n_train'))}."
            )
    if derived_from:
        budget = _mapping(derived_from.get("training_budget"))
        lines.append(
            f"- Lineage (derived_from): parent target {_code(derived_from.get('parent_target_id') or 'unrecorded')}, "
            f"parent sha256 {_code(derived_from.get('parent_sha256') or 'unrecorded')}, defense "
            f"{_code(derived_from.get('defense_id') or 'unrecorded')}, training budget "
            f"{_code(_json_text(budget)) if budget else 'unrecorded'}."
        )
    lines.append("- The derived model is a separate Target; its own campaigns measure it. This block records "
                 "lineage and the budget the defense ran under, not a claim about the result.")
    return lines


def is_llm_probe_record(record: CampaignRecord) -> bool:
    """``True`` when the record is an LLM probe run (spec 11.6; LLM-24, LLM-28).

    The frozen ``CampaignKind`` has no probe member, so the signal is duck-typed
    on what the LLM tracks record: a ``kind`` of ``llm_probe`` (a widened record),
    a target whose metadata names ``endpoint_kind`` or ``modality`` ``llm``, or a
    manifest endpoint block of kind ``llm``. Such a record never carries an MRI.
    """
    if getattr(record, "kind", None) == "llm_probe":
        return True
    metadata = record.target.metadata if record.target is not None else {}
    if metadata.get("endpoint_kind") == "llm" or metadata.get("modality") == "llm":
        return True
    manifest = record.provenance.model_manifest if record.provenance is not None else {}
    endpoint = _mapping(manifest.get("endpoint"))
    return endpoint.get("kind") == "llm" or endpoint.get("endpoint_kind") == "llm"


def _llm_scorecard_of(record: CampaignRecord) -> dict[str, Any] | None:
    """The ``LLMProbeScorecard`` dump a probe record carries, when the worker embedded one.

    Looked up tolerantly under ``provenance.model_manifest["llm_scorecard"]`` and
    ``target.metadata["llm_scorecard"]``; ``None`` when the run keeps its scorecard
    only behind ``GET /v1/runs/{id}/llm-scorecard``.
    """
    sources: list[dict[str, Any]] = []
    if record.provenance is not None:
        sources.append(record.provenance.model_manifest)
    if record.target is not None:
        sources.append(record.target.metadata)
    for source in sources:
        card = source.get("llm_scorecard")
        if isinstance(card, dict) and card:
            return card
    return None


def _llm_section(record: CampaignRecord, generated_at: datetime) -> list[str]:
    """The LLM probe scorecard block, rendered by the LLM track's module when present.

    Imported inside the function (the module is Phase B and worker-side); when it
    is absent the block says so rather than inventing a scorecard. The fragment
    ``render_llm_section`` returns (its own heading, k/n per probe family, never an
    MRI) is embedded line for line under :data:`LLM_HEADING`, its headings nested
    through :func:`_nest_heading` so the report keeps its six ``##`` sections.
    """
    try:
        from redsim.ml.llm.report_section import render_llm_section
    except ImportError:
        return [LLM_HEADING, "",
                "LLM probe results were recorded for this run but the LLM report renderer "
                "(`redsim.ml.llm.report_section`) is not available in this build; no scorecard is shown. "
                "Use `GET /v1/runs/{id}/llm-scorecard` for the k/n table."]
    card = _llm_scorecard_of(record)
    if card is None:
        return [LLM_HEADING, "",
                "This run is an LLM probe run. Its k/n probe scorecard is not embedded in this record; "
                "`GET /v1/runs/{id}/llm-scorecard` serves it. Probe results never enter an MRI."]
    fragments: Any = render_llm_section(card, generated_at=generated_at)
    markdown: Any = getattr(fragments, "markdown", fragments)
    fragment_lines = markdown.splitlines() if isinstance(markdown, str) else [str(line) for line in list(markdown)]
    return [LLM_HEADING, "", LLM_EMBED_NOTE, "", *(_nest_heading(line) for line in fragment_lines)]


def _licence_of(record: CampaignRecord) -> str | None:
    """The licence string the manifests recorded (spec 21.5), read tolerantly from the snapshot and provenance."""
    snapshot = _mapping(record.config.target_snapshot)
    candidates: list[Any] = [
        snapshot.get("license"), _mapping(snapshot.get("manifest")).get("license"),
        _mapping(snapshot.get("detail")).get("license"),
        _mapping(_mapping(snapshot.get("detail")).get("manifest")).get("license"),
    ]
    if record.provenance is not None:
        manifest = record.provenance.model_manifest
        candidates += [manifest.get("license"), _mapping(manifest.get("dataset")).get("license")]
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return _text(value)
    return None


def _scorecard(record: CampaignRecord) -> list[str]:
    lines = [SCORECARD_HEADING, ""]
    score = record.score
    config = record.config
    if score is None:
        status = record.score_status
        state = status.state if status is not None else "unavailable"
        reason = _text(status.reason) if status is not None and status.reason else "no reason recorded"
        lines += [
            f"**MRI not computed** — score {state}: {reason}.",
            "",
            _weights_line(config.scoring.weights.as_dict()),
            "",
            "The MRI is never shown without its five subscores, their denominators and the ε curve; "
            "no score record exists for this run, so no number, grade or subscore is reported.",
            "",
            *_curve_block(record.curve),
            "",
            "Reading: none (no grade was assigned).",
            "",
            GRADE_STATEMENT,
        ]
    else:
        lines.append(
            f"Scoring {_text(score.scoring_version)}; settings hash {_code(score.settings_hash)}; attacks "
            f"{', '.join(_code(a) for a in score.attack_ids)}; norm {score.norm}; ε grid "
            f"{', '.join(f'{e:g}' for e in score.eps_grid)}; reference ε {score.reference_eps:g}; finding ASR "
            f"threshold {score.finding_asr_threshold:g}; computed at {_when(score.computed_at)}; "
            f"completeness **{score.completeness}**."
        )
        lines.append("")
        if score.mri is not None:
            lines.append(f"**MRI {score.mri} — grade {score.grade}**")
        else:
            missing = "; ".join(_text(m) for m in score.missing) or "not stated"
            lines.append(f"**MRI not computed** (partial score record). Missing: {missing}.")
        lines += ["", _weights_line(score.weights.as_dict())]
        lines += ["", "**Subscores** (0–100; weights as configured, never renormalised; per-attack value with its n)",
                  ""]
        attack_ids = [*score.attack_ids, *(a for a in score.per_attack if a not in score.attack_ids)]
        lines.extend(_table(["Subscore", "Weight", "Value", *[f"{a} (value, n)" for a in attack_ids]],
                            _subscore_rows(score)))
        lines += ["", "**Scoring inputs** (one row per attack and ε, with denominators)", ""]
        if score.inputs:
            lines.extend(_table(
                ["Attack", "ε", "acc_clean", "acc_adv", "ASR", "pert", "conf_gap", "expl_shift", "queries",
                 "n", "n_correct_clean", "n_attacked", "n_explained"],
                [[row.attack_id, _g(row.eps), _fmt(row.acc_clean), _fmt(row.acc_adv), _fmt(row.asr),
                  _fmt(row.pert), _fmt(row.conf_gap), _fmt(row.expl_shift), _g(row.queries), row.n,
                  row.n_correct_clean, row.n_attacked, row.n_explained] for row in score.inputs],
            ))
        else:
            lines.append(f"No scoring inputs were recorded ({NO_EVIDENCE}).")
        lines += ["", *_curve_block(record.curve), ""]
        if score.reading:
            lines.append(f"Reading (attack-scoped): {_text(score.reading)}")
        else:
            lines.append("Reading: none (no grade was assigned).")
        lines += ["", GRADE_STATEMENT]
    lines += [
        "",
        f"Scoring scope: up to {config.explain_k} flipped and {config.explain_k} unflipped samples explained; "
        f"explanations computed at ε = {config.reference_eps:g} only; slice n = {config.n_samples}. "
        "The full limitations are in section 6.",
    ]
    return lines


def _delta_block(record: CampaignRecord) -> list[str]:
    lines = [DELTA_HEADING, ""]
    defense = record.config.defense
    provenance_defense = record.provenance.defense if record.provenance is not None else None
    if defense is not None:
        lines.append(
            f"Changed variable: defense {_code(defense.id)} ({_code(defense.art_class or 'ART class unrecorded')}), "
            f"params {_code(_json_text(defense.params))}. The model, dataset revision, sample indices, attack set, "
            "ε grid and scoring settings are those of the baseline run."
        )
    elif provenance_defense is not None:
        lines.append(f"Changed variable: defense {_code(_json_text(provenance_defense))} (from provenance).")
    else:
        lines.append("Changed variable: no defense is recorded on this verify run.")
    lines.extend(_derived_model_lines(record))
    lines.append("")
    score = record.score
    delta = score.delta if score is not None else None
    if score is None or delta is None:
        reasons = [_text(lim) for lim in record.limitations if "MRI delta not computed" in lim]
        lines.append("**ΔMRI not computed.** " + (" ".join(reasons) if reasons
                                                  else "No delta was measured; see the limitations in section 6."))
        return lines
    lines += [
        f"Baseline run {_code(delta.baseline_run_id)} → verify run {_code(record.run_id)}; settings hash "
        f"{_code(score.settings_hash)} (a delta is only computed when both runs carry this same hash).",
        "",
        f"**ΔMRI {_signed(delta.delta)}** (MRI {delta.mri_before} → {delta.mri_after}).",
        "",
        f"Clean accuracy: {_point(delta.delta_acc_clean.before)} → {_point(delta.delta_acc_clean.after)} "
        f"(Δ {_signed(delta.delta_acc_clean.delta, 4)}).",
        "",
        *_table(["Subscore", "Δ (points)"],
                [[key, _signed(getattr(delta.delta_subscores, key))] for key in SUBSCORE_KEYS]),
        "",
    ]
    if delta.delta_families:
        lines.extend(_table(
            ["Measurement", "Before (correct / n)", "After (correct / n)", "Δ accuracy"],
            [[f.measurement_id, _point(f.before), _point(f.after), _signed(f.delta, 4)]
             for f in delta.delta_families],
        ))
    else:
        lines.append("No per-family deltas were recorded.")
    return lines


def _section_measurements(record: CampaignRecord) -> list[str]:
    config = record.config
    provenance = record.provenance
    indices = provenance.sample_indices_sha256 if provenance is not None else None
    lines = [SECTION_HEADINGS[1], ""]
    lines.append(
        f"Slice: dataset {_text(config.dataset_id)} (revision "
        f"{_text(config.dataset_revision) if config.dataset_revision else 'unrecorded'}, split "
        f"{_text(config.dataset_split)}); n_samples = {config.n_samples}, seed = {config.seed}; sample selection: "
        f"the target's seeded sample of the split, indices sha256 "
        f"{_code(indices) if indices else 'unrecorded'}. Every row of this run is computed on the same indices."
    )
    completeness = (
        "Completeness: complete." if record.completeness == "complete"
        else "Completeness: **partial** — " + ("; ".join(_text(m) for m in record.missing) or "reason not stated")
        + "."
    )
    lines += [completeness, "", "**Results by test family** (every rate with its fraction)", ""]
    if not record.measurements:
        lines.append(f"No measurements were recorded ({NO_EVIDENCE}).")
    else:
        clean = next((m for m in record.measurements if m.family == "clean"), None)
        lines.extend(_table(
            ["Attack", "Epsilon", "N", "Clean correct", "Correct / N (accuracy)",
             "Flipped / clean correct (ASR)", "Mean L∞", "Mean L2", "Wall time (s)", "Family", "Id", "Params",
             "Notes"],
            [_family_row(m, clean) for m in record.measurements],
        ))
        lines.append("")
        lines += ["**Reference-budget aggregates** (each mean with its denominator)", ""]
        aggregate_rows = _aggregate_rows(record.measurements)
        if aggregate_rows:
            lines.extend(_table(
                ["Measurement", "Perturbation at first success (mean, n)", "Confidence gap (mean, n)",
                 "Explanation shift (mean, n)", "Explanation noise floor (mean, n)", "Queries (mean)"],
                aggregate_rows,
            ))
        else:
            lines.append(f"No reference-budget aggregates were recorded ({NO_EVIDENCE}).")
        lines.append("")
        lines.extend(_per_class_block(record.measurements))
        lines.extend(_text_budget_block(record.measurements, clean))
        lines.extend(_detection_scorecard_block(record.measurements))
    lines += ["", *_scorecard(record)]
    if _is_verify(record):
        lines += ["", *_delta_block(record)]
    return lines


# ---------------------------------------------------------------------------
# 3. Observations
# ---------------------------------------------------------------------------


def _section_observations(record: CampaignRecord) -> list[str]:
    lines = [SECTION_HEADINGS[2], ""]
    observations = record.observations
    if not observations:
        lines.append(f"No observations were recorded ({NO_EVIDENCE}).")
        return lines
    flipped = sum(1 for o in observations if o.flipped)
    first = observations[0]
    lines += [
        f"{len(observations)} explained samples ({flipped} flipped, {len(observations) - flipped} not flipped) "
        f"out of n = {record.config.n_samples}. Metric kind: **{first.metric_kind}** — {_text(first.metric_note)}",
        "",
    ]
    rows: list[list[Any]] = []
    for o in observations:
        centre_mass = UNAVAILABLE
        if o.center_mass_ratio_clean is not None or o.center_mass_ratio_adv is not None:
            centre_mass = f"{_fmt(o.center_mass_ratio_clean, 3)} → {_fmt(o.center_mass_ratio_adv, 3)} [{o.metric_kind}]"
        features = UNAVAILABLE
        if o.top_features_clean or o.top_features_adv:
            features = (", ".join(_text(f) for f in o.top_features_clean[:5]) or UNAVAILABLE) + " → " + (
                ", ".join(_text(f) for f in o.top_features_adv[:5]) or UNAVAILABLE)
        rows.append([
            o.id, o.sample_index, o.true_label,
            f"{_text(o.pred_clean)} ({o.confidence_clean:.2f})",
            f"{_text(o.pred_adv)} ({o.confidence_adv:.2f})",
            "yes" if o.flipped else "no",
            centre_mass, _fmt(o.expl_shift, 3), features,
        ])
    lines.extend(_table(
        ["Id", "Sample", "True label", "Clean prediction (confidence)", "Adversarial prediction (confidence)",
         "Flipped", "Centre-mass ratio clean → adv (heuristic)", "Explanation shift", "Top features clean → adv"],
        rows,
    ))
    lines.extend(_text_evidence_block(observations))
    lines.extend(_detection_evidence_block(observations))
    lines += ["", "**Artifacts** (ids and sha256 digests as recorded)", ""]
    artifact_rows: list[list[Any]] = []
    for o in observations:
        for name, artifact_id in o.artifacts.items():
            artifact_rows.append([o.id, name, artifact_id, o.artifact_sha256.get(name) or "unrecorded"])
    if artifact_rows:
        lines.extend(_table(["Observation", "Artifact", "Id", "sha256"], artifact_rows))
    else:
        lines.append("No artifacts were recorded for the observations.")
    return lines


# ---------------------------------------------------------------------------
# 4. Interpretation
# ---------------------------------------------------------------------------


def _section_interpretation(record: CampaignRecord) -> list[str]:
    lines = [SECTION_HEADINGS[3], ""]
    thresholds = record.config.scoring.interpretation.model_dump()
    lines += [
        "Thresholds used (config.scoring.interpretation): "
        + ", ".join(f"{k} = {v:g}" for k, v in thresholds.items()) + ".",
        "",
    ]
    if not record.interpretation:
        lines.append("No interpretation statements were produced.")
        return lines
    lines.extend(
        f"- **{_text(item.id)}** [{item.kind}] {_text(item.statement)} — basis: "
        + ", ".join(_code(b) for b in item.basis)
        for item in record.interpretation
    )
    return lines


# ---------------------------------------------------------------------------
# 5. Candidate recommendations
# ---------------------------------------------------------------------------


def _measured_sentence(recommendation: CandidateRecommendation, record: CampaignRecord) -> list[str]:
    """Spec 16.4 (5): the measured figure always reads as a delta at settings, never a bare number."""
    measured = recommendation.measured
    assert measured is not None  # the schema validator pairs ``validation == "measured"`` with a block
    score = record.score
    delta = score.delta if score is not None else None
    if (
        delta is not None
        and record.run_id == measured.verify_run_id
        and delta.baseline_run_id == measured.baseline_run_id
        and delta.delta == measured.delta_mri
    ):
        before_after = f"MRI {delta.mri_before} → {delta.mri_after}"
    else:
        before_after = f"MRI before/after are recorded on verify run {_text(measured.verify_run_id)}"
    defense = (
        f"{_text(measured.defense.art_class or measured.defense.id)}({_json_text(measured.defense.params)})"
    )
    clean = f"{_point(measured.delta_acc_clean.before)} → {_point(measured.delta_acc_clean.after)}"
    sentence = (
        f"Measured ΔMRI {_signed(measured.delta_mri)} ({before_after}; clean accuracy {clean}; verify run "
        f"{_text(measured.verify_run_id)}, settings {_text(measured.settings_hash)[:12]}, defense {defense})"
    )
    settings = (
        f"Settings: baseline run {_code(measured.baseline_run_id)} and verify run {_code(measured.verify_run_id)} "
        f"share settings hash {_code(measured.settings_hash)} (before = after); measured at "
        f"{_when(measured.measured_at)}."
    )
    dimensions = ", ".join(
        f"{key} {_signed(getattr(measured.delta_subscores, key))}" for key in SUBSCORE_KEYS
    )
    return [f"  - {sentence}", f"  - {settings}", f"  - Per-dimension Δ: {dimensions}"]


def _section_recommendations(record: CampaignRecord) -> list[str]:
    lines = [SECTION_HEADINGS[4], ""]
    if not record.recommendations:
        lines.append("No candidate recommendations were produced.")
        return lines
    for rec in record.recommendations:
        lines += [
            f"- **{_text(rec.id)}** [{rec.status}] {_text(rec.title)}",
            f"  - Rationale: {_text(rec.rationale)}",
            "  - Triggered by: " + ", ".join(_code(t) for t in rec.triggered_by),
            f"  - Validation: {rec.validation}",
        ]
        if rec.measured is None:
            lines.append(f"  - {NOT_MEASURED}")
        else:
            lines.extend(_measured_sentence(rec, record))
        references = ", ".join(_code(r) for r in rec.references) or "none"
        lines.append(f"  - References (inert text, not links): {references}")
        if rec.narrative:
            lines.append(f"  - Narrative (source: {rec.narrative_source}):")
            lines.extend(_quoted(rec.narrative, indent="  "))
        else:
            lines.append(f"  - Narrative: none (narrative_source: {rec.narrative_source})")
        lines.append("")
    while lines and lines[-1] == "":
        lines.pop()
    return lines


# ---------------------------------------------------------------------------
# 6. Limitations and reviewer notes
# ---------------------------------------------------------------------------


def _section_limitations(record: CampaignRecord) -> list[str]:
    lines = [SECTION_HEADINGS[5], ""]
    if record.limitations:
        lines.extend(f"- {_text(item)}" for item in record.limitations)
    else:
        lines.append(f"No limitations were recorded (run status: {record.status}).")
    if not any("export-redaction" in item for item in record.limitations):
        lines.append(f"- {EXPORT_REDACTION_NOTE}")
    if record.reviewer_notes:
        lines += ["", REVIEWER_NOTES_HEADING, "", *_quoted(record.reviewer_notes)]
    return lines


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def render_markdown(record: CampaignRecord, *, generated_at: datetime | None = None) -> str:
    """The Markdown report: spec 14.8's six sections in order, user strings unescaped."""
    stamp = generated_at if generated_at is not None else datetime.now(UTC)
    parts: list[str] = [REPORT_TITLE, ""]
    measurements = _section_measurements(record)
    if is_llm_probe_record(record):
        # LLM probe results live beside the measurements as their own block (spec 11.6):
        # k/n per probe family, never an MRI, and only when the record is a probe record.
        measurements = [*measurements, "", *_llm_section(record, stamp)]
    for section in (
        _section_configuration(record, stamp),
        measurements,
        _section_observations(record),
        _section_interpretation(record),
        _section_recommendations(record),
        _section_limitations(record),
    ):
        parts.extend(section)
        parts.append("")
    return "\n".join(parts).rstrip("\n") + "\n"


def render_html(markdown: str, record: CampaignRecord) -> str:
    """HTML built from the Markdown through ``redsim.report``'s escaping helpers; no anchors."""
    body = _md_to_html_min(markdown)
    title = html_escape(f"Redsim ML campaign report — {record.run_id}")
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{title}</title><style>{_HTML_CSS}</style></head><body>{body}</body></html>"
    )


def render_campaign_reports(
    record: CampaignRecord,
    *,
    generated_at: datetime | None = None,
    formats: Sequence[str] | None = None,
) -> list[tuple[str, bytes, str]]:
    """Return Markdown, canonical JSON, escaped HTML and (on request) PDF report artifacts.

    ``formats`` defaults to :data:`REPORT_FORMATS_TEXT`; pass :data:`REPORT_FORMATS_ALL`
    (or any subset naming ``pdf``) to add ``report.pdf``, typeset from the same
    Markdown by ``redsim.ml.pdf`` (imported only then). The output order is the
    order of :data:`REPORT_FORMATS_ALL`. ``report.json`` is exactly
    ``record.model_dump(mode="json")`` — the RunRecord dump with the campaign
    projections and the ``MRIRecord`` under ``score`` — so it round-trips to the
    record and carries everything needed to rerun (spec 14.4).
    """
    wanted = set(REPORT_FORMATS_TEXT if formats is None else formats)
    unknown = sorted(wanted - set(REPORT_FORMATS_ALL))
    if unknown:
        raise ValueError(f"unknown report formats: {unknown}; choose from {list(REPORT_FORMATS_ALL)}")
    stamp = generated_at if generated_at is not None else datetime.now(UTC)
    markdown = render_markdown(record, generated_at=stamp)
    out: list[tuple[str, bytes, str]] = []
    if "md" in wanted:
        out.append(("report.md", markdown.encode(), REPORT_CONTENT_TYPES["md"]))
    if "json" in wanted:
        json_bytes = (
            json.dumps(
                record.model_dump(mode="json"),
                sort_keys=True,
                indent=2,
                separators=(",", ": "),
            )
            + "\n"
        ).encode()
        out.append(("report.json", json_bytes, REPORT_CONTENT_TYPES["json"]))
    if "html" in wanted:
        out.append(("report.html", render_html(markdown, record).encode(), REPORT_CONTENT_TYPES["html"]))
    if "pdf" in wanted:
        from redsim.ml.pdf import render_pdf

        out.append(("report.pdf", render_pdf(record, generated_at=stamp, markdown=markdown),
                    REPORT_CONTENT_TYPES["pdf"]))
    return out


__all__ = [
    "BUDGET_LABELS",
    "DEFAULT_WEIGHTS_NOTE",
    "DELTA_HEADING",
    "DERIVED_MODEL_HEADING",
    "DETECTION_EVIDENCE_HEADING",
    "DETECTION_SCORECARD_HEADING",
    "EXPORT_REDACTION_NOTE",
    "LICENCE_UNRECORDED",
    "LLM_EMBED_NOTE",
    "LLM_HEADING",
    "NON_DEFAULT_WEIGHTS_BADGE",
    "NOT_MEASURED",
    "REPORT_CONTENT_TYPES",
    "REPORT_FORMATS_ALL",
    "REPORT_FORMATS_TEXT",
    "REVIEWER_NOTES_HEADING",
    "SCORECARD_HEADING",
    "SECTION_HEADINGS",
    "TEXT_BUDGET_HEADING",
    "TEXT_EVIDENCE_HEADING",
    "is_llm_probe_record",
    "render_campaign_reports",
    "render_html",
    "render_markdown",
]
