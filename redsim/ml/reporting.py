"""Pure report rendering for persisted adversarial-ML campaign records."""

from __future__ import annotations

import html
import json

from redsim.ml.schema import CampaignRecord


def _markdown(record: CampaignRecord) -> str:
    score = record.score
    lines = [
        "# Redsim Adversarial-ML Campaign Report",
        "",
        f"**Run ID:** {record.run_id}",
        f"**Status:** {record.status}",
        f"**Model:** {record.target.name} (`{record.target.id}`)",
        f"**Dataset:** {record.config.dataset_id} / {record.config.dataset_split}",
        f"**Settings hash:** `{record.settings_hash}`",
        "",
        "## Score",
        "",
    ]
    if score is None or score.mri is None:
        lines.append("MRI is unavailable because the campaign evidence is partial.")
    else:
        lines.extend([
            f"- MRI: **{score.mri}**",
            f"- Grade: **{score.grade}**",
            f"- Completeness: {score.completeness}",
        ])
    lines.extend(["", "## Measurements", ""])
    if not record.measurements:
        lines.append("No measurements were recorded.")
    else:
        clean = next(
            (item for item in record.measurements if item.id == "m.clean"),
            None,
        )
        clean_accuracy = clean.accuracy if clean is not None else None
        lines.extend([
            (
                "| Attack | Epsilon | N | Clean correct | Clean accuracy | "
                "Row accuracy | Flipped | ASR |"
            ),
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ])
        for item in record.measurements:
            eps = item.params.get("eps")
            eps_text = f"{float(eps):g}" if isinstance(eps, (int, float)) else "—"
            attack = item.attack_id or item.family
            clean_text = (
                f"{clean_accuracy:.4f}" if clean_accuracy is not None else "—"
            )
            flipped = (
                str(item.n_flipped_from_clean)
                if item.n_flipped_from_clean is not None else "—"
            )
            asr = (
                f"{item.attack_success_rate:.4f}"
                if item.attack_success_rate is not None else "—"
            )
            lines.append(
                f"| {html.escape(attack)} | {eps_text} | {item.n} | "
                f"{item.n_clean_correct if item.n_clean_correct is not None else '—'} | "
                f"{clean_text} | {item.accuracy:.4f} | {flipped} | {asr} |"
            )
    lines.extend(["", "## Recommendations", ""])
    if not record.recommendations:
        lines.append("No recommendations were produced.")
    else:
        for recommendation in record.recommendations:
            lines.append(
                f"- **{html.escape(recommendation.title)}** — "
                f"{html.escape(recommendation.rationale)}"
            )
    lines.extend(["", "## Limitations", ""])
    lines.extend(
        f"- {html.escape(item)}" for item in record.limitations
    )
    return "\n".join(lines) + "\n"


def render_campaign_reports(
    record: CampaignRecord,
) -> list[tuple[str, bytes, str]]:
    """Return Markdown, canonical JSON, and inert HTML report artifacts."""
    markdown = _markdown(record)
    json_bytes = (
        json.dumps(
            record.model_dump(mode="json"),
            sort_keys=True,
            indent=2,
            separators=(",", ": "),
        )
        + "\n"
    ).encode()
    document = (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>Redsim ML campaign report</title></head><body><pre>"
        f"{html.escape(markdown)}</pre></body></html>"
    ).encode()
    return [
        ("report.md", markdown.encode(), "text/markdown"),
        ("report.json", json_bytes, "application/json"),
        ("report.html", document, "text/html"),
    ]


__all__ = ["render_campaign_reports"]