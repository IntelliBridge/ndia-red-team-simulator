"""The dataset card (text/markdown) rendered from the manifest by a template (INTEROP-09).

The card is a Hugging Face ``datasets``-style README: YAML front matter (license,
task categories, size category, tags) over a body that restates the manifest's
provenance block, the campaign configuration, the ATLAS techniques, the run's
limitations verbatim and the grade statement, closing with an explicit "measured
evidence, not a readiness statement" footer. It is written by this template over
the manifest and the run's limitations — never by the LLM narrator (spec 27 rule 2),
so it can carry no claim the manifest does not. This module imports only the
standard library and ``redsim.ml.schema``.
"""

from __future__ import annotations

from typing import Any

from redsim.ml.schema import GRADE_STATEMENT


def _size_category(n_rows: int) -> str:
    if n_rows < 1_000:
        return "n<1K"
    if n_rows < 10_000:
        return "1K<n<10K"
    if n_rows < 100_000:
        return "10K<n<100K"
    return "100K<n<1M"


def _yaml_list(values: list[str]) -> str:
    return "\n".join(f"  - {value}" for value in values)


def render_card(manifest: dict[str, Any], *, limitations: list[str], license: str,
                total_rows: int = 0) -> str:
    """Render the dataset card markdown from ``manifest`` and the run's ``limitations``."""
    provenance = manifest.get("redsim:provenance", {}) if isinstance(manifest, dict) else {}
    campaign = provenance.get("campaign", {}) if isinstance(provenance, dict) else {}
    atlas = provenance.get("atlas", {}) if isinstance(provenance, dict) else {}
    run_id = provenance.get("source_run_id", "")
    kind = provenance.get("kind", "attack")
    baseline = provenance.get("baseline_run_id")
    dataset_id = provenance.get("dataset_id", "")
    dataset_revision = provenance.get("dataset_revision")
    model_sha = provenance.get("model_sha256")
    settings_hash = provenance.get("settings_hash")

    front_matter = [
        "---",
        f"license: {license}",
        "task_categories:",
        "  - other",
        "tags:",
        _yaml_list(["adversarial-ml", "redsim", "evaluation", f"modality-{campaign.get('modality', 'unknown')}"]),
        "size_categories:",
        f"  - {_size_category(total_rows)}",
        "---",
        "",
    ]

    lines: list[str] = [
        f"# Adversarial evaluation dataset — {run_id}",
        "",
        (manifest.get("description", "") if isinstance(manifest, dict) else ""),
        "",
        "## Provenance",
        "",
        f"- Source run: `{run_id}` ({kind} run)",
    ]
    if baseline:
        lines.append(f"- Baseline run: `{baseline}` (this is a verify-run export; not merged with its baseline)")
    lines += [
        f"- Source dataset: `{dataset_id}`" + (f" @ `{dataset_revision}`" if dataset_revision else ""),
        f"- License: {license}",
        f"- Model digest: `{model_sha}`" if model_sha else "- Model digest: not recorded",
        f"- Settings hash: `{settings_hash}`" if settings_hash else "- Settings hash: not recorded",
        "",
        "## Campaign",
        "",
        f"- Modality: {campaign.get('modality', 'unknown')}",
        f"- Attacks: {', '.join(campaign.get('attack_ids', [])) or 'none'}",
        f"- Norm: {campaign.get('norm', 'unknown')}",
        f"- ε grid: {campaign.get('eps_grid', [])} (reference {campaign.get('reference_eps')})",
        f"- Samples: {campaign.get('n_samples')} (seed {campaign.get('seed')})",
        "",
        "## Files",
        "",
        "Each `data/*.parquet` shard is one family at one setting; columns are the same across shards "
        "(`family`, `attack`, `eps`, `norm`, `sample_index`, `true_label`, `flipped`, per-sample "
        "predictions and confidences where retained, and the numeric `input` vector). Feature-vector "
        "and tensor inputs only: no raw string ever leaves in a row.",
        "",
    ]

    if atlas:
        lines += ["## MITRE ATLAS", ""]
        for attack, technique in atlas.items():
            tid = technique.get("id") if isinstance(technique, dict) else None
            tname = technique.get("name") if isinstance(technique, dict) else None
            lines.append(f"- `{attack}` → {tid} ({tname})")
        lines.append("")

    lines += ["## Limitations", ""]
    for limitation in limitations:
        lines.append(f"- {limitation}")
    lines += [
        "",
        "## Grade statement",
        "",
        GRADE_STATEMENT,
        "",
        "This dataset is measured evidence under one declared attack set, ε grid and sample slice. "
        "It is not a readiness or certification statement, and it says nothing about behaviour under "
        "conditions that were not run.",
        "",
    ]
    return "\n".join(front_matter) + "\n".join(lines) + "\n"


__all__ = ["render_card"]
