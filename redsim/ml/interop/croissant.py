"""The Croissant (MLCommons JSON-LD) manifest over the Parquet shards (INTEROP-05, -06, -12).

``build_manifest`` projects a terminal campaign or verify record and its shards
into an MLCommons Croissant 1.0 document: ``@context`` / ``conformsTo``, ``name``,
``description``, ``license``, a ``FileObject`` per shard carrying its ``sha256``
and ``contentSize``, one ``RecordSet`` per family with typed ``Field`` entries,
and a ``redsim:provenance`` block carrying the model and settings digests, the
source dataset id/revision/licence with the coverage caveat, the campaign
configuration, the limitations verbatim, the ATLAS technique per attack and (for
a verify run) the baseline run id. The document is serialised with sorted keys
so two builds of the same record are byte-identical, and its own ``sha256`` is
the dataset version.

Nothing that would leak leaves in the manifest: no model weights or weight-file
path, no dataset bytes beyond the shards, no Pythia settings, no credentials, no
user ids, no reviewer notes, and no bare MRI value (the D9 bound). Digests, ids
and counts only. ``croissant_validate`` is the structural gate the export job
runs before writing; ``check_projection`` is the projection-equality guard that
refuses to export a row that disagrees with the run's ``flip_matrix`` oracle.

This module imports only the standard library and ``redsim.ml`` constant helpers
(no pyarrow at import time); ``check_projection`` reads shards back through
``parquet.read_table`` lazily.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

from redsim.ml.schema import GRADE_STATEMENT, contains_banned_score_word

if TYPE_CHECKING:  # pragma: no cover - typing only
    from redsim.ml.interop.parquet import Shard
    from redsim.ml.schema import CampaignRecord

CROISSANT_1_0 = "http://mlcommons.org/croissant/1.0"

CROISSANT_CONTEXT: dict[str, Any] = {
    "@language": "en",
    "@vocab": "https://schema.org/",
    "sc": "https://schema.org/",
    "cr": "http://mlcommons.org/croissant/",
    "rai": "http://mlcommons.org/croissant/RAI/",
    "dct": "http://purl.org/dc/terms/",
    "column": "cr:column",
    "data": {"@id": "cr:data", "@type": "@json"},
    "dataType": {"@id": "cr:dataType", "@type": "@vocab"},
    "extract": "cr:extract",
    "field": "cr:field",
    "fileObject": "cr:fileObject",
    "format": "cr:format",
    "includes": "cr:includes",
    "recordSet": "cr:recordSet",
    "repeated": "cr:repeated",
    "source": "cr:source",
    "sha256": "sc:sha256",
    "redsim": "https://github.com/IntelliBridge/ndia-red-team-simulator#",
}

# Substrings that must never appear anywhere in a manifest: a serialised model,
# a credential-bearing env name, a reviewer note or a user subject. Vocabulary
# URIs in ``@context`` are metadata, not data, so the check targets these tokens
# rather than banning every URL.
_BANNED_TOKENS: tuple[str, ...] = (
    ".pt", ".pth", ".onnx", ".joblib", ".safetensors", ".pkl", ".ckpt",
    "reviewer_notes", "reviewer_note", "PYTHIA_", "OPENAI", "AWS_",
    "secret", "password", "api_key", "authorization", "auth_profile",
)


class ExportMismatch(Exception):
    """An exported row disagreed with the run record's oracle; the export is refused.

    The export job records this as its ``Job.error`` and writes a ``success=False``
    ``dataset.export.execute`` row rather than ship labels that are not the record's.
    """

    code = "export_projection_mismatch"


class CroissantValidationError(ValueError):
    """The manifest is not structurally a Croissant 1.0 dataset (or carries banned content)."""

    code = "croissant_invalid"


def manifest_digest(manifest_bytes: bytes) -> str:
    """The dataset version: the sha256 of the manifest bytes."""
    return hashlib.sha256(manifest_bytes).hexdigest()


def _file_object(shard: Shard) -> dict[str, Any]:
    return {
        "@type": "cr:FileObject",
        "@id": shard.name,
        "name": shard.name,
        "contentUrl": f"data/{shard.name}",
        "encodingFormat": "application/vnd.apache.parquet",
        "sha256": shard.sha256,
        "contentSize": f"{shard.size} B",
    }


def _field(family: str, column: str, datatype: str, shard_ids: list[str]) -> dict[str, Any]:
    field: dict[str, Any] = {
        "@type": "cr:Field",
        "@id": f"{family}/{column}",
        "name": column,
        "dataType": datatype,
        "source": {"fileObject": shard_ids, "extract": {"column": column}},
    }
    if column == "input":
        field["repeated"] = True
        field["description"] = "flattened feature vector or input tensor (see redsim:input_shape)"
    return field


def _record_set(family: str, shards: list[Shard], input_shape: list[int] | None) -> dict[str, Any]:
    from redsim.ml.interop.parquet import COLUMN_DATATYPES, COLUMNS

    shard_ids = [s.name for s in shards]
    fields = [_field(family, col, COLUMN_DATATYPES[col], shard_ids) for col in COLUMNS]
    return {
        "@type": "cr:RecordSet",
        "@id": family,
        "name": family,
        "description": f"{family} rows, one per sample per (attack, eps) slice.",
        "field": fields,
        "redsim:n_rows": sum(s.n_rows for s in shards),
        "redsim:input_shape": list(input_shape or []),
    }


def _atlas_for(attacks: list[str]) -> dict[str, Any]:
    """``{attack: {id, name, atlas_version}}`` via the atlas-foundry contract, degrading gracefully.

    ``redsim.ml.atlas.technique_for_attack`` is the sibling track's function; when the
    tree lags it, the pinned constant in ``redsim.ml.atlas_data`` answers. A control or
    an unmapped attack has no technique.
    """
    tech: Any = None
    try:
        from redsim.ml.atlas import technique_for_attack as tech
    except Exception:  # noqa: BLE001 - sibling track may not be on the tree yet
        try:
            from redsim.ml.atlas_data import primary_technique_for_attack as tech
        except Exception:  # noqa: BLE001
            tech = None
    out: dict[str, Any] = {}
    if tech is None:
        return out
    for attack in attacks:
        try:
            mapped = tech(attack)
        except Exception:  # noqa: BLE001 - an unmapped attack is simply absent
            mapped = None
        if mapped is not None:
            out[attack] = mapped.model_dump() if hasattr(mapped, "model_dump") else dict(mapped)
    return out


def _atlas_release() -> dict[str, Any]:
    try:
        from redsim.ml.atlas_data import ATLAS_RELEASE, ATLAS_VERSION

        return {"release": ATLAS_RELEASE, "version": ATLAS_VERSION}
    except Exception:  # noqa: BLE001
        return {}


def _input_shape(record: CampaignRecord) -> list[int]:
    manifest = (record.provenance.model_manifest if record.provenance else None) or {}
    shape = manifest.get("input_shape") or record.target.metadata.get("input_shape")
    if isinstance(shape, list) and all(isinstance(v, int) for v in shape):
        return list(shape)
    return []


def build_manifest(record: CampaignRecord, shards: list[Shard], *, dataset_license: str,
                   regenerated: bool = False, checked_against: str = "flip_matrix",
                   ) -> tuple[dict[str, Any], bytes, str]:
    """Build the Croissant manifest, its canonical bytes and its sha256 (the dataset version)."""
    families: dict[str, list[Shard]] = {}
    for shard in shards:
        families.setdefault(shard.family, []).append(shard)
    shape = _input_shape(record)

    distribution = [_file_object(shard) for shard in shards]
    record_sets = [_record_set(family, families[family], shape) for family in sorted(families)]

    provenance = record.provenance
    atlas = _atlas_for(list(record.config.attack_ids))
    redsim_block: dict[str, Any] = {
        "source_run_id": record.run_id,
        "kind": record.kind,
        "baseline_run_id": record.baseline_run_id,
        "settings_hash": record.settings_hash,
        "model_sha256": provenance.model_sha256 if provenance else None,
        "dataset_id": record.config.dataset_id,
        "dataset_revision": record.config.dataset_revision,
        "dataset_license": dataset_license,
        "coverage_caveat": ("This dataset covers only the declared attack set, ε grid and sample slice; "
                            "it is not evidence about attacks, budgets or inputs that were not run."),
        "campaign": {
            "modality": record.config.modality,
            "attack_ids": list(record.config.attack_ids),
            "eps_grid": list(record.config.eps_grid),
            "reference_eps": record.config.reference_eps,
            "norm": record.config.norm,
            "n_samples": record.config.n_samples,
            "seed": record.config.seed,
        },
        "atlas": atlas,
        "atlas_release": _atlas_release(),
        "input_shape": shape,
        "limitations": list(record.limitations),
        "projection_checked_against": checked_against,
        "regenerated": bool(regenerated),
        "regenerated_nondeterminism": list(provenance.nondeterminism) if (regenerated and provenance) else [],
        "grade_statement": GRADE_STATEMENT,
    }
    manifest: dict[str, Any] = {
        "@context": CROISSANT_CONTEXT,
        "@type": "sc:Dataset",
        "conformsTo": CROISSANT_1_0,
        "name": f"redsim-adversarial-{record.run_id}",
        "description": (
            "Adversarial evaluation dataset exported from a redsim campaign: per-sample clean, "
            "adversarial and control slices with true labels and the flipped flag, one Parquet "
            "shard per (attack, ε). A projection of the run record, not a recomputation."),
        "license": dataset_license,
        "version": record.settings_hash or record.run_id,
        "distribution": distribution,
        "recordSet": record_sets,
        "redsim:provenance": redsim_block,
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return manifest, manifest_bytes, manifest_digest(manifest_bytes)


def croissant_validate(manifest: dict[str, Any]) -> None:
    """Structural gate: raise :class:`CroissantValidationError` when the manifest is not a
    well-formed Croissant 1.0 dataset, or carries a banned token or a bare MRI value."""
    if manifest.get("conformsTo") != CROISSANT_1_0:
        raise CroissantValidationError(f"conformsTo must be {CROISSANT_1_0!r}")
    if not isinstance(manifest.get("@context"), dict):
        raise CroissantValidationError("@context must be an object")
    for key in ("name", "description", "license"):
        if not isinstance(manifest.get(key), str) or not manifest[key].strip():
            raise CroissantValidationError(f"{key!r} must be a non-empty string")

    distribution = manifest.get("distribution")
    if not isinstance(distribution, list) or not distribution:
        raise CroissantValidationError("distribution must be a non-empty list of FileObjects")
    for file_object in distribution:
        if not isinstance(file_object, dict):
            raise CroissantValidationError("every distribution entry must be an object")
        if file_object.get("@type") not in ("cr:FileObject", "sc:FileObject"):
            raise CroissantValidationError("a distribution entry must be a cr:FileObject")
        sha = file_object.get("sha256")
        if not (isinstance(sha, str) and len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)):
            raise CroissantValidationError(f"FileObject {file_object.get('name')!r} needs a sha256")
        for key in ("name", "contentUrl", "encodingFormat", "contentSize"):
            if not file_object.get(key):
                raise CroissantValidationError(f"FileObject {file_object.get('name')!r} missing {key!r}")

    record_sets = manifest.get("recordSet")
    if not isinstance(record_sets, list) or not record_sets:
        raise CroissantValidationError("recordSet must be a non-empty list")
    for record_set in record_sets:
        if not isinstance(record_set, dict) or record_set.get("@type") != "cr:RecordSet":
            raise CroissantValidationError("a recordSet entry must be a cr:RecordSet")
        fields = record_set.get("field")
        if not isinstance(fields, list) or not fields:
            raise CroissantValidationError(f"recordSet {record_set.get('name')!r} needs fields")
        for one in fields:
            if not isinstance(one, dict) or one.get("@type") != "cr:Field":
                raise CroissantValidationError("a field must be a cr:Field")
            if not one.get("name") or not one.get("dataType"):
                raise CroissantValidationError(f"field {one.get('name')!r} needs a name and dataType")

    provenance = manifest.get("redsim:provenance")
    if isinstance(provenance, dict) and "mri" in provenance:
        raise CroissantValidationError("the manifest must not carry a bare MRI value (D9)")

    text = json.dumps(manifest, ensure_ascii=False).lower()
    for token in _BANNED_TOKENS:
        if token.lower() in text:
            raise CroissantValidationError(f"manifest carries a banned token: {token!r}")
    if '"mri"' in text:
        raise CroissantValidationError("the manifest must not carry a bare MRI value (D9)")
    # The grade statement is the only permitted grade text; nothing else may use a banned score word.
    scrubbed = text.replace(GRADE_STATEMENT.lower(), "")
    if contains_banned_score_word(scrubbed):
        raise CroissantValidationError("manifest carries a banned score word")


def check_projection(shards: list[Shard], flip_matrix: dict[str, Any] | None) -> str:
    """Refuse the export unless every adversarial row's ``flipped`` equals the run's oracle.

    The oracle is ``ml.flip_matrix`` (per-(attack, eps) flipped flags aligned to its
    ``indices``). A shard whose family the record's oracle does not carry, a sample the
    oracle does not name, or a ``flipped`` value that disagrees is an :class:`ExportMismatch`.
    Returns the name of the oracle checked against so the manifest can record it.
    """
    from redsim.ml.interop.parquet import FAMILY_ADVERSARIAL, eps_tag, read_table

    fm = (flip_matrix or {}).get("flipped", {}) or {}
    fm_indices = [int(i) for i in (flip_matrix or {}).get("indices", [])]
    for shard in shards:
        if shard.family != FAMILY_ADVERSARIAL:
            continue
        tag = eps_tag(shard.eps) if shard.eps is not None else None
        oracle_flags = fm.get(shard.attack, {}).get(tag) if tag is not None else None
        if oracle_flags is None:
            raise ExportMismatch(
                f"flip_matrix has no oracle for {shard.attack!r} at {tag!r}; the export cannot be verified")
        oracle = {idx: bool(flag) for idx, flag in zip(fm_indices, oracle_flags)}
        table = read_table(shard.data)
        indices = table.column("sample_index").to_pylist()
        flipped = table.column("flipped").to_pylist()
        for idx, value in zip(indices, flipped):
            want = oracle.get(int(idx))
            if want is None:
                raise ExportMismatch(
                    f"sample {idx} of shard {shard.name!r} is not in the flip_matrix oracle")
            if bool(value) != want:
                raise ExportMismatch(
                    f"exported flipped for sample {idx} of {shard.name!r} is {value!r}, "
                    f"the run record's flip_matrix says {want!r}")
    return "flip_matrix"


__all__ = [
    "CROISSANT_1_0", "CROISSANT_CONTEXT", "CroissantValidationError", "ExportMismatch",
    "build_manifest", "check_projection", "croissant_validate", "manifest_digest",
]
