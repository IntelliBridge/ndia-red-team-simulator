"""MITRE ATLAS stamping and coverage over the pinned ``redsim.ml.atlas_data`` table (spec 27.2).

Plan 12 wave B3, ``atlas-foundry`` track (register INTEROP-18, -20, -21). Three
things live here and nothing else:

* :func:`technique_for_attack` is the **stamp**: the one top-level technique a
  finding on ``attack_id`` carries at ``schema_blob.ml.atlas_technique``
  (``redsim.services.ml_findings.build_finding_detail`` calls it). The table is
  :data:`STAMP_TECHNIQUE_IDS`; every entry is checked against
  ``atlas_data.ATTACK_TECHNIQUE_IDS`` so the stamp is always one of the
  techniques the vendored table already attributes to that attack. A control
  or an unknown id yields ``None``: nothing is guessed, nothing is back-filled.
* :func:`attack_atlas_row` is what ``GET /v1/attacks`` adds to each catalog row
  (route-level enrichment; the frozen ``AttackInfo`` gains no field).
* :func:`coverage` is the per-campaign **coverage view**: the techniques the
  in-scope attacks that ran exercised, the techniques of declared attacks
  recorded ``not_run`` (spec 9.5), and the catalog techniques outside the
  declared set. It is a description of the declared attack set, not a score:
  it carries no numeric field at all (the function refuses its own output if
  one appears), no colour grade, and says nothing about techniques not run.

The mapping (spec 27.2 table, plan 12 wave B3 brief):

* ``fgsm``, ``pgd``, ``cw_l2``, ``deepfool`` (gradient-crafted evasion) and the
  tabular surrogate-transfer PGD stamp ``AML.T0043 Craft Adversarial Data``.
* ``hopskipjump`` and ``zoo`` reach the model only through its prediction
  interface and stamp ``AML.T0040``, the inference-API access technique (the
  2026.08 release names it "AI Model Inference API Access"; ``atlas_data``
  records the earlier "ML Model Inference API Access" as a prior name of the
  same id).
* ``word_substitution`` (text evasion) stamps ``AML.T0043``: ATLAS has no
  text-specific evasion technique among the vendored ids, so the evasion
  technique applies and the black-box sub-technique rides in ``techniques``.
* ``dpatch`` (physical patch) stamps ``AML.T0043``: ATLAS ``2026.08`` has no
  patch-specific technique among the vendored ids either; the white-box
  sub-technique rides in ``techniques``. Adding a patch technique is a
  registry change in ``atlas_data`` with a release bump, never a guess here.
* The poisoning ids are **reserved**: they are mapped so the data-poisoning
  module (brief package F) stamps the same way, but no adapter of that family
  is registered on this tree and nothing here claims otherwise.

This module imports ``redsim.ml.atlas_data`` and ``redsim.ml.schema`` only
(pydantic), so the API process serves the vocabulary without an ML library.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from redsim.ml import atlas_data
from redsim.ml.schema import AtlasTechnique

#: The stamp per attack id: one top-level technique from ``atlas_data.ATTACK_TECHNIQUE_IDS``.
STAMP_TECHNIQUE_IDS: dict[str, str] = {
    # White-box evasion: gradient-crafted adversarial examples.
    "fgsm": "AML.T0043",
    "pgd": "AML.T0043",
    "cw_l2": "AML.T0043",
    "deepfool": "AML.T0043",
    "surrogate_transfer_pgd": "AML.T0043",
    # Black-box query attacks against the prediction interface.
    "hopskipjump": "AML.T0040",
    "zoo": "AML.T0040",
    # Text evasion (word substitution) and the physical patch: see the module docstring.
    "word_substitution": "AML.T0043",
    "dpatch": "AML.T0043",
    # Reserved for the data-poisoning module (brief package F); no adapter on this tree.
    "label_flip_poisoning": "AML.T0020",
    "backdoor_poisoning": "AML.T0020",
}

#: Why each attack stamps what it stamps (shown beside the tag; never a score word).
STAMP_REASONS: dict[str, str] = {
    "fgsm": "white-box evasion: gradient-crafted adversarial data",
    "pgd": "white-box evasion: gradient-crafted adversarial data",
    "cw_l2": "white-box minimal-norm evasion: gradient-crafted adversarial data",
    "deepfool": "white-box minimal-norm evasion: gradient-crafted adversarial data",
    "surrogate_transfer_pgd": "white-box evasion through a surrogate: black-box transfer of crafted adversarial data",
    "hopskipjump": "decision-based black-box attack: reaches the model only through its inference API",
    "zoo": "score-based black-box attack: reaches the model only through its inference API",
    "word_substitution": ("text evasion by word substitution: crafted adversarial text; ATLAS has no text-specific "
                          "technique among the vendored ids, so the evasion technique applies"),
    "dpatch": ("physical adversarial patch: crafted adversarial data; ATLAS has no patch-specific technique among "
               "the vendored ids, so the evasion technique applies"),
    "label_flip_poisoning": "reserved: training-data poisoning (data-poisoning module, not on this tree)",
    "backdoor_poisoning": "reserved: training-data poisoning with a backdoor trigger (not on this tree)",
}

#: Control adapters: they demonstrate no technique and never create a finding (spec 12.4).
CONTROL_ATTACK_IDS: frozenset[str] = frozenset({"noise_control", "random_swap", "random_patch"})
CONTROL_REASON = "a control demonstrates no adversarial technique and never creates a finding"
UNKNOWN_REASON = "not in the vendored ATLAS mapping; nothing is guessed for an unmapped attack id"

#: The sentence every coverage view carries (spec 27.2 "Coverage view"; the D9(i) analogue).
COVERAGE_STATEMENT = ("Describes the declared attack set of this one campaign; it is not a score, enters no "
                      "subscore, has no grade and says nothing about techniques that were not run.")
#: How a stored tag from an earlier release should be read (spec 27.2 "Drift").
STORED_NAME_NOTE = ("A finding keeps the technique id, name and atlas_version it was stamped with; a name that "
                    "differs from this release is the same technique under an earlier ATLAS name "
                    "(atlas_data.ATLAS_PRIOR_NAMES).")

#: Interpretation id prefix the campaign frame writes for an attack recorded ``not_run`` (spec 9.5).
NOT_RUN_INTERPRETATION_PREFIX = "i.attack.not_run."


def _check_stamp_table() -> None:
    """Every stamp is a top-level technique the vendored table already attributes to that attack."""
    for attack_id, technique_id in STAMP_TECHNIQUE_IDS.items():
        attributed = atlas_data.ATTACK_TECHNIQUE_IDS.get(attack_id, ())
        if technique_id not in attributed:
            raise RuntimeError(f"atlas stamp for {attack_id!r} ({technique_id}) is not among the techniques "
                               f"atlas_data attributes to it: {attributed}")
        if atlas_data.ATLAS_TECHNIQUES[technique_id].parent is not None:
            raise RuntimeError(f"atlas stamp for {attack_id!r} must be a top-level technique, got {technique_id}")
    for attack_id in atlas_data.ATTACK_TECHNIQUE_IDS:
        if attack_id not in STAMP_TECHNIQUE_IDS:
            raise RuntimeError(f"atlas_data maps {attack_id!r} but STAMP_TECHNIQUE_IDS has no stamp for it")


_check_stamp_table()


# --------------------------------------------------------------------------- the stamp


def technique_for_attack(attack_id: str) -> AtlasTechnique | None:
    """The ``AtlasTechnique`` a finding on ``attack_id`` is stamped with, or ``None`` (controls, unknown ids)."""
    technique_id = STAMP_TECHNIQUE_IDS.get(attack_id)
    if technique_id is None:
        return None
    return atlas_data.technique_tag(technique_id)


def techniques_for_attack(attack_id: str) -> list[dict[str, str | None]]:
    """Every vendored technique attributed to ``attack_id`` (the stamp first), as plain rows."""
    rows = [{"id": r.id, "name": r.name, "family": r.family, "parent": r.parent}
            for r in atlas_data.techniques_for_attack(attack_id)]
    stamp = STAMP_TECHNIQUE_IDS.get(attack_id)
    rows.sort(key=lambda r: 0 if r["id"] == stamp else 1)
    return rows


def stamp_reason(attack_id: str) -> str:
    """Why ``attack_id`` stamps what it stamps, or why it stamps nothing."""
    if attack_id in STAMP_REASONS:
        return STAMP_REASONS[attack_id]
    if attack_id in CONTROL_ATTACK_IDS:
        return CONTROL_REASON
    return UNKNOWN_REASON


def attack_atlas_row(attack_id: str) -> dict[str, Any]:
    """The ATLAS block ``GET /v1/attacks`` adds to a catalog row (additive; ``AttackInfo`` is unchanged).

    ``atlas_technique`` is the stamp (``{id, name, atlas_version}``) or ``None``;
    ``atlas_techniques`` lists every attributed technique with its parent;
    ``atlas_reason`` says why. A control's technique is ``None`` with the
    control reason (spec 27.2 table, third row).
    """
    tag = technique_for_attack(attack_id)
    return {
        "atlas_technique": tag.model_dump(mode="json") if tag is not None else None,
        "atlas_techniques": techniques_for_attack(attack_id),
        "atlas_reason": stamp_reason(attack_id),
    }


def release_citation() -> dict[str, str]:
    """The pinned ATLAS release as strings only (no byte counts, no technique counts)."""
    record = atlas_data.release_record()
    return {
        "release": str(record["release"]),
        "version": str(record["version"]),
        "format_version": str(record["format_version"]),
        "published": str(record["published"]),
        "checked_on": str(record["checked_on"]),
        "data_file": str(record["data_file"]),
        "data_sha256": str(record["data_sha256"]),
        "license": str(record["license"]),
        "license_sha256": str(record["license_sha256"]),
        "attribution": str(record["attribution"]),
    }


# --------------------------------------------------------------------------- the coverage view


def _as_mapping(record: Any) -> Mapping[str, Any]:
    dump = getattr(record, "model_dump", None)
    if callable(dump):
        result = dump(mode="json")
        if isinstance(result, Mapping):
            return result
    if isinstance(record, Mapping):
        return record
    raise TypeError(f"coverage needs a run record or its mapping, got {type(record).__name__}")


def declared_attack_ids(record: Any) -> list[str]:
    """``config.attack_ids`` of a record, in declared order, without repeats."""
    data = _as_mapping(record)
    config = data.get("config")
    ids = config.get("attack_ids") if isinstance(config, Mapping) else None
    return [str(a) for a in dict.fromkeys(ids or [])]


def exercised_attack_ids(record: Any) -> list[str]:
    """Declared attacks with at least one evasion measurement row (the attack ran)."""
    data = _as_mapping(record)
    declared = declared_attack_ids(data)
    ran: set[str] = set()
    for row in data.get("measurements") or []:
        if isinstance(row, Mapping) and row.get("family") == "evasion" and row.get("attack_id"):
            ran.add(str(row["attack_id"]))
    return [a for a in declared if a in ran]


def not_run_reasons(record: Any) -> dict[str, str]:
    """``attack_id -> reason`` for every declared attack without a measurement row (spec 9.5).

    The reason is the frame's own ``i.attack.not_run.<attack_id>`` interpretation
    statement when the record carries one; otherwise the record's status says
    why nothing was measured. Never a number.
    """
    data = _as_mapping(record)
    ran = set(exercised_attack_ids(data))
    statements: dict[str, str] = {}
    for row in data.get("interpretation") or []:
        if not isinstance(row, Mapping):
            continue
        row_id = str(row.get("id") or "")
        if row_id.startswith(NOT_RUN_INTERPRETATION_PREFIX):
            statements[row_id[len(NOT_RUN_INTERPRETATION_PREFIX):]] = str(row.get("statement") or "")
    status = str(data.get("status") or "unknown")
    error = data.get("error")
    out: dict[str, str] = {}
    for attack_id in declared_attack_ids(data):
        if attack_id in ran:
            continue
        if statements.get(attack_id):
            out[attack_id] = statements[attack_id]
        elif status == "succeeded":
            out[attack_id] = "recorded not_run: the campaign wrote no measurement row for this attack"
        else:
            suffix = f" ({error})" if isinstance(error, str) and error else ""
            out[attack_id] = f"the campaign is {status}{suffix}; no measurement row exists for this attack"
    return out


def _technique_block(attack_id: str) -> dict[str, Any]:
    tag = technique_for_attack(attack_id)
    return {
        "attack_id": attack_id,
        "technique": tag.model_dump(mode="json") if tag is not None else None,
        "techniques": techniques_for_attack(attack_id),
        "reason": stamp_reason(attack_id),
    }


def numeric_paths(value: Any, path: str = "") -> list[str]:
    """Paths of every ``int`` / ``float`` in ``value`` (``bool`` excluded); ``[]`` for a number-free payload."""
    found: list[str] = []
    if isinstance(value, bool) or value is None:
        return found
    if isinstance(value, (int, float)):
        return [path or "<root>"]
    if isinstance(value, Mapping):
        for key, inner in value.items():
            found.extend(numeric_paths(inner, f"{path}.{key}" if path else str(key)))
    elif isinstance(value, (list, tuple)):
        for index, inner in enumerate(value):
            found.extend(numeric_paths(inner, f"{path}[{index}]"))
    return found


def coverage(
    record: Any,
    *,
    catalog_attacks: Iterable[tuple[str, str]] | Sequence[str] | None = None,
) -> dict[str, Any]:
    """The per-campaign ATLAS coverage view (spec 27.2 "Coverage view"; register INTEROP-21).

    ``record`` is a ``CampaignRecord`` / ``RunRecord`` or its mapping.
    ``catalog_attacks`` is the attack catalog as ``(attack_id, family)`` pairs
    (or bare ids, family taken from the mapping); when ``None`` the vendored
    mapping's own attack ids stand in and ``catalog_source`` says so.

    The result has no numeric field: membership lists and text only. It raises
    ``ValueError`` if a number slipped in, so a caller can never serve a score
    under the coverage name by accident.
    """
    data = _as_mapping(record)
    declared = declared_attack_ids(data)
    ran = exercised_attack_ids(data)
    reasons = not_run_reasons(data)
    if catalog_attacks is None:
        pairs: list[tuple[str, str]] = [(a, "evasion") for a in atlas_data.ATTACK_TECHNIQUE_IDS]
        pairs += [(c, "control") for c in sorted(CONTROL_ATTACK_IDS)]
        catalog_source = "atlas_data.ATTACK_TECHNIQUE_IDS (the attack registry was not consulted)"
    else:
        pairs = []
        for item in catalog_attacks:
            if isinstance(item, tuple):
                pairs.append((str(item[0]), str(item[1])))
            else:
                aid = str(item)
                pairs.append((aid, "control" if aid in CONTROL_ATTACK_IDS else "evasion"))
        catalog_source = "attack registry"
    declared_set = set(declared)
    outside = [aid for aid, family in pairs if family != "control" and aid not in declared_set]
    controls = [aid for aid, family in pairs if family == "control"]
    exercised_rows = [{**_technique_block(aid), "status": "run"} for aid in ran]
    not_run_rows = [{**_technique_block(aid), "status": "not_run", "not_run_reason": reasons.get(aid, "")}
                    for aid in declared if aid not in set(ran)]
    exercised_ids = sorted({row["technique"]["id"] for row in exercised_rows if row["technique"]})
    exercised_names = {row["technique"]["id"]: row["technique"]["name"]
                       for row in exercised_rows if row["technique"]}
    out: dict[str, Any] = {
        "kind": "atlas_coverage",
        "run_id": str(data.get("run_id") or ""),
        "campaign_kind": str(data.get("kind") or "attack"),
        "campaign_status": str(data.get("status") or "unknown"),
        "atlas": release_citation(),
        "declared_attack_ids": list(declared),
        "exercised": exercised_rows,
        "declared_not_run": not_run_rows,
        "catalog_outside_declared": [_technique_block(aid) for aid in outside],
        "controls": [{"attack_id": aid, "technique": None, "reason": CONTROL_REASON} for aid in controls],
        "techniques_exercised": [{"id": tid, "name": exercised_names[tid]} for tid in exercised_ids],
        "catalog_source": catalog_source,
        "statement": COVERAGE_STATEMENT,
        "stored_name_note": STORED_NAME_NOTE,
    }
    numbers = numeric_paths(out)
    if numbers:
        raise ValueError(f"the ATLAS coverage view carries numeric fields: {numbers}")
    return out


__all__ = [
    "CONTROL_ATTACK_IDS",
    "CONTROL_REASON",
    "COVERAGE_STATEMENT",
    "NOT_RUN_INTERPRETATION_PREFIX",
    "STAMP_REASONS",
    "STAMP_TECHNIQUE_IDS",
    "STORED_NAME_NOTE",
    "UNKNOWN_REASON",
    "attack_atlas_row",
    "coverage",
    "declared_attack_ids",
    "exercised_attack_ids",
    "not_run_reasons",
    "numeric_paths",
    "release_citation",
    "stamp_reason",
    "technique_for_attack",
    "techniques_for_attack",
]
