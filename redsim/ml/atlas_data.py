"""Vendored MITRE ATLAS technique ids and names, pinned to one atlas-data release (INTEROP-19, spec 27.2, 27.4).

The ids and names below were read from ``ATLAS-2026.08.yaml`` of the
``mitre-atlas/atlas-data`` release ``v2026.08`` (published 2026-09-01) on
``ATLAS_CHECKED_ON``; the file's sha256 and the repository LICENSE digest are
recorded so a later re-verification can prove it looked at the same bytes.
Nothing here fetches: the table is a constant, the YAML is not shipped, and
``verify_atlas_data`` checks a locally supplied copy against this table.

Rules (spec 27.2 "Drift", spec 25 "ATLAS mapping drift"):

* A change to this table is a registry change: bump ``ATLAS_RELEASE`` /
  ``ATLAS_VERSION`` and ``ATLAS_CHECKED_ON`` in the same commit, with the new
  data-file digest, and adjust ``tests/ml/test_atlas_data.py``.
* Stored findings are never rewritten. A finding stamped under an earlier
  release keeps the id, name and ``atlas_version`` it was stamped with; the
  coverage view says which release a row came from. ``ATLAS_PRIOR_NAMES``
  records the names earlier releases used for the same ids so a reader can
  match old rows to the current table.
* Only techniques redsim can demonstrate or plans to demonstrate are
  vendored (evasion, poisoning, inference-API access, their outcome
  techniques). Controls demonstrate no technique and have no entry.

This module imports only ``redsim.ml.schema`` (pydantic) so the API process
can serve the coverage vocabulary without any ML library.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from redsim.ml.schema import AtlasTechnique

# --- the pinned release ------------------------------------------------------------------------------------------

ATLAS_REPO = "mitre-atlas/atlas-data"
ATLAS_REPO_URL = f"https://github.com/{ATLAS_REPO}"
ATLAS_RELEASE = "v2026.08"                       # release tag
ATLAS_VERSION = "2026.08"                        # ``collection.version`` inside the data file
ATLAS_FORMAT_VERSION = "6.0.0"                   # ``format-version`` inside the data file
ATLAS_RELEASE_PUBLISHED = "2026-09-01"
ATLAS_RELEASE_URL = f"{ATLAS_REPO_URL}/releases/tag/{ATLAS_RELEASE}"
ATLAS_TAG_OBJECT_SHA = "b86134041efd5eac8038f9e56e40b262f511ac1e"      # git tag object of v2026.08
ATLAS_DATA_FILE = "ATLAS-2026.08.yaml"
ATLAS_DATA_URL = f"{ATLAS_REPO_URL}/releases/download/{ATLAS_RELEASE}/{ATLAS_DATA_FILE}"
ATLAS_DATA_SHA256 = "a8d32f676854cc57721c217ec5b39f07db518076dee4a6c1335df0a7bc8271a2"
ATLAS_DATA_SIZE_BYTES = 808834
ATLAS_CHECKED_ON = "2026-09-09"
ATLAS_SITE = "https://atlas.mitre.org"

ATLAS_LICENSE = "Apache-2.0"
ATLAS_LICENSE_FILE = "LICENSE"
ATLAS_LICENSE_URL = f"https://raw.githubusercontent.com/{ATLAS_REPO}/{ATLAS_RELEASE}/LICENSE"
ATLAS_LICENSE_SHA256 = "fa6c92ab3dc75d41413884e8b38cc54cd4e72f4c8f68fc7e77824e48e3047d40"
# The notice from that LICENSE file, kept verbatim next to the vendored names as Apache-2.0 section 4 asks.
ATLAS_NOTICE = (
    "Copyright 2021-2026 MITRE\n"
    "\n"
    "Licensed under the Apache License, Version 2.0 (the \"License\");\n"
    "you may not use this file except in compliance with the License.\n"
    "You may obtain a copy of the License at\n"
    "\n"
    "    http://www.apache.org/licenses/LICENSE-2.0\n"
    "\n"
    "Unless required by applicable law or agreed to in writing, software\n"
    "distributed under the License is distributed on an \"AS IS\" BASIS,\n"
    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n"
    "See the License for the specific language governing permissions and\n"
    "limitations under the License.\n"
)
ATLAS_ATTRIBUTION = (f"MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems), data release "
                     f"{ATLAS_RELEASE} ({ATLAS_REPO_URL}), Apache-2.0. Technique ids and names reproduced; "
                     "descriptions are not.")

RELEASE_TAG_PATTERN = re.compile(r"^v\d{4}\.\d{2}$")
VERSION_PATTERN = re.compile(r"^\d{4}\.\d{2}$")
TECHNIQUE_ID_PATTERN = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")

Family = Literal["evasion", "poisoning", "access", "outcome"]


@dataclass(frozen=True)
class AtlasTechniqueRecord:
    """One vendored technique: id, current name, parent id for a sub-technique, redsim's family grouping."""

    id: str
    name: str
    family: Family
    parent: str | None = None

    def as_schema(self) -> AtlasTechnique:
        """The frozen ``schema.AtlasTechnique`` stamped onto a finding (carries the pinned release)."""
        return AtlasTechnique(id=self.id, name=self.name, atlas_version=ATLAS_VERSION)


def _t(tid: str, name: str, family: Family, parent: str | None = None) -> AtlasTechniqueRecord:
    return AtlasTechniqueRecord(id=tid, name=name, family=family, parent=parent)


# --- the vendored table (ids and names verbatim from ATLAS-2026.08.yaml) -------------------------------------------

ATLAS_TECHNIQUES: dict[str, AtlasTechniqueRecord] = {
    r.id: r for r in (
        # Evasion family: crafting adversarial inputs (FGSM, PGD, CW, DeepFool, HopSkipJump, ZOO, word substitution,
        # DPatch) and what they aim at.
        _t("AML.T0043", "Craft Adversarial Data", "evasion"),
        _t("AML.T0043.000", "White-Box Optimization", "evasion", "AML.T0043"),
        _t("AML.T0043.001", "Black-Box Optimization", "evasion", "AML.T0043"),
        _t("AML.T0043.002", "Black-Box Transfer", "evasion", "AML.T0043"),
        _t("AML.T0043.003", "Manual Modification", "evasion", "AML.T0043"),
        _t("AML.T0015", "Evade AI Model", "outcome"),
        _t("AML.T0031", "Erode AI Model Integrity", "outcome"),
        # Access: score- or decision-based attacks reach the model only through its inference API.
        _t("AML.T0040", "AI Model Inference API Access", "access"),
        _t("AML.T0024", "Exfiltration via AI Inference API", "access"),
        # Poisoning family (data-poisoning module, brief package F): training-data and model manipulation.
        _t("AML.T0020", "Training Data Poisoning", "poisoning"),
        _t("AML.T0018", "Manipulate AI Model", "poisoning"),
        _t("AML.T0018.000", "Poison AI Model", "poisoning", "AML.T0018"),
        _t("AML.T0043.004", "Insert Backdoor Trigger", "poisoning", "AML.T0043"),
        _t("AML.T0059", "Erode Dataset Integrity", "outcome"),
    )
}

# Names earlier ATLAS releases used for the same ids (the 4.x naming redsim's Phase A table was written against, where
# every "ML" became "AI" in the 2026 releases). A stored finding carrying one of these names is the same technique.
ATLAS_PRIOR_NAMES: dict[str, tuple[str, ...]] = {
    "AML.T0040": ("ML Model Inference API Access",),
    "AML.T0015": ("Evade ML Model",),
    "AML.T0031": ("Erode ML Model Integrity",),
    "AML.T0018": ("Backdoor ML Model",),
    "AML.T0018.000": ("Poison ML Model",),
    "AML.T0020": ("Poison Training Data",),
    "AML.T0024": ("Exfiltration via ML Inference API",),
}

# Family -> technique ids, for the coverage view (no numeric field is ever derived from this; spec 27.4).
FAMILY_TECHNIQUE_IDS: dict[str, tuple[str, ...]] = {
    "evasion": tuple(r.id for r in ATLAS_TECHNIQUES.values() if r.family == "evasion"),
    "poisoning": tuple(r.id for r in ATLAS_TECHNIQUES.values() if r.family == "poisoning"),
    "access": tuple(r.id for r in ATLAS_TECHNIQUES.values() if r.family == "access"),
    "outcome": tuple(r.id for r in ATLAS_TECHNIQUES.values() if r.family == "outcome"),
}

# The attack-id -> technique mapping redsim's registry stamps (spec 27.2): the Phase A ids plus the Phase B attacks
# named in plan 12 wave B1. ``redsim.ml.attacks.ATLAS_TECHNIQUES`` (Phase A, 4.x names) stays as written; the B3
# atlas-foundry track replaces it with lookups into this table. A control demonstrates no technique.
ATTACK_TECHNIQUE_IDS: dict[str, tuple[str, ...]] = {
    "fgsm": ("AML.T0043", "AML.T0043.000"),
    "pgd": ("AML.T0043", "AML.T0043.000"),
    "cw_l2": ("AML.T0043", "AML.T0043.000"),
    "deepfool": ("AML.T0043", "AML.T0043.000"),
    "hopskipjump": ("AML.T0043", "AML.T0043.001", "AML.T0040"),
    "zoo": ("AML.T0043", "AML.T0043.001", "AML.T0040"),
    "word_substitution": ("AML.T0043", "AML.T0043.001", "AML.T0040"),
    "dpatch": ("AML.T0043", "AML.T0043.000"),
    "surrogate_transfer_pgd": ("AML.T0043", "AML.T0043.002"),
    "label_flip_poisoning": ("AML.T0020", "AML.T0059"),
    "backdoor_poisoning": ("AML.T0020", "AML.T0018.000", "AML.T0043.004"),
}


def technique(technique_id: str) -> AtlasTechniqueRecord:
    """The vendored record for ``technique_id``; ``KeyError`` names the pinned release when it is absent."""
    try:
        return ATLAS_TECHNIQUES[technique_id]
    except KeyError:
        raise KeyError(f"{technique_id!r} is not vendored from ATLAS {ATLAS_RELEASE}; add it to "
                       "redsim.ml.atlas_data.ATLAS_TECHNIQUES with a release bump") from None


def technique_tag(technique_id: str) -> AtlasTechnique:
    """``schema.AtlasTechnique`` for a finding stamp, carrying ``ATLAS_VERSION``."""
    return technique(technique_id).as_schema()


def techniques_for_attack(attack_id: str) -> tuple[AtlasTechniqueRecord, ...]:
    """The technique records an attack id maps to (empty for controls and unknown ids)."""
    return tuple(technique(t) for t in ATTACK_TECHNIQUE_IDS.get(attack_id, ()))


def primary_technique_for_attack(attack_id: str) -> AtlasTechnique | None:
    """The first (top-level) technique of an attack as a finding stamp, or ``None`` for a control."""
    ids = ATTACK_TECHNIQUE_IDS.get(attack_id)
    return technique_tag(ids[0]) if ids else None


def is_same_technique(stored: AtlasTechnique, technique_id: str) -> bool:
    """True when a stored tag names ``technique_id`` under the current or a prior release name."""
    if stored.id != technique_id:
        return False
    current = ATLAS_TECHNIQUES.get(technique_id)
    names = {current.name} if current else set()
    names.update(ATLAS_PRIOR_NAMES.get(technique_id, ()))
    return stored.name in names


def release_record() -> dict[str, Any]:
    """What the coverage view and the interop manifests cite for the ATLAS release."""
    return {"repo": ATLAS_REPO_URL, "release": ATLAS_RELEASE, "version": ATLAS_VERSION,
            "format_version": ATLAS_FORMAT_VERSION, "published": ATLAS_RELEASE_PUBLISHED, "release_url": ATLAS_RELEASE_URL,
            "data_file": ATLAS_DATA_FILE, "data_sha256": ATLAS_DATA_SHA256, "data_size_bytes": ATLAS_DATA_SIZE_BYTES,
            "license": ATLAS_LICENSE, "license_sha256": ATLAS_LICENSE_SHA256, "checked_on": ATLAS_CHECKED_ON,
            "attribution": ATLAS_ATTRIBUTION, "n_techniques_vendored": len(ATLAS_TECHNIQUES)}


# --- offline verification against a local copy of the data file ----------------------------------------------------

def _load_yaml(path: Path) -> dict[str, Any]:
    import yaml  # PyYAML is a redsim dependency; imported lazily so the constants stay import-light

    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: not an ATLAS data mapping")
    return data


def technique_names(data: dict[str, Any]) -> dict[str, str]:
    """``{id: name}`` from an ATLAS data mapping (format 6.x keys techniques by id; older formats list them)."""
    techs = data.get("techniques")
    out: dict[str, str] = {}
    if isinstance(techs, dict):
        for key, value in techs.items():
            if isinstance(value, dict):
                out[str(value.get("id", key))] = str(value.get("name", ""))
    elif isinstance(techs, list):
        for value in techs:
            if isinstance(value, dict) and "id" in value:
                out[str(value["id"])] = str(value.get("name", ""))
    return out


def verify_atlas_data(path: Path, *, expected_sha256: str | None = ATLAS_DATA_SHA256,
                      ids: Iterable[str] | None = None) -> list[str]:
    """Check a local ATLAS data file against the vendored table; one message per problem, ``[]`` when it agrees.

    Checks: the file digest (when ``expected_sha256`` is given), ``collection.version`` equals ``ATLAS_VERSION``,
    and every vendored id is present with the vendored name. Never touches the network.
    """
    path = Path(path)
    problems: list[str] = []
    if not path.is_file():
        return [f"{path}: missing"]
    if expected_sha256:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected_sha256:
            problems.append(f"{path.name}: sha256 {digest[:12]}... is not the pinned {expected_sha256[:12]}...")
    data = _load_yaml(path)
    version = str((data.get("collection") or {}).get("version", ""))
    if version != ATLAS_VERSION:
        problems.append(f"{path.name}: collection.version {version!r} is not {ATLAS_VERSION!r}")
    names = technique_names(data)
    for tid in (ids if ids is not None else ATLAS_TECHNIQUES):
        record = ATLAS_TECHNIQUES[tid]
        if tid not in names:
            problems.append(f"{tid}: not in {path.name}")
        elif names[tid] != record.name:
            problems.append(f"{tid}: name {names[tid]!r} in {path.name}, vendored {record.name!r}")
    return problems


__all__ = [
    "ATLAS_ATTRIBUTION", "ATLAS_CHECKED_ON", "ATLAS_DATA_FILE", "ATLAS_DATA_SHA256", "ATLAS_DATA_SIZE_BYTES",
    "ATLAS_DATA_URL", "ATLAS_FORMAT_VERSION", "ATLAS_LICENSE", "ATLAS_LICENSE_SHA256", "ATLAS_LICENSE_URL",
    "ATLAS_NOTICE", "ATLAS_PRIOR_NAMES", "ATLAS_RELEASE", "ATLAS_RELEASE_PUBLISHED", "ATLAS_RELEASE_URL",
    "ATLAS_REPO", "ATLAS_REPO_URL", "ATLAS_SITE", "ATLAS_TAG_OBJECT_SHA", "ATLAS_TECHNIQUES", "ATLAS_VERSION",
    "ATTACK_TECHNIQUE_IDS", "FAMILY_TECHNIQUE_IDS", "RELEASE_TAG_PATTERN", "TECHNIQUE_ID_PATTERN",
    "VERSION_PATTERN", "AtlasTechniqueRecord", "Family", "is_same_technique", "primary_technique_for_attack",
    "release_record", "technique", "technique_names", "technique_tag", "techniques_for_attack",
    "verify_atlas_data",
]
