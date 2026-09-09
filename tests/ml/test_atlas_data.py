"""The vendored ATLAS table is pinned to one release, licensed, self-consistent and agrees with the Phase A table.

Pure Python (pydantic + PyYAML for the offline verifier); no ``ml`` marker so the torch-less lane runs it.
Nothing here reaches the network: ``verify_atlas_data`` is exercised on a synthetic data file.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from redsim.ml import atlas_data as atlas
from redsim.ml.schema import AtlasTechnique

yaml = pytest.importorskip("yaml")


def test_release_is_pinned_to_an_exact_tag_with_digests_and_a_check_date() -> None:
    assert atlas.RELEASE_TAG_PATTERN.match(atlas.ATLAS_RELEASE) and atlas.VERSION_PATTERN.match(atlas.ATLAS_VERSION)
    assert "x" not in atlas.ATLAS_VERSION and atlas.ATLAS_RELEASE == f"v{atlas.ATLAS_VERSION}"
    assert re.fullmatch(r"[0-9a-f]{64}", atlas.ATLAS_DATA_SHA256) and re.fullmatch(r"[0-9a-f]{64}", atlas.ATLAS_LICENSE_SHA256)
    assert re.fullmatch(r"[0-9a-f]{40}", atlas.ATLAS_TAG_OBJECT_SHA)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", atlas.ATLAS_CHECKED_ON)
    assert atlas.ATLAS_DATA_FILE == f"ATLAS-{atlas.ATLAS_VERSION}.yaml" and atlas.ATLAS_DATA_FILE in atlas.ATLAS_DATA_URL
    assert atlas.ATLAS_RELEASE in atlas.ATLAS_LICENSE_URL and atlas.ATLAS_DATA_SIZE_BYTES > 0
    record = atlas.release_record()
    assert record["release"] == atlas.ATLAS_RELEASE and record["data_sha256"] == atlas.ATLAS_DATA_SHA256
    assert record["n_techniques_vendored"] == len(atlas.ATLAS_TECHNIQUES) and record["license"] == "Apache-2.0"


def test_notice_is_the_apache_license_file_verbatim() -> None:
    """The vendored notice hashes to the LICENSE file of the pinned release (Apache-2.0 section 4 attribution)."""
    assert hashlib.sha256(atlas.ATLAS_NOTICE.encode("utf-8")).hexdigest() == atlas.ATLAS_LICENSE_SHA256
    assert "Apache License, Version 2.0" in atlas.ATLAS_NOTICE and "MITRE" in atlas.ATLAS_NOTICE
    assert "Apache-2.0" in atlas.ATLAS_ATTRIBUTION and atlas.ATLAS_REPO_URL in atlas.ATLAS_ATTRIBUTION


def test_table_is_self_consistent() -> None:
    ids = set(atlas.ATLAS_TECHNIQUES)
    for tid, rec in atlas.ATLAS_TECHNIQUES.items():
        assert rec.id == tid and atlas.TECHNIQUE_ID_PATTERN.match(tid) and rec.name.strip()
        if "." in tid[len("AML.T0000"):]:
            assert rec.parent == tid.rsplit(".", 1)[0] and rec.parent in ids, tid
        else:
            assert rec.parent is None
        assert rec.family in ("evasion", "poisoning", "access", "outcome")
    assert {"AML.T0043", "AML.T0040", "AML.T0020", "AML.T0015", "AML.T0018.000"} <= ids
    assert atlas.ATLAS_TECHNIQUES["AML.T0043"].name == "Craft Adversarial Data"
    assert atlas.ATLAS_TECHNIQUES["AML.T0040"].name == "AI Model Inference API Access"
    assert atlas.ATLAS_TECHNIQUES["AML.T0020"].name == "Training Data Poisoning"
    families = [tid for fam in atlas.FAMILY_TECHNIQUE_IDS.values() for tid in fam]
    assert sorted(families) == sorted(ids)                       # every id in exactly one family
    assert set(atlas.FAMILY_TECHNIQUE_IDS["poisoning"]) >= {"AML.T0020", "AML.T0018", "AML.T0018.000", "AML.T0043.004"}
    assert set(atlas.FAMILY_TECHNIQUE_IDS["evasion"]) >= {"AML.T0043", "AML.T0043.000", "AML.T0043.001"}
    for tid, names in atlas.ATLAS_PRIOR_NAMES.items():
        assert tid in ids and all(n and n != atlas.ATLAS_TECHNIQUES[tid].name for n in names)


def test_attack_mapping_names_only_vendored_techniques_and_no_control() -> None:
    for attack_id, tids in atlas.ATTACK_TECHNIQUE_IDS.items():
        assert tids and all(t in atlas.ATLAS_TECHNIQUES for t in tids), attack_id
        assert atlas.ATLAS_TECHNIQUES[tids[0]].parent is None    # the stamp is the top-level technique
    assert "noise_control" not in atlas.ATTACK_TECHNIQUE_IDS and "random_swap" not in atlas.ATTACK_TECHNIQUE_IDS
    assert atlas.primary_technique_for_attack("noise_control") is None
    tag = atlas.primary_technique_for_attack("hopskipjump")
    assert tag == AtlasTechnique(id="AML.T0043", name="Craft Adversarial Data", atlas_version=atlas.ATLAS_VERSION)
    assert [r.id for r in atlas.techniques_for_attack("hopskipjump")] == ["AML.T0043", "AML.T0043.001", "AML.T0040"]
    assert atlas.techniques_for_attack("unknown") == ()
    assert atlas.technique_tag("AML.T0040").atlas_version == atlas.ATLAS_VERSION
    with pytest.raises(KeyError, match=atlas.ATLAS_RELEASE):
        atlas.technique("AML.T9999")


def test_phase_a_table_agrees_under_current_or_prior_names() -> None:
    """``redsim.ml.attacks.ATLAS_TECHNIQUES`` (4.x names) maps onto the vendored ids; renamed rows are recognised."""
    from redsim.ml.attacks import ATLAS_TECHNIQUES as phase_a

    for attack_id, tag in phase_a.items():
        assert tag.id in atlas.ATLAS_TECHNIQUES, attack_id
        assert atlas.is_same_technique(tag, tag.id), (attack_id, tag)
        assert tag.id in atlas.ATTACK_TECHNIQUE_IDS[attack_id]
    old = AtlasTechnique(id="AML.T0040", name="ML Model Inference API Access", atlas_version="4.x")
    assert atlas.is_same_technique(old, "AML.T0040") and not atlas.is_same_technique(old, "AML.T0043")
    assert not atlas.is_same_technique(AtlasTechnique(id="AML.T0040", name="Something Else", atlas_version="x"), "AML.T0040")


def _data_file(tmp_path: Path, *, version: str = atlas.ATLAS_VERSION, rename: dict[str, str] | None = None,
               drop: set[str] | None = None, as_list: bool = False) -> Path:
    techs: dict[str, dict[str, str]] = {}
    for tid, rec in atlas.ATLAS_TECHNIQUES.items():
        if drop and tid in drop:
            continue
        techs[tid] = {"id": tid, "name": (rename or {}).get(tid, rec.name), "object-type": "technique"}
    techs["AML.T0000"] = {"id": "AML.T0000", "name": "Search Open Technical Databases", "object-type": "technique"}
    payload = {"format-version": atlas.ATLAS_FORMAT_VERSION,
               "collection": {"name": "ATLAS", "version": version, "id": "ATLAS-collection"},
               "techniques": list(techs.values()) if as_list else techs}
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "ATLAS.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    return path


def test_verify_atlas_data_agrees_and_reports_drift(tmp_path: Path) -> None:
    good = _data_file(tmp_path)
    digest = hashlib.sha256(good.read_bytes()).hexdigest()
    assert atlas.verify_atlas_data(good, expected_sha256=digest) == []
    assert atlas.verify_atlas_data(good, expected_sha256=None) == []
    assert atlas.verify_atlas_data(_data_file(tmp_path / "l", as_list=True), expected_sha256=None) == []
    assert any("sha256" in p for p in atlas.verify_atlas_data(good))          # the synthetic file is not the release
    assert atlas.verify_atlas_data(tmp_path / "absent.yaml") == [f"{tmp_path / 'absent.yaml'}: missing"]
    drift = atlas.verify_atlas_data(_data_file(tmp_path / "v", version="2027.01"), expected_sha256=None)
    assert drift == ["ATLAS.yaml: collection.version '2027.01' is not '2026.08'"] or drift[0].startswith("ATLAS.yaml: collection.version")
    renamed = atlas.verify_atlas_data(_data_file(tmp_path / "r", rename={"AML.T0043": "Craft Bad Data"}), expected_sha256=None)
    assert renamed == ["AML.T0043: name 'Craft Bad Data' in ATLAS.yaml, vendored 'Craft Adversarial Data'"]
    dropped = atlas.verify_atlas_data(_data_file(tmp_path / "d", drop={"AML.T0059"}), expected_sha256=None,
                                      ids=["AML.T0059", "AML.T0043"])
    assert dropped == ["AML.T0059: not in ATLAS.yaml"]
    names = atlas.technique_names(yaml.safe_load(good.read_text(encoding="utf-8")))
    assert names["AML.T0043"] == "Craft Adversarial Data" and "AML.T0000" in names


def test_module_stays_free_of_ml_libraries() -> None:
    import sys

    src = Path(atlas.__file__).read_text(encoding="utf-8")
    for name in ("torch", "art", "onnxruntime", "shap", "sklearn", "numpy"):
        assert f"import {name}" not in src and f"from {name}" not in src
    assert "redsim.ml.atlas_data" in sys.modules
