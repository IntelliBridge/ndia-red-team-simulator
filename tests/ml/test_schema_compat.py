"""Schema-compatibility tripwire for the P0-frozen ``redsim/ml/schema.py`` (TESTS_DOCS-40).

Plan 01 section 8 rule 3 and plan 12 section 1: every Phase B field lands
additive and default-valued, so the frozen P0 record
``tests/ml/fixtures/run_record.json`` must still validate as ``CampaignRecord``,
byte-identical, after each schema change.

The P0 property list is generated from the fixture itself. The record was dumped
through the models when P0 froze, so every field of every nested model it
reaches is present, and no stored copy of the schema is needed. That keeps this
file independent of the schema-additive track landing first while still
catching, from ``CampaignRecord.model_json_schema()``:

* a P0 property removed (the fixture carries a key the schema no longer has);
* a P0 property retyped (a fixture value's JSON type or enum value is no longer
  accepted by that property);
* a property added since P0 without a default (a property absent from the
  fixture that the schema lists as ``required``), which would break every
  stored P0 record.

``tests/ml/fixtures/run_record_phase_b.json`` is the frozen fixture plus the
additive fields of plan 12 section 3 that a ``CampaignRecord`` carries. The
tests that need those fields skip, naming what is missing, until the
schema-additive track lands them.

Pure pydantic, no ``ml`` extra: runs on both unit lanes.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from redsim.ml import schema as S

FIXTURES = Path(__file__).parent / "fixtures"
P0_FIXTURE = FIXTURES / "run_record.json"
PHASE_B_FIXTURE = FIXTURES / "run_record_phase_b.json"

#: sha256 of the frozen P0 fixture. Changing the file changes the frozen
#: ``GET /v1/runs/{id}/campaign`` shape and follows plan 01 section 8.
P0_FIXTURE_SHA256 = "e5266f1873dc3fcd0d784acf3bf9e97463595d3bbff351edf7560ca1716d9c1a"

#: Name the walker gives the root definition (the JSON schema's own title).
ROOT = "CampaignRecord"

#: P0 vocabularies reachable from ``CampaignRecord`` (``schema.py`` at the freeze),
#: keyed ``<definition>.<property>``. A Literal may grow (plan 12 section 3 adds
#: ``text``, ``detection``, ``edit`` and ``patch_area``); it may never lose a value,
#: or every stored record carrying that value stops validating.
P0_ENUMS: dict[str, frozenset[str]] = {
    "CampaignRecord.status": frozenset(
        {"queued", "running", "succeeded", "failed", "cancelled", "not_implemented"}
    ),
    "CampaignRecord.kind": frozenset({"attack", "verify", "ingest"}),
    "CampaignRecord.completeness": frozenset({"complete", "partial"}),
    "TargetInfo.domain": frozenset({"image", "tabular", "llm"}),
    "TargetInfo.status": frozenset({"available", "not_implemented"}),
    "AttackInfo.domain": frozenset({"image", "tabular", "llm"}),
    "AttackInfo.family": frozenset({"evasion", "control"}),
    "AttackInfo.access": frozenset({"white-box", "black-box"}),
    "CampaignConfig.modality": frozenset({"image", "tabular"}),
    "CampaignConfig.norm": frozenset({"linf", "l2"}),
    "Measurement.family": frozenset({"clean", "evasion", "control"}),
    "MRIRecord.grade": frozenset({"A", "B", "C", "D", "F"}),
    "MRIRecord.completeness": frozenset({"complete", "partial"}),
    "ScoreStatus.state": frozenset({"pending", "unavailable"}),
    "CandidateRecommendation.validation": frozenset({"not evaluated", "measured"}),
    "CandidateRecommendation.narrative_source": frozenset({"rules", "llm"}),
}

#: ``STAGES`` at the freeze. Plan 12 section 3 inserts ``defense_apply``; the P0
#: names keep their relative order so stored ``stages_done`` lists still read.
P0_STAGES: tuple[str, ...] = (
    "load_target", "sample", "clean_eval", "attack", "control", "explain", "score",
    "interpret", "recommend", "report",
)

#: Additive Phase B fields the Phase B fixture carries (plan 12 section 3), as
#: ``(definition, property)``. Nested Phase B models (``DetectionMetrics``,
#: ``TextObservation``, ``DetectionObservation``) are carried as ``null`` because
#: the fixture is an image classification campaign and their shapes belong to
#: the schema-additive track.
PHASE_B_FIELDS: tuple[tuple[str, str], ...] = (
    ("CampaignRecord", "schema_version"),   # REVIEW_REPORTS-18
    ("Measurement", "edit_fraction_mean"),  # MODALITIES-03
    ("Measurement", "detection"),           # MODALITIES-03
    ("Observation", "text"),                # MODALITIES-04
    ("Observation", "detection"),           # MODALITIES-04
)

#: Vocabulary additions of plan 12 section 3, as ``(<definition>.<property>, value)``.
PHASE_B_ENUM_ADDITIONS: tuple[tuple[str, str], ...] = (
    ("TargetInfo.domain", "text"),
    ("TargetInfo.domain", "detection"),
    ("CampaignConfig.modality", "text"),
    ("CampaignConfig.modality", "detection"),
    ("CampaignConfig.norm", "edit"),
    ("CampaignConfig.norm", "patch_area"),
)

#: The Phase B fixture's own additions on top of the frozen record, besides the
#: fields above: its run id and one extra limitation sentence naming what it is.
PHASE_B_RUN_ID = "run-fixture-phase-b-0001"
PHASE_B_LIMITATION_PREFIX = "FIXTURE (Phase B):"


# ---------------------------------------------------------------------------
# Walking the fixture against the JSON schema
# ---------------------------------------------------------------------------


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise TypeError(f"not a JSON value: {type(value).__name__}")


def _type_accepts(schema_type: Any, value: Any) -> bool:
    types = schema_type if isinstance(schema_type, list) else [schema_type]
    observed = _json_type(value)
    return observed in types or (observed == "integer" and "number" in types)


class _SchemaWalk:
    """Walks a fixture payload against ``CampaignRecord.model_json_schema()``.

    Records, per definition, the property names the fixture carries (the P0
    property list) and every incompatibility between a fixture value and the
    schema node that now describes it (a removed or retyped P0 property).
    """

    def __init__(self, schema: dict[str, Any]) -> None:
        self.schema = schema
        self.defs: dict[str, dict[str, Any]] = schema.get("$defs", {})
        self.p0_keys: dict[str, set[str]] = defaultdict(set)
        self._problems: dict[str, None] = {}  # insertion-ordered set: one line per path

    @property
    def problems(self) -> list[str]:
        return list(self._problems)

    def _problem(self, message: str) -> None:
        self._problems[message] = None

    def definition(self, name: str) -> dict[str, Any]:
        return self.schema if name == ROOT else self.defs[name]

    def _resolve(self, node: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        ref = node.get("$ref")
        if ref is None:
            return None, node
        name = ref.rsplit("/", 1)[-1]
        if name not in self.defs:
            raise KeyError(f"schema reference {ref!r} has no definition")
        return name, self.defs[name]

    def _accepts(self, value: Any, node: dict[str, Any]) -> bool:
        _, node = self._resolve(node)
        if "anyOf" in node:
            return any(self._accepts(value, branch) for branch in node["anyOf"])
        if "enum" in node:
            return value in node["enum"]
        if "const" in node:
            return value == node["const"]
        if "type" in node:
            return _type_accepts(node["type"], value)
        if "properties" in node:
            return isinstance(value, dict)
        if "items" in node:
            return isinstance(value, list)
        return True  # ``Any``: nothing to check

    def walk(self, value: Any, node: dict[str, Any], path: str, definition: str) -> None:
        name, node = self._resolve(node)
        if name is not None:
            definition = name
        if "anyOf" in node:
            branches = [b for b in node["anyOf"] if self._accepts(value, b)]
            if not branches:
                self._problem(
                    f"{path}: {_json_type(value)} value is no longer accepted by {node['anyOf']}"
                )
                return
            self.walk(value, branches[0], path, definition)
            return
        if "enum" in node:
            if value not in node["enum"]:
                self._problem(f"{path}: {value!r} was removed from the enum {node['enum']}")
            return
        if "const" in node:
            if value != node["const"]:
                self._problem(f"{path}: {value!r} no longer matches const {node['const']!r}")
            return
        if "type" in node and not _type_accepts(node["type"], value):
            self._problem(
                f"{path}: fixture has a {_json_type(value)}, the schema now says {node['type']!r}"
            )
            return
        if isinstance(value, dict) and "properties" in node:
            properties = node["properties"]
            self.p0_keys[definition] |= set(value)
            for key, sub in value.items():
                if key not in properties:
                    self._problem(f"{path}.{key}: P0 property removed from {definition}")
                    continue
                self.walk(sub, properties[key], f"{path}.{key}", definition)
            return
        if isinstance(value, dict):
            extra = node.get("additionalProperties")
            if isinstance(extra, dict):
                for key, sub in value.items():
                    self.walk(sub, extra, f"{path}[{key!r}]", definition)
            return
        if isinstance(value, list) and "items" in node:
            for sub in value:
                self.walk(sub, node["items"], f"{path}[]", definition)

    def additive_violations(self) -> list[str]:
        """Properties added since P0 (absent from the fixture) that are ``required``."""
        out: list[str] = []
        for definition, keys in sorted(self.p0_keys.items()):
            node = self.definition(definition)
            required = set(node.get("required", []))
            for prop in node.get("properties", {}):
                if prop not in keys and prop in required:
                    out.append(f"{definition}.{prop} is new since P0 but required")
        return out

    def added_properties(self) -> dict[str, list[str]]:
        """Properties the schema has that the P0 fixture does not, per definition."""
        out: dict[str, list[str]] = {}
        for definition, keys in sorted(self.p0_keys.items()):
            props = self.definition(definition).get("properties", {})
            added = sorted(p for p in props if p not in keys)
            if added:
                out[definition] = added
        return out


def _enum_values(schema: dict[str, Any], dotted: str) -> set[str]:
    """The enum of ``<definition>.<property>``, following ``$ref`` and nullable ``anyOf``."""
    definition, prop = dotted.split(".", 1)
    node = (schema if definition == ROOT else schema["$defs"][definition])["properties"][prop]
    while True:
        if "$ref" in node:
            node = schema["$defs"][node["$ref"].rsplit("/", 1)[-1]]
        elif "anyOf" in node:
            node = next(b for b in node["anyOf"] if b.get("type") != "null")
        elif "enum" in node:
            return set(node["enum"])
        elif "const" in node:
            return {node["const"]}
        else:
            raise AssertionError(f"{dotted} is no longer an enum: {node}")


def _has_property(schema: dict[str, Any], definition: str, prop: str) -> bool:
    node = schema if definition == ROOT else schema.get("$defs", {}).get(definition, {})
    return prop in node.get("properties", {})


def _missing_phase_b_fields(schema: dict[str, Any]) -> list[str]:
    return [f"{d}.{p}" for d, p in PHASE_B_FIELDS if not _has_property(schema, d, p)]


def _strip_phase_b(payload: dict[str, Any]) -> dict[str, Any]:
    """The Phase B fixture with its additions removed, for comparison with the frozen record."""
    stripped = json.loads(json.dumps(payload))
    stripped["run_id"] = "run-fixture-0001"
    stripped.pop("schema_version", None)
    for row in stripped["measurements"]:
        row.pop("edit_fraction_mean", None)
        row.pop("detection", None)
    for row in stripped["observations"]:
        row.pop("text", None)
        row.pop("detection", None)
    stripped["limitations"] = [
        s for s in stripped["limitations"] if not s.startswith(PHASE_B_LIMITATION_PREFIX)
    ]
    return stripped


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def p0_bytes() -> bytes:
    return P0_FIXTURE.read_bytes()


@pytest.fixture(scope="module")
def p0_payload(p0_bytes: bytes) -> dict[str, Any]:
    return json.loads(p0_bytes)


@pytest.fixture(scope="module")
def json_schema() -> dict[str, Any]:
    return S.CampaignRecord.model_json_schema()


@pytest.fixture(scope="module")
def walk(p0_payload: dict[str, Any], json_schema: dict[str, Any]) -> _SchemaWalk:
    walker = _SchemaWalk(json_schema)
    walker.walk(p0_payload, json_schema, ROOT, ROOT)
    return walker


@pytest.fixture(scope="module")
def phase_b_payload() -> dict[str, Any]:
    return json.loads(PHASE_B_FIXTURE.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The frozen P0 fixture
# ---------------------------------------------------------------------------


def test_p0_fixture_is_byte_identical(p0_bytes: bytes) -> None:
    digest = hashlib.sha256(p0_bytes).hexdigest()
    assert digest == P0_FIXTURE_SHA256, (
        f"tests/ml/fixtures/run_record.json changed (sha256 {digest}). The file is the frozen "
        "GET /v1/runs/{id}/campaign shape; a change follows plan 01 section 8 and updates "
        "P0_FIXTURE_SHA256 in the same commit."
    )


def test_p0_fixture_validates_and_round_trips_unchanged(p0_payload: dict[str, Any]) -> None:
    record = S.CampaignRecord.model_validate(p0_payload)
    # ``exclude_unset`` is the old-record view: every key the fixture carries comes back
    # with the value it had, and fields added since P0 (never set) do not appear.
    assert record.model_dump(mode="json", exclude_unset=True) == p0_payload


def test_p0_fixture_reaches_every_panel(walk: _SchemaWalk) -> None:
    """The generated P0 property list covers the record and its nested models, not just the root."""
    for definition in ("CampaignRecord", "CampaignConfig", "TargetInfo", "AttackInfo", "Provenance",
                       "Measurement", "Observation", "Interpretation", "CandidateRecommendation",
                       "MRIRecord", "MRIInputRow", "RobustnessCurve", "CurvePoint"):
        assert walk.p0_keys[definition], f"the P0 fixture never reaches {definition}"
    assert walk.p0_keys[ROOT] == set(json.loads(P0_FIXTURE.read_text(encoding="utf-8")))


def test_no_p0_property_was_removed_or_retyped(walk: _SchemaWalk) -> None:
    assert walk.problems == [], "\n".join(walk.problems)


def test_every_property_added_since_p0_has_a_default(walk: _SchemaWalk) -> None:
    """A property the P0 fixture lacks must not be required (JSON schema), and the model field agrees."""
    assert walk.additive_violations() == [], "\n".join(walk.additive_violations())
    # Belt and braces from the model classes: pydantic omits ``default`` from the JSON
    # schema for ``default_factory`` fields, so ``required`` is the schema-side truth and
    # ``is_required()`` the model-side one. They must agree on every added field.
    for definition, added in walk.added_properties().items():
        model = getattr(S, definition, None)
        if model is None:
            continue
        for prop in added:
            field = model.model_fields[prop]
            assert not field.is_required(), f"{definition}.{prop} was added without a default"


@pytest.mark.parametrize("dotted", sorted(P0_ENUMS))
def test_p0_vocabularies_are_never_narrowed(json_schema: dict[str, Any], dotted: str) -> None:
    current = _enum_values(json_schema, dotted)
    missing = P0_ENUMS[dotted] - current
    assert not missing, f"{dotted} lost the P0 value(s) {sorted(missing)}; the enum is now {sorted(current)}"


def test_p0_stages_keep_their_relative_order() -> None:
    assert set(P0_STAGES) <= set(S.STAGES), sorted(set(P0_STAGES) - set(S.STAGES))
    kept = tuple(stage for stage in S.STAGES if stage in P0_STAGES)
    assert kept == P0_STAGES, f"P0 stage order changed: {kept}"
    assert S.STAGES[-1] == "report"


# ---------------------------------------------------------------------------
# The Phase B fixture
# ---------------------------------------------------------------------------


def test_phase_b_fixture_is_the_frozen_fixture_plus_additive_fields(
    p0_payload: dict[str, Any], phase_b_payload: dict[str, Any],
) -> None:
    """Runs on every lane today: the Phase B file differs from the frozen one only by the section 3 fields."""
    assert phase_b_payload["run_id"] == PHASE_B_RUN_ID
    assert phase_b_payload["schema_version"] == "campaign-record-1"
    for row in phase_b_payload["measurements"]:
        assert "edit_fraction_mean" in row and "detection" in row
    for row in phase_b_payload["observations"]:
        assert "text" in row and "detection" in row
    assert any(s.startswith(PHASE_B_LIMITATION_PREFIX) for s in phase_b_payload["limitations"])
    assert _strip_phase_b(phase_b_payload) == p0_payload


def test_phase_b_fixture_round_trips_once_the_fields_land(
    json_schema: dict[str, Any], phase_b_payload: dict[str, Any],
) -> None:
    missing = _missing_phase_b_fields(json_schema)
    if missing:
        pytest.skip(f"Phase B schema fields not landed yet (plan 12 section 3): {missing}")
    record = S.CampaignRecord.model_validate(phase_b_payload)
    # Every Phase B key is set explicitly in the file, so the old-record view keeps it: a
    # field silently dropped as an unknown extra would fail this equality.
    assert record.model_dump(mode="json", exclude_unset=True) == phase_b_payload
    assert getattr(record, "schema_version") == "campaign-record-1"
    assert S.CampaignRecord.model_fields["schema_version"].default == "campaign-record-1"


def test_phase_b_section_3_lands_as_one_set(json_schema: dict[str, Any]) -> None:
    """Once the sentinel field is on the tree, the whole section 3 vocabulary must be there too."""
    if not _has_property(json_schema, ROOT, "schema_version"):
        pytest.skip("CampaignRecord.schema_version not landed yet (plan 12 section 3)")
    assert _missing_phase_b_fields(json_schema) == []
    for dotted, value in PHASE_B_ENUM_ADDITIONS:
        assert value in _enum_values(json_schema, dotted), f"{dotted} lacks {value!r}"
    assert "defense_apply" in S.STAGES, "STAGES lacks defense_apply (ATTACKS_HARDEN-15)"
