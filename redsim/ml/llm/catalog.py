"""Committed catalog of garak probes the LLM track may run (spec 11.6, 12.2; LLM-02, -07, -08, -09).

``catalog.json`` next to this module is a snapshot regenerated from the pinned
garak release by :func:`build_catalog_from_garak` (worker or developer machine
only: it imports garak). :func:`load_catalog` reads the snapshot with pydantic
and json alone, so the API can serve ``GET /v1/llm/probes`` without importing
garak, the OpenAI client or transformers.

Two named sets:

* ``redsim-core``: every probe of the offline-detector families (DAN and
  in-the-wild jailbreaks, prompt injection, latent injection, encoding,
  Do-Not-Answer, goodside, grandma, phrasing, divergence, exploitation, web
  injection) whose primary detector is a string, trigger or regex matcher. It
  runs with no Hugging Face model and no second LLM.
* ``redsim-extended``: ``redsim-core`` plus the probes whose primary detector is
  a Hugging Face classifier (``LatentJailbreak``, RealToxicityPrompts). Opt-in:
  it needs a pre-cached model directory and ``HF_HUB_OFFLINE=1`` (LLM-09).

Excluded on purpose, recorded with the reason so the exclusion is visible
(LLM-08): the HarmBench-backed ``fitd.FITD`` (needs a red-team generator and a
model-as-judge detector, owner decision LLM-08), ``dan.AutoDAN`` (drives a
separate red-team model), ``grandma.GrandmaIntent`` (intent-routed detectors),
and the ``*Full`` / ``*Extended`` corpus variants (the capped sibling covers the
same corpus under the prompt cap; the uncapped variant is not offered so
gateway spend stays bounded).

A probe hit means the detector fired on the model's output: for a jailbreak or
Do-Not-Answer probe, the output did not contain a recognisable refusal; for an
injection or encoding probe, the planted payload appeared. Detectors are
keyword and pattern matchers and can misclassify in both directions; the
scorecard carries that limitation on every run.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CATALOG_PATH = Path(__file__).with_name("catalog.json")
CATALOG_VERSION = "llm-probe-catalog-1"
#: The garak line the child accepts (``pyproject.toml`` pins ``garak>=0.16,<0.17``).
EXPECTED_GARAK_VERSION = "0.16.0"

CORE_SET = "redsim-core"
EXTENDED_SET = "redsim-extended"
PROBE_SETS: tuple[str, ...] = (CORE_SET, EXTENDED_SET)

#: Probe modules whose offline-detector members form ``redsim-core`` (spec 11.6).
CORE_MODULES: tuple[str, ...] = (
    "dan", "promptinject", "latentinjection", "encoding", "donotanswer", "goodside", "grandma",
    "phrasing", "divergence", "exploitation", "web_injection",
)
#: Modules whose HF-detector members join ``redsim-extended`` on top of the core modules.
EXTENDED_MODULES: tuple[str, ...] = CORE_MODULES + ("realtoxicityprompts",)

#: ``AuditEvent.action`` is ``String(64)``; the per-probe action is ``llm.probe.<module>.<short_id>``.
AUDIT_ACTION_PREFIX = "llm.probe."
AUDIT_ACTION_MAX = 64
SHORT_ID_MAX = 40

#: Detector base classes that need a model download or a second LLM (never offline).
NON_OFFLINE_DETECTOR_BASES: frozenset[str] = frozenset({"HFDetector", "ModelAsJudge", "EvaluationJudge"})
NON_OFFLINE_DETECTOR_MODULES: frozenset[str] = frozenset({"judge", "perspective"})

GARAK_DOCS_BASE = "https://reference.garak.ai/en/latest/"
GARAK_REPO = "https://github.com/NVIDIA/garak"
GARAK_LICENCE = "Apache-2.0 (garak package)"

DetectorStatus = Literal["run", "not_run"]
ProbeStatus = Literal["available", "excluded"]
PromptSource = Literal["garak_data", "garak_resources", "in_code", "generated"]

# ---------------------------------------------------------------------------
# Exclusions (owner decisions and structural reasons), keyed by probe id
# ---------------------------------------------------------------------------

HARMBENCH_EXCLUSION = (
    "HarmBench material is reached in garak 0.16 only through fitd.FITD, an inactive multi-turn probe that "
    "needs a red-team generator and a model-as-judge detector (two further LLM roles, each an LLM call). "
    "Excluded from Phase B by owner decision LLM-08; named in the LLM limitations."
)
EXCLUSIONS: dict[str, tuple[str, str]] = {
    # probe id -> (decision, reason)
    "fitd.FITD": ("LLM-08", HARMBENCH_EXCLUSION),
    "dan.AutoDAN": ("LLM-07", "generative AutoDAN drives a separate red-team model (OPENAI_API_KEY / NIM); "
                    "the cached variant dan.AutoDANCached is offered instead"),
    "grandma.GrandmaIntent": ("LLM-09", "IntentProbe: detectors are resolved per intent at run time and may "
                              "include model-as-judge or HF detectors; not offered in either set"),
}
UNCAPPED_VARIANT_SUFFIXES: tuple[str, ...] = ("Full", "Extended")


def uncapped_sibling(probe_id: str) -> str | None:
    """``dan.DanInTheWildFull`` -> ``dan.DanInTheWild``; ``None`` when the id is not a corpus variant."""
    module, _, cls = probe_id.partition(".")
    for suffix in UNCAPPED_VARIANT_SUFFIXES:
        if cls.endswith(suffix) and len(cls) > len(suffix):
            return f"{module}.{cls[: -len(suffix)]}"
    return None


# ---------------------------------------------------------------------------
# Licence notes per corpus (spec 11.5 / 11.6, TESTS_DOCS-33)
# ---------------------------------------------------------------------------

LICENCE_NOTES: dict[str, str] = {
    "default": GARAK_LICENCE + "; prompts are loaded by garak's own probe classes and never redistributed by redsim",
    "inthewild": GARAK_LICENCE + "; the in-the-wild jailbreak corpus (arXiv 2308.03825) carries no confirmed "
                 "upstream licence and is not redistributed",
    "harmbench": GARAK_LICENCE + "; HarmBench ships its own LICENSE and README under garak/data/harmbench",
    "donotanswer": GARAK_LICENCE + "; Do-Not-Answer (Wang et al. 2023) as packaged by garak",
    "realtoxicityprompts": GARAK_LICENCE + "; RealToxicityPrompts (Gehman et al. 2020) as packaged by garak",
}


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


def short_id_for(module: str, cls: str) -> str:
    """A stable short id so ``llm.probe.<module>.<short_id>`` fits ``AuditEvent.action`` (64 chars).

    The class name when it fits (at most 40 chars and within the action budget);
    otherwise the head of the class name plus a four-hex digest of the full name.
    Catalog data, never re-derived at run time, so audit history keeps its meaning.
    """
    budget = AUDIT_ACTION_MAX - len(AUDIT_ACTION_PREFIX) - len(module) - 1
    limit = min(SHORT_ID_MAX, budget)
    if len(cls) <= limit:
        return cls
    digest = hashlib.sha256(f"{module}.{cls}".encode()).hexdigest()[:4]
    return f"{cls[: limit - 5]}-{digest}"


class ProbeInfo(BaseModel):
    """One garak probe as the catalog records it. Counts and ids only, never prompt text."""

    model_config = ConfigDict(extra="forbid")

    id: str                                  # ``<module>.<Class>`` as garak names it
    module: str
    cls: str
    short_id: str
    family: str                              # the garak module; the scorecard groups by it
    tier: int
    tier_name: str
    goal: str
    description: str
    doc_uri: str | None = None
    garak_docs_uri: str
    tags: list[str] = Field(default_factory=list)
    active_upstream: bool                    # garak's own ``active`` flag (its default selection)
    primary_detector: str | None
    primary_detector_offline: bool
    extended_detectors: list[str] = Field(default_factory=list)
    extended_detectors_offline: dict[str, bool] = Field(default_factory=dict)
    detector_offline: bool                   # the primary detector runs with no model download and no LLM
    honours_prompt_cap: bool                 # garak applies ``run.soft_probe_prompt_cap`` inside the probe
    prompt_source: PromptSource
    data_files: list[str] = Field(default_factory=list)   # paths under ``garak/data``
    upstream_licence_note: str
    sets: list[str] = Field(default_factory=list)
    status: ProbeStatus = "available"
    exclusion_reason: str | None = None
    exclusion_decision: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> ProbeInfo:
        if self.id != f"{self.module}.{self.cls}":
            raise ValueError(f"probe id {self.id!r} does not match module.cls")
        if len(self.short_id) > SHORT_ID_MAX:
            raise ValueError(f"short_id {self.short_id!r} exceeds {SHORT_ID_MAX} chars")
        if len(audit_action_for(self)) > AUDIT_ACTION_MAX:
            raise ValueError(f"audit action for {self.id} exceeds {AUDIT_ACTION_MAX} chars")
        if self.status == "excluded" and (not self.exclusion_reason or self.sets):
            raise ValueError(f"excluded probe {self.id} needs a reason and no set membership")
        if self.status == "available" and self.exclusion_reason:
            raise ValueError(f"available probe {self.id} carries an exclusion reason")
        if CORE_SET in self.sets and not self.detector_offline:
            raise ValueError(f"{self.id} is in {CORE_SET} but its primary detector is not offline")
        for name in self.sets:
            if name not in PROBE_SETS:
                raise ValueError(f"{self.id} names unknown set {name!r}")
        return self


class ProbeSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    detector_policy: Literal["offline", "hf"]
    opt_in: bool = False
    requires: str | None = None
    probe_ids: list[str] = Field(default_factory=list)


class ProbeCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    catalog_version: Literal["llm-probe-catalog-1"] = "llm-probe-catalog-1"
    garak_version: str
    garak_repo: str = GARAK_REPO
    generated_by: str
    sets: dict[str, ProbeSet]
    probes: list[ProbeInfo]

    @model_validator(mode="after")
    def _sets_consistent(self) -> ProbeCatalog:
        by_id = {p.id: p for p in self.probes}
        if len(by_id) != len(self.probes):
            raise ValueError("duplicate probe ids in catalog")
        for name in PROBE_SETS:
            if name not in self.sets:
                raise ValueError(f"catalog lacks set {name!r}")
        for name, probe_set in self.sets.items():
            if probe_set.id != name:
                raise ValueError(f"set {name!r} carries id {probe_set.id!r}")
            for pid in probe_set.probe_ids:
                probe = by_id.get(pid)
                if probe is None or probe.status != "available" or name not in probe.sets:
                    raise ValueError(f"set {name!r} lists {pid!r} inconsistently")
        for probe in self.probes:
            for name in probe.sets:
                if probe.id not in self.sets[name].probe_ids:
                    raise ValueError(f"{probe.id} claims set {name!r} but the set does not list it")
        core = set(self.sets[CORE_SET].probe_ids)
        if not core <= set(self.sets[EXTENDED_SET].probe_ids):
            raise ValueError(f"{EXTENDED_SET} must contain {CORE_SET}")
        return self

    # -- lookups ----------------------------------------------------------------------------------

    def by_id(self) -> dict[str, ProbeInfo]:
        return {p.id: p for p in self.probes}

    def get(self, probe_id: str) -> ProbeInfo | None:
        return self.by_id().get(probe_id)

    def available(self) -> list[ProbeInfo]:
        return [p for p in self.probes if p.status == "available"]

    def excluded(self) -> list[ProbeInfo]:
        return [p for p in self.probes if p.status == "excluded"]

    def probe_ids_for_set(self, set_id: str) -> list[str]:
        if set_id not in self.sets:
            raise KeyError(set_id)
        return list(self.sets[set_id].probe_ids)

    def families(self) -> list[str]:
        return sorted({p.family for p in self.probes})


def audit_action_for(probe: ProbeInfo) -> str:
    """``llm.probe.<module>.<short_id>``: the per-probe audit action (LLM-19)."""
    return f"{AUDIT_ACTION_PREFIX}{probe.module}.{probe.short_id}"


def row_id(probe_id: str, detector: str) -> str:
    """The scorecard row id a rule or finding cites: ``llm.<probe>.<detector>`` (LLM-13, -16)."""
    return f"llm.{probe_id}.{detector}"


@lru_cache(maxsize=1)
def load_catalog(path: Path | None = None) -> ProbeCatalog:
    """The committed snapshot, validated. Pure json and pydantic; safe for the API process."""
    target = Path(path) if path is not None else CATALOG_PATH
    data = json.loads(target.read_text(encoding="utf-8"))
    return ProbeCatalog.model_validate(data)


def catalog_sha256(path: Path | None = None) -> str:
    target = Path(path) if path is not None else CATALOG_PATH
    return hashlib.sha256(target.read_bytes()).hexdigest()


def canonical_json(catalog: ProbeCatalog) -> str:
    return json.dumps(catalog.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=False) + "\n"


class ProbeSelection(BaseModel):
    """What a request resolves to against the catalog: what runs, what is refused, and why."""

    model_config = ConfigDict(extra="forbid")

    requested: list[str]
    runnable: list[str]
    unknown: list[str] = Field(default_factory=list)
    excluded: dict[str, str] = Field(default_factory=dict)          # probe id -> reason
    detector_unavailable: dict[str, str] = Field(default_factory=dict)   # probe id -> reason


DETECTOR_OFFLINE_REASON = "detector_model_unavailable_offline"
UNKNOWN_PROBE_REASON = "unknown_probe"
EXCLUDED_PROBE_REASON = "probe_excluded"


def resolve_selection(
    catalog: ProbeCatalog,
    *,
    probe_set: str | None = None,
    probe_ids: Iterable[str] | None = None,
    detector_mode: Literal["offline", "hf"] = "offline",
) -> ProbeSelection:
    """Resolve a set id or explicit ids to what the child may run under ``detector_mode``.

    Exactly one of ``probe_set`` / ``probe_ids`` is given. Unknown ids, excluded
    probes and probes whose detector needs a model the mode does not allow are
    reported, never silently dropped.
    """
    if (probe_set is None) == (probe_ids is None):
        raise ValueError("give exactly one of probe_set or probe_ids")
    if probe_set is not None:
        requested = catalog.probe_ids_for_set(probe_set)
    else:
        requested = list(dict.fromkeys(str(p) for p in probe_ids or ()))
    by_id = catalog.by_id()
    selection = ProbeSelection(requested=requested, runnable=[])
    for pid in requested:
        probe = by_id.get(pid)
        if probe is None:
            selection.unknown.append(pid)
            continue
        if probe.status == "excluded":
            selection.excluded[pid] = probe.exclusion_reason or EXCLUDED_PROBE_REASON
            continue
        if detector_mode == "offline" and not probe.detector_offline:
            selection.detector_unavailable[pid] = DETECTOR_OFFLINE_REASON
            continue
        selection.runnable.append(pid)
    return selection


# ---------------------------------------------------------------------------
# Regeneration from an installed garak (worker / developer only)
# ---------------------------------------------------------------------------


def _detector_offline(name: str) -> bool | None:
    """``True`` when the detector class needs no model download and no LLM; ``None`` if it cannot be imported."""
    import importlib

    module, _, cls = name.partition(".")
    if module in NON_OFFLINE_DETECTOR_MODULES:
        return False
    try:
        mod = importlib.import_module(f"garak.detectors.{module}")
        klass = getattr(mod, cls)
    except Exception:  # noqa: BLE001 - a detector that does not import is not offline-runnable
        return None
    mro = {c.__name__ for c in klass.__mro__}
    if mro & NON_OFFLINE_DETECTOR_BASES:
        return False
    extra = getattr(klass, "extra_dependency_names", None) or []
    return not extra


def _probe_class(probe_id: str) -> Any:
    import importlib

    module, _, cls = probe_id.partition(".")
    return getattr(importlib.import_module(f"garak.probes.{module}"), cls)


def _data_files_for(module: str, cls: str, klass: Any, data_root: Path) -> tuple[list[str], PromptSource]:
    """Best-effort map of the ``garak/data`` files a probe reads, verified to exist."""
    candidates: list[str] = []
    source: PromptSource = "in_code"
    prompt_file = getattr(klass, "prompt_file", None)
    if isinstance(prompt_file, str) and prompt_file:
        candidates.append(prompt_file)
        source = "garak_data"
    dna = getattr(klass, "dna_category", None)
    if isinstance(dna, str) and dna:
        candidates.append(f"donotanswer/{dna}.jsonl")
        source = "garak_data"
    payload_name = getattr(klass, "payload_name", None)
    if isinstance(payload_name, str) and payload_name:
        candidates.append(f"payloads/{payload_name}.json")
        source = "generated"
    payloads = getattr(klass, "payloads", None)
    if isinstance(payloads, (list, tuple)):
        for name in payloads:
            if isinstance(name, str):
                candidates.append(f"payloads/{name}.json")
        source = "generated"
    if module == "phrasing":
        candidates.append("phrasing/past_tense_en.txt" if "Past" in cls else "phrasing/future_tense_en.txt")
        source = "garak_data"
    if module == "web_injection" and "Extended" in cls:
        candidates += [f"xss/{n}" for n in ("xss_domains.txt", "xss_var_names.txt", "xss_injection_markers.txt",
                                            "xss_injected_actions.txt", "xss_encodings.txt",
                                            "xss_link_display_texts.txt")]
        source = "generated"
    if module == "realtoxicityprompts":
        source = "garak_data"
        rtp_dir = data_root / "realtoxicityprompts"
        if rtp_dir.is_dir():
            wanted = cls.removeprefix("RTP").lower()
            for path in sorted(rtp_dir.iterdir()):
                if wanted in path.name.lower():
                    candidates.append(f"realtoxicityprompts/{path.name}")
    if module == "promptinject":
        source = "garak_resources"
    if module == "encoding" and not candidates:
        source = "generated"
    files = sorted({c for c in candidates if (data_root / c).is_file()})
    return files, source


def _licence_note(probe_id: str, data_files: list[str]) -> str:
    if probe_id.startswith("fitd."):
        return LICENCE_NOTES["harmbench"]
    if any(f.startswith("inthewild") for f in data_files):
        return LICENCE_NOTES["inthewild"]
    if probe_id.startswith("donotanswer."):
        return LICENCE_NOTES["donotanswer"]
    if probe_id.startswith("realtoxicityprompts."):
        return LICENCE_NOTES["realtoxicityprompts"]
    return LICENCE_NOTES["default"]


def _honours_cap(module: str, klass: Any) -> bool:
    """Whether the probe (or a mixin of its module) applies ``run.soft_probe_prompt_cap`` itself.

    Read from the source of the classes in the probe's MRO that live in its garak
    module; when none of those sources is retrievable (classes built with
    ``type()`` at import), the module source decides.
    """
    import inspect

    marker = "soft_probe_prompt_cap"
    seen_source = False
    for base in klass.__mro__:
        if getattr(base, "__module__", "") != f"garak.probes.{module}":
            continue
        try:
            src = inspect.getsource(base)
        except (OSError, TypeError):
            continue
        seen_source = True
        if marker in src:
            return True
    if seen_source:
        return False
    module_obj = inspect.getmodule(klass)
    if module_obj is None:
        return False
    try:
        return marker in inspect.getsource(module_obj)
    except (OSError, TypeError):
        return False


def build_catalog_from_garak() -> ProbeCatalog:
    """Enumerate the installed garak and build the catalog. Imports garak: never in the API process."""
    import garak
    from garak import _plugins
    from garak.probes._tier import Tier

    data_root = Path(garak.__file__).resolve().parent / "data"
    modules = set(EXTENDED_MODULES) | {"fitd"}
    enumerated = [(name, active) for name, active in _plugins.enumerate_plugins(category="probes")
                  if name.split(".", 2)[1] in modules]
    known_ids = {name.split(".", 1)[1] for name, _ in enumerated}
    probes: list[ProbeInfo] = []
    for full_name, active in enumerated:
        _, module, cls = full_name.split(".", 2)
        probe_id = f"{module}.{cls}"
        info = _plugins.plugin_info(full_name)
        klass = _probe_class(probe_id)
        primary = info.get("primary_detector")
        primary_offline = _detector_offline(primary) if primary else None
        extended = [str(d) for d in (info.get("extended_detectors") or [])]
        extended_offline = {d: bool(_detector_offline(d)) for d in extended}
        data_files, source = _data_files_for(module, cls, klass, data_root)
        tier_value = int(info.get("tier") or Tier.UNLISTED)
        try:
            tier_name = Tier(tier_value).name
        except ValueError:
            tier_name = "UNLISTED"
        status: ProbeStatus = "available"
        reason: str | None = None
        decision: str | None = None
        if probe_id in EXCLUSIONS:
            decision, reason = EXCLUSIONS[probe_id]
            status = "excluded"
        elif (sibling := uncapped_sibling(probe_id)) is not None and sibling in known_ids:
            status, decision = "excluded", "LLM-07"
            reason = (f"uncapped corpus variant of {sibling}; the capped sibling covers the same corpus under the "
                      f"prompt cap, so the variant is not offered to keep gateway spend bounded")
        elif primary is None or primary_offline is None:
            status, decision = "excluded", "LLM-09"
            reason = "no importable primary detector; the harness would abort the run"
        detector_offline = bool(primary_offline)
        membership: list[str] = []
        if status == "available":
            if module in CORE_MODULES and detector_offline:
                membership = [CORE_SET, EXTENDED_SET]
            elif module in EXTENDED_MODULES and not detector_offline:
                membership = [EXTENDED_SET]
            elif module in CORE_MODULES:
                membership = [EXTENDED_SET]
        probes.append(ProbeInfo(
            id=probe_id, module=module, cls=cls, short_id=short_id_for(module, cls), family=module,
            tier=tier_value, tier_name=tier_name, goal=str(info.get("goal") or ""),
            description=str(info.get("description") or ""), doc_uri=(str(info["doc_uri"]) or None) if info.get("doc_uri") else None,
            garak_docs_uri=f"{GARAK_DOCS_BASE}garak.probes.{module}.html", tags=[str(t) for t in (info.get("tags") or [])],
            active_upstream=bool(active), primary_detector=primary, primary_detector_offline=bool(primary_offline),
            extended_detectors=extended, extended_detectors_offline=extended_offline, detector_offline=detector_offline,
            honours_prompt_cap=_honours_cap(module, klass), prompt_source=source, data_files=data_files,
            upstream_licence_note=_licence_note(probe_id, data_files), sets=membership, status=status,
            exclusion_reason=reason, exclusion_decision=decision,
        ))
    probes.sort(key=lambda p: p.id)
    core_ids = [p.id for p in probes if CORE_SET in p.sets]
    extended_ids = [p.id for p in probes if EXTENDED_SET in p.sets]
    sets = {
        CORE_SET: ProbeSet(
            id=CORE_SET, detector_policy="offline",
            description=("Offline-detector probes of the DAN / in-the-wild, prompt-injection, latent-injection, "
                         "encoding, Do-Not-Answer, goodside, grandma, phrasing, divergence, exploitation and "
                         "web-injection families. String, trigger and regex detectors only: no Hugging Face "
                         "model, no second LLM. HarmBench is excluded (LLM-08)."),
            probe_ids=core_ids,
        ),
        EXTENDED_SET: ProbeSet(
            id=EXTENDED_SET, detector_policy="hf", opt_in=True,
            requires="REDSIM_LLM_PROBE_HF_DETECTORS=1 on the worker and a pre-cached detector model directory "
                     "(HF_HOME) with HF_HUB_OFFLINE=1; the child never downloads a model",
            description=(f"{CORE_SET} plus the probes whose primary detector is a Hugging Face classifier "
                         "(latent jailbreak toxicity, RealToxicityPrompts). Model-as-judge detectors are never "
                         "included."),
            probe_ids=extended_ids,
        ),
    }
    return ProbeCatalog(garak_version=str(garak.__version__), generated_by="redsim.ml.llm.catalog.build_catalog_from_garak",
                        sets=sets, probes=probes)


def write_catalog(catalog: ProbeCatalog, path: Path | None = None) -> Path:
    target = Path(path) if path is not None else CATALOG_PATH
    target.write_text(canonical_json(catalog), encoding="utf-8")
    load_catalog.cache_clear()
    return target


__all__ = [
    "AUDIT_ACTION_MAX",
    "AUDIT_ACTION_PREFIX",
    "CATALOG_PATH",
    "CATALOG_VERSION",
    "CORE_MODULES",
    "CORE_SET",
    "DETECTOR_OFFLINE_REASON",
    "EXCLUDED_PROBE_REASON",
    "EXCLUSIONS",
    "EXPECTED_GARAK_VERSION",
    "EXTENDED_MODULES",
    "EXTENDED_SET",
    "HARMBENCH_EXCLUSION",
    "PROBE_SETS",
    "SHORT_ID_MAX",
    "UNKNOWN_PROBE_REASON",
    "ProbeCatalog",
    "ProbeInfo",
    "ProbeSelection",
    "ProbeSet",
    "audit_action_for",
    "build_catalog_from_garak",
    "canonical_json",
    "catalog_sha256",
    "load_catalog",
    "resolve_selection",
    "row_id",
    "short_id_for",
    "uncapped_sibling",
    "write_catalog",
]
