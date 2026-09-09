"""``ATTACKS`` singleton (P0 seam) and the attack capability tags (spec 12.1).

Registration divergence, recorded here on purpose: spec 12.1 says adapters register in
``redsim.registry.Registry`` (the name-keyed scanner registry whose adapters carry a
``capabilities`` set) under the tags ``adversarial_ml`` and ``explainability``. The ML
vertical instead registers into ``redsim.ml.registry.Registry`` (id-keyed, duplicate-id
detection, the P0 seam ``ATTACKS``), because ``AttackInfo`` is keyed by ``id`` and
``GET /v1/attacks`` lists ``AttackInfo`` as is. The tag vocabulary is kept: every adapter
declares ``capabilities`` (a ``frozenset[str]`` drawn from ``KNOWN_ATTACK_CAPABILITIES``),
``attack_capabilities()`` derives the same tags from ``info()`` so the two never disagree,
and ``register_attack()`` refuses an adapter whose tags leave the vocabulary. The
``explainability`` tag names the explainer side (``redsim.ml.explain``). No attack adapter
carries it, and a control carries ``family:control`` so it is never mistaken for an attack.

Norms (spec 12.3, Phase B ATTACKS_HARDEN-03): an adapter may declare ``norms`` (a
``frozenset`` of the campaign norms it can be evaluated under). When it does not, the set is
derived: ``{"linf", "l2"}`` for an adapter with a ``norm_l2`` parameter, ``{"linf"}``
otherwise. ``attack_capabilities()`` exposes them as ``norm:<name>`` tags so a client can
show them, and :func:`attack_supports_norm` is the one admission question ("may this attack
run under this campaign norm?") the runner and the campaign service ask before a run. A
campaign whose norm the adapter does not support is refused, never silently re-normed.

Domain defaults (ATTACKS_HARDEN-04): an adapter that serves more than one modality may carry
``domain_defaults = {"<domain>": {param: value}}`` with per-modality cost defaults. They are
applied only to keys the caller omitted (:func:`apply_domain_defaults`), so an explicit
parameter always wins and the resolved values land in ``Measurement.params`` as usual.
"""

from __future__ import annotations

from typing import Any

from redsim.ml.attacks.base import AttackAdapter
from redsim.ml.registry import Registry
from redsim.ml.schema import AttackInfo

ATTACKS: Registry[AttackAdapter] = Registry("attack", AttackAdapter)

# Spec 12.1 (S1 section 4) capability tags shared with the platform registry vocabulary.
CAPABILITY_ADVERSARIAL_ML = "adversarial_ml"
CAPABILITY_EXPLAINABILITY = "explainability"

#: Campaign norms an adapter may declare in ``norms``. ``linf`` / ``l2`` are the Phase A
#: ``schema.Norm`` literals; ``edit`` (text) and ``patch_area`` (detection) are the Phase B
#: additions of the same literal (plan 12 section 3). Kept as strings so this module never
#: depends on the frozen schema growing before a sibling adapter registers.
KNOWN_NORMS: frozenset[str] = frozenset({"linf", "l2", "edit", "patch_area"})

#: The adapter parameter that switches a takes-eps attack to the L2 norm (PGD, the control,
#: HopSkipJump). Its presence is what derives ``{"linf", "l2"}`` for an adapter without ``norms``.
L2_SWITCH_PARAM = "norm_l2"

#: Modalities whose budget is not a pixel or feature norm: an adapter serving only these and declaring no
#: ``norms`` is evaluated in the modality's own norm (spec 12.3 edit grid, detection patch-area grid).
MODALITY_NORMS: dict[str, frozenset[str]] = {"text": frozenset({"edit"}), "detection": frozenset({"patch_area"})}

# Open but checked vocabulary: adding a tag is a one-line append, and a tag outside the set is
# a registration error, so a typo can never create a silent new capability.
KNOWN_ATTACK_CAPABILITIES: frozenset[str] = frozenset({
    CAPABILITY_ADVERSARIAL_ML,
    CAPABILITY_EXPLAINABILITY,
    "white_box",            # needs a differentiable estimator (AttackInfo.access == "white-box")
    "black_box",            # predict / decision access only
    "surrogate_transfer",   # white-box gradients taken on a declared surrogate, scored on the real model
    "query_counted",        # records queries_mean
    "decision_based",       # black-box over predicted labels only (HopSkipJump)
    "score_based",          # black-box over probability outputs (ZOO); labels-only endpoints make it not applicable
    "takes_eps",            # eps is an input from the campaign grid
    "minimal_norm",         # no eps input; the grid is an evaluation grid (spec 12.3)
    "family:evasion",
    "family:control",
    "modality:image",
    "modality:tabular",
    "modality:text",
    "modality:detection",
    "modality:llm",
    # Norms the adapter may be evaluated under (spec 12.3; derived from ``norms``, see attack_norms()).
    "norm:linf",
    "norm:l2",
    "norm:edit",
    "norm:patch_area",
})


def attack_norms(adapter: Any) -> frozenset[str]:
    """Campaign norms the adapter supports.

    The adapter's own ``norms`` declaration when it has one; otherwise the modality's own norm for an
    adapter that serves only text or detection (``MODALITY_NORMS``), else ``{"linf", "l2"}`` when its
    ``params_schema`` carries a ``norm_l2`` switch and ``{"linf"}`` when it does not. The result is
    never empty and every member is in ``KNOWN_NORMS`` (``ValueError`` otherwise, so a typo in an
    adapter's declaration fails at registration, not at the first campaign).
    """
    declared = getattr(adapter, "norms", None)
    if declared:
        norms = frozenset(str(n) for n in declared)
    else:
        info: AttackInfo = adapter.info()
        domains = frozenset(str(d) for d in (getattr(adapter, "domains", None) or {info.domain}))
        if domains and domains <= MODALITY_NORMS.keys():
            # A text or detection adapter without a declaration is evaluated in its modality's own norm.
            norms = frozenset().union(*(MODALITY_NORMS[d] for d in domains))
        else:
            has_l2_switch = any(spec.name == L2_SWITCH_PARAM for spec in info.params_schema)
            norms = frozenset({"linf", "l2"}) if has_l2_switch else frozenset({"linf"})
    unknown = sorted(norms - KNOWN_NORMS)
    if unknown:
        raise ValueError(f"attack {getattr(adapter, 'id', '?')!r} declares unknown norm(s) {unknown}; "
                         f"known: {sorted(KNOWN_NORMS)}")
    return norms


def attack_supports_norm(adapter: Any, norm: str) -> bool:
    """``True`` when a campaign with ``norm`` may name this adapter (admission and runner question).

    A minimal-norm attack (``takes_eps`` False) is evaluated by thresholding its achieved norm against
    the grid, so "supports" means the achieved-norm comparison is meaningful in that norm; a
    takes-eps attack must be able to optimise in it. Both are what ``norms`` declares.
    """
    return str(norm) in attack_norms(adapter)


def attack_domain_defaults(adapter: Any, domain: str | None) -> dict[str, Any]:
    """The adapter's per-modality default parameters for ``domain`` (empty when none are declared)."""
    if domain is None:
        return {}
    table = getattr(adapter, "domain_defaults", None) or {}
    block = table.get(str(domain)) if isinstance(table, dict) else None
    return dict(block) if isinstance(block, dict) else {}


def apply_domain_defaults(adapter: Any, domain: str | None, params: dict[str, Any] | None) -> dict[str, Any]:
    """``params`` with the adapter's ``domain_defaults[domain]`` filled in for every key the caller omitted.

    Explicit values always win; the returned dict still has to go through ``resolve_params`` (bounds,
    types, defaults for everything else). The runner and admission call this before ``resolve_params``
    so the applied values land in ``Measurement.params`` like any other parameter.
    """
    out = dict(params or {})
    for key, value in attack_domain_defaults(adapter, domain).items():
        out.setdefault(key, value)
    return out


def attack_capabilities(adapter: AttackAdapter) -> frozenset[str]:
    """Capability tags for one adapter: the tags it declares plus those derived from ``info()``.

    Derived tags: ``adversarial_ml`` always, ``white_box`` / ``black_box`` from ``access``,
    ``family:<family>``, ``modality:<domain>`` for every domain in the adapter's ``domains``
    (falling back to ``info().domain``), ``takes_eps`` or ``minimal_norm`` from ``takes_eps``, and
    ``norm:<n>`` for every norm in :func:`attack_norms`.
    Raises ``ValueError`` when any tag is outside ``KNOWN_ATTACK_CAPABILITIES``.
    """
    info: AttackInfo = adapter.info()
    tags: set[str] = {CAPABILITY_ADVERSARIAL_ML, f"family:{info.family}"}
    tags.add("white_box" if info.access == "white-box" else "black_box")
    domains = getattr(adapter, "domains", None) or frozenset({info.domain})
    tags.update(f"modality:{d}" for d in domains)
    tags.add("takes_eps" if getattr(adapter, "takes_eps", True) else "minimal_norm")
    tags.update(f"norm:{n}" for n in attack_norms(adapter))
    declared = getattr(adapter, "capabilities", None) or frozenset()
    tags.update(str(t) for t in declared)
    unknown = sorted(tags - KNOWN_ATTACK_CAPABILITIES)
    if unknown:
        raise ValueError(f"attack {info.id!r} declares unknown capability tag(s) {unknown}; "
                         f"known: {sorted(KNOWN_ATTACK_CAPABILITIES)}")
    return frozenset(tags)


def register_attack(adapter: AttackAdapter) -> AttackAdapter:
    """Validate the adapter's capability tags (norms included), then register it (duplicate ids raise)."""
    attack_capabilities(adapter)
    return ATTACKS.register(adapter)


def get_attack(attack_id: str) -> AttackAdapter:
    return ATTACKS.get(attack_id)


def list_attacks() -> list[AttackInfo]:
    return [a.info() for a in ATTACKS]


def list_attack_capabilities() -> dict[str, list[str]]:
    """``{attack_id: sorted tags}`` for every registered adapter."""
    return {a.id: sorted(attack_capabilities(a)) for a in ATTACKS}


def attacks_with_capability(tag: str) -> list[AttackAdapter]:
    """Registered adapters carrying ``tag`` (sorted by id). Unknown tags are a ``ValueError``."""
    if tag not in KNOWN_ATTACK_CAPABILITIES:
        raise ValueError(f"unknown capability tag {tag!r}; known: {sorted(KNOWN_ATTACK_CAPABILITIES)}")
    return [a for a in ATTACKS if tag in attack_capabilities(a)]
