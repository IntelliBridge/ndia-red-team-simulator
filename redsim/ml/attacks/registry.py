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
"""

from __future__ import annotations

from redsim.ml.attacks.base import AttackAdapter
from redsim.ml.registry import Registry
from redsim.ml.schema import AttackInfo

ATTACKS: Registry[AttackAdapter] = Registry("attack", AttackAdapter)

# Spec 12.1 (S1 section 4) capability tags shared with the platform registry vocabulary.
CAPABILITY_ADVERSARIAL_ML = "adversarial_ml"
CAPABILITY_EXPLAINABILITY = "explainability"

# Open but checked vocabulary: adding a tag is a one-line append, and a tag outside the set is
# a registration error, so a typo can never create a silent new capability.
KNOWN_ATTACK_CAPABILITIES: frozenset[str] = frozenset({
    CAPABILITY_ADVERSARIAL_ML,
    CAPABILITY_EXPLAINABILITY,
    "white_box",            # needs a differentiable estimator (AttackInfo.access == "white-box")
    "black_box",            # predict / decision access only
    "surrogate_transfer",   # white-box gradients taken on a declared surrogate, scored on the real model
    "query_counted",        # records queries_mean
    "takes_eps",            # eps is an input from the campaign grid
    "minimal_norm",         # no eps input; the grid is an evaluation grid (spec 12.3)
    "family:evasion",
    "family:control",
    "modality:image",
    "modality:tabular",
    "modality:llm",
})


def attack_capabilities(adapter: AttackAdapter) -> frozenset[str]:
    """Capability tags for one adapter: the tags it declares plus those derived from ``info()``.

    Derived tags: ``adversarial_ml`` always, ``white_box`` / ``black_box`` from ``access``,
    ``family:<family>``, ``modality:<domain>`` for every domain in the adapter's ``domains``
    (falling back to ``info().domain``), and ``takes_eps`` or ``minimal_norm`` from ``takes_eps``.
    Raises ``ValueError`` when any tag is outside ``KNOWN_ATTACK_CAPABILITIES``.
    """
    info: AttackInfo = adapter.info()
    tags: set[str] = {CAPABILITY_ADVERSARIAL_ML, f"family:{info.family}"}
    tags.add("white_box" if info.access == "white-box" else "black_box")
    domains = getattr(adapter, "domains", None) or frozenset({info.domain})
    tags.update(f"modality:{d}" for d in domains)
    tags.add("takes_eps" if getattr(adapter, "takes_eps", True) else "minimal_norm")
    declared = getattr(adapter, "capabilities", None) or frozenset()
    tags.update(str(t) for t in declared)
    unknown = sorted(tags - KNOWN_ATTACK_CAPABILITIES)
    if unknown:
        raise ValueError(f"attack {info.id!r} declares unknown capability tag(s) {unknown}; "
                         f"known: {sorted(KNOWN_ATTACK_CAPABILITIES)}")
    return frozenset(tags)


def register_attack(adapter: AttackAdapter) -> AttackAdapter:
    """Validate the adapter's capability tags, then register it (duplicate ids raise)."""
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
