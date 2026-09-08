"""``ATTACKS`` singleton (P0 seam). Concrete adapters call ``ATTACKS.register(...)`` on import."""

from __future__ import annotations

from redsim.ml.attacks.base import AttackAdapter
from redsim.ml.registry import Registry
from redsim.ml.schema import AttackInfo

ATTACKS: Registry[AttackAdapter] = Registry("attack", AttackAdapter)


def get_attack(attack_id: str) -> AttackAdapter:
    return ATTACKS.get(attack_id)


def list_attacks() -> list[AttackInfo]:
    return [a.info() for a in ATTACKS]
