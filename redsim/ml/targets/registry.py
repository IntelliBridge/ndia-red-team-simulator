"""``TARGETS`` singleton (P0 seam). Concrete targets call ``TARGETS.register(...)`` on import."""

from __future__ import annotations

from redsim.ml.registry import Registry
from redsim.ml.schema import TargetInfo
from redsim.ml.targets.base import Target

TARGETS: Registry[Target] = Registry("target", Target)


def get_target(target_id: str) -> Target:
    return TARGETS.get(target_id)


def list_targets() -> list[TargetInfo]:
    return [t.info() for t in TARGETS]
