"""Built-in target registry.

Only honest catalog entries live here.  The bundled CIFAR-10 target will be
registered when its implementation and assets exist; deferred domains are
visible now but fail closed if an evaluation operation is attempted.
"""

from pathlib import Path

from redsim.registry import Registry
from redsim.schema import TargetInfo
from redsim.targets.base import Target
from redsim.targets.cifar10_assets import TorchCifar10Backend
from redsim.targets.image_cifar10 import Cifar10Target
from redsim.targets.llm_stub import LlmTarget
from redsim.targets.tabular_stub import TabularTarget

TARGETS = Registry[Target]("target", protocol=Target)
TARGETS.register(TabularTarget())
TARGETS.register(LlmTarget())


def get_target(target_id: str) -> Target:
    """Return a target or raise a contextual ``KeyError``."""

    return TARGETS.get(target_id)


def list_targets() -> list[TargetInfo]:
    """Return stable, serializable catalog metadata sorted by target ID."""

    return [target.info() for target in TARGETS]


def register_cifar10_assets(assets_dir: str | Path) -> Cifar10Target:
    """Register the live target only when its complete asset bundle exists."""

    existing = TARGETS.maybe_get(Cifar10Target.id)
    if existing is not None:
        if not isinstance(existing, Cifar10Target):
            raise TypeError("target 'cifar10' is registered with an unexpected implementation")
        return existing

    backend = TorchCifar10Backend(assets_dir)
    if not backend.assets_available():
        raise FileNotFoundError(
            f"CIFAR-10 assets are incomplete in {Path(assets_dir)}; "
            "run `python -m redsim.setup_assets`"
        )
    target = Cifar10Target(backend)
    target.load()
    TARGETS.register(target)
    return target