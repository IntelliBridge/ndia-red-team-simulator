"""Generic name-keyed registry shared by the scanner and agent subsystems.

Both subsystems were maintaining structurally identical ``_REGISTRY`` dicts
with their own ``register`` / ``get`` / ``list`` helpers. :class:`Registry`
collapses that duplication and adds an opt-in entry-point discovery hook
(:meth:`maybe_load_entry_points`) gated by ``AEGIS_PLUGINS=1`` so third-party
plugins can never perturb the offline test path.
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Generic, Protocol, TypeVar, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class _Named(Protocol):
    name: str


T = TypeVar("T", bound=_Named)


class Registry(Generic[T]):
    """A ``name -> item`` table with an opt-in entry-point discovery hook.

    ``kind`` only labels error messages (``"scanner"`` / ``"agent"``).
    ``validate`` is an optional hook invoked on each item at registration; it
    may log or raise, but a non-raising hook still registers the item (the
    open-vocabulary "warn but register" behaviour scanners rely on).
    """

    def __init__(self, kind: str, *, validate: Callable[[T], None] | None = None) -> None:
        self._kind = kind
        self._validate = validate
        self._items: dict[str, T] = {}

    def register(self, item: T) -> None:
        if self._validate is not None:
            self._validate(item)
        self._items[item.name] = item

    def get(self, name: str) -> T:
        if name not in self._items:
            raise KeyError(f"unknown {self._kind}: {name!r}. "
                           f"available: {sorted(self._items)}")
        return self._items[name]

    def list_names(self) -> list[str]:
        return sorted(self._items)

    def maybe_load_entry_points(self, group: str) -> None:
        """Discover third-party items via entry points, gated by AEGIS_PLUGINS=1."""
        if os.environ.get("AEGIS_PLUGINS") != "1":
            return
        try:
            from importlib.metadata import entry_points
            eps = entry_points(group=group)
        except Exception:  # pragma: no cover - importlib edge
            return
        for ep in eps:
            try:
                factory = ep.load()
                self.register(factory())
            except Exception:  # pragma: no cover - third-party plugin failure
                logger.warning("failed to load %s plugin %r", self._kind, ep.name)
                continue
