"""Id-keyed registry for the ML vertical (API per docs/plans/01 section 4.1).

Distinct from ``redsim.registry.Registry`` (name-keyed, entry-point discovery).
``TARGETS`` and ``ATTACKS`` are singletons of this class; other modules only
``register`` into them and read with ``items()`` / ``maybe_get()`` / iteration.
"""

from __future__ import annotations

from typing import Generic, Iterator, Protocol, TypeVar, runtime_checkable


@runtime_checkable
class _Identified(Protocol):
    id: str


T = TypeVar("T", bound=_Identified)


class DuplicateRegistration(ValueError):
    """Two items registered under the same ``id``."""


class Registry(Generic[T]):
    def __init__(self, kind: str, protocol: type | None = None) -> None:
        self._kind = kind
        self._protocol = protocol
        self._items: dict[str, T] = {}

    @property
    def kind(self) -> str:
        return self._kind

    def register(self, item: T) -> T:
        if self._protocol is not None and not isinstance(item, self._protocol):
            raise TypeError(f"cannot register {self._kind}: does not satisfy {self._protocol.__name__}")
        item_id = getattr(item, "id", None)
        if not isinstance(item_id, str) or not item_id:
            raise TypeError(f"cannot register {self._kind}: missing non-empty string 'id'")
        if item_id in self._items:
            raise DuplicateRegistration(f"{self._kind} {item_id!r} already registered")
        self._items[item_id] = item
        return item

    def get(self, item_id: str) -> T:
        try:
            return self._items[item_id]
        except KeyError:
            raise KeyError(f"unknown {self._kind}: {item_id!r}") from None

    def maybe_get(self, item_id: str) -> T | None:
        return self._items.get(item_id)

    def ids(self) -> list[str]:
        return sorted(self._items)

    def items(self) -> list[T]:
        return [self._items[k] for k in self.ids()]

    def __contains__(self, item_id: object) -> bool:
        return item_id in self._items

    def __iter__(self) -> Iterator[T]:
        return iter(self.items())

    def __len__(self) -> int:
        return len(self._items)

    def clear(self) -> None:
        """Test hook."""
        self._items.clear()
