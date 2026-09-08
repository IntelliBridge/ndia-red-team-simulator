"""Unit tests for the generic target/attack registry boundary."""

from typing import Protocol, runtime_checkable

import pytest

from redsim.registry import DuplicateRegistration, Registry


class Item:
    def __init__(self, item_id: str, rank: int = 0) -> None:
        self.id = item_id
        self.rank = rank


@runtime_checkable
class RankedItem(Protocol):
    id: str
    rank: int


def test_register_returns_item_and_supports_lookup() -> None:
    registry = Registry[Item]("target")
    item = Item("cifar10")

    assert registry.register(item) is item
    assert registry.get("cifar10") is item
    assert registry.maybe_get("cifar10") is item
    assert "cifar10" in registry
    assert len(registry) == 1


def test_duplicate_id_is_rejected_without_replacing_original() -> None:
    registry = Registry[Item]("attack")
    original = registry.register(Item("fgsm", rank=1))

    with pytest.raises(DuplicateRegistration, match="'fgsm' already registered"):
        registry.register(Item("fgsm", rank=2))

    assert registry.get("fgsm") is original


def test_unknown_id_has_contextual_error_and_maybe_get_is_safe() -> None:
    registry = Registry[Item]("target")

    with pytest.raises(KeyError, match="unknown target: 'missing'"):
        registry.get("missing")
    assert registry.maybe_get("missing") is None


def test_ids_items_and_iteration_are_sorted_by_id() -> None:
    registry = Registry[Item]("attack")
    for item_id in ("pgd", "fgsm", "noise_control"):
        registry.register(Item(item_id))

    expected = ["fgsm", "noise_control", "pgd"]
    assert registry.ids() == expected
    assert [item.id for item in registry.items()] == expected
    assert [item.id for item in registry] == expected


@pytest.mark.parametrize("bad_id", ["", None, 7])
def test_registration_requires_a_non_empty_string_id(bad_id: object) -> None:
    registry = Registry("target")
    item = Item("temporary")
    item.id = bad_id  # type: ignore[assignment]

    with pytest.raises(TypeError, match="missing non-empty string 'id'"):
        registry.register(item)


def test_optional_runtime_protocol_is_enforced() -> None:
    registry = Registry("ranked item", protocol=RankedItem)

    class MissingRank:
        id = "incomplete"

    with pytest.raises(TypeError, match="does not satisfy RankedItem protocol"):
        registry.register(MissingRank())


def test_clear_removes_all_registrations() -> None:
    registry = Registry[Item]("attack")
    registry.register(Item("fgsm"))
    registry.clear()

    assert len(registry) == 0
    assert registry.ids() == []


def test_registries_do_not_share_state() -> None:
    targets = Registry[Item]("target")
    attacks = Registry[Item]("attack")
    targets.register(Item("shared-id"))

    assert "shared-id" in targets
    assert "shared-id" not in attacks