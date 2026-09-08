"""Contract tests for built-in target discovery and unavailable domains."""

from collections.abc import Callable

import numpy as np
import pytest

from redsim.targets import TARGETS, get_target, list_targets


def test_catalog_lists_deferred_domains_in_stable_order() -> None:
    targets = list_targets()

    assert [target.id for target in targets] == ["llm", "tabular"]
    assert [target.domain for target in targets] == ["llm", "tabular"]
    assert all(target.status == "not_implemented" for target in targets)
    assert all(target.reason for target in targets)


def test_registry_contains_only_honest_built_in_entries() -> None:
    assert TARGETS.ids() == ["llm", "tabular"]
    assert "cifar10" not in TARGETS


def test_llm_entry_documents_pythia_without_connecting() -> None:
    info = get_target("llm").info()

    assert info.metadata["gateway"] == "Pythia"
    assert info.metadata["protocol"] == "OpenAI-compatible"
    assert info.metadata["api_key_env"] == "PYTHIA_API_KEY"
    assert info.metadata["launch_behavior"] == "HTTP 501 Not Implemented"


def test_tabular_entry_explains_milestone_boundary() -> None:
    info = get_target("tabular").info()

    assert info.domain == "tabular"
    assert "outside the first milestone" in info.reason
    assert info.metadata["launch_behavior"] == "HTTP 501 Not Implemented"


@pytest.mark.parametrize(
    "operation",
    [
        lambda target: target.load(),
        lambda target: target.sample(10, 0),
        lambda target: target.predict_proba(np.zeros((1, 1))),
        lambda target: target.art_classifier(),
        lambda target: target.torch_model(),
        lambda target: target.manifest(),
    ],
)
@pytest.mark.parametrize("target_id", ["llm", "tabular"])
def test_unavailable_targets_refuse_all_evaluation_operations(
    target_id: str, operation: Callable
) -> None:
    with pytest.raises(NotImplementedError, match="not implemented"):
        operation(get_target(target_id))


def test_unknown_target_raises_contextual_error() -> None:
    with pytest.raises(KeyError, match="unknown target: 'missing'"):
        get_target("missing")