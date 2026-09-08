"""Catalog entry for the deferred tabular evaluation domain."""

from redsim.targets.unavailable import UnavailableTarget


class TabularTarget(UnavailableTarget):
    id = "tabular"
    name = "Tabular classifier"
    domain = "tabular"
    reason = "Tabular evaluation is outside the first milestone; only bundled CIFAR-10 is supported."
    metadata = {
        "planned_access": "bundled public or synthetic dataset",
        "launch_behavior": "HTTP 501 Not Implemented",
    }