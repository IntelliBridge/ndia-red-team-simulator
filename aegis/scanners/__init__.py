"""Pluggable scanner registry."""

from aegis.scanners.registry import (
    ScannerAdapter,
    ScanOptions,
    ScanResult,
    dispatch,
    get,
    list_scanners,
    register,
)

# Eagerly register the built-in adapters so callers don't have to import each.
from aegis.scanners import strix_adapter, trivy_adapter, semgrep_adapter, nuclei_adapter  # noqa: F401

__all__ = [
    "ScannerAdapter", "ScanOptions", "ScanResult",
    "dispatch", "get", "list_scanners", "register",
]
