"""Pluggable scanner registry."""

# Eagerly register the built-in adapters so callers don't have to import each.
from aegis.scanners import (  # noqa: F401
    bandit_adapter,
    checkov_adapter,
    codeql_adapter,
    grype_adapter,
    nuclei_adapter,
    semgrep_adapter,
    sonarqube_adapter,
    strix_adapter,
    syft_adapter,
    trivy_adapter,
    trufflehog_adapter,
    zap_adapter,
)
from aegis.scanners.registry import (
    ScannerAdapter,
    ScanOptions,
    ScanResult,
    dispatch,
    get,
    list_scanners,
    register,
)

__all__ = [
    "ScannerAdapter", "ScanOptions", "ScanResult",
    "dispatch", "get", "list_scanners", "register",
]
