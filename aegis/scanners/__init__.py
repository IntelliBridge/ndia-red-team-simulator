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
from aegis.scanners import (  # noqa: F401
    strix_adapter,
    trivy_adapter,
    semgrep_adapter,
    nuclei_adapter,
    zap_adapter,
    codeql_adapter,
    bandit_adapter,
    grype_adapter,
    checkov_adapter,
    trufflehog_adapter,
    sonarqube_adapter,
    syft_adapter,
)

__all__ = [
    "ScannerAdapter", "ScanOptions", "ScanResult",
    "dispatch", "get", "list_scanners", "register",
]
