"""Single source for the UPPERCASE vulnerability-severity → canonical map shared by the trivy runner, grype adapter, and offline finding-ingest path."""

from __future__ import annotations

from redsim.schema import Severity

# UPPERCASE vulnerability severity vocabulary (Trivy / Grype) → canonical
# Redsim severity. NEGLIGIBLE and UNKNOWN collapse to ``low``. This is the single
# source of truth; previously copies lived in trivy_runner, grype_adapter, and
# finding_ingest (where the trivy_runner copy had drifted by omitting
# NEGLIGIBLE).
_UPPER_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NEGLIGIBLE": "low",
    "UNKNOWN": "low",
}


def canon_severity(raw: str | None) -> Severity:
    """Map a raw UPPERCASE severity string to a canonical :class:`Severity`.

    Casing/whitespace is normalized; unknown or empty input falls back to
    ``"low"`` (the safe default used across the scanner layers).
    """
    return _UPPER_SEVERITY_MAP.get((raw or "").strip().upper(), "low")
