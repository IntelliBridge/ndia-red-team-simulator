"""Aegis domain schema: ``AegisFinding``, ``CodeLocation``, and the shared
severity/status/confidence vocabularies they are typed against.

These were dataclasses through v0.12; as of the architecture-hardening pass they
are Pydantic v2 models so that construction is *validated at runtime* — a scanner
adapter that emits an out-of-vocabulary ``severity`` or drops a required field now
fails at the source instead of silently persisting a malformed finding.

The public surface is unchanged: ``to_dict()`` / ``from_dict()`` keep the same
signatures so the dozens of call sites (``save_findings``, report rendering, the
worker tasks) need no edits. ``from_dict`` is deliberately *lenient* on read: the
old dataclasses never validated, so historical ``findings.schema_blob`` rows may
violate the new constraints. Rather than hard-fail a read, it falls back to an
unvalidated construction and logs — new writes stay fail-closed (validated at
construction), legacy reads stay best-effort.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

logger = logging.getLogger(__name__)

Severity = Literal["critical", "high", "medium", "low"]
FindingType = Literal[
    "dependency", "sast", "dast", "runtime", "config", "code", "code_audit", "supply_chain"
]
Status = Literal["open", "fixing", "fixed", "failed", "false_positive"]
Confidence = Literal["high", "medium", "low"]


class CodeLocation(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    file: str
    start_line: int
    end_line: int
    snippet: str | None = None
    label: str | None = None
    fix_before: str | None = None
    fix_after: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, d: dict) -> CodeLocation:
        return cls.model_validate(d)


class AegisFinding(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    # Required fields
    id: str
    title: str
    severity: Severity
    finding_type: FindingType
    description: str
    source_tool: str                 # producing adapter name (e.g. an ML attack adapter) | manual
    source_run_id: str
    affected_component: str          # package name, endpoint, file path
    confidence: Confidence
    status: Status
    created_at: str                  # ISO 8601
    updated_at: str                  # ISO 8601

    # Optional fields
    cvss: float | None = None
    cve: str | None = None
    cwe: str | None = None
    target: str | None = None
    endpoint: str | None = None
    method: str | None = None
    code_locations: list[CodeLocation] | None = None
    poc_script_code: str | None = None
    remediation_steps: str | None = None
    evidence: str | None = None
    references: list[str] | None = None
    artifact_path: str | None = None

    # Dependency-specific (for vuln-fixer routing)
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None

    # Adapter pass-through fields (not in common schema but useful; retained
    # for schema compatibility with historical findings)
    impact: str | None = None
    technical_analysis: str | None = None
    poc_description: str | None = None
    timestamp: str | None = None
    cvss_breakdown: dict[str, Any] | None = None

    @property
    def is_dependency_finding(self) -> bool:
        return (self.finding_type == "dependency"
                and self.package_name is not None
                and self.installed_version is not None)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, d: dict) -> AegisFinding:
        """Reconstruct a finding from a stored dict.

        Happy path validates (``extra='ignore'`` drops unknown keys, nested
        ``code_locations`` dicts coerce to ``CodeLocation`` automatically). Legacy
        ``schema_blob`` rows written by the old, unvalidated dataclasses may carry
        out-of-vocabulary values; rather than break the read, fall back to an
        unvalidated ``model_construct`` (the pre-migration behaviour) and log.
        """
        try:
            return cls.model_validate(d)
        except ValidationError as exc:
            logger.warning(
                "AegisFinding.from_dict: blob failed validation (id=%r), loading "
                "unvalidated: %s", d.get("id"), exc,
            )
            data = dict(d)
            locs = data.get("code_locations")
            if isinstance(locs, list):
                data["code_locations"] = [
                    _coerce_code_location(loc) for loc in locs
                ]
            known = set(cls.model_fields)
            return cls.model_construct(**{k: v for k, v in data.items() if k in known})


def _coerce_code_location(loc: Any) -> Any:
    """Best-effort dict -> CodeLocation for the unvalidated fallback path."""
    if not isinstance(loc, dict):
        return loc
    try:
        return CodeLocation.model_validate(loc)
    except ValidationError:
        known = set(CodeLocation.model_fields)
        return CodeLocation.model_construct(**{k: v for k, v in loc.items() if k in known})
