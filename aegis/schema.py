from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


@dataclass
class CodeLocation:
    file: str
    start_line: int
    end_line: int
    snippet: str | None = None
    label: str | None = None
    fix_before: str | None = None
    fix_after: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> CodeLocation:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class AegisFinding:
    # Required fields
    id: str
    title: str
    severity: str                    # critical|high|medium|low
    finding_type: str                # dependency|sast|dast|runtime|config
    description: str
    source_tool: str                 # strix|cai|manual
    source_run_id: str
    affected_component: str          # package name, endpoint, file path
    confidence: str                  # high|medium|low
    status: str                      # open|fixing|fixed|failed|false_positive
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
    references: list[str] | None = field(default=None)
    artifact_path: str | None = None

    # Dependency-specific (for vuln-fixer routing)
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None

    # Strix pass-through fields (not in common schema but useful)
    impact: str | None = None
    technical_analysis: str | None = None
    poc_description: str | None = None
    timestamp: str | None = None
    cvss_breakdown: dict | None = None

    @property
    def is_dependency_finding(self) -> bool:
        return (self.finding_type == "dependency"
                and self.package_name is not None
                and self.installed_version is not None)

    def to_dict(self) -> dict:
        d = {}
        for k, v in asdict(self).items():
            d[k] = v
        return d

    @classmethod
    def from_dict(cls, d: dict) -> AegisFinding:
        data = dict(d)
        # Convert code_locations dicts to CodeLocation objects
        if 'code_locations' in data and data['code_locations'] is not None:
            data['code_locations'] = [
                CodeLocation.from_dict(loc) if isinstance(loc, dict) else loc
                for loc in data['code_locations']
            ]
        # Only pass fields that exist on the dataclass
        valid_fields = cls.__dataclass_fields__
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)
