"""``RunStateAPI`` — the shared interface every state backend implements.

Phase 2's ``aegis.state.RunState`` is filesystem-only. Phase 3 introduces a
Postgres backend (``aegis.state.PostgresRunState``) so the API and the
workers can use the same persistence layer the CLI uses offline. Both
backends satisfy this Protocol.

State methods are **pure persistence**: they do not emit audit events. The
service layer (``aegis.services``) emits audit events at operation
boundaries. This separation makes both backends interchangeable and keeps
the audit chain in exactly one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from aegis.schema import AegisFinding, Status


@dataclass(frozen=True)
class ArtifactRef:
    sha256: str
    location: str           # filesystem path or blob URI
    size_bytes: int
    content_type: str = "application/octet-stream"


class RunStateAPI(Protocol):
    """Public surface that both filesystem and Postgres backends implement."""

    run_id: str
    run_path: Path

    @property
    def findings_path(self) -> Path: ...

    @property
    def artifacts_path(self) -> Path: ...

    @property
    def remediation_log_path(self) -> Path: ...

    @property
    def report_path(self) -> Path: ...

    def save_findings(self, findings: list[AegisFinding]) -> None: ...

    def load_findings(self) -> list[dict[str, Any]]: ...

    def save_artifact(self, name: str, content: bytes | str) -> Path: ...

    def append_remediation_log(self, finding_id: str, action: str,
                               result: str, success: bool) -> None: ...

    def update_finding_status(self, finding_id: str, status: Status) -> None: ...

    def record_artifact(self, name: str, content: bytes | str,
                        content_type: str = "application/octet-stream") -> ArtifactRef: ...

    def close(self) -> None:
        """Release any backend resource (e.g. a factory-owned DB session)."""
        ...
