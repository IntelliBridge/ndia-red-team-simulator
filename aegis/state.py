"""Aegis run state persistence."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class RunState:
    """Manages per-run persistence under output_dir/runs/<run_id>/."""

    def __init__(self, output_dir: str, run_id: str | None = None):
        self.output_dir = Path(output_dir)
        self.run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6]
        self.run_path = self.output_dir / "runs" / self.run_id
        self.run_path.mkdir(parents=True, exist_ok=True)

    @property
    def findings_path(self) -> Path:
        return self.run_path / "findings.json"

    @property
    def artifacts_path(self) -> Path:
        return self.run_path / "artifacts"

    @property
    def remediation_log_path(self) -> Path:
        return self.run_path / "remediation-log.json"

    @property
    def report_path(self) -> Path:
        return self.run_path / "report.md"

    def save_findings(self, findings: list) -> None:
        """Save list of AegisFinding dicts to findings.json."""
        data = [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]
        with open(self.findings_path, "w") as fh:
            json.dump(data, fh, indent=2)

    def load_findings(self) -> list[dict]:
        """Load findings from findings.json. Returns list of dicts."""
        if not self.findings_path.exists():
            return []
        with open(self.findings_path) as fh:
            return json.load(fh)

    def save_artifact(self, name: str, content: str | bytes) -> Path:
        """Save a raw artifact (e.g., strix-events.jsonl) to the artifacts dir."""
        self.artifacts_path.mkdir(exist_ok=True)
        artifact_file = self.artifacts_path / name
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(artifact_file, mode) as fh:
            fh.write(content)
        return artifact_file

    def append_remediation_log(self, finding_id: str, action: str, result: str, success: bool) -> None:
        """Append a remediation action to the log."""
        log = []
        if self.remediation_log_path.exists():
            with open(self.remediation_log_path) as fh:
                log = json.load(fh)
        log.append({
            "finding_id": finding_id,
            "action": action,
            "result": result,
            "success": success,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        with open(self.remediation_log_path, "w") as fh:
            json.dump(log, fh, indent=2)

    def update_finding_status(self, finding_id: str, status: str) -> None:
        """Update the status of a specific finding."""
        findings = self.load_findings()
        for f in findings:
            if f["id"] == finding_id:
                f["status"] = status
                f["updated_at"] = datetime.now(timezone.utc).isoformat()
                break
        with open(self.findings_path, "w") as fh:
            json.dump(findings, fh, indent=2)

    @classmethod
    def list_runs(cls, output_dir: str) -> list[str]:
        """List all run IDs in the output directory."""
        runs_dir = Path(output_dir) / "runs"
        if not runs_dir.exists():
            return []
        return sorted([d.name for d in runs_dir.iterdir() if d.is_dir()], reverse=True)

    @classmethod
    def latest_run(cls, output_dir: str) -> RunState | None:
        """Get the most recent run."""
        runs = cls.list_runs(output_dir)
        if not runs:
            return None
        return cls(output_dir, runs[0])
