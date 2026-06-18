"""Adapter to convert Strix vulnerability findings to AegisFinding objects."""

from __future__ import annotations

from datetime import datetime, timezone

from aegis.schema import AegisFinding, CodeLocation


def convert_strix_finding(raw: dict, run_id: str) -> AegisFinding:
    """Convert a single Strix finding dict to an AegisFinding."""
    # Map code_locations dicts to CodeLocation objects
    code_locs = None
    if raw.get("code_locations"):
        code_locs = [CodeLocation.from_dict(loc) for loc in raw["code_locations"]]

    # Determine affected_component: prefer endpoint, fall back to target
    affected = raw.get("endpoint") or raw.get("target") or "unknown"

    # Parse timestamp or use now
    ts = raw.get("timestamp")
    if ts:
        # Strix format: "2026-05-27 10:30:00 UTC" -> ISO 8601
        try:
            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S %Z")
            iso_ts = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            iso_ts = datetime.now(timezone.utc).isoformat()
    else:
        iso_ts = datetime.now(timezone.utc).isoformat()

    return AegisFinding(
        id=raw["id"],
        title=raw["title"],
        severity=raw.get("severity", "medium").lower(),
        finding_type="dast",  # Strix is a DAST tool
        description=raw.get("description", ""),
        source_tool="strix",
        source_run_id=run_id,
        affected_component=affected,
        confidence="high",  # Strix validates with PoC
        status="open",
        created_at=iso_ts,
        updated_at=iso_ts,
        cvss=raw.get("cvss"),
        cve=raw.get("cve"),
        cwe=raw.get("cwe"),
        target=raw.get("target"),
        endpoint=raw.get("endpoint"),
        method=raw.get("method"),
        code_locations=code_locs,
        poc_script_code=raw.get("poc_script_code"),
        remediation_steps=raw.get("remediation_steps"),
        references=[],
        impact=raw.get("impact"),
        technical_analysis=raw.get("technical_analysis"),
        poc_description=raw.get("poc_description"),
        timestamp=raw.get("timestamp"),
        cvss_breakdown=raw.get("cvss_breakdown"),
    )


def convert_strix_findings(findings: list[dict], run_id: str) -> list[AegisFinding]:
    """Convert a list of Strix findings to AegisFindings."""
    return [convert_strix_finding(f, run_id) for f in findings]


def load_strix_events(events_jsonl_path: str, run_id: str) -> list[AegisFinding]:
    """Load findings from a Strix events.jsonl file."""
    import json
    from pathlib import Path

    findings = []
    path = Path(events_jsonl_path)
    if not path.exists():
        return []

    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            # Strix emits findings as:
            #   {"event_type": "finding.created", "payload": {"report": {...}}}
            # Keep support for older/fixture shapes that may use "data" or a raw payload.
            if event.get("event_type") != "finding.created":
                continue

            raw_finding = None
            payload = event.get("payload")
            if isinstance(payload, dict):
                raw_finding = payload.get("report") or payload
            if raw_finding is None and isinstance(event.get("data"), dict):
                raw_finding = event["data"]

            if isinstance(raw_finding, dict) and "id" in raw_finding and "title" in raw_finding:
                findings.append(convert_strix_finding(raw_finding, run_id))
    return findings
