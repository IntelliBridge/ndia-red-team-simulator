"""aegis.export_chains_to_worm — periodic WORM export of audit chains.

Beat-scheduled (see ``celery_app.beat_schedule``) export of every audit
chain to the Object-Lock WORM bucket. The task **self-gates**: when
``AEGIS_WORM_EXPORT`` is not enabled it early-returns ``{"status":
"disabled"}``, so a deployment without WORM configured just no-ops on every
beat tick.

Like the reaper, this is a system-scope periodic task: it loads config,
resolves the audit writer, runs the export, and emits a single
``audit.worm_export`` event recording the (secret-free) summary counts back
onto the audit chain.
"""

from __future__ import annotations

from typing import Any

from aegis.workers.celery_app import app


@app.task(name="aegis.export_chains_to_worm")
def export_chains_to_worm() -> dict[str, Any]:
    """Export all audit chains to the WORM bucket; no-op when disabled."""
    from aegis.audit.chain import resolve_writer
    from aegis.config import load_config
    from aegis.storage.worm import WormArchive, worm_export_enabled

    if not worm_export_enabled():
        return {"status": "disabled"}

    config = load_config()
    writer = resolve_writer(config)
    archive = WormArchive.from_env()
    summary = archive.export_all(writer, verify=True)

    # Record the export on the (system) audit chain. Detail is the summary
    # counts only — no creds, no event contents.
    try:
        writer.append(
            action="audit.worm_export",
            actor="worker:worm_export",
            target=f"s3://{archive.bucket}",
            allowlist_check="n/a",
            override=False,
            success=len(summary.broken_chains) == 0,
            detail=summary.to_dict(),
        )
    except Exception:  # pragma: no cover - audit emit must not fail the export
        pass

    result = summary.to_dict()
    result["status"] = "ok"
    return result
