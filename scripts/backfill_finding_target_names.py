"""Replace a blob location or URL in ``schema_blob.target`` with the model's registered name.

    redsim-run api python scripts/backfill_finding_target_names.py [--dry-run]

Findings projected before ``finding_target_label`` existed carry the target
row's raw ``value`` as the model name. For an uploaded model that is the S3
location of the weights and for an endpoint it is the URL. This walks every
finding whose ``target`` equals its target row's ``value`` and rewrites it to
the label the projection now writes (``redsim.services.ml_findings.
finding_target_label``). Bundled findings keep ``bundled:<id>`` and are left
alone, and so is a finding whose target row recorded no name.
"""
from __future__ import annotations

import os
import sys

from sqlalchemy.orm.attributes import flag_modified

from redsim.db.models import Finding, Run, Target
from redsim.db.session import get_session, init_engine
from redsim.services.ml_findings import finding_target_label


def main(argv: list[str]) -> int:
    dry = "--dry-run" in argv
    init_engine(os.environ["REDSIM_DB_URL"])
    changed = skipped = 0
    with get_session() as session:
        for finding in session.query(Finding).all():
            blob = dict(finding.schema_blob or {})
            current = blob.get("target")
            run = session.get(Run, finding.run_id)
            target = session.get(Target, run.target_id) if run is not None and run.target_id else None
            label = finding_target_label(target)
            if target is None or not isinstance(current, str) or current != str(target.value) or label == current:
                skipped += 1
                continue
            blob["target"] = label
            if not dry:
                finding.schema_blob = blob
                flag_modified(finding, "schema_blob")
            changed += 1
            print(f"{finding.id}: {current} -> {label}")
        if dry:
            session.rollback()
    print(f"findings updated: {changed}, left as they were: {skipped}{' (dry run)' if dry else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
