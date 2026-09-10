"""The worker's audit trail carries the spec 5.11 / 10.5 vocabulary on the run chain.

One ``attack.run`` job runs end to end on the sqlite harness of
``tests/ml/test_tasks.py`` with the JSONL chain writer, so
every row has a real ``prev_hash`` / ``this_hash`` and ``verify_chain`` walks
the campaign trail exactly as ``redsim audit verify --run`` does. Rows are
checked for the emission order, the service actor, the redaction rules (ids,
digests and counts only, never text or a key shape) and the ``success=False``
shape of a refused step.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import pytest

# ``redsim.services.ml_findings`` reaches ``redsim.ml.eval`` (numpy); skip cleanly on the 3.13 lane.
pytest.importorskip("numpy")

from redsim.audit.chain import verify_chain
from redsim.audit.redact import redact_audit_detail
from tests.ml.test_tasks import (
    ATTACK_JOB_ID,
    ATTACK_RUN_ID,
    Harness,
    fixture_record,
)

pytestmark = pytest.mark.integration

ATTACK_ORDER = [
    "model.load",
    "attack.execute.fgsm",
    "attack.execute.pgd",
    "explain.execute",
    "campaign.score",
    "harden.execute",
    "report.render",
    "job.complete",
]
_KEY_SHAPES = (re.compile(r"\bpk_[A-Za-z0-9_-]{8,}"), re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"))


@pytest.fixture
def harness(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(tmp_path, monkeypatch)


def _walk(value: Any) -> list[Any]:
    if isinstance(value, dict):
        return [v for item in value.values() for v in _walk(item)]
    if isinstance(value, list):
        return [v for item in value for v in _walk(item)]
    return [value]


def test_full_chain_carries_5_11_vocabulary(harness: Harness) -> None:
    harness.add_attack_job()
    harness.install_sandbox(fixture_record())

    harness.run_job(ATTACK_JOB_ID)

    events = harness.events(ATTACK_RUN_ID)
    assert [e["action"] for e in events] == ATTACK_ORDER
    assert all(e["chain_id"] == f"run:{ATTACK_RUN_ID}" for e in events)
    assert all(e["run_id"] == ATTACK_RUN_ID and e["project_id"] == "project-1" for e in events)
    # every row is the service actor, correlated with the admitting principal through detail
    assert {e["actor"] for e in events} == {"worker:attack.run"}
    assert all(e["detail"]["requested_by"] == "user:alice" for e in events)
    assert all(e["detail"]["job_id"] == ATTACK_JOB_ID for e in events)
    assert all(e["target"] is None and e["allowlist_check"] == "n/a" for e in events)
    assert all(len(e["action"]) <= 64 for e in events)
    assert all(e["success"] is True for e in events)

    by_action = {e["action"]: e for e in events}
    load = by_action["model.load"]["detail"]
    assert load["target_id"] == "tgt-tiny-fixture" and load["source"] == "bundled"
    assert load["sha256"] == fixture_record().provenance.model_sha256
    attack = by_action["attack.execute.fgsm"]["detail"]
    assert attack["attack_id"] == "fgsm" and attack["eps_grid"] == [0.01, 0.03, 0.1]
    assert attack["reference_eps"] == 0.03 and "params" in attack
    explain = by_action["explain.execute"]["detail"]
    assert explain["n_observations"] == 4 and explain["explain_k"] == 8
    score = by_action["campaign.score"]["detail"]
    assert score["mri"] == 42 and score["grade"] == "D" and score["completeness"] == "complete"
    assert score["settings_hash"] == fixture_record().settings_hash
    assert score["scoring_version"] == "mri-1"
    assert re.fullmatch(r"[0-9a-f]{64}", score["score_sha256"])
    harden = by_action["harden.execute"]["detail"]
    assert harden["n_candidates"] == 3 and harden["rules_fired"] == ["r.R1", "r.R2", "r.R3"]
    assert harden["llm_used"] is False and harden["narrative_source"] == "rules"
    assert harden["skipped_reason"] == "not requested"
    assert harden["prompt_sha256"] is None and harden["completion_sha256"] is None
    report = by_action["report.render"]["detail"]
    # Wave B4 (REVIEW_REPORTS-16): the completion path renders every format, the PDF included when
    # reportlab is importable; when it is not, the row lists the text formats and names the failure.
    if "pdf_unavailable" in report:
        assert report["formats"] == ["md", "json", "html"]
        assert set(report["artifact_ids"]) == {"report.md", "report.json", "report.html"}
    else:
        assert report["formats"] == ["md", "json", "html", "pdf"]
        assert set(report["artifact_ids"]) == {"report.md", "report.json", "report.html", "report.pdf"}
    complete = by_action["job.complete"]["detail"]
    assert complete["job_type"] == "attack.run" and complete["status"] == "succeeded"
    assert complete["n_findings"] == 2 and complete["n_measurements"] == 10
    assert complete["n_artifacts"] >= 10 and complete["completeness"] == "complete"
    assert re.fullmatch(r"[0-9a-f]{64}", complete["envelope_sha256"])
    # the envelope digest is the persisted ml.run_record artifact
    record_rows = [a for a in harness.artifacts(ATTACK_RUN_ID) if a.kind == "ml.run_record"]
    assert record_rows[0].sha256 == complete["envelope_sha256"]

    # the chain verifies, and any mutation breaks it
    assert verify_chain(events).verified is True
    mutated = [dict(e) for e in events]
    mutated[3]["detail"] = {**mutated[3]["detail"], "n_observations": 99}
    broken = verify_chain(mutated)
    assert broken.verified is False and broken.broken_at == 4


def test_refused_steps_are_success_false_rows_that_still_chain(harness: Harness) -> None:
    from redsim.ml.errors import SandboxKilled

    harness.add_attack_job()
    harness.install_sandbox(fixture_record(), stages=["load_target", "sample", "clean_eval", "attack:fgsm"],
                            raise_after=SandboxKilled("ML sandbox child died with signal SIGKILL"))

    with pytest.raises(SandboxKilled):
        harness.run_job(ATTACK_JOB_ID)

    events = harness.events(ATTACK_RUN_ID)
    actions = [e["action"] for e in events]
    # live rows the parent emitted as the child progressed (pgd never ran, so it has no row), then
    # the failed completion
    assert actions == ["model.load", "attack.execute.fgsm", "job.complete"]
    assert [e["success"] for e in events] == [True, True, False]
    complete = events[-1]
    assert complete["actor"] == "worker:attack.run"
    assert complete["detail"]["error_class"] == "SandboxKilled"
    assert complete["detail"]["status"] == "failed" and complete["detail"]["completeness"] == "partial"
    assert complete["detail"]["stages_done"] == ["load_target", "sample", "clean_eval", "attack:fgsm"]
    assert verify_chain(events).verified is True


def test_not_run_attack_is_a_refused_attack_execute_row(harness: Harness) -> None:
    from redsim.ml.schema import Interpretation

    record = fixture_record()
    # The child recorded pgd not_run (spec 9.5): no attack:pgd stage, an interpretation with the reason.
    not_run = Interpretation(
        id="i.attack.not_run.pgd",
        statement="Attack 'pgd' was not run against this target (no loss gradients); recorded as not_run.",
        basis=["m.clean"],
    )
    child = record.model_copy(update={
        "interpretation": [*record.interpretation, not_run],
        "stages_done": [s for s in record.stages_done if s != "attack:pgd"],
    })
    harness.add_attack_job()
    harness.install_sandbox(child, stages=list(child.stages_done))

    harness.run_job(ATTACK_JOB_ID)

    events = harness.events(ATTACK_RUN_ID)
    pgd_rows = [e for e in events if e["action"] == "attack.execute.pgd"]
    assert len(pgd_rows) == 1, "exactly one row per declared attack"
    assert pgd_rows[0]["success"] is False
    assert "not_run" in pgd_rows[0]["detail"] and "no loss gradients" in pgd_rows[0]["detail"]["not_run"]
    fgsm_rows = [e for e in events if e["action"] == "attack.execute.fgsm"]
    assert len(fgsm_rows) == 1 and fgsm_rows[0]["success"] is True
    assert verify_chain(events).verified is True


def test_audit_detail_carries_digests_and_ids_never_text_or_keys(harness: Harness, monkeypatch: pytest.MonkeyPatch,
                                                                ) -> None:
    """The row shape stays redaction-safe: no key shapes, no prompt text, and the writer redacts."""
    harness.add_attack_job()
    harness.install_sandbox(fixture_record())
    monkeypatch.setenv("PYTHIA_API_KEY", "pk_live_never_in_an_audit_row_0123456789")

    harness.run_job(ATTACK_JOB_ID)

    events = harness.events(ATTACK_RUN_ID)
    serialized = json.dumps(events)
    assert "pk_live_never" not in serialized
    for pattern in _KEY_SHAPES:
        assert not pattern.search(serialized)
    for event in events:
        for leaf in _walk(event["detail"]):
            if isinstance(leaf, str):
                assert len(leaf) <= 512, "audit detail carries ids, digests and short reasons only"
                assert "\n" not in leaf or event["action"] == "attack.execute.pgd"
        # no key of a secret-bearing name survives the writer's redaction
        assert redact_audit_detail(event["detail"]) == event["detail"]
    # the writer itself scrubs a credential-shaped value that reaches it
    scrubbed = redact_audit_detail({"note": "token " + "AKIA" + "ABCDEFGHIJKLMNOP", "api_key": "x"})
    assert scrubbed == {"note": "token <REDACTED>", "api_key": "<REDACTED>"}
    # every digest in the trail is a sha256 hex string that names a real artifact or the envelope
    digests = {
        leaf for e in events for leaf in _walk(e["detail"])
        if isinstance(leaf, str) and re.fullmatch(r"[0-9a-f]{64}", leaf)
    }
    artifact_digests = {a.sha256 for a in harness.artifacts(ATTACK_RUN_ID)}
    model_sha = fixture_record().provenance.model_sha256
    unexplained = digests - artifact_digests - {model_sha}
    # observation artifact digests come from the fixture record (synthetic evidence), everything else
    # the parent computed itself
    fixture_obs = {d for o in fixture_record().observations for d in o.artifact_sha256.values()}
    assert unexplained <= fixture_obs
    assert hashlib.sha256(b"").hexdigest() not in digests
