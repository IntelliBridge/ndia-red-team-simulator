"""INTEROP-26: the Foundry push against a real, non-operational Foundry instance.

Skips unless the operator points it at a stack:

* ``REDSIM_FOUNDRY_LIVE_URL``: ``https://<stack host>`` (no path).
* ``REDSIM_FOUNDRY_LIVE_RID``: the target dataset rid (``ri.foundry.main.dataset.<uuid>``).
* ``REDSIM_FOUNDRY_LIVE_TOKEN_FILE``: a file holding the bearer token. The
  token is read once, handed to ``POST /v1/auth-profiles`` and never printed.

The rest is the shared e2e harness: a real campaign on the bundled tabular
target in the sandbox child, the admin's push through the API admission, the
eager worker's push through ``FoundryClient``, then a read-back of the two
files through the Datasets v2 API so the transaction is proven committed.
Nothing here is a product claim: the stack is the operator's test instance.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from tests.e2e import harness as h
from tests.e2e.harness import E2EApp, E2EOrg

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

LIVE_URL_ENV = "REDSIM_FOUNDRY_LIVE_URL"
LIVE_RID_ENV = "REDSIM_FOUNDRY_LIVE_RID"
LIVE_TOKEN_FILE_ENV = "REDSIM_FOUNDRY_LIVE_TOKEN_FILE"


def _live() -> tuple[str, str, str]:
    url, rid, token_file = (os.environ.get(k, "").strip() for k in (LIVE_URL_ENV, LIVE_RID_ENV, LIVE_TOKEN_FILE_ENV))
    if not (url and rid and token_file):
        pytest.skip(f"set {LIVE_URL_ENV}, {LIVE_RID_ENV} and {LIVE_TOKEN_FILE_ENV} to run the live Foundry lane")
    token = Path(token_file).read_text(encoding="utf-8").strip()
    if not token:
        pytest.skip(f"{LIVE_TOKEN_FILE_ENV} is empty")
    return url, rid, token


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_live_foundry_push_commits_the_scorecard(
    e2e_app: E2EApp, e2e_org: E2EOrg, e2e_bundled: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from urllib.parse import quote, urlsplit

    import httpx
    from cryptography.fernet import Fernet

    from redsim.integrations import ADMISSION_ACTION, EXECUTE_ACTION, PUSH_RUN_KIND
    from redsim.integrations.foundry import (
        FOUNDRY_ATTESTATION_ENV,
        FOUNDRY_DATASET_RID_ENV,
        FOUNDRY_URL_ENV,
        validate_push_payload,
    )
    from redsim.llm.pythia import tls_verify
    from redsim.workers.tasks.integration_push import STAGES

    url, rid, token = _live()
    host = urlsplit(url).hostname or ""
    assert host, url

    # -- a real campaign on the bundled tabular target -------------------------------------------------------
    scanner, admin, viewer = e2e_org.client("scanner"), e2e_org.client("admin"), e2e_org.client("viewer")
    model_id = e2e_bundled[h.TABULAR_MODEL_ID]
    campaign = h.run_campaign_via_api(scanner, model_id, h.tabular_campaign(), timeout_s=600.0)
    run_id = campaign.run_id
    assert campaign.run["status"] == "succeeded", campaign.run.get("stage_table")
    assert campaign.campaign is not None

    # -- configure the integration the way a deployment does: process environment plus the allowlist ---------
    monkeypatch.setenv("REDSIM_AUTH_PROFILES_KEY", Fernet.generate_key().decode("ascii"))
    monkeypatch.setenv(FOUNDRY_URL_ENV, url)
    monkeypatch.setenv(FOUNDRY_ATTESTATION_ENV, "1")
    monkeypatch.setenv(FOUNDRY_DATASET_RID_ENV, rid)
    monkeypatch.setenv("REDSIM_TARGET_ALLOWLIST", f"127.0.0.1,localhost,{host}")
    roster = viewer.get("/v1/integrations").json()["integrations"]["foundry"]
    assert roster["status"] == "configured", roster
    assert host not in json.dumps(roster) and token not in json.dumps(roster)

    profile = admin.post("/v1/auth-profiles", json={
        "project_id": e2e_org.project_id, "name": "foundry-live", "kind": "bearer",
        "config": {"platform": "foundry"}, "secret": token,
    })
    assert profile.status_code == 201, profile.text
    assert token not in profile.text
    profile_id = str(profile.json()["id"])

    # -- the push ---------------------------------------------------------------------------------------------
    pushed = admin.post(f"/v1/runs/{run_id}/integrations/foundry",
                        json={"auth_profile_id": profile_id, "target_ref": rid, "payload": "scorecard"})
    assert pushed.status_code == 202, pushed.text
    handle = pushed.json()
    push_run_id = str(handle["run_id"])
    assert handle["campaign_run_id"] == run_id and handle["target_ref"] == rid and handle["kind"] == PUSH_RUN_KIND
    push_run = h.wait_for_run(admin, push_run_id, timeout_s=120.0)
    chain = e2e_app.read_chain(f"run:{push_run_id}")
    assert push_run["status"] == "succeeded", (push_run.get("stage_table"), [ev["detail"] for ev in chain])
    assert push_run["stage_table"]["stages_done"] == list(STAGES)

    admission, execute, complete = chain
    assert [ev["action"] for ev in chain] == [ADMISSION_ACTION, EXECUTE_ACTION, "job.complete"]
    assert admission["detail"]["host"] == host and admission["detail"]["target_ref"] == rid
    assert execute["success"] is True and execute["detail"]["outcome"] == "pushed"
    assert execute["detail"]["dataset_rid"] == rid and execute["detail"]["n_files"] == 2
    transaction_rid = execute["detail"]["transaction_rid"]
    assert transaction_rid.startswith("ri.foundry.main.transaction.")
    chain_text = json.dumps(chain, default=str)
    assert token not in chain_text and url not in chain_text

    # -- read back from Foundry: both files sit in the committed transaction with the recorded digests --------
    verify, _mode = tls_verify()
    with httpx.Client(base_url=url, verify=verify, timeout=60,
                      headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}) as foundry:
        txn = foundry.get(f"/api/v2/datasets/{quote(rid, safe='')}/transactions/{quote(transaction_rid, safe='')}")
        assert txn.status_code == 200, txn.status_code
        assert txn.json()["status"] == "COMMITTED", txn.json()
        prefix = f"redsim/scorecards/{run_id}"
        digests = {"scorecard.json": execute["detail"]["payload_sha256"], "rows.jsonl": execute["detail"]["rows_sha256"]}
        for name, expected in digests.items():
            content = foundry.get(f"/api/v2/datasets/{quote(rid, safe='')}/files/{quote(f'{prefix}/{name}', safe='')}/content",
                                  params={"endTransactionRid": transaction_rid})
            assert content.status_code == 200, (name, content.status_code)
            assert _sha256(content.content) == expected, name
            if name == "scorecard.json":
                payload: dict[str, Any] = json.loads(content.content)
                assert validate_push_payload(payload) == []
                assert payload["run_id"] == run_id
                assert payload["settings_hash"] == campaign.campaign["settings_hash"]
    print(f"\nLIVE FOUNDRY PUSH: host={host} transaction={transaction_rid} files={prefix}/{{scorecard.json,rows.jsonl}}")
