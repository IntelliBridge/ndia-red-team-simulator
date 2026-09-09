# Brief 13 handoff: unfinished and delegated work

Snapshot: 2026-09-09. Owner/requester: William. Source of acceptance criteria:
[brief 13](13-llm-live-gateway-brief.md).

Package L is implemented, but PRs #31–#35 are still open. Runtime enablement
and real-gateway acceptance are **not complete**. No live Pythia requests,
runtime Terraform applies, probe-secret provisioning, or deployment of these
changes were performed during this brief-13 implementation work.

William delegated Pythia verification to another person and excluded D1–D4
from this implementation assignment. Those items remain open for their next
owners; they are not waived acceptance criteria. This handoff was explicitly
requested separately. Owner roles below are proposed routing, not confirmed
individual assignments.

## Requirement ledger

| Item | State and evidence | Remaining action / next owner |
| --- | --- | --- |
| L1: bounded retries | Implemented in [PR #31](https://github.com/IntelliBridge/ndia-red-team-simulator/pull/31), `ea4136f`; fake-gateway regression passed. | Maintainer: review, rebase, rerun checks, merge. Live confirmation belongs to A3. |
| L2: gateway/persona capacity | Implemented in [PR #34](https://github.com/IntelliBridge/ndia-red-team-simulator/pull/34), `4d1d90d`; SQLite and real Postgres concurrency tests passed. | Maintainer: merge and deploy; operator: verify surplus deferral live. |
| L3: blocked prompts | Implemented in [PR #32](https://github.com/IntelliBridge/ndia-red-team-simulator/pull/32), `4465a43`; fake gateway verifies blocked counts and evaluated denominators. | Maintainer: merge; Pythia verifier: conditional A3 test on an operator-approved test persona. |
| L4: unavailable provider | Implemented in [PR #33](https://github.com/IntelliBridge/ndia-red-team-simulator/pull/33), `1d20208`; typed failure propagated to persisted results and audit. | Maintainer: merge; verifier: confirm live behavior. Implementation uses the brief's first-request abort option: one request for an immediately unavailable run, zero retries, remaining rows `not_run`. Do not expect five requests for five prompts in this path. |
| L5: fake gateway | Merged in PR #28. | No implementation work outstanding. Retain regression coverage when rebasing. |
| L6: behavior documentation | Retry/capacity contract and blocked-output limitations updated in the L stack; strict MkDocs passed. | Merge with L PRs. This completed work does not close D1–D4. |
| R1: worker image | [PR #35](https://github.com/IntelliBridge/ndia-red-team-simulator/pull/35), `15cc590`, adds `.[worker,ml,garak]` after CPU torch and image import/help checks. | Build/release owner: finish the image build, record passing image checks, publish and pin its digest, coordinate brief-10 A3 verification. No new image has been deployed. |
| R2: runtime environment | **Not implemented.** Runtime common environment still disables LLM for all services. | Runtime implementer: default-only enablement, secret references, shared profiles key, gateway admission allowlist, tests and reviewed plan; operator: apply and roll out. Details below. |
| R3: runtime probe profile | **Partial local draft**, not committed or in a PR: `redsim/ml/llm/seed_profile.py`. Reads Secrets Manager in memory or stdin; uses the audited AuthProfile service and refuses an existing mismatched key. | Implementer: finish review/validation, commit and open PR, add narrowly scoped secret-read IAM for the seed task. Operator: create the real profile, rerun to prove idempotence and list it without secret material. Pythia owner: resolve LLM-26 persona/key. Documentation owner: record profile ID and persona status. |
| R4: VPC egress check | **Not performed; delegated.** Existing foundation supports approved destination CIDRs for default-worker HTTPS egress, but the VPC has no NAT route. | Runtime/network owner: supply an approved route and destination rules. Pythia verifier: perform the one-shot entitlement check from the actual default-pool network configuration and retain sanitized evidence. |
| R5: Compose parity | **Partial local draft**, not committed or in a PR: Compose environment split, shared profiles-key wiring, `scripts/probe_key_profile.py`, Make target and tests. | Implementer: finish and publish code, resolve allowlist configuration, coordinate Helm parity with brief-10 A10. Compose owner: run the stack and seed twice; real Compose acceptance remains unverified. |
| A1: real gateway on Compose | **Not run; delegated.** | Pythia verifier/Compose owner: registration, bounded probe, scorecard/artifacts/audit/usage checks and Phase B gate. |
| A2: real gateway on Fargate | **Not run; delegated.** | Pythia verifier/runtime owner: same evidence through `https://redsim.ndia.agiledefense.xyz` after deployment prerequisites. |
| A3: live behavior checks | **Not run; delegated.** | Pythia verifier: provider-unavailable behavior, capacity deferral and, only if a test persona is available, blocked-output behavior. Recheck current entitlement/provider state first. |
| D1: Pythia observations/runbook | **Deferred to documentation owner.** L6 text exists, but D1 has not been accepted as complete. | Reconcile dated observations/catalog, persona and guardrail changes, report links and R3 status with actual evidence. |
| D2: runtime deployment sequence | **Deferred to documentation owner.** | Document variables, image, profile seed, profile ID, egress and acceptance sequence after implementation and operator verification. |
| D3: top-level status parity | **Deferred to documentation owner.** | Update README, CLAUDE and architecture status consistently. Keep live acceptance open until evidence exists. |
| D4: brief-10 cross-reference | **Deferred to documentation owner.** | Add the brief-13 reference and touched-file list in brief 10. |

## Integration and release work still required

The PRs are stacked, with each based on the preceding feature branch:

1. #31 — retry handling, base `main`.
2. #32 — blocked prompts, base `feat/brief13-retries`.
3. #33 — provider failures, base `feat/brief13-blocked-prompts`.
4. #34 — capacity, base `feat/brief13-provider-unavailable`.
5. #35 — worker image, base `feat/brief13-gateway-capacity`.
6. Publish the local R3/R5 work from `feat/brief13-probe-profile` after review.
7. Implement/publish R2 and any required routing/IAM changes.

After each squash merge, rebase the next branch's own changes onto updated
`main`, retarget its PR, inspect the diff for duplicated ancestors and rerun
checks. Prior branch-local passing checks are not evidence that the eventual
rebased merge commit passes CI. No final integrated CI acceptance is recorded
here. Coordinate shared Dockerfile, Compose, Helm and runtime files with the
brief-10 owner. No messages to other owners have been sent on William's behalf.

The R1 local `linux/amd64` build was still installing dependencies at this
snapshot. Its first attempt failed certificate verification; existing local
system CA certificates were exported into ignored `deploy/certs/` for the
retry. TLS verification was retained. Build log:
`/tmp/redsim-brief13-worker-build.log` (local, not committed). The build context
predates the local R3/R5 changes, so even a successful result needs rebuilding
to include the seed module. Record the final image digest and run:

```sh
docker run --rm --entrypoint python <worker-image-at-digest> -c 'import garak, redsim.ml.llm.probe_child'
docker run --rm --entrypoint python <worker-image-at-digest> -m redsim.ml.llm.probe_child --help
```

## Runtime and credential prerequisites

- Implement default-worker-only removal of `REDSIM_DISABLE_LLM`; keep it `1`
  for API, scans and beat. Wire the narrative writer's Pythia settings only
  into the default pool. The probe credential must instead reach the product
  through an encrypted bearer AuthProfile.
- Ensure API and the profile-seeding/probe tasks use the same
  `REDSIM_AUTH_PROFILES_KEY` via Secrets Manager references. Verify rotation
  compatibility with existing encrypted profiles before changing that key.
- Configure the gateway host in the application's target allowlist. The local
  Compose draft names `REDSIM_TARGET_ALLOWLIST`, but `redsim/config.py` does
  **not currently parse this environment variable**. Implement and test a
  validated override or use the supported YAML configuration; setting the
  draft variable alone does not enable gateway admission.
- Keep gateway capacity consistent across admission and dispatch processes;
  default is two children per host/persona. Preserve validated transport
  overrides from L1 in the deployed default worker.
- Foundation `deploy/terraform/network.tf` permits default-worker TCP 443 to
  configured `pythia_ipv4_cidrs`; an empty set permits none. A security-group
  rule alone does not supply routing. Arrange NAT or an approved private
  gateway route, check DNS/TLS from the task and record the actual change.
  No NAT implementation or apply was performed in this assignment.
- Give the one-off seed task's **application role** access to the specific
  probe secret, and KMS decrypt if its key requires it. Merely giving the ECS
  execution role secret-injection permissions does not authorize the module's
  SDK call. Do not inject the probe key into task environment or Terraform.
- Seed the project before its profile and target. PR #29 did not establish
  that a project row or LLM target had been seeded; verify these explicitly.
- The intended seed invocation inside an appropriately configured task is:
  `python -m redsim.ml.llm.seed_profile --project <project-id> --secret-arn <secret-arn> --name pythia-probe`.
  The JSON field defaults to `api_key`; use `--secret-field` if needed. Only
  the profile ID should be emitted. Run it twice and confirm the same ID and
  no duplicate row. A changed existing key is deliberately rejected.
- `deploy/runtime/scripts/run_task.py --command` can override the assets
  container command, but currently selects only `migration` or `assets`.
  It does **not** perform R4 from the default worker's security group. Configure
  a suitable default-pool one-off invocation for that check; an assets-task
  result is insufficient evidence of default-pool egress.
- Obtain a permission-gate-only probe persona/key from the Pythia operators
  (LLM-26). The brief records a historical fallback to `default` with filtering
  disabled by the owner; current settings have not been verified. Never infer
  today's guardrail state from that historical observation.
- Finish brief-10 E4 deployment integration: publish/pin image digests, run
  required migrations, then roll out the new task definitions. A forced
  deployment of an old pinned digest does not deploy these changes. Recheck
  CI deployment variables, including `ECS_CLUSTER`, with the runtime owner.
- Add Terraform assertions and inspect a plan for the intended environment,
  secret references, IAM and network changes before applying. No passing
  brief-13 R2 Terraform test or plan is recorded yet.

The last runtime inspection showed six services desired/running at one each,
and the default task still had `REDSIM_DISABLE_LLM=1` without Pythia settings.
Service health is not LLM acceptance evidence. Preserve the public HTTPS demo
ingress requested by William; gateway egress work does not require restricting
demo access to William's IP.

## Compose and offline validation handoff

Finish/review these local draft files together before committing:

- `redsim/ml/llm/seed_profile.py`
- `scripts/probe_key_profile.py`
- `tests/ml/test_probe_profile_seed.py`
- `deploy/docker-compose.yml`
- `Makefile`

The helper passes the operator-shell probe key over stdin, removes probe and
Pythia keys from its Docker CLI child environment, and never puts the key in
argv. Configure the shared profiles encryption key and project first. After
the R1 image and remaining configuration are available, the Compose owner
should run `make up`, `make seed`, then `make probe-key-profile` twice with
`REDSIM_PROBE_PROJECT` set to the intended project. Supply credentials through
the approved operator environment, never a command containing a literal key.
Verify that only the default worker receives the narrative Pythia credential.
The four local seed/profile/Compose-structure tests passed after correcting
the ciphertext assertion to compare bytes. The actual Compose sequence and
Helm parity have not been verified.

Recorded L-stack validation, before final rebases: 25 garak-tier tests;
7 gateway-capacity tests; 2 real-Postgres tests using a non-superuser role;
79 affected LLM/batch regression tests; 30 capacity/API-isolation tests.
These selections overlap and must not be summed into a unique test count.
Ruff, mypy (254 source files at L2) and strict MkDocs passed. This is not a
claim that the entire repository test suite or real-gateway acceptance passed.

Useful final validation commands after integrating the remaining code:

```sh
.venv/bin/python -m pytest -q -p no:cacheprovider -m garak tests
.venv/bin/python -m pytest -q tests/ml/test_probe_profile_seed.py
.venv/bin/ruff check --select E4,E7,E9,F,I redsim tests scripts/probe_key_profile.py
.venv/bin/mypy redsim
.venv/bin/mkdocs build --strict
```

## Live acceptance handoff and evidence to retain

At this snapshot, `scripts/phase_b_gate.sh` and `tests/e2e/test_ml_llm.py`
were absent from the checked-out tree. Coordinate their delivery with the B4
owner before claiming `make check-phase-b` acceptance; do not silently replace
the required gate with the classifier smoke. PR #29's asset bundle covered
vehicles, not the missing `url_trees` bundle, and its asset-doctor check had a
reported Docker-related limitation. Brief-10/B4 owners should reconcile these
dependencies with the gate's actual requirements.

For A1 and A2, the verifier should:

1. Confirm current model entitlement, persona and guardrail mode. Register an
   entitled chat target using the seeded AuthProfile, with appropriate admin
   authorization; execute using remediator or above.
2. Keep traffic at no more than two children, one or two probe IDs and
   `max_prompts_per_probe: 5`, using the offline detector.
3. Fetch the scorecard and verify evaluated `k/n`, blocked counts if relevant,
   and absence of MRI. Verify all five expected `ml.llm.*` artifact kinds and
   their digests, the rendered report, both API and CLI audit verification,
   and one `LLMUsage(task="ml.llm_probe")` row.
4. Run the delivered Phase B gate with `REDSIM_API_URL` pointing to Compose,
   then separately to `https://redsim.ndia.agiledefense.xyz` for A2. Coordinate
   any required target/profile ID inputs with B4.
5. For A3, recheck an unavailable provider before testing it, demonstrate
   surplus capacity deferral, and test filtering only on an approved persona.
   Do not change shared persona guardrails merely to produce a test result.

Retain environment/date, deployed commit and image digest, task revision,
project/profile/target/run IDs, per-probe counts and typed error codes,
artifact kinds/digests, audit verification, usage-row count and gate result.
Do not copy keys, prompts or completions into logs, this document or PRs.
No real profile IDs, target IDs or acceptance run IDs exist from this work.
Do not claim this was the runtime's first campaign without checking its
history; another owner may run one before A2.

Documentation owner: use that evidence to close D1–D4 and update this ledger.
Until then, real-gateway acceptance remains open on both Compose and Fargate.
