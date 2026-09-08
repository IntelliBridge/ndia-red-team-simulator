# F001 — Project Access

## Reconciliation with the product spec (2026-09-08)

This feature is the feature-level layer beneath the canonical product spec, [docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md](../../docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md), which overrides the stack assumptions in this file wherever they conflict. Under decisions D1 (reuse the full redsim platform) and D10 (feature map), F001 "Project access" maps onto redsim components already present at the restored redsim head rather than onto new code: managed identity is Keycloak OIDC through NextAuth (`web/src/server/auth-options.ts`, `web/src/app/api/auth/[...nextauth]/route.ts`; realm in `deploy/keycloak/realm-export.json`), with an Redsim-signed API session cookie for browsers (`redsim/api/session_cookie.py`) and a JWKS-verified bearer JWT for CLI/CI (`redsim/api/auth.py`); membership travels in the IdP token claim `redsim_project_roles` (`{project_id: role}`) into `CurrentUser.project_memberships`, is mirrored in the `users` and `project_memberships` tables (`redsim/db/models.py`), and is exposed by `GET /v1/projects` and `GET /v1/projects/{slug}/membership` (`redsim/api/v1/projects.py`); server-side authorization is `ensure_project_access` (read: any membership) and `check(user, Action, project_id)` (write: role rank) in `redsim/api/policy.py`, delegated to the static/OPA/Cedar engine in `redsim/policy/engine.py`; tenant isolation is Postgres row-level security by `org_id` (migrations `0006_tenant_rls` and `0009_tenant_org_id_guard`; GUC set by `redsim/api/middleware/tenant.py` and `redsim/db/session.py`); accountable history is the hash-chained audit log (`redsim/audit/chain.py`, append-only since migration `0004_audit_append_only`). Decision D002 is RESOLVED by the product owner on 2026-09-08 as "redsim Keycloak OIDC + NextAuth, dev-token mode allowed for the demo" (recorded in [../_shared/decisions.md](../_shared/decisions.md) in its resolution format); D007 (named owner and reviewers) stays OPEN, so the Owner line below remains "Unassigned". Against John's milestones (S1 section 14), F001 is a prerequisite the platform already supplies rather than a milestone of its own: M0 (scaffold) adds the ML mutating actions to `Action`/`_ACTION_MIN_ROLE` and the rank-0 `viewer` role described under FR-003; M5 (UI) reuses `useRoles`/`RoleGated` gating on the new `/models` and findings screens; M7 (deploy) runs Keycloak on Fargate or dev mode, as S1 section 12 allows. F001 is not on the D8 demo-critical order inside Phase A; every row marked "deferred to Phase B" below is in-app membership or invitation management, which the demo performs in the Keycloak admin console instead. The redsim mechanisms are documented in [docs/architecture/auth.md](../../docs/architecture/auth.md) and [docs/architecture/multi-tenancy.md](../../docs/architecture/multi-tenancy.md). A concurrent code fix-up is making the restored platform import-clean; nothing in this section claims the ML vertical itself is implemented.

**Role mapping used in the table** (the product spec's access-matrix section is authoritative where it differs): Owner → `admin` (rank 4); Reviewer → `approver` (rank 3); Analyst → `remediator` (rank 2); Viewer → `scanner` (rank 1) in Phase A, per the shared baseline in `specs/_shared/architecture.md`: redsim has no read-only role, read access is granted to any active membership, and campaign start is registered at `remediator` (`Action.ATTACK_RUN`, `attack.run`) so that `scanner` stays read-mostly in the ML vertical, though it can still start a legacy `scan.start` scan; a strict rank-0 `viewer` role is a Phase B policy change. redsim ranks are linear (a higher rank holds every lower rank's permissions), so the shared matrix cells "Reviewer: No" for registering catalog entries, starting evaluations, and drafting findings become "Yes" under redsim; the "except own authored item" independent-approval rule is enforced by F006's author-is-not-approver check, not by rank.

| Requirement | Status after consolidation | Note |
| --- | --- | --- |
| US1 | amended | Project entry and per-role action visibility are the existing redsim flow: `/login` → Keycloak → `/projects` listing only member projects (`GET /v1/projects`), `useRoles`/`RoleGated` hiding controls, and `check()`/`ensure_project_access` denying server-side (covered by `tests/test_project_access_read.py`, `tests/test_projects_api.py`). The "suspended membership" scenario has no Phase A state (see FR-006): in Phase A a membership is present or absent. The Viewer scenario is exercised with a `scanner` membership (FR-003): evidence is readable and the management controls (`target.manage`, `attack.run`, `run.cancel`, `verify.replay`) are hidden by `RoleGated` and denied by `check()`; the residual gap is that `scanner` can start a legacy scan, which the ML pages do not offer. "Authentication unavailable" is redsim's existing behavior when Keycloak/JWKS is unreachable or `REDSIM_OIDC_JWKS_URL` is unset: the request fails (401/500) and no access is granted. |
| US2 | deferred to Phase B | redsim exposes no in-app role or status mutation endpoint, and `project_memberships` has no status or revision column. In Phase A, role changes are made in the Keycloak admin console (the `redsim_project_roles` claim); the last-owner boundary and stale-update handling arrive with the Phase B membership editor. |
| US3 | deferred to Phase B | redsim has no Invitation entity, delivery-acknowledgement contract, or acceptance route. Phase A onboarding is Keycloak-side: an administrator creates the user and assigns project roles, and the user signs in through the existing code flow. The roster view exists today at `/projects/[slug]/settings` and is readable by any member of the project. |
| FR-001 | amended | Managed identity is Keycloak OIDC; no custom passwords exist. Two bounded exceptions to "no locally minted tokens" are recorded: (1) dev-token mode, `Authorization: Bearer dev:<email>` when `REDSIM_AUTH_MODE=dev`, rejected outright when `REDSIM_ENV=prod`, permitted for the hackathon demo by D002/D11; (2) the Redsim-signed RS256 API session cookie minted by the NextAuth callback after a successful Keycloak login, and the HMAC worker service-account tokens, both session artifacts derived from an IdP login or a deploy-time signing key rather than passwords or invitation credentials. |
| FR-002 | amended | Enforcement is named: `ensure_project_access`/`accessible_project_ids` for reads, `check()` for mutations, and org-level Postgres RLS as defense in depth. The invitation-acceptance exception clause is inert in Phase A because acceptance (FR-015) is deferred. The ML mutating actions (register model, start attack campaign, explain, harden, verify; Job types `attack.run`, `explain.run`, `harden.recommend`, `verify.replay`) require entries in `Action`/`_ACTION_MIN_ROLE` at M0; `VERIFY_REPLAY` and `TARGET_MANAGE` already exist. |
| FR-003 | amended | Roles are the redsim rank roles per the mapping above. Two departures from the shared matrix: linear rank gives Reviewer (`approver`) every Analyst (`remediator`) permission; and Viewer maps onto `scanner` in Phase A (the baseline mapping), which is read-mostly rather than read-only because `scan.start` sits at rank 1. A strict rank-0 `viewer` entry in `_ROLE_RANK` (`redsim/api/policy.py`), in the realm roles of `deploy/keycloak/realm-export.json`, and in any OPA/Cedar policy in use is a Phase B policy change; until then the ML vertical registers its own mutating actions (`attack.run`, `explain.run`, `harden.recommend`) at `remediator` so a `scanner` member cannot start a campaign. |
| FR-004 | superseded | The repository is no longer on Replit; it is the GitHub fork IntelliBridge/ndia-red-team-simulator. The rule survives in general form: repository collaboration and the existence of a Keycloak realm user neither create nor imply project membership; only an `redsim_project_roles` entry (or `project_memberships` row) does. |
| FR-005 | amended | Roster read is any-member in redsim (`GET /v1/projects/{slug}/membership`), not Owner-only; the product spec keeps redsim behavior. Role/status changes are Keycloak-side in Phase A, so their record is Keycloak's admin event log; any Phase B in-app mutation must append to the redsim audit chain (`AuditWriter.append`) before commit. The "F008 event envelope" is the redsim `AuditEvent` (actor, action, target, success, detail, project_id, run_id, ts, seq, prev_hash/this_hash). |
| FR-006 | deferred to Phase B | `project_memberships` carries only user_id, project_id, role, created_at. Phase A states are "member" and "not a member"; suspension is role removal in Keycloak, effective when the token or session cookie expires (FR-012). Retained, non-authorizing "removed" records need a status column and an Alembic revision after `0009_tenant_org_id_guard`. |
| FR-007 | deferred to Phase B | No last-owner guard exists in redsim, and there is no in-app transition to guard in Phase A. Phase A relies on the realm-import `admin` user keeping the `admin` role; the transactional guard ships with the Phase B membership editor. |
| FR-008 | amended | Initial Owner bootstrap is the Keycloak realm import (`deploy/keycloak/realm-export.json` seeds `admin` with realm role `admin`) and, in dev-token mode, every `dev:<email>` principal holds `{"default": "admin"}`. The Owner-issued invitation half is deferred to Phase B with US3. |
| FR-009 | deferred to Phase B | Confirmation dialogs and optimistic-concurrency (revision) checks need the in-app membership editor; no revision column exists. |
| FR-010 | amended | Accountability references already live in the append-only audit chain (migration `0004_audit_append_only`; `redsim audit verify`), so deleting a membership row cannot erase history. Membership soft-delete (keeping the row as "removed") is Phase B with FR-006. |
| FR-011 | unchanged | Implemented by `web/src/hooks/useRoles.ts` and `RoleGated` (`packages/design-system/src/components/role-gated.tsx`) for visibility and by server-side `check()` as the boundary; loading, empty, denied, and unavailable states follow the existing `/projects` pages. The conflict (stale) state is Phase B with FR-009. |
| FR-012 | amended | Sign-out clears the NextAuth session and the Redsim cookies (`/api/auth/signout-redsim`); JWT `exp` and cookie TTL (`REDSIM_API_SESSION_TTL_SECONDS`, default 900) are validated on every request. Because roles travel in the token claim and are not re-read from the database per request, suspension or removal in Keycloak takes effect at the next token/cookie expiry, not instantly; the product spec records this bound. Failures fail closed (401/403). |
| FR-013 | deferred to Phase B | No invitation entity or states exist in redsim. |
| FR-014 | deferred to Phase B | No delivery-acknowledgement contract exists in redsim; Keycloak's own user-creation and email-verification flows carry onboarding in Phase A. |
| FR-015 | deferred to Phase B | Identity verification is Keycloak's; atomic membership creation from an invitation has no redsim counterpart. |
| FR-016 | deferred to Phase B | Non-disclosing outcomes for expired, revoked, mismatched, or duplicate invitations follow the Phase B invitation entity. |
| SC-001 | amended | Holds today for absent memberships (`tests/test_project_access_read.py`, `tests/test_projects_api.py`, `tests/test_tenant_rls.py`, `tests/test_api_auth.py`); the suspended/removed clauses depend on FR-006 (Phase B). |
| SC-002 | deferred to Phase B | Follows FR-007. |
| SC-003 | deferred to Phase B | Invitation clauses follow FR-013 to FR-016; the Replit clause is superseded with FR-004. |

**Key entities → redsim:** ManagedIdentity → `users` (sub, email, display_name) plus the request-scoped `CurrentUser`; Project → `projects` within `organizations` (the RLS boundary is the organization; membership is per project); Membership → `project_memberships` (no status or revision in Phase A); Invitation → no redsim table (Phase B); AccessDecision → the policy-engine `Decision` returned by `resolve_policy_engine().evaluate(...)`. Denied decisions are returned as 403 and are not persisted to the audit chain today; recording denied actions is a Phase B addition to F008.

### Locations in plan.md and tasks.md that point at the Replit monorepo

D10 replaces William's "Proposed implementation locations" with redsim paths. The items below are listed, not rewritten; plan.md and tasks.md stand as written and no task box is checked.

plan.md:

- Approach step 3 and the "Shared API integration" row: `lib/api-spec/openapi.yaml` → the FastAPI routers are the contract, `redsim/api/v1/projects.py` (membership endpoints) and `redsim/api/auth.py` (principal resolution); the human-readable reference is `docs/api/v1.md`. A feature-local draft at `specs/001-project-access/contracts/project-access.openapi.yaml` may still be written, but nothing is "coordinated into" a shared YAML.
- Approach step 4 and the "Authorization middleware" row: `artifacts/api-server/src/services/assurance/project-access.ts` → `redsim/api/auth.py` (`get_current_user`), `redsim/api/policy.py` (`check`, `ensure_project_access`, `_ROLE_RANK`, `_ACTION_MIN_ROLE`), `redsim/policy/engine.py`, `redsim/api/middleware/tenant.py`.
- "Access routes" row: `artifacts/api-server/src/routes/assurance/project-access.ts` → `redsim/api/v1/projects.py` (registered in `redsim/api/app.py` under `/v1`).
- Approach step 6 and the "Persistence schema" row: `lib/db/src/schema/project-access.ts` → `redsim/db/models.py` (`User`, `ProjectMembership`, `Project`, `Organization`) plus a new Alembic revision in `redsim/db/migrations/versions/` after `0009_tenant_org_id_guard.py` for any Phase B status/revision columns.
- Approach step 5 and the "Membership UI" row: `artifacts/ai-assurance/src/features/project-access/` → the `@redsim/web` app under `web/`: `web/src/app/login/page.tsx`, `web/src/app/projects/page.tsx`, `web/src/app/projects/[slug]/settings/page.tsx`; gating in `web/src/hooks/useRoles.ts`, `web/src/hooks/useRequireAuth.ts`, `packages/design-system/src/components/role-gated.tsx`.
- "Invitation issue/revoke UI" and "Invitation acceptance UI" rows: `.../InvitationManager.tsx`, `.../InvitationAcceptance.tsx` → no Phase A location (onboarding is Keycloak-side); Phase B components belong under `web/src/app/projects/[slug]/settings/` or a new route under `web/src/app/`, decided when Phase B is planned.
- "Focused server checks" row: `artifacts/api-server/src/tests/assurance/project-access.test.ts` → `tests/test_api_auth.py`, `tests/test_projects_api.py`, `tests/test_project_access_read.py`, `tests/test_tenant_rls.py`, `tests/test_cookie_and_bearer_auth_parity.py`, `tests/test_ws_origin_and_auth.py` (pytest, sqlite-backed).
- "Focused UI checks" row: `artifacts/ai-assurance/src/tests/project-access.test.tsx` → co-located Vitest files `web/src/app/login/page.test.tsx`, `web/src/app/projects/page.test.tsx`, `web/src/app/projects/[slug]/settings/page.test.tsx`, `web/src/hooks/useRoles.test.ts`, `web/src/server/auth-options.test.ts`.
- Approach step 7: the "minimal agreed F008 event envelope" → `redsim/audit/chain.py` (`AuditWriter.append`; `PostgresAuditWriter` online, `JsonlAuditWriter` offline).
- Approach step 8: "generate clients and validators through the existing generation flow" → redsim has no generated client or validator layer; the web app calls the API through `web/src/lib/api.ts`. The step has no redsim counterpart.
- "Feature data model" and "Reviewable contract" rows (`specs/001-project-access/data-model.md`, `.../contracts/project-access.openapi.yaml`): paths under `specs/` remain valid as feature documentation; only their downstream "coordinate into `lib/...`" targets change as above.

tasks.md:

- T005: `lib/api-spec/openapi.yaml` → `redsim/api/v1/projects.py` plus `docs/api/v1.md`; there is no regeneration step.
- T006: `artifacts/api-server/src/services/assurance/project-access.ts` → `redsim/api/auth.py`, `redsim/api/policy.py`, `redsim/policy/engine.py`.
- T007: `artifacts/api-server/src/routes/assurance/project-access.ts` → `redsim/api/v1/projects.py`.
- T008: `artifacts/ai-assurance/src/features/project-access/ProjectAccessGate.tsx` → `web/src/hooks/useRequireAuth.ts`, `web/src/hooks/useRoles.ts`, `packages/design-system/src/components/role-gated.tsx`, `web/src/app/login/page.tsx`.
- T009, T013, T017: `artifacts/api-server/src/tests/assurance/project-access.test.ts` → `tests/test_projects_api.py`, `tests/test_project_access_read.py`, `tests/test_api_auth.py`, `tests/test_tenant_rls.py` (the T013/T017 content is Phase B).
- T010: `lib/db/src/schema/project-access.ts` → `redsim/db/models.py` plus a new revision in `redsim/db/migrations/versions/` (Phase B).
- T011, T014: "the F001 service/routes" → `redsim/api/v1/projects.py` (Phase B).
- T012: `.../MembershipEditor.tsx` → `web/src/app/projects/[slug]/settings/page.tsx` (Phase B).
- T015, T016: `.../InvitationManager.tsx`, `.../InvitationAcceptance.tsx` → no Phase A location (Keycloak-side); the Phase B location is decided with the invitation entity.
- T018: `.../MembershipRoster.tsx` → `web/src/app/projects/[slug]/settings/page.tsx` (the roster table is already rendered there).
- T019: `artifacts/ai-assurance/src/tests/project-access.test.tsx` → the co-located Vitest files listed for the plan's "Focused UI checks" row.
- T001, T002: the path `specs/_shared/decisions.md` is correct. D002 is resolved as of 2026-09-08, so T001's remaining content is only the invitation clauses, which move to Phase B; T002 (D007) remains OPEN.

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned  
**Suggested owner role:** Engineering lead  
**Required reviewers:** Product owner; security/data reviewer

## What and why

Provide managed application identity, project membership, and least-privilege roles so each assurance object and action has an accountable, authorized actor.
Application access is intentionally separate from Replit editor collaboration.

## Scope

- Sign in and sign out through a managed identity provider.
- Bootstrap an initial project owner through an approved administrative process.
- Let an Owner issue and revoke a future application invitation with a project and role.
- Create membership only after the recipient's managed-provider identity is verified and matches the invitation.
- List members and manage Owner, Analyst, Reviewer, and Viewer roles.
- Suspend, restore, and remove memberships while retaining accountability history.
- Enforce membership and object-level authorization on UI and server actions.
- Emit the agreed F008 event envelope for access changes and denied actions.

## Exclusions

- Custom passwords or credential storage.
- Treating a Replit collaborator invitation as application membership.
- Sending an actual invitation, configuring a provider, or onboarding a real person during this documentation phase.
- Locally minted authentication or invitation bearer tokens.
- Full audit history UI, retention tooling, or provider setup.
- Any operational, weapons, mission-system, or sensitive-data access.

## Prioritized user stories

### US1 (P1) — Enter a project with the correct role

As a managed-identity user, I can enter only projects where I have active membership and see actions allowed by my role.

**Independent test:** Use identities with active, suspended, and absent memberships; verify project visibility, action visibility, and server authorization independently.

- **Given** an active Viewer membership, **when** the member opens the project, **then** evidence is readable and management controls are absent.
- **Given** no active membership, **when** the identity requests a project object directly, **then** access is denied without revealing object details.
- **Given** authentication is unavailable, **when** sign-in is attempted, **then** the UI reports identity service unavailability and grants no access.

### US2 (P1) — Manage membership safely

As an Owner, I can change member roles and membership states without removing the project's last active Owner.

**Independent test:** Exercise role change, suspension, restoration, removal, stale updates, and the last-owner boundary through UI and direct requests.

- **Given** two active Owners, **when** one Owner demotes the other to Analyst, **then** the change succeeds and is recorded.
- **Given** one active Owner, **when** any actor attempts to suspend, remove, or demote that Owner, **then** the action is blocked with a last-owner explanation.
- **Given** an Analyst, **when** membership management is requested directly, **then** the server denies it even if a control was manually exposed.

### US3 (P1) — Invite a teammate and review the roster

As an Owner, I can propose onboarding a teammate with a role, revoke a pending invitation, and review the resulting roster; as a recipient, I can accept only after managed identity verification.

**Independent test:** Exercise acknowledged, failed, expired, revoked, mismatched, and duplicate invitation paths plus empty, mixed-state, and concurrently changed rosters without sending a real invitation.

- **Given** an Owner selects a project, role, and recipient, **when** the approved provider acknowledges delivery, **then** one pending application invitation is shown without granting membership.
- **Given** a matching recipient completes managed-provider identity verification, **when** the pending invitation is accepted, **then** one active membership with the invited role is created and the invitation becomes accepted.
- **Given** provider failure or no delivery acknowledgement, **when** issue is attempted, **then** the UI shows explicit failure and does not claim an invitation email/message was sent.
- **Given** an expired, revoked, identity-mismatched, or duplicate invitation, **when** acceptance is attempted, **then** no access is granted and the reason is explicit.
- **Given** no matching members, **when** an Owner filters the roster, **then** an empty state explains that no memberships match.
- **Given** a suspended membership, **when** an Owner restores it, **then** its previous or selected valid role becomes active.
- **Given** a stale roster version, **when** an Owner submits an edit, **then** no overwrite occurs and refresh/retry guidance is shown.

## Functional requirements

- **FR-001:** The product MUST use managed identity and MUST NOT implement custom passwords, local authentication tokens, or locally minted invitation bearer tokens.
- **FR-002:** Every project read or mutation MUST require active membership and object-level authorization, except a narrowly scoped acceptance request authorized by a verified matching identity and eligible invitation under FR-015.
- **FR-003:** The system MUST support Owner, Analyst, Reviewer, and Viewer permissions exactly as defined by the shared access matrix.
- **FR-004:** Replit editor collaboration MUST NOT create, imply, or modify application membership.
- **FR-005:** Only an active Owner MAY list all memberships or change role/status, and each attempted change MUST use the F008 event envelope.
- **FR-006:** Membership states MUST include active, suspended, and removed; removed records remain attributable and cannot authorize access.
- **FR-007:** The system MUST block any transition that would leave a project without an active Owner, including concurrent transitions.
- **FR-008:** Initial Owner bootstrap MUST remain supported; after D002 approval, only an active Owner MAY issue a future invitation containing one project, one recipient identity hint, and one valid role.
- **FR-009:** Role edits, suspension, restoration, and removal MUST require explicit target and intended-state confirmation; stale updates MUST fail without overwrite.
- **FR-010:** Membership hard deletion MUST NOT be offered; archived accountability and access-event references MUST remain intact.
- **FR-011:** UI controls MUST reflect permissions, loading, empty, success, denied, unavailable, and conflict states without serving as the authorization boundary.
- **FR-012:** Sign-out, suspension, removal, and identity expiry MUST prevent subsequent protected actions; failures MUST not silently retain access.
- **FR-013:** Invitation states MUST include pending, accepted, expired, revoked, and delivery_failed; only an active Owner MAY revoke a pending invitation, and no invitation state alone grants access.
- **FR-014:** An invitation MUST become pending only after the approved provider acknowledges delivery; provider error or absent acknowledgement MUST produce explicit failure and MUST NOT display or record an invitation email/message as “sent.”
- **FR-015:** Acceptance MUST require successful managed-provider identity verification matching the intended recipient and MUST atomically create at most one active membership with the invited project and role.
- **FR-016:** Expired, revoked, identity-mismatched, already-accepted, or duplicate invitations MUST NOT create or reactivate membership and MUST return a non-disclosing, actionable outcome.

## Key entities

- **ManagedIdentity:** Provider subject and non-secret display attributes; not a local credential.
- **Project:** Access boundary with at least one active Owner.
- **Membership:** Project, identity, role, status, revision, and lifecycle timestamps.
- **Invitation:** Project, intended recipient identity hint, role, provider reference, state, expiry, issuer, revision, and lifecycle timestamps; never an authentication credential.
- **AccessDecision:** Actor, project/object, action, outcome, reason, and correlation reference.

## Edge cases

- Two Owners concurrently attempt changes that would each leave no remaining Owner.
- The identity provider subject changes display details but retains the same stable identity.
- A member is suspended while viewing a page or submitting another action.
- A removed identity later returns; no prior access is automatically restored.
- Provider acknowledgement arrives after an Owner revoked or retried an invitation.
- A recipient signs in successfully with a different managed identity than the intended recipient.
- Concurrent acceptance requests or an invitation for an already-active project member occur.
- Event writing is unavailable during a privileged mutation; the mutation fails explicitly.

## Success criteria

- **SC-001:** Focused checks reject 100% of sampled protected requests from absent, suspended, or removed memberships across every role.
- **SC-002:** Focused concurrency checks show zero accepted transitions that leave a project without an active Owner.
- **SC-003:** Focused checks show zero memberships created by expired, revoked, mismatched, duplicate, unacknowledged, or provider-failed invitations; moderated users distinguish Replit collaboration from application invitations.

## Unresolved decisions and gates

- **D002:** Managed identity provider, initial Owner bootstrap, invitation delivery/acknowledgement, identity matching, expiry, and revocation behavior block implementation.
- **D007:** Named feature owner and reviewers remain unassigned.
- F008 event envelope must be agreed before access mutations are implementation-ready; full F008 is not a dependency.