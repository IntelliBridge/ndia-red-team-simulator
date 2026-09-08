# F001 — Project Access

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