# Implementation Plan: Audit and Governance

**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: security and data governance lead)  
**Constraint:** Planning only; no implementation begins from this document.
## Proposed technical approach

1. Split delivery into an early foundation and later governance capabilities.
2. First define a minimal versioned AuditEvent contract, metadata allowlist, bounds, writer result, and caller failure policy.
3. Add an append-only application writer alongside F001; do not wait for the audit browser.
4. Later add Owner-authorized project history queries over bounded indexed event fields.
5. Define versioned governance policy drafts, independent approval, immutable approved versions, and a narrow policy-decision interface for F007.
6. Add retention request and deletion-marker behavior only after D006 and relevant storage entity contracts are approved.
7. Model partial purge outcomes honestly and never imply deleted content remains available.
8. Label this facility as application event history, not independently certified tamper-proof logging.

## Clarification and approval gates

- **G1 / D002:** Managed identity/service identity semantics before production event attribution.
- **G2:** Approve minimal event fields, metadata allowlist, size bounds, and action-specific writer failure policy.
- **G3 / D006:** Approve redaction, licensing, policy retention, and retention rules; blocks all destructive operations.
- **G4:** Relevant F002–F007 storage owners define eligible entity/version deletion behavior before retention execution.
- **G5 / D007:** Assign owner and reviewers and approve contracts, data model, security review, and plan.

## Dependencies and sequencing

- **Foundation:** Minimal F008 event envelope/writer starts alongside F001 and is consumed by later features.
- It depends only on project/actor identity contract, not on full F001 UI or other feature implementations.
- **Full governance UI:** Depends on F001 Owner authorization and persisted AuditEvents.
- **Policy interface:** May precede F007 exports; F007 consumes it and creates no reverse dependency.
- **Retention operations:** Depend on D006 plus later storage entities and deletion semantics; those features only emit/use contracts, avoiding graph cycles.

## Interface and data ownership

- F008 owns AuditEvent, GovernancePolicyVersion, PolicyDecision, RetentionRequest, and DeletionMarker.
- Source features own their entities and provide stable type/ID/version references only.
- Proposed contract: `specs/008-audit-governance/contracts/audit-event.yaml`.
- Proposed policy contract: `specs/008-audit-governance/contracts/governance-policy.yaml`.
- Proposed shared API edits: `lib/api-spec/openapi.yaml`, coordinated by the integration owner.
- Proposed schemas: `lib/db/src/schema/audit-events.ts` and `lib/db/src/schema/governance-policies.ts`.
- Proposed services: `artifacts/api-server/src/services/assurance/audit-writer.ts`, `audit-query.ts`, `governance-policy.ts`, and `retention.ts`.
- Proposed routes: `artifacts/api-server/src/routes/assurance/audit.ts` and `governance.ts`.
- Proposed frontend feature: `artifacts/ai-assurance/src/features/governance/`.
- Generated clients/validators remain `lib/api-client-react/` and `lib/api-zod/`; never hand-edit.

## Verification strategy

- Contract/property checks for allowlisted metadata, bounds, required identity, idempotency, and mutation rejection.
- Authorization checks for browse, policy, retention, cross-project references, and stale revisions.
- Policy-decision checks for deny-by-default failure and exact policy version.
- Retention checks are designed now but remain blocked until D006; later cover full, partial, denied, and retry outcomes.
- UI checks for empty, denied, unavailable, gaps, and non-tamper-proof disclosure.

## Readiness statement

No event schema, writer, UI, policy engine, purge operation, exact retention duration, or platform task is approved. Proposed paths must be reconfirmed after the applicable gates close.