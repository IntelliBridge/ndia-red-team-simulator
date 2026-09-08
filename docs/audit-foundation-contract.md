# Audit foundation: proposed v1 contract

**Status:** Draft awaiting UI/UX review; not approved for implementation or production.

This is the bounded internal writer slice of F008, not the full audit/governance
feature. It proposes application event history, not tamper-proof evidence,
certification, non-repudiation, or a guarantee that every external action is logged.

## Plain-language contract

The proposed backend records **who did what, to which project and versioned
item, when, and with what result**. It records references and a few safe facts,
not the underlying content.

- Every event identifies a person or a service explicitly; a background job
  must not appear to be a person.
- Events describe an action as successful, failed, or denied. That action result
  is separate from whether the audit record itself was saved.
- Ordinary application code can append events but cannot edit or delete them.
  This is not protection against a host administrator altering files.
- Retrying the exact same event does not add another row. Reusing its ID with
  different content is an error, not an edit.
- Invalid data, unavailable storage, full storage, and damaged history must be
  reported explicitly. The writer never silently claims that recording succeeded.
- This first version builds only the internal writer. It supplies no screen,
  history-reading API, search, export, permissions system, or live event callers.

All field choices, limits, and behavior below remain proposals until reviewed.

## Review order and implementation gate

1. **UI/UX reviews this draft first.** Check whether the available information
   and its meaning can support the intended audit-history experience. Flag
   missing information before code is written; no UI implementation is requested.
2. **Incorporate feedback and confirm scope with the product owner.** Record
   changes and explicit decisions, rather than treating silence as approval.
3. **Engineering and security/data review the revised contract.** Engineering
   checks feasibility, concurrency, durability, and error semantics; security/data
   checks attribution, allowed content, storage boundaries, and privacy.
4. **Record explicit scoped approval, then implement and test the writer.**
   UI/UX feedback alone does not approve backend reliability or security.
5. **Review live integration separately.** Identity binding, permissions,
   history-reading interfaces, and action-specific responses to audit failure
   remain outside this slice.

Implementation is paused for this review sequence. No early internal-prototype
implementation has been authorized.

## Review boundary

The requested decision is scoped approval of a writer-only implementation, not
completion of full G2/F008. Full G2 includes action-specific caller failure
policies, which cannot be closed while live integration is out of scope.
Product, engineering, and security/data ownership must not be inferred from
repository access or project collaboration.

- Product owner: unassigned.
- UI/UX reviewer: unassigned; feedback pending.
- Engineering reviewer: unassigned.
- Security/data reviewer: unassigned.
- Approval of this specific contract: pending.
- Production identity binding and action-specific failure policies: unresolved.

An independent automated technical review can inform this decision but does not
represent human product or security/data approval. Approval of this slice must
not be recorded as approval of all F008 requirements or the full constitution.
If internal prototype implementation is authorized before named team review,
record that explicit scope decision and keep team approval and live integration
blocked; do not silently reinterpret an unassigned reviewer as approval.

## UI/UX review guide

Start with the event envelope, closed vocabularies, synthetic examples, and
writer results below. The persistence section is primarily for engineering
and security/data review.

### What a future history experience could use

| Available information | Design implication or limitation |
| --- | --- |
| Actor kind and opaque actor ID | Distinguish people from services. Names and avatars are not stored; resolving labels and handling deleted actors require a later contract. |
| Action, entity type, ID, and version | Can identify the action and exact referenced version. No item title, free-text description, before/after diff, or raw content is included. |
| UTC event timestamp | Can be formatted for a viewer's timezone. It represents the caller's stated action time, not necessarily the journal's acceptance order. |
| Per-project sequence | Provides recorded order within one project. It is not global ordering across projects. |
| Action outcome and optional reason code | Can distinguish successful, failed, and denied actions without displaying raw errors. Reason codes are optional and deliberately limited. |
| Correlation ID | Can associate related events. It does not itself provide navigation or an API for finding them. |
| Small allowlisted metadata | Can expose approved counts or duration, but not arbitrary explanatory text or event content. |

These are data affordances for future work, not a promise of a browser-facing
response or an approved audit-history screen. The internal writer's return
value is not a history-listing API.

### States that must not be confused

- **Action result versus recording result:** an action may succeed even when
  saving its audit event fails. This library neither reverses that action nor
  decides whether a future caller should block it.
- **Saved versus uncertain:** only `accepted` and `duplicate` establish successful
  recording. A failure with `recording_state: unknown` cannot truthfully be
  displayed as either definitely saved or definitely absent.
- **Duplicate versus another action:** retrying an identical audit write should
  not produce a second history entry. A separate real action needs its own event ID.
- **No history versus unavailable history:** a later history-reading contract
  must distinguish an empty result from denied access, loading, or read failure.
  Those read states and their UI are not implemented by this writer.

### Questions for the UI/UX reviewer

- [ ] Do the action and entity labels cover the intended first audit-history
  stories without implying that all those features already emit events?
- [ ] Can the design distinguish a person, a service, and an unresolved/deleted
  identity without relying on names being present in the event?
- [ ] Are stable item/version references enough? List any proposed extra field,
  the user need it serves, and whether it could contain sensitive content.
- [ ] Is the distinction between action outcome and recording uncertainty clear?
- [ ] Is it clear how timestamps, recorded order, and related actions differ?
- [ ] Which future filtering, detail, or navigation needs would require a
  separate read API or label-resolution contract rather than a writer change?
- [ ] Is there any design assumption that requires editing/deleting history,
  storing raw content, or promising complete/tamper-proof evidence? Flag it.

Please return feedback as **section/field → user need → suggested change**,
marked either **blocking for this contract** or **future UI/read-API work**.
Open questions are welcome; checking these boxes is not engineering or
security approval. Reviewer names, feedback, and approval decisions remain
unfilled until the responsible people provide them.

## Scope and integration boundary

- An internal Python library with strict validation and local filesystem
  persistence. No HTTP endpoint or browser-facing interface.
- No new external dependencies are proposed. Focused standard-library tests
  should also be collectable by the repository's existing pytest runner.
- Do not modify or instrument the existing run store, authentication, request
  handlers, evaluation runtime, or UI in this slice.
- Callers supply identity references from a trusted application/service context.
  This library neither authenticates those references nor accepts identity
  assertions directly from untrusted request bodies.
- Human and service attribution are distinct. A background operation must not
  fabricate a human actor.
- The library does not enforce project membership or cross-project request
  authorization. Those are future trusted-caller responsibilities; this slice
  cannot claim full authorization guarantees or SC-001 coverage of F008.
- Python with local filesystem persistence is the scoped proposal for the
  actual application, not approval of the draft TypeScript/database design.

## Event envelope

All fields below are required except `metadata`, which defaults to an empty object.
Reject unknown envelope or actor fields; do not silently coerce types.

| Field | Proposed rule |
| --- | --- |
| `schema_version` | Integer `1`; booleans and other versions rejected. |
| `event_id` | Canonical UUID chosen once by the caller and reused for retries. |
| `project_id` | Stable opaque project ID, 1–128 ASCII characters. |
| `actor` | Exactly `kind` (`user` or `service`) and a stable opaque `id`. |
| `occurred_at` | Explicit timezone-aware timestamp, normalized to UTC for persistence and comparison. |
| `action` | A value from the closed vocabulary below, not arbitrary text. |
| `entity_type` | A value from the closed vocabulary below. |
| `entity_id` | Stable opaque entity ID, 1–128 ASCII characters. |
| `entity_version` | Stable version reference, 1–64 ASCII characters; explicit `unversioned` for entities without versioning. |
| `outcome` | Exactly `succeeded`, `failed`, or `denied`. This describes the action, not whether audit storage succeeded. |
| `correlation_id` | Canonical UUID linking a logical operation across events. |
| `metadata` | Only the typed allowlist below; no nested objects, lists, nulls, arbitrary strings, or additional keys. |

Opaque identifiers allow only letters, digits, underscore, hyphen, period, and
colon; they are references, never usernames, email addresses, display names,
URLs, credential values, or raw payloads. Actor IDs have the same 128-character
bound. Recognizable credential/token patterns are rejected as an additional
safeguard, not claimed as complete secret detection.

The serialized UTF-8 event is limited to **8 KiB**. Metadata is additionally
limited to **1 KiB**. Validation errors expose bounded reason codes only, never
the rejected input or storage paths.

Snapshot validated data before writing so caller mutation cannot change what is
recorded. Canonical comparison uses sorted JSON keys, compact separators, UTF-8,
and UTC timestamps with exactly six fractional digits and a `Z` suffix. Missing
metadata and an explicit empty object are equivalent; missing required fields
are not. No other payload normalization or silent redaction is permitted.

### Closed vocabularies

Actions:
`created`, `updated`, `invited`, `accepted`, `role_changed`, `revoked`,
`approved`, `rejected`, `archived`, `deleted`, `requested`, `started`,
`completed`, `failed`, `cancelled`, `retried`, `submitted`, `confirmed`,
`withdrawn`, `exported`, `policy_changed`.

Entity types:
`project`, `membership`, `invitation`, `catalog_entry`, `catalog_version`,
`profile`, `profile_version`, `run`, `finding`, `report`, `policy`.

These labels do not authorize their corresponding actions or promise an
integrated caller. In particular, `deleted` describes another feature's action;
it does not expose deletion of audit records.

### Metadata allowlist

All seven keys are optional. Numeric fields require integers, not booleans,
floats, or numeric strings.

| Key | Accepted values |
| --- | --- |
| `reason_code` | `validation_failed`, `not_authorized`, `conflict`, `not_found`, `unavailable`, `timeout`, `cancelled`, `internal_error`, `policy_rejected` |
| `source` | `api`, `worker`, `scheduler`, `system` |
| `attempt` | Integer 1–1,000 |
| `item_count` | Integer 0–1,000,000 |
| `changed_field_count` | Integer 0–1,024 |
| `duration_ms` | Integer 0–86,400,000 |
| `retryable` | Boolean |

Prompts, outputs, datasets, artifacts, request/response bodies, free-text
exceptions, credentials, tokens, and operational content are prohibited.
Reject rather than automatically redact or silently discard unsupported data.
Changes to the allowlist require a reviewed contract update.

## Synthetic event examples

These are invented fixtures illustrating the proposed event envelope, not
observed activity or evidence of live integration. Display names, UI copy,
storage sequence, and writer results are deliberately not envelope fields.

### Person updates a catalog version

```json
{
  "schema_version": 1,
  "event_id": "11111111-1111-4111-8111-111111111111",
  "project_id": "demo_project_001",
  "actor": {
    "kind": "user",
    "id": "demo_user_001"
  },
  "occurred_at": "2026-09-08T14:00:00.000000Z",
  "action": "updated",
  "entity_type": "catalog_version",
  "entity_id": "demo_catalog_001",
  "entity_version": "v2",
  "outcome": "succeeded",
  "correlation_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "metadata": {
    "source": "api",
    "changed_field_count": 2
  }
}
```

The event records that an update succeeded and how many fields changed; it
does not store the changed values or identify which fields changed.

### Service records a failed run action

```json
{
  "schema_version": 1,
  "event_id": "22222222-2222-4222-8222-222222222222",
  "project_id": "demo_project_001",
  "actor": {
    "kind": "service",
    "id": "demo_worker_001"
  },
  "occurred_at": "2026-09-08T14:05:00.000000Z",
  "action": "failed",
  "entity_type": "run",
  "entity_id": "demo_run_001",
  "entity_version": "unversioned",
  "outcome": "failed",
  "correlation_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  "metadata": {
    "source": "worker",
    "reason_code": "unavailable",
    "duration_ms": 1500
  }
}
```

This event describes a failed action. If the writer durably saves it, the
writer result is `accepted`, despite the action's `failed` outcome. Retrying
that same envelope unchanged returns `duplicate`, not another event.

## Persistence, ordering, and retries

- Use a dedicated audit directory under a trusted, configured output location;
  do not reuse mutable run-record files.
- Proposed implementation target: a bounded per-project append-only journal on
  a local Linux filesystem, with exclusive inter-process locking and durable
  flush before acknowledging a write. Network filesystems and distributed
  writers are not supported by this initial contract.
- Store caller-independent, monotonically increasing per-project sequence
  numbers. Ordering describes journal acceptance, not causal ordering or a
  guarantee that caller timestamps are monotonic.
- Bound a journal to **16 MiB** for this initial slice. A full journal rejects
  new writes explicitly; it must not rotate, overwrite, purge, or silently
  discard events. Identical retries remain possible at the limit.
- Scope idempotency to `(project_id, event_id)`. A retry with the same validated,
  canonical event returns the existing sequence without appending. Different
  content under the same identity is a conflict, not an update.
- One per-project critical section must serialize both threads and processes
  across history validation, duplicate/conflict checks, sequence allocation,
  physical capacity checks, append, and durability. Check valid duplicates
  before capacity; the size limit includes the entire stored record framing.
- Frame each stored record as one newline-terminated canonical JSON object
  containing its event, sequence, and a checksum of its canonical payload.
  Require consecutive sequences and validate framing, checksums, and stored
  events before appending. Checksums detect accidental corruption, not an
  administrator's valid-looking rewriting or deletion of history.
- Use a fixed-length hash of the validated project ID for storage names; never
  join caller-supplied IDs directly into paths. Reject symlinks, hard-linked
  journals, and non-regular files in audit-managed components, including locks.
- Operate beneath a trusted application-owned root whose ancestors cannot be
  changed by untrusted users. Managed directories/files must be owned by the
  process user with no group/other access; reject unsafe existing permissions
  instead of silently changing them. No protection against a hostile host
  administrator or a process running as the same OS user is claimed.
- Managed-directory access must avoid resolve-then-use races; lock identity
  remains stable across writers and ordinary operation never replaces journal
  or lock files. Flush every newly created directory entry required to recover
  an acknowledged journal after a crash.
- An incomplete/corrupt journal must fail explicitly and preserve existing
  bytes. No automatic truncation or repair is authorized.
- Distinguish errors before publication from ambiguous failures during/after
  a write. Same-ID retries recover only complete, valid records with uncertain
  durability; callers must not assume a storage failure means no bytes exist.
- A torn/corrupt journal can block the entire project's writer, including
  retries of earlier accepted events. It remains unavailable pending a
  separately approved recovery process; this slice must not claim that retry
  alone repairs partial writes.
- No append acknowledgement until the required file/directory durability
  operations succeed. Retrying a previously uncertain event must re-establish
  durability before reporting success.

## Writer results and caller failure policy

Return an explicit result with one of:

- `accepted`: newly durably recorded, with its project sequence.
- `duplicate`: identical event already recorded; existing sequence returned.
- `rejected`: invalid/prohibited event; no append attempted.
- `conflict`: event identity already exists with different content; no mutation.
- `storage_failure`: write/read/lock/capacity/corruption/durability failure,
  using a bounded reason code and no raw exception text.

Storage-failure reason codes are `unavailable`, `unsafe_path`, `lock_failed`,
`capacity_exceeded`, `corrupt_journal`, `write_failed`, or `sync_failed`.
All results include `recording_state`: `recorded` only for accepted/duplicate;
`not_recorded` when this validated event was determined absent and no write
began; or `unknown` when existing history cannot be checked or a write/flush
may have partially or fully succeeded. Rejected/conflicting requests never
receive a sequence or a successful-recording claim for the submitted content.

Only `accepted` and `duplicate` count as successful audit recording. Results
must not silently downgrade failures or fabricate success.

There are no live action callers in this slice. Each future security-relevant
caller must obtain its own approved fail-closed/fail-open policy and
transactional integration design. This writer does not choose that policy,
undo another feature's action, or claim atomicity with application state.

## Acceptance checks

- Required/unknown fields, strict types, bounds, closed vocabularies, and
  prohibited payloads.
- Human and service events, stable references, and immutable event snapshots.
- Reopening persisted history; identical retries and conflicting ID reuse.
- Concurrent threads/processes appending unique and duplicate events without
  lost accepted records or duplicate sequences.
- Canonical-equivalent retries, omitted/empty metadata equivalence, and
  concurrent capacity exhaustion; valid duplicates still work at capacity.
- File/path attacks, malformed/truncated journals, capacity limits, and
  simulated short writes, flush failures, and interrupted writes.
- Poisoned-tail retries remain explicit failures without changing bytes;
  uncertain complete-record retries must establish durability before success.
- Managed-directory/lock/journal substitution, hard links, and unsafe existing
  permissions fail without following or mutating an unintended target.
- No ordinary update/delete interface; rejected/conflicting operations leave
  existing event bytes unchanged.
- Only synthetic test data; no user credentials, external service calls, UI
  changes, or claims of production authorization.