# Legacy architecture docs

This directory holds historical planning + snapshot documents that were
superseded by tagged releases. The current architecture lives one level
up:

| Topic                  | Current doc                                       |
|------------------------|---------------------------------------------------|
| System overview        | [`../overview.md`](../overview.md)                |
| Auth flows             | [`../auth.md`](../auth.md)                        |
| Audit chain            | [`../audit-chain.md`](../audit-chain.md)          |
| Observability          | [`../observability.md`](../observability.md)      |
| Fork PR safety         | [`../../security/fork-prs.md`](../../security/fork-prs.md) |

## Contents

- **`PLAN_PHASE3.md`** — the Phase-3 implementation plan. Shipped in
  full by the v0.3.0 tag. Kept here for the design rationale; do not
  treat its claims as current.
- **`phase3.md`** — Phase-3-era architecture snapshot. Many of its
  components still hold; where they don't, the current docs above
  override.

The `CHANGELOG.md` at the repo root is the source of truth for what
landed when. The Phase-4 plan that drove the v0.3.1 / v0.4.0 / v0.4.1
release split was never committed (it lived in the planning
artefacts); the release tags + CHANGELOG entries are the only durable
record of what was decided and shipped.
