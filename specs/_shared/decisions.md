# Clarification and Decision Register

Every row is **OPEN** unless a reviewer explicitly records a decision. Recommendations below are proposals, not decisions already made by the user.

| ID | Decision needed | Proposed starting point | Blocks | Suggested decision owner |
| --- | --- | --- | --- | --- |
| D001 | First domain and benign use case | Pick either a public/synthetic document-category classifier or a synthetic FAQ assistant; not both | Domain-specific behavior in F002–F007 | Product lead + evaluation researcher |
| D002 | Managed identity provider, initial owner bootstrap, and invitation verification/expiry policy | Reuse a supported managed provider for sign-in and invitations; no custom passwords or locally invented authentication tokens | F001 implementation and all shared-data release | Project owner + engineering lead |
| D003 | Model/dataset access, permitted formats, and catalog approval policy | Versioned metadata plus approved benign fixtures; independent Reviewer/Owner approval per the proposed matrix; defer arbitrary uploads and arbitrary API endpoints | F002 validation/approval, F003 compatibility, F004 execution | Evaluation researcher + security reviewer |
| D004 | Approved runtime, isolation boundary, resource ceilings, timeout/cancel semantics | A bounded worker separate from the web process; OpenSandbox is only a candidate | F004 live execution | Platform lead + security reviewer |
| D005 | Evaluation definitions, benign controls, denominators, review thresholds, and explanation support | One versioned suite and one adapter; SHAP only if meaningful and supported for the selected domain | F003–F007 domain-specific acceptance | Evaluation lead + independent reviewer |
| D006 | Retention period, export redaction, license restrictions, and audit metadata retention | Minimize retained content; exports redacted by policy; block destructive purge until approved | F007 export policy and F008 retention operations | Data owner + security reviewer |
| D007 | Named feature owners and independent reviewers | Assign one accountable owner per feature; specialists may contribute across features | Team scheduling and approval, not document drafting | Project owner |

## Recording a resolution

For each decision, add:

- Decision ID and status: OPEN / RESOLVED / SUPERSEDED.
- Chosen option, rationale, and alternatives rejected.
- Approver and approval date.
- Affected feature requirements and acceptance scenarios.
- Any new dependencies or changed exclusions.

When a decision is superseded, retain the previous record and re-review affected specs and plans. Do not mark a feature approved simply because its files exist.

## Work that can begin before decisions close

The team can review stories, map evidence fields, draft UI flows, define managed-auth requirements, and evaluate runtime feasibility. Live evaluation, provider setup, uploads, destructive retention operations, and production release remain gated by the relevant decisions.