# AI Assurance Constitution

**Version:** 0.1.0 — draft for team ratification  
**Ratified:** Not yet  
**Last amended:** 2026-09-08

## I. Specify before implementing

Describe the user need and observable behavior in `spec.md` before choosing implementation details in `plan.md`. Derive `tasks.md` from the reviewed specification and plan. Every task must trace to a user story or a named foundational requirement.

**Why:** A link to a tool or a conversational recommendation is not an approved product requirement.

## II. Non-operational, authorized evaluation only

The first release is general-purpose assurance research using public or synthetic, non-sensitive data and approved benign targets. Do not implement combat targeting, weapons optimization, operational military model evaluation, or connections to mission systems.

Only approved evaluation profiles may run. This repository must not include operational attack recipes, live-system exploitation, or unrestricted execution of uploaded code.

**Why:** The original context is preserved as a source, not as authorization to implement every described application.

## III. Evidence before claims

Observed results, explanations, reviewer judgments, and candidate recommendations must remain distinguishable. Findings must retain provenance. Illustrative data must be labeled. Never manufacture metrics or claim a mitigation works before a separate comparison supports it.

SHAP attribution is not causal proof. LLM detector flags are not automatically confirmed findings. Passing a suite is not certification or operational readiness.

## IV. Access and execution boundaries are product behavior

Enforce permissions server-side and on every object. Replit project collaborators and future application members are separate concepts. Use managed authentication rather than custom password handling.

Unapproved inputs, missing permissions, unavailable execution isolation, and unsupported evaluation capabilities must fail explicitly. Never fall back to executing untrusted work in the web process.

## V. Reproducibility with honest limits

Capture immutable versions of inputs, profiles, evaluator configuration, and result schemas. Preserve the relationship between reruns and original runs. Disclose nondeterminism and missing evidence; do not promise bit-for-bit repeatability for nondeterministic providers.

## VI. Reviewable increments

Prioritize independently demonstrable user stories. A story is not done without its visible behavior, server-side checks where relevant, failure states, and acceptance evidence. Critical access, state-transition, and evidence-integrity behavior requires focused automated checks.

Contract-backed development is the default for future software: review the API contract, regenerate clients, then implement coordinated UI and backend changes. No mock response may stand in for a completed integration.

## VII. Minimize and govern data

Keep secrets outside repository files, exports, and logs. Archive referenced configuration instead of silently rewriting history. Treat deletion of stored evidence as an explicit, authorized retention operation, not ordinary editing.

## Governance

- All feature packages begin as **Draft / not approved for implementation**.
- The product owner approves scope; an engineering reviewer approves the plan; a security/data reviewer approves relevant data and execution boundaries.
- Record decisions and unresolved blockers in `specs/_shared/decisions.md`.
- Constitution exceptions require a written rationale and named approval; exclusions in Principle II are not bypassed by a feature plan.
- Behavior changes update the spec first, then plan, tasks, and acceptance evidence.
- A new required principle is a minor version change; incompatible governance changes are major; editorial clarification is patch.

## Workflow

Constitution → Specify → Clarify → Plan → Tasks → Analyze → Implement → Verify.

This is a project-authored, Spec Kit–style constitution. The Spec Kit CLI and slash-command integrations have not been installed.