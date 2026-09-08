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

## Amendment proposals (2026-09-08)

**Status:** proposed, pending named approval. Nothing above this heading has changed. Under the Governance section, a constitution exception requires a written rationale and named approval, and Principle II exclusions are not bypassed by a feature plan. The product owner's decisions of 2026-09-08 (recorded in `specs/_shared/decisions.md` D001–D005 and in `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md`) diverge from three principles as written. Each proposal below states the divergence, the rationale, and the bounds that would apply if it is approved. Ratification of the constitution, and approval of these proposals, is not claimed.

### (a) Principle II — evaluation imagery

- **Divergence:** D001 selects aerial-target / military-vehicle imagery as the demonstration domain. Principle II describes the first release as "general-purpose assurance research using public or synthetic, non-sensitive data and approved benign targets" and excludes "operational military model evaluation".
- **Rationale:** the original use case is target-recognition robustness; a demonstration on recognizable imagery shows the failure mode the product exists to surface. The models evaluated are the team's own bundled classifiers and user-supplied classifiers under evaluation, not fielded systems.
- **Bounds:** imagery comes only from open, unclassified, public datasets with a clear licence, recorded in the asset manifest. The tool evaluates and hardens the robustness of a classifier; it never trains, optimizes, or deploys targeting or weapons models. No connection to any mission system. No operational or sensitive dataset. The remaining Principle II exclusions (combat targeting, weapons optimization, operational attack recipes, live-system exploitation) stand unchanged.
- **Proposed wording change:** replace "public or synthetic, non-sensitive data" with "open, unclassified, publicly licensed or synthetic data", and add "Evaluating a classifier's robustness on such data is in scope; training, optimizing, or deploying targeting or weapons models is not."

### (b) Principle II — "unrestricted execution of uploaded code"

- **Divergence:** D003 admits white-box model artifact upload in Phase A. Principle II excludes "unrestricted execution of uploaded code".
- **Rationale:** the use case requires evaluating a user's own model. The upload path is bounded, not unrestricted: ONNX preferred; PyTorch `state_dict` accepted only with an explicit, registered architecture; full pickles refused by default; every uploaded model is loaded and run only on the worker, inside redsim's plugin sandbox (separate process, no network, rlimits, minimal environment), never in the API process; each upload appends an audit event carrying the artifact's sha256 and never its bytes.
- **Bounds:** no format that executes arbitrary code on load is accepted by default; a change to accept one requires a further amendment and a named security review. The API process never deserializes a model. Endpoint connectors remain Phase B and query-only.
- **Proposed wording change:** keep "unrestricted execution of uploaded code" as excluded and add "Bounded loading of declared-format model artifacts (ONNX, `state_dict` with a registered architecture) inside the worker sandbox is permitted; formats that execute code on load are refused by default."

### (c) Principle III — a single-number score

- **Divergence:** D005 adopts the Model Robustness Index, one number per campaign. Principle III requires that observed results, explanations, reviewer judgments, and candidate recommendations remain distinguishable, and the project brief's reporting principles say to avoid a universal score that mixes unrelated domains.
- **Rationale:** a per-campaign summary makes the before/after of the verify loop legible. The constraints below are what keep the evidence distinguishable.
- **Bounds:** one MRI per campaign — one model × one modality × a declared attack set × a declared ε grid × a reference budget — never aggregated across modalities or domains and never compared across campaigns with different settings. The MRI is never shown without its five subscores, the per-test-family accuracy table with denominators, and the ε curve. Grade-band readings describe robustness under the in-scope attacks only; no grade is a readiness, safety, or certification statement. Finding severity is derived from ε at first success and attack success rate, not hand-set. ΔMRI measured on this model at these settings is the only sanctioned form of "gain"; a recommendation carries no numeric expected gain until a verify measures it. Demo-script numbers are labelled illustrative. Measurements, observations, interpretation, and candidate recommendations stay separate fields and separate UI panels with `Literal`-typed labels.
- **Proposed wording change:** add to Principle III: "A per-campaign summary score is permitted only when it travels with its subscores, denominators, and settings, is never aggregated across domains, and is never presented as a readiness or certification statement."

### Approval record

- Proposal (a): approver / date: —
- Proposal (b): approver / date: —
- Proposal (c): approver / date: —
- Constitution version after approval: 0.2.0 if any proposal is approved (a new required constraint is a minor version change).
