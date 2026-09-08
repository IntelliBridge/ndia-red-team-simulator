# Specification Readiness Checklist

Apply this checklist separately to each feature. Copy it into the feature's `checklists/` directory when beginning a formal review. These boxes are deliberately unchecked: document generation is not team approval.

## Specify

- [ ] The user outcome and explicit exclusions are clear.
- [ ] Stories are prioritized and independently demonstrable.
- [ ] Each story has Given/When/Then acceptance scenarios.
- [ ] Functional requirements have stable FR identifiers.
- [ ] Success criteria are observable and measurable without inventing results.
- [ ] Permissions, create/edit/archive/delete behavior where applicable, and failure/empty states are specified.
- [ ] The spec describes what and why; implementation choices live in the plan.

## Clarify

- [ ] Relevant decisions in the shared register are resolved or explicitly non-blocking.
- [ ] The first benign domain and data boundary are recorded where relevant.
- [ ] Provider/runtime capabilities are verified before depending on them.
- [ ] No research reference has been silently converted into a required dependency.

## Plan

- [ ] The plan respects the constitution and identifies dependencies without cycles.
- [ ] Data ownership, state transitions, and interface contracts are reviewed.
- [ ] Proposed paths have been checked against the repository before implementation.
- [ ] UI, API, persistence, and failure handling are planned together.
- [ ] Access enforcement, data minimization, and execution boundaries are covered.
- [ ] Relevant automated checks and acceptance evidence are identified.

## Tasks and analysis

- [ ] Every FR is covered by one or more implementation and verification tasks.
- [ ] Tasks have IDs, proposed target files, and suggested ownership.
- [ ] Parallel markers refer to genuinely independent work after prerequisites.
- [ ] Cross-feature vocabulary, roles, states, and provenance agree.
- [ ] Incomplete integration is not concealed by fallback fixtures or fake results.
- [ ] A reviewer has checked the spec, plan, and tasks together.

## Approval record

- Feature:
- Product owner / date:
- Engineering reviewer / date:
- Security or data reviewer / date, when relevant:
- Remaining non-blocking limitations:
- Decision: Draft / Changes requested / Approved for implementation.

## Done is a separate gate

After implementation, record passing checks, actual acceptance evidence, relevant accessibility/error-state checks, and a reviewed behavior-to-spec comparison. Specification approval alone is not feature completion.