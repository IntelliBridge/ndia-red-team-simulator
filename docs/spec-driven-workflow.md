# Working Spec-First as a Team

We follow GitHub Spec Kit's distinction between the **what**, the **how**, and the **work to do**. Start with the [feature map](../specs/README.md).

The product-level **what** is the [Adversarial ML Red-Team Simulator — Product Spec](superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md); feature specs decompose it and must agree with it.

## Workflow and responsibilities

| Stage | Team activity | File or output | Reviewer |
| --- | --- | --- | --- |
| Constitution | Agree on non-negotiable product, evidence, and safety principles | `.specify/memory/constitution.md` | Project owner + engineering/security leads |
| Specify | Describe a user's outcome, stories, requirements, exclusions, and acceptance criteria | `specs/<feature>/spec.md` | Product owner + user/domain representative |
| Clarify | Resolve ambiguity and record the rationale | `specs/_shared/decisions.md`; feature spec updated | Relevant decision owner |
| Plan | Choose the technical approach and define interfaces, state/data ownership, and checks | `specs/<feature>/plan.md`; then `research.md`, `data-model.md`, and `contracts/` as needed | Engineering + security/data reviewers |
| Tasks | Break the approved plan into story-sized contributions | `specs/<feature>/tasks.md` | Feature owner |
| Analyze | Check spec/plan/task coverage and contradictions across features | Feature readiness checklist and review record | Independent reviewer |
| Implement | Complete the agreed tasks without silently changing intended behavior | Application changes and focused checks | Assigned contributors |
| Verify | Demonstrate acceptance scenarios and record limitations | Feature acceptance evidence | Independent reviewer + product owner |

The feature packages currently contain **draft specs, proposed plans, and draft tasks**. Producing all three now helps the team see the work ahead; it does not skip the clarification or approval gates.

## Command equivalents

In a separately configured Spec Kit integration, the workflow uses commands such as `/speckit.constitution`, `/speckit.specify`, `/speckit.clarify`, `/speckit.plan`, `/speckit.tasks`, `/speckit.analyze`, and `/speckit.implement`.

**Those commands and the Spec Kit CLI have not been installed in this project.** You can follow the same file-based process now. The templates here are project-authored starting points, not a complete vendored Spec Kit distribution. If command integration is added later, review the generated changes instead of overwriting existing specs or assuming current templates are CLI-compatible.

Official reference: [GitHub Spec Kit](https://github.com/github/spec-kit).

## Example: taking one story into development

1. The owner selects `F002/US1` from the catalog specification.
2. Product and evaluation reviewers agree on what registration means; D003 (resolved 2026-09-08) fixes the allowed references: bundled sample models, and ONNX / PyTorch `state_dict` uploads loaded only on the sandboxed worker, with full pickles refused and endpoint connectors deferred to Phase B. Arbitrary file upload must not slip in as an implementation detail.
3. Engineering finalizes the catalog plan, version semantics, access checks, and API contract.
4. The owner assigns relevant `F002/T…` tasks. A frontend contributor and a backend contributor may work in parallel only after the shared contract is stable.
5. The reviewer checks the acceptance scenarios, including rejected and archived records—not only the happy path.
6. A changed requirement updates the spec before implementation continues.

## Reviews and handoffs

Each contribution should state:

- Feature, story, and task IDs.
- Requirement IDs it implements or changes.
- Prerequisites and resolved decisions.
- Files or contracts changed.
- Checks run and actual results.
- Known limitations and remaining work.

Never describe a UI-only stub as a completed integration, or an implemented backend without its required UI as a completed user story.

## Research versus implementation

D001–D005 were resolved on 2026-09-08 (see `specs/_shared/decisions.md`): image + tabular via ART, SHAP for both, Celery worker + aegis plugin sandbox; OpenSandbox not used. The paragraph below is kept as the method statement.

Research may reduce uncertainty without selecting a dependency. The ART/garak choice depends on the approved domain. SHAP support depends on the selected model and explanation method. OpenSandbox feasibility depends on the approved execution environment. The TIP paper informs potential coverage, not a promise of garak compatibility or validated defenses.

Do not implement all candidates first and decide the scope afterward.