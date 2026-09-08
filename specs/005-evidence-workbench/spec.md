# Feature Specification: Evidence Workbench

**Feature:** F005 — Evidence Workbench  
**Status:** Draft / not approved for implementation  
**Owner:** Unassigned (suggested role: evaluation research lead)  
**Approval required:** Product owner, engineering reviewer, security/data reviewer
## What and why

The evidence workbench lets authorized project members inspect original or baseline observations beside evaluated observations for one completed or partial run. It makes denominators, coverage, missing evidence, explanation limitations, and provenance visible so that measurements are not mistaken for causal conclusions.

## Scope

- Read-only browsing of F004 evidence for public or synthetic benign evaluations.
- Side-by-side original/baseline and evaluated evidence where both exist.
- Metric definitions, numerator, denominator, excluded or skipped cases, and coverage.
- Modality-appropriate explanations: SHAP only when configured and supported; text evidence for LLM evaluations.
- Optional display of F006 recommendation summaries without making F005 depend on F006.
- Explicit partial, unavailable, unsupported, empty, and access-denied states.

## Exclusions

- Editing evidence, run records, findings, reviews, or recommendations.
- Causal attribution, certification, universal scores, or operational-readiness claims.
- Fabricated heatmaps or substitute explanations when an explanation is unsupported.
- Tactical, weapons, live-target, sensitive-data, or attack-recipe functionality.
- Starting runs, applying defenses, or changing models from this workbench.

## User stories

### US1 — Compare evidence (P1)

As an authorized analyst or reviewer, I want original/baseline and evaluated observations shown together so I can inspect what changed without losing provenance.

**Independent test:** Open one authorized evidence item with two observations and verify labels, versions, completeness, and limitations without any finding or report feature.

- **Given** a member can read a run containing both observations, **When** they open an evidence item, **Then** both are shown side by side with stable evidence and run references.
- **Given** only one observation is available, **When** the item opens, **Then** the absent side is labeled unavailable with its recorded reason and no substitute content.
- **Given** the run is partial, **When** evidence is viewed, **Then** partial completeness remains visible at item and run context.

### US2 — Understand metrics and coverage (P1)

As a reviewer, I want every metric shown with its denominator and coverage so I can judge the limits of the result.

**Independent test:** Open a result family containing evaluated, skipped, and unavailable cases and reconcile its displayed counts to the source evidence contract.

- **Given** a metric has a definition and counts, **When** it is displayed, **Then** its numerator, denominator, units, exclusions, and coverage are visible.
- **Given** no evidence exists for a selected family, **When** it is selected, **Then** an empty state explains that no evidence was recorded rather than showing zero success.
- **Given** evidence cannot be loaded, **When** retrieval fails, **Then** an explicit retryable or terminal error is shown without stale values.

### US3 — Inspect appropriate explanations (P2)

As an analyst, I want supported explanations and optional reviewed recommendation summaries clearly separated from observations so I do not mistake interpretation for measurement.

**Independent test:** View one supported explanation, one unsupported explanation, and the page with F006 unavailable; evidence remains useful in all three cases.

- **Given** a supported explanation exists, **When** it is opened, **Then** its type, configuration, source, and limitations are visible.
- **Given** SHAP is unsupported or absent, **When** explanation space is shown, **Then** an unsupported state appears and no heatmap is fabricated.
- **Given** F006 supplies summaries, **When** they are displayed, **Then** they are labeled candidate or reviewed summaries and remain distinct from evidence.

## Functional requirements

- **FR-001:** The workbench MUST require active project membership and server-authorized object access before returning run or evidence content.
- **FR-002:** The workbench MUST let authorized members browse and select read-only evidence by run, test family, case, and recorded completeness.
- **FR-003:** The workbench MUST present original/baseline and evaluated observations side by side when available, preserving evidence, run, input-version, and configuration references.
- **FR-004:** The workbench MUST label absent, skipped, partial, failed-to-load, and unsupported evidence distinctly and MUST NOT infer missing values.
- **FR-005:** Every metric MUST expose its definition, numerator, denominator, units, exclusions, skipped/unavailable counts, and coverage scope; unrelated metrics MUST NOT become a universal score.
- **FR-006:** Explanations MUST identify modality, explanation type, configuration, provenance, and limitations; SHAP MUST appear only when the run records it as supported.
- **FR-007:** LLM evidence MUST use recorded text-oriented inputs/outputs, detector observations, or review evidence and MUST NOT fabricate visual attribution.
- **FR-008:** Evidence and explanations MUST remain read-only; create, edit, archive, and delete actions are not permitted in F005, and unauthorized mutation attempts MUST fail.
- **FR-009:** Optional F006 recommendation summaries MAY be displayed when authorized and available, but MUST be labeled separately and their absence MUST not impair core evidence browsing.
- **FR-010:** Empty, access-denied, not-found, schema-incompatible, and retrieval-failure states MUST be explicit and MUST not expose content from another project.
- **FR-011:** The workbench MUST disclose that attribution is not causal proof, detector flags are not confirmed findings, and partial or passing results are not certification.

## Key entities

- **Evidence:** F004-owned immutable observation references, metric context, explanation metadata, limitations, schema version, and completeness.
- **EvidenceComparisonView:** Read-only selection of available original/baseline and evaluated observations; it creates no new evidence.
- **MetricContext:** Definition, numerator, denominator, units, exclusions, coverage, and unavailable or skipped counts.
- **ExplanationView:** Supported modality-specific explanation plus configuration, provenance, and limitations.
- **RecommendationSummary:** Optional F006-owned projection, never evidence and never edited here.

## Edge cases

- A run completes while the viewer has a previously partial page open.
- Original and evaluated payloads have different but compatible display shapes.
- Metric denominator is zero or unknown; no percentage is calculated.
- Explanation metadata exists but its payload is unavailable or redacted.
- A referenced recommendation revision is withdrawn or no longer readable.
- Membership is revoked between list retrieval and item retrieval.

## Success criteria

- **SC-001:** In acceptance review, 100% of sampled metric views expose a reconcilable denominator, exclusions, and coverage or an explicit unavailable reason.
- **SC-002:** In acceptance review, every sampled unsupported explanation displays a labeled unsupported state and zero fabricated visual attribution.
- **SC-003:** Authorized reviewers complete baseline/evaluated comparison for at least 90% of representative supported fixtures without consulting raw storage references.

## Unresolved decisions

- **D001:** First benign domain determines evidence presentation.
- **D005:** Metric definitions, denominators, thresholds, and explanation support.
- **D007:** Accountable owner and independent reviewers.