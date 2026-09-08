> **Phase P5 · Milestones M5a/M5b · UI for F002/F005/F006/F007 (v2, aegis substrate)**
>
> Read `docs/plans/00-master-plan.md` (v2, sections 2, 5, 7) first. The
> authoritative contracts are the canonical spec
> `docs/superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md` sections 17
> and 18, and `specs/005-evidence-workbench/spec.md`. This file plans the
> `@aegis/web` UI only. It builds no backend code.

# Phase P5 — Web UI (aegis substrate)

Owner: Dev D (WS5). Milestones M5a (image UI slice, the demo cut line per D8)
and M5b (model catalog UI). Features F002 (catalog), F005 (evidence workbench),
F006 (findings actions), F007 (reports and compare, UI surface). Wave: Slice 1
for `/models`, Slice 2 for the run page, Slice 3 for the finding page.

The app is `@aegis/web`: the Next.js 14 app router under `web/`, Tailwind,
`@aegis/design-system` from `packages/design-system`, and the `api()` client in
`web/src/lib/api.ts`. The app already has auth: NextAuth with the Keycloak
provider plus the dev-token path, the aegis session cookie minted in
`web/src/server/`, and the hooks `useRequireAuth`, `useRoles`, `useRunEvents`.
P5 extends these pages. It does not add a new auth stack.

---

## 1. Objective

Ship the browser experience for the ML vertical against the P0/P4 API contract
and a committed campaign fixture:

- `/models` and `/models/[id]` — the model catalog and the campaign launcher.
- `/runs/[id]` — the 13-panel campaign page with the MRI scorecard, the
  per-family measurement table, the robustness curve, and the observation
  gallery.
- `/findings/[id]` — the three-pane screen: Input, Explanation, Candidates,
  with a Verify fix action.
- `/targets` — a redirect to `/models`.

The UI keeps the honesty labels at all times. Inferred statements read
"inferred". Candidate recommendations read "candidate · not evaluated", or
"candidate · measured ΔMRI ±x at these settings" once verified. Proxy metrics
read "heuristic". The banned words "hardened", "deployment-ready", "certified",
"safe", and "tamper-proof" never appear. Every page carries the S2 footer line:
"Proof of concept on open, unclassified public data. Results are evidence for
human review, not a safety, readiness, or certification determination."

Auth is real, not a placeholder. Pages present role-gated controls with
`RoleGated` and `useRoles`, but the API is the authoritative boundary. The
session cookie carries the caller's project roles, and Postgres RLS plus
`aegis/api/policy.py` enforce every action server-side. The UI never relies on
client gating for security.

## 2. Scope

### In scope

- ML wire types added to `web/src/lib/api.ts` that mirror `aegis/ml/schema.py`
  and the section 17 responses.
- Action helpers in `web/src/lib/api.ts`: `startCampaign`, `explainFinding`,
  `hardenFinding`, `verifyFinding`, `dismissFinding`, `patchReviewerNotes`,
  `compareRuns`, and `artifactUrl(id)`.
- SWR hooks under `web/src/hooks/` for the catalog and campaign reads.
- `/models` (list plus the Add model dialog) and `/models/[id]` (summary,
  campaign launcher, campaign history).
- The 13-panel `/runs/[id]` campaign page.
- The three-pane `/findings/[id]` page.
- New design-system components in `packages/design-system/src/components/`:
  `MriScorecard`, `DimensionBars`, `RobustnessCurve`, `MeasurementTable`,
  `ObservationCard`, `LabelBadge`, `PanelSection`, `CompatibilityList`. Add
  `viewer` to the `ROLES` tuple in `role-gated.tsx` (section 7.2).
- The `/targets` redirect to `/models`, deleting the pentest launcher and its
  tests.
- vitest, testing-library, and vitest-axe tests, following the existing
  `web/src/**` patterns.

### Out of scope

- All backend code. WS4 owns the routers under `aegis/api/v1/`. WS2 and WS3 own
  the engine, scoring, explain, recommend, and verify tasks.
- Model upload deep validation, attack execution, SHAP, and scoring. The UI
  renders their results, never computes them.
- The endpoint connector, text and detection modalities, PDF export, per-project
  scoring overrides, and `Idempotency-Key`. These are Phase B. The UI renders
  them disabled with the reason from `/v1/ml/capabilities`, never hidden.
- The `/agents` and `/tools` pages. They are removed with the CAI agents and
  Kali tooling.
- New primitives. Compose the existing primitives rather than add one.

## 3. Prerequisites and dependencies

P5 runs in parallel with the backend. It needs two things from the earlier
milestones, both citable before the routes are live:

1. **The P0/P4 API contract.** The `RunConfig` widening and the evidence schema
   from WS0 (M0, `aegis/ml/schema.py`), and the section 17 route surface from
   WS4 (F004, routers under `aegis/api/v1/`). The wire types in
   `web/src/lib/api.ts` are hand-written against these. There is no generated
   client. The FastAPI OpenAPI document is the contract, and vitest fixtures are
   typed against these hand-written types (section 19.4).
2. **A campaign fixture.** `web/src/__fixtures__/campaign.json`, shaped like
   `GET /v1/runs/{id}/campaign` (section 17.2): `config`, `target`, `attacks`,
   `provenance`, `measurements` for the `clean`, `evasion`, and `control`
   families, a `curve`, `observations` with artifact ids, `interpretation`,
   `recommendations`, `limitations`, `reviewer_notes`, `completeness`, and a
   `score` MRIRecord with its five subscores. Add `models.json` (a `/v1/models`
   list) and `finding.json` (a `/v1/findings/{id}` row) fixtures for the other
   two pages. The tests import these so the real screens render before WS4 is
   done.

No dependency on WS1, WS2, WS3, or WS6 code. The app already ships `swr`,
`vitest`, `@testing-library/react`, and `vitest-axe`, so no new packages are
required. When `NEXT_PUBLIC_AEGIS_API_URL` points at the live API the same pages
drive a real campaign with no code change.

## 4. Interfaces consumed

### 4.1 Endpoints (section 17)

| Method | Path | Gate | P5 use |
|---|---|---|---|
| GET | `/v1/models?project=` | membership | `useModels` → `/models` list |
| POST | `/v1/models` (bundled / upload) | remediator | Add model dialog |
| GET | `/v1/models/{id}` | membership | `useModel` → `/models/[id]` |
| DELETE | `/v1/models/{id}` | admin | Delete a model |
| POST | `/v1/models/{id}/attacks` | scanner | `startCampaign` → 202 `{run_id, job_ids, status_url}` |
| GET | `/v1/attacks?modality=` | authenticated | `useAttacks` → launcher checklist |
| GET | `/v1/datasets` | authenticated | `useDatasets` → dataset picker |
| GET | `/v1/defenses` | authenticated | `useDefenses` → Verify fix chooser |
| GET | `/v1/ml/capabilities` | authenticated | `useCapabilities` → honest disabled states |
| GET | `/v1/runs/{id}/campaign` | membership | `useCampaign` → `/runs/[id]` |
| GET | `/v1/runs/{id}/artifacts` | membership | artifact roster |
| GET | `/v1/artifacts/{id}` | membership | `artifactUrl(id)` for every `<img>` |
| GET | `/v1/runs/{id}/compare?with=` | membership | `compareRuns` → Compare drawer |
| PATCH | `/v1/runs/{id}/reviewer-notes` | remediator | `patchReviewerNotes` |
| POST | `/v1/findings/{id}/explain` | scanner | `explainFinding` |
| POST | `/v1/findings/{id}/harden` | remediator | `hardenFinding` |
| POST | `/v1/findings/{id}/verify` | remediator | `verifyFinding(defense, params)` |
| GET | `/v1/findings?run=` / `/v1/findings/{id}` | membership | findings tables and the finding page |
| GET | `/v1/runs/{id}/report.{md,json,html}` | membership | `reportUrl`, download links |

Reads require project membership. Every mutating call is admission-first and
audited server-side before any Run or Job row is written. New ML routes return
the structured error envelope `{"detail": {"code", "message", "phase"?,
"field"?, "reasons"?}}` (section 17.3), so the UI renders the refusal without
parsing prose. Retained routes keep `{"detail": "<string>"}`.

### 4.2 Existing api.ts helpers (reuse, do not reinvent)

- `api<T>(path, init?)` — the fetch wrapper. It attaches the session cookie or
  the bearer token, the CSRF header on mutations, and the request id. It throws
  `ApiError` on a non-2xx response, so hooks and handlers read `err.status` and
  `err.body`.
- `apiBase` and `apiWsBase` — resolved base URLs.
- `reportUrl(runId, ext)` — the `report.md|json|html` URL. Use it verbatim for
  the three download links. Unchanged.
- `cancelRun`, `isCancellable`, `deleteTarget` — unchanged.

### 4.3 New api.ts surface (section 18.6)

- Types: `ModelTarget`, `AttackInfo`, `DatasetInfo`, `DefenseInfo`,
  `Capabilities`, `Campaign`, `CampaignConfig`, `Measurement`, `Observation`,
  `Interpretation`, `CandidateRecommendation`, `MRIRecord`, `ArtifactRow`,
  `Comparison`, `MlErrorDetail`.
- Helpers: `startCampaign(modelId, config)`, `explainFinding(id, body)`,
  `hardenFinding(id, body)`, `verifyFinding(id, defense, params?)`,
  `dismissFinding(id)`, `patchReviewerNotes(runId, notes)`,
  `compareRuns(runId, withId)`, and `artifactUrl(id)`. Note that `artifactUrl`
  now takes a single artifact id and builds `${apiBase}/v1/artifacts/{id}`. It
  no longer takes a run id plus a relative path.

### 4.4 Design-system surface

Reuse unchanged: `RunStatusBadge`, `StageTimeline`, `SeverityChip`,
`FindingCard`, `RoleGated`, `AuditChainBadge`, `EvidenceDiff`, `ToastList`, and
the primitives (`Table`, `Card`, `Alert`, `Input`, `Textarea`, `AlertDialog`,
`Tooltip`, `Command`, `Skeleton`, `cn`). Add the new components in section 2.

## 5. Ordered implementation steps

1. **Wire types in `web/src/lib/api.ts`.** Add the types in 4.3, matching field
   names to `aegis/ml/schema.py` and section 17. Keep `api`, `apiBase`,
   `ApiError`, `reportUrl`, `cancelRun`, `isCancellable`, and `deleteTarget`
   untouched. Add a typed reader for `MlErrorDetail` so callers branch on
   `code`.
2. **Action helpers in `web/src/lib/api.ts`.** Add `startCampaign`,
   `explainFinding`, `hardenFinding`, `verifyFinding`, `dismissFinding`,
   `patchReviewerNotes`, `compareRuns`, and `artifactUrl(id)`. `startCampaign`
   POSTs the `CampaignConfig` to `/v1/models/{id}/attacks` and returns the
   `JobHandle`.
3. **SWR hooks in `web/src/hooks/`.** Follow the `useRoles` pattern. Add
   `useModels(projectId)`, `useModel(id)`, `useCampaign(runId)`,
   `useAttacks(modality)`, `useDatasets()`, `useDefenses()`, `useCapabilities()`,
   and `useFinding(id)`. `useCampaign` refreshes on a slow fallback poll while
   the run is not terminal and stops at a terminal status. `useRunEvents` drives
   liveness on the run page and calls `mutate()` on each job frame.
4. **`LabelBadge` and `PanelSection` first.** Build these two design-system
   components before the pages, because every panel uses them. `LabelBadge`
   carries the variants `candidate`, `inferred`, `heuristic`, `measured`,
   `illustrative`, `partial`, `phase-b`. `PanelSection` gives the fixed panel
   frame with its distinct visual treatment. Define the honesty wording once, in
   `LabelBadge`, so tests assert one source.
5. **`/targets` redirect.** Replace `web/src/app/targets/page.tsx` with a client
   redirect to `/models`. Delete the pentest launcher body and its tests.
6. **`/models` page.** Render the model list (name, source badge, modality,
   format, short `sha256`, clean accuracy with `n`, status with reason). Add the
   Add model dialog with three tabs: Bundled sample (picker), Upload artifact
   (ONNX or state_dict plus architecture select, license statement, dataset,
   refusal rules shown before a file is chosen), Connect endpoint (disabled with
   the Phase B reason from `/v1/ml/capabilities`). Gate Add to remediator and
   Delete to admin with `RoleGated`. On an upload refusal (413, 415, 422) show
   the `code`, the message, and the remedy. Never render a partially created
   model.
7. **`MeasurementTable`, `RobustnessCurve`, `DimensionBars`, `MriScorecard`
   components.** Build these in `packages/design-system/src/components/`.
   `MeasurementTable` shows one row per family with `n`, `n_correct`, accuracy,
   `n_flipped_from_clean / n_clean_correct`, mean L∞, mean L2, and wall time,
   with a collapsible per-class sub-table. A family with `n = 0` shows "no
   evidence recorded", never 0 %. `RobustnessCurve` draws accuracy vs ε per
   attack with the control line and clean baseline as inline SVG, theme-aware,
   with denominators in tooltips. `DimensionBars` draws the five weighted
   subscore bars. `MriScorecard` receives the score, the per-family table, and
   the curve together and renders the number, the grade, and the bars **only
   when all three are present**. If any is missing it renders "Score
   unavailable: <reason>" and no number. Its fixed caption reads "Per-campaign
   summary under the in-scope attacks at the stated settings. Not a readiness or
   certification statement." A ΔMRI badge appears only when the score carries a
   `delta`, labelled "measured". There is no "expected gain" element anywhere.
8. **`ObservationCard` component.** For each observation, render the four images
   through `artifactUrl(id)`: clean, adversarial, SHAP clean, SHAP adversarial,
   each with real `alt` text. Show true and predicted labels, confidences, and
   both `center_mass_ratio_*` values badged "heuristic" with the `metric_note`
   as a tooltip. For tabular observations render the feature diff table and the
   SHAP bar and beeswarm PNGs. When no explanation was recorded, say so with the
   reason and draw nothing.
9. **`/models/[id]` page.** Render the model summary (manifest, license,
   dataset compatibility, validation status with refusal reason and a link to
   the ingest job) and the campaign history table (run, attacks, reference ε,
   status, and a "scorecard" link, never a bare MRI number). Build the campaign
   launcher (18.2) from `/v1/attacks`, `/v1/datasets`, `/v1/defenses`, and
   `/v1/ml/capabilities`, never from hard-coded lists. The attack checklist
   groups by phase, renders Phase B rows disabled with their reason, and renders
   white-box attacks disabled with "target has no differentiable estimator" when
   the manifest `gradients` is false. Add the ε-grid multi-select (default
   `{0.01, 0.03, 0.1}`), the reference-ε radio (must be one of the selected
   values), `finding_asr_threshold` (default 0.2), the dataset picker (CIFAR-10
   labelled "CI fixture — not the demo dataset"), sample size 50–500, seed,
   benign noise control (default on), `explain_k`, the LLM-narrative checkbox
   (enabled only when `capabilities.llm_narrative.configured` is true), and the
   read-only scoring weights. Submit calls `startCampaign`, disables the button
   until the response arrives, then routes to `/runs/[id]`. Disable the launcher
   with the reason inline when the model is `registered`, `validating`, or
   `refused`, when `capabilities.worker_ml_extra` is false, or when the caller's
   role is below scanner.
10. **`/runs/[id]` page (13 panels).** Extend the existing page. Keep the header
    (run id, status pill, Cancel dialog gated to remediator, report links) and
    the `StageTimeline` fed by `useRunEvents` with the fallback poll. Render the
    panels in this fixed order, each as a distinct `PanelSection`, never
    interleaved: (1) completeness banner, (2) campaign settings next to the
    score, (3) `MriScorecard`, (4) measurements plus `RobustnessCurve`,
    (5) observations gallery of `ObservationCard`, (6) interpretation
    statements badged "inferred" with `basis` links, (7) candidate
    recommendations badged "candidate · not evaluated" with `triggered_by`
    links, the ART defense link, a Verify fix button (remediator), and the
    narrative block labelled by source, (8) limitations (always rendered),
    (9) provenance with a Rerun-with-same-config button, (10) reviewer notes
    bound to `patchReviewerNotes` (remediator), (11) findings table with
    `SeverityChip`, Attack, ε at first success, and a Dismiss action (approver),
    (12) Compare drawer via `compareRuns`, (13) `AuditChainBadge` with the chain
    id `run:<id>`.
11. **`/findings/[id]` page (three panes).** Replace the body. Keep the
    `FindingCard` header with the `validation_state` chip and its ML-facing
    wording. Render three panes side by side on wide screens and stacked on
    narrow ones: Input (original vs adversarial with the perturbation map, the
    measured L∞ and L2, and the noise-control image at the same ε, or the
    tabular feature diff via `EvidenceDiff`), Explanation (SHAP clean vs
    adversarial, centre-mass heuristics badged "heuristic", the explanation-shift
    measurement with its `n`, and the fixed disclosure "Attribution describes
    model sensitivity; it is not causal proof"; an Explain button for scanner
    when no observation exists), and Candidates (the ranked rule outputs, each
    "candidate · not evaluated" until a verify record exists, a Verify fix button
    with the defense chooser from `/v1/defenses`, and after verification the
    measured ΔMRI with per-dimension deltas and the re-measured ASR table).
    Below the panes: the highlighted ε row on the campaign curve, the finding's
    audit events, and a link back to the campaign.
12. **Honest states.** Apply the section 18.5 table on every page. Render 503 as
    an explicit unavailable state with retry guidance, never an in-process
    fallback. Show fixture data in vitest and Storybook only, behind a visible
    "FIXTURE — illustrative" ribbon, never in the deployed app.
13. **Tests.** Add the suites in section 7.

## 6. Files to create or modify

### Modify

- `web/src/lib/api.ts` — add the wire types and action helpers (steps 1, 2).
  Keep the existing helpers as they are.
- `web/src/app/targets/page.tsx` — replace with the redirect to `/models`
  (step 5).
- `web/src/app/runs/[id]/page.tsx` — extend to the 13-panel campaign page
  (step 10).
- `web/src/app/findings/[id]/page.tsx` — replace the body with the three-pane
  screen (step 11).
- `web/src/app/dashboard/page.tsx` — swap the Scanner column for Model and link
  the empty state to `/models` (section 18.1).
- `web/src/app/runs/page.tsx` and `web/src/app/findings/page.tsx` — the changed
  columns of section 18.1.
- `packages/design-system/src/components/role-gated.tsx` — add `viewer` to the
  `ROLES` tuple.
- `packages/design-system/src/index.ts` — export the new components.

### Create

- `web/src/hooks/useModels.ts`, `useModel.ts`, `useCampaign.ts`, `useAttacks.ts`,
  `useDatasets.ts`, `useDefenses.ts`, `useCapabilities.ts`, `useFinding.ts` —
  the SWR hooks (step 3). Co-locate related hooks in one file if that matches
  the existing `useRoles` layout.
- `web/src/app/models/page.tsx` — the model list and Add model dialog (step 6).
- `web/src/app/models/[id]/page.tsx` — the summary, launcher, and history
  (step 9).
- `packages/design-system/src/components/label-badge.tsx`
- `packages/design-system/src/components/panel-section.tsx`
- `packages/design-system/src/components/mri-scorecard.tsx`
- `packages/design-system/src/components/dimension-bars.tsx`
- `packages/design-system/src/components/robustness-curve.tsx`
- `packages/design-system/src/components/measurement-table.tsx`
- `packages/design-system/src/components/observation-card.tsx`
- `packages/design-system/src/components/compatibility-list.tsx`
- `packages/design-system/src/components/*.stories.tsx` — one Storybook story per
  new component (the F16 gate), each with the "FIXTURE — illustrative" ribbon.
- `web/src/__fixtures__/campaign.json`, `models.json`, `finding.json` — the
  typed fixtures (section 3).
- Tests (section 7):
  - `web/src/app/runs/[id]/page.test.tsx`
  - `web/src/app/runs/[id]/page.a11y.test.tsx`
  - `web/src/app/models/page.test.tsx`
  - `web/src/app/models/page.a11y.test.tsx`
  - `web/src/app/findings/[id]/page.test.tsx`
  - `packages/design-system/src/components/mri-scorecard.test.tsx`
  - `packages/design-system/src/components/observation-card.test.tsx`

## 7. Testing and validation

Follow the existing `web/src/**` patterns: `vitest` with the `jsdom` environment
from `web/vitest.config.ts`, `@testing-library/react` for render and query, and
`vitest-axe` for the a11y check (see `web/src/app/runs/page.a11y.test.tsx`). Mock
`swr`, `@/hooks/useRequireAuth`, `@/hooks/useRoles`, and `@/lib/api` with
`vi.hoisted` and `vi.mock`, exactly as the layout and runs a11y tests do, so the
suites are offline and deterministic. Mock `next/navigation` where a page reads
the router, params, or the query string.

Required tests (section 22):

1. **Campaign page from fixture** — `runs/[id]/page.test.tsx`. Render the page
   with `campaign.json` and assert:
   - the 13 panels render in the fixed order;
   - measurements, observations, interpretation, and candidates are distinct
     sections, never interleaved;
   - the MRI score and grade render and all five dimension labels appear;
   - the measurement table shows the clean, evasion, and control rows with their
     denominators;
   - the gallery renders the four images per observation, each `src` built from
     `artifactUrl`, each with `alt` text;
   - the limitations panel is visible.
2. **Scorecard honesty** — assert that `MriScorecard` renders no number and shows
   "Score unavailable: <reason>" when the curve (or the table, or the score) is
   absent from the fixture. This is D9(ii).
3. **Honesty labels present** — assert that "candidate", "not evaluated",
   "inferred", and "heuristic" all appear on the rendered campaign page, and that
   none of the banned words ("hardened", "deployment-ready", "certified", "safe",
   "tamper-proof") appear.
4. **Models page** — `models/page.test.tsx`. Assert that the Connect endpoint tab
   is disabled with its Phase B reason, and that an upload refusal renders its
   error `code`. Assert that Add is gated to remediator and Delete to admin.
5. **Role-gating** — render each page with a viewer-only role and assert that the
   launcher, Cancel, Verify fix, reviewer notes, and Dismiss controls are hidden
   or disabled with the reason. State in the test that the API is the
   authoritative boundary and the UI gate is presentational.
6. **Finding page** — `findings/[id]/page.test.tsx`. Assert "not evaluated" until
   a verify record is present and "measured ΔMRI" afterwards, and that the three
   panes render.
7. **Accessibility** — `runs/[id]/page.a11y.test.tsx` and
   `models/page.a11y.test.tsx`. Run `axe` on the rendered page and assert
   `results.violations` is empty, as the existing a11y tests do. Keep and extend
   `layout.a11y.test.tsx`, `runs/page.a11y.test.tsx`, and
   `findings/page.a11y.test.tsx`.
8. **Component units** — `mri-scorecard.test.tsx` (number and grade present only
   with score plus table plus curve; the renormalization-free weights) and
   `observation-card.test.tsx` (four images, `artifactUrl` src, heuristic label).

Run `npm --prefix web test`, `npm --prefix web run typecheck`, and the
design-system package tests. All must pass. `vitest` is the frontend gate. The
Playwright config is kept for an optional end-to-end smoke of the demo path.

## 8. Acceptance criteria (definition of done)

1. `/models`, `/models/[id]`, `/runs/[id]`, and `/findings/[id]` render real
   content from the fixtures before WS4 is live. No "Not implemented yet"
   placeholder remains.
2. `/models` lists models with status and reason, gates Add to remediator and
   Delete to admin, and renders upload refusals with their `code`, message, and
   remedy. The Connect endpoint tab is disabled with the Phase B reason.
3. `/models/[id]` builds the launcher from `/v1/attacks`, `/v1/datasets`,
   `/v1/defenses`, and `/v1/ml/capabilities`, defaults the ε grid to
   `{0.01, 0.03, 0.1}` with a reference ε in the grid, POSTs a valid
   `CampaignConfig` to `/v1/models/{id}/attacks`, and routes to `/runs/[id]` on
   202. It disables the launcher with the reason when the model is not
   `available` or the caller is below scanner.
4. `/runs/[id]` renders the 13 panels in order. The `MriScorecard` renders the
   number and grade only when the score, the per-family table, and the curve are
   all present, and renders "Score unavailable: <reason>" otherwise. A ΔMRI badge
   appears only for a measured delta, and no "expected gain" element exists.
5. `/findings/[id]` renders the three panes, shows "candidate · not evaluated"
   until a verify record exists and the measured ΔMRI afterwards, and offers
   Verify fix with the defense chooser to remediator.
6. `/targets` redirects to `/models`. The pentest launcher and its tests are
   deleted.
7. Every honesty label is present, the banned words never appear, and every page
   carries the S2 footer. A family with `n = 0` reads "no evidence recorded", a
   503 shows an explicit unavailable state, and fixture data appears only behind
   the "FIXTURE — illustrative" ribbon in stories.
8. Role-gated controls present with `RoleGated` and `useRoles`, and the tests
   assert that the API remains the authoritative boundary.
9. The vitest suites in section 7 pass, including the axe checks. `typecheck`
   passes and each new design-system component has a Storybook story.
10. When `NEXT_PUBLIC_AEGIS_API_URL` points at the live API, the same pages drive
    a real campaign from `/models` through the scorecard and the verify-after-
    harden loop with no code change.

## 9. Effort estimate and special considerations

Estimate: about 4 to 5 developer-days. Roughly one day for the wire types,
helpers, and hooks; one day for `/models` and `/models/[id]`; one and a half
days for the 13-panel run page with the scorecard, curve, and gallery; one day
for the finding page; and half a day for tests and stories.

Considerations:

- **SWR polling.** Give `useCampaign` a function-form `refreshInterval` that
  returns a slow value while the run is `queued` or `running` and `0` once it is
  terminal, so a finished campaign stops fetching. Let `useRunEvents` drive
  freshness and call `mutate()` on each job frame. Read `/v1/ml/capabilities`
  once per session. Use stable SWR keys so it dedupes.
- **Role gating.** `RoleGated` and `useRoles` are presentational. The API, the
  session-cookie roles, and Postgres RLS are the authoritative boundary. Gate
  Add and reviewer notes to remediator, Verify to remediator, Dismiss to
  approver, Delete to admin, and the launcher to scanner. Never rely on the UI
  gate for security, and never fabricate a result a role cannot produce.
- **Artifact images.** Pass the artifact id straight to `artifactUrl(id)`. Use a
  plain `<img>` with width and real `alt` text, not `next/image`, because these
  are cross-origin API bytes served with a strict CSP. Handle a missing artifact
  with an `onError` fallback, not a broken image.
- **Dark mode.** Use the existing CSS tokens (`bg-card`,
  `text-muted-foreground`, `border-border`, and the design-system variants). Do
  not hard-code colors, so the scorecard bars, the SVG robustness curve, and the
  severity chips read in both themes.
- **Stay on the primitives.** Build the bars, the curve, and the gallery layout
  from `Card`, `Table`, inline SVG, and flex or grid divs with tokens. Do not add
  a chart or icon library. The master plan freezes the design-system surface to
  the components in section 2.
- **Honesty is a test, not a convention.** The label strings and the banned
  words are asserted in section 7, so define the wording once in `LabelBadge` and
  reuse it everywhere.
- **Fixture drift.** If WS0 or WS4 revises the schema, re-derive the fixtures and
  update the wire types in the same change. The fixtures are typed against the
  hand-written types, so a drift fails `typecheck` early.
- **Phase B seams.** Render the endpoint connector, text and detection
  modalities, and the compare-across-models path as disabled controls with the
  reason from `/v1/ml/capabilities`. Do not build them, and do not hide them.
