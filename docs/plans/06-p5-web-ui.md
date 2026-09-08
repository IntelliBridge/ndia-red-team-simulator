> **SUPERSEDED / RECONCILED (2026-09-08 spec update).** This file was written for v1 against the deleted `redsim/` package. It now maps to: **Milestones M5a/M5b**; UI for features **F002/F005/F006/F007**.
>
> Substrate corrections (see `00-master-plan.md` §2 and the canonical spec): app is `@aegis/web`; add auth-aware pages — `/models`, `/models/[id]` launcher, 13-panel `/runs/[id]`, three-pane `/findings/[id]`, plus `/login`/`/projects` from F001 (v1 had no auth screens); new design-system components `MriScorecard`/`DimensionBars`/`RobustnessCurve`; `/targets` redirects to `/models`.
>
> Use this file for the parallel-execution shape only, not the literal paths, signatures, or mechanisms below.

# Phase P5 — Web UI

Status: v1, 2026-09-08. Owner: Dev D (Dev C pairs on the scorecard and
gallery). Wave: 1. Critical path: yes, for the demo screen.

Read `docs/plans/00-master-plan.md` first, then this file. P5 builds the four
feature routes of the Next.js app against the P0 API contract (master section
6.7) and a committed fixture. P5 never blocks on backend logic. It renders a
fixture `RunRecord` shaped like `GET /v1/runs/{id}` and switches to the live
API when P4 lands.

---

## 1. Objective

Ship the browser experience for redsim:

- `/targets` — a table of bundled targets with honest availability.
- `/runs/new` — a launch form built from `/v1/attacks`.
- `/runs` — a table of runs that polls every 5 seconds.
- `/runs/[id]` — the money screen. A two-column layout: Evidence on the left,
  Interpretation and candidates on the right.

The page must keep the design spec's honesty labels at all times. Candidates
read "candidate / not evaluated". Heuristic metrics read "heuristic". Inferred
statements read "inferred". Stubs show a reason and no fabricated panels.

The screen answers three questions side by side: can the model be fooled (the
MRI scorecard and measurements), why did it fail (the SHAP gallery), and how do
we harden it (the candidate recommendations). This mirrors the hackathon spec
section 11 three-pane money screen, folded onto the design spec's two-column
Evidence | Interpretation layout.

## 2. Scope

### In scope

- Wire types added to `web/src/lib/api.ts` that match the frozen P0 schema.
- SWR hooks: `useTargets`, `useAttacks`, `useRuns` (5 second poll), `useRun`
  (poll until the run reaches a terminal status).
- The four routes above, replacing the current placeholders.
- New presentational components under `web/src/components/`: the MRI scorecard,
  the observation gallery, and the measurements table, built only from
  `@redsim/design-system` primitives.
- vitest + testing-library + vitest-axe tests for the run page, the targets
  page, and the new components.

### Out of scope

- Any backend code. P4 owns `runs.py`, `jobs.py`, and the live routes.
- The Croissant dataset UI (P6 adds it later; leave a seam, do not build it).
- Auth, multi-tenancy, and the audit trail (removed from redsim).
- New design-system primitives. If a primitive is missing, compose the ones
  that exist rather than add one.
- Report rendering. The page links to `report.{md,json,html}`; the backend
  renders them.

## 3. Prerequisites and dependencies

P5 is fully parallel with the backend. It needs only two things, both from P0:

1. **The frozen API contract** — master section 6.7 (the endpoint table) and
   section 6.1 (the schema additions: `Scoring`, the `AttackInfo` ATLAS fields,
   `Measurement.severity`, `RunRecord.scoring` and `RunRecord.atlas_coverage`).
   The base wire models already exist in `redsim/schema.py`.
2. **A fixture** — `tests/fixtures/run_record.json`, committed by P0, shaped
   like `GET /v1/runs/{id}`. It must include a `scoring` block, `measurements`
   for the clean / evasion / control families, `observations` with artifact
   paths, `interpretation`, `recommendations`, `limitations`, and
   `atlas_coverage`. P5 copies it to `web/src/__fixtures__/run_record.json` (or
   imports it directly) so the tests render the real screen before P4 is done.

No dependency on P1, P2, P3, or P4 code. The app already ships SWR (`swr`
`^2.2.5`), vitest, testing-library, and vitest-axe in `web/package.json`, so no
new packages are required.

## 4. Interfaces consumed

### 4.1 Endpoints (master section 6.7)

| Method | Path | P5 use |
|---|---|---|
| GET | `/v1/targets` | `useTargets` → `/targets` table |
| GET | `/v1/attacks` | `useAttacks` → `/runs/new` form |
| POST | `/v1/runs` | submit `/runs/new`; 202 `{run_id}`, 501 stub, 422 bad params |
| GET | `/v1/runs` | `useRuns` (5 s poll) → `/runs` table |
| GET | `/v1/runs/{id}` | `useRun` (poll until terminal) → `/runs/[id]` |
| PATCH | `/v1/runs/{id}/reviewer-notes` | save reviewer notes |
| GET | `/v1/runs/{id}/artifacts/{path}` | image `src` in the gallery |
| GET | `/v1/runs/{id}/report.{md,json,html}` | download links |

### 4.2 Existing api.ts helpers (reuse, do not reinvent)

- `api<T>(path, init?)` — the fetch wrapper. Throws `ApiError` on a non-2xx
  response, so the hooks and the submit handler can read `err.status` (501,
  422) and `err.body`.
- `apiBase` — the resolved base URL, for completeness.
- `reportUrl(runId, ext)` — builds the `report.md|json|html` URL. Use it
  verbatim for the three download links.
- `artifactUrl(runId, relPath)` — builds the artifact URL. Use it verbatim for
  every `<img>` `src` in the gallery, passing the run-relative path from
  `Observation.artifacts` (for example `artifacts["shap_adv"]`).

### 4.3 Design-system components (from `@redsim/design-system`)

Use only these:

- Table family: `Table`, `TableHeader`, `TableBody`, `TableHead`, `TableRow`,
  `TableCell`, `TableCaption`.
- `Card`, `CardHeader`, `CardTitle`, `CardDescription`, `CardContent`,
  `CardFooter`.
- `Alert`, `AlertTitle`, `AlertDescription` — for stubs, errors, and honesty
  callouts.
- `Input`, `Textarea` — form fields and the reviewer-notes box.
- `Tooltip`, `TooltipTrigger`, `TooltipContent`, `TooltipProvider` — the
  "heuristic" and "inferred" explainers.
- `AlertDialog` family — confirm a launch if needed.
- `RunStatusBadge` — run status in the tables and the run header.
- `SeverityChip` — measurement severity, driven by `Measurement.severity`.
- `StageTimeline` — run progress in the run header, fed from
  `RunRecord.stage` / `stages_done`.
- `Skeleton` — loading states.
- `cn` — class merging.

## 5. Ordered implementation steps

1. **Wire types in `web/src/lib/api.ts`.** Add TypeScript interfaces that mirror
   `redsim/schema.py` plus the P0 additions. Keep the existing helpers
   untouched. Add, at minimum:
   - `Domain = "image" | "tabular" | "llm"`, `TargetStatus`, `RunStatus`,
     `AttackFamily`, `MeasurementFamily`, `Grade = "A"|"B"|"C"|"D"|"F"`,
     `Severity = "critical"|"high"|"medium"|"low"`.
   - `TargetInfo`, `ParamSpec`, `AttackInfo` (with `atlas_technique_id` and
     `atlas_technique_name`), `RunConfig`.
   - `Measurement` (with optional `severity`), `Observation`, `Interpretation`,
     `CandidateRecommendation`, `Scoring` (mri, grade, subscores, weights,
     reference_eps, eps_grid, delta_mri), `Provenance`.
   - `RunRecord` (with `scoring: Scoring | null` and `atlas_coverage: string[]`)
     and `RunSummary`.
   Match field names exactly, including `params_schema`, `n_flipped_from_clean`,
   `center_mass_ratio_clean/adv`, `metric_kind`, `triggered_by`, `validation`.
2. **SWR hooks in `web/src/hooks/use-api.ts`.** A shared `fetcher` calls
   `api<T>`. Then:
   - `useTargets()` → `GET /v1/targets`.
   - `useAttacks()` → `GET /v1/attacks`.
   - `useRuns()` → `GET /v1/runs` with `refreshInterval: 5000`.
   - `useRun(id)` → `GET /v1/runs/{id}` with a `refreshInterval` that returns
     `5000` while the status is `queued` or `running`, and `0` once the status
     is terminal (`succeeded`, `failed`, `not_implemented`). Use SWR's function
     form of `refreshInterval` so polling stops on its own.
   Each hook returns `{ data, error, isLoading }` for the page to branch on.
3. **`/targets` page.** Render a `Table`: name, domain, status
   (`RunStatusBadge` mapped from `TargetStatus`), reason when
   `status === "not_implemented"`, and metadata (dataset name and clean
   accuracy read from `metadata`). Available rows get an "Evaluate" link to
   `/runs/new?target={id}`. Stubs show their `reason` in the row, honestly, with
   no Evaluate button.
4. **`/runs/new` page.** Read `target` from the query string. Load
   `useAttacks()` and filter to the target's domain. Render a form:
   - attack select (from `/v1/attacks`),
   - one field per `ParamSpec`: `float`/`int` → `Input type="number"` with
     `min`/`max`/`step` from the spec, `bool` → a checkbox, each seeded with
     `default`,
   - `n_samples` (10–1000), `seed`, `include_control`, `explain_k` (0–32).
   On submit, POST `RunConfig` to `/v1/runs`. On 202, redirect to
   `/runs/{run_id}`. On 422, show the field error from `ApiError.body`. On 501,
   show "target not implemented" and keep the user on the form.
5. **`/runs` page.** Render a `Table` of `RunSummary` rows with `RunStatusBadge`,
   target, attack, and created time. Poll with `useRuns()`. Each row links to
   `/runs/{id}`. Add a "New evaluation" link to `/runs/new`.
6. **`/runs/[id]` header.** Show target, attack, params, `RunStatusBadge`, and
   `StageTimeline` fed from `stages_done` and `stage`. If `status` is
   `not_implemented`, render only an `Alert` with the reason and stop. If
   `failed`, render the header and an `Alert` with `error`.
7. **MRI scorecard component.** `web/src/components/mri-scorecard.tsx`. Input:
   `Scoring`. Show the score, the grade, and five dimension bars for `S_acc`,
   `S_asr`, `S_eps`, `S_conf`, `S_expl` read from `subscores`. Mark a missing
   `S_expl` as "not scored (renormalized)" rather than zero. Render bars with
   plain divs and design tokens; do not add a chart library.
8. **Measurements table component.** `web/src/components/measurements-table.tsx`.
   One row per family (clean / evasion / control) with `n`, `n_correct`,
   `accuracy`, `n_flipped_from_clean`, the perturbation norms, and a
   `SeverityChip` from `Measurement.severity`. Always show the denominator
   (`n_correct` of `n`). Add a collapsible per-class table from `per_class`.
9. **Observation gallery component.**
   `web/src/components/observation-gallery.tsx`. For each `Observation`, a
   `Card` with four images via `artifactUrl(runId, path)`: clean, adversarial,
   SHAP clean, SHAP adversarial. Show true label, clean prediction, adversarial
   prediction, the flipped flag, and both center-mass ratios marked "heuristic"
   with a `Tooltip` carrying `metric_note`. Give every image real `alt` text.
10. **`/runs/[id]` right column.** Interpretation statements each labelled
    "inferred" with their `basis`. Candidate recommendations each labelled
    "candidate / not evaluated", each showing the triggering measurement
    (`triggered_by`), the ATLAS technique(s) from `atlas_coverage` /
    `attack.atlas_technique_id`, and `references`. Below: the `limitations`
    list, a reviewer-notes `Textarea` that PATCHes
    `/v1/runs/{id}/reviewer-notes` on save, and the three report links built
    with `reportUrl`.
11. **Loading and empty states.** Use `Skeleton` while `isLoading`, and an
    `Alert` on `error`. A queued or running run shows the header and timeline
    while the evidence fills in on the next poll.
12. **Tests.** Add the vitest suites in section 7.

## 6. Files to create or modify

### Modify

- `web/src/lib/api.ts` — add the wire types (step 1). Keep `api`, `apiBase`,
  `ApiError`, `reportUrl`, `artifactUrl` as they are.
- `web/src/app/targets/page.tsx` — replace the placeholder (step 3).
- `web/src/app/runs/page.tsx` — replace the placeholder (step 5).
- `web/src/app/runs/new/page.tsx` — replace the placeholder (step 4).
- `web/src/app/runs/[id]/page.tsx` — replace the placeholder (steps 6, 10, 11).

### Create

- `web/src/hooks/use-api.ts` — the SWR hooks (step 2).
- `web/src/components/mri-scorecard.tsx` — the scorecard (step 7).
- `web/src/components/measurements-table.tsx` — the measurements table (step 8).
- `web/src/components/observation-gallery.tsx` — the gallery (step 9).
- `web/src/components/honesty-label.tsx` — a small shared label/badge for
  "candidate / not evaluated", "inferred", and "heuristic", so the wording is
  defined once.
- `web/src/__fixtures__/run_record.json` — a copy of
  `tests/fixtures/run_record.json` for the tests to import.
- Tests (section 7):
  - `web/src/app/runs/[id]/page.test.tsx`
  - `web/src/app/runs/[id]/page.a11y.test.tsx`
  - `web/src/app/targets/page.test.tsx`
  - `web/src/components/mri-scorecard.test.tsx`
  - `web/src/components/observation-gallery.test.tsx`

## 7. Testing and validation

Follow the existing patterns in `web/src/**`: `vitest` with the `jsdom`
environment from `web/vitest.config.ts`, `@testing-library/react` for render and
query, `vitest-axe` for the a11y check (see `web/src/app/layout.a11y.test.tsx`).
Mock `next/navigation` (`useRouter`, `useSearchParams`, `useParams`) as the
layout test mocks it. Mock the SWR hooks (or `api`) so tests are offline and
deterministic.

Required tests:

1. **Run page from fixture** — `runs/[id]/page.test.tsx`. Render the page with
   the fixture `RunRecord`. Assert:
   - the MRI score and grade render, and all five dimension labels appear;
   - the measurements table shows the clean / evasion / control rows with their
     denominators;
   - the gallery renders four images per observation, each `src` built from
     `artifactUrl`, each with `alt` text;
   - the interpretation and candidate sections render;
   - the three report links carry the `reportUrl` hrefs.
2. **Honesty labels present** — assert the strings "candidate", "not
   evaluated", "inferred", and "heuristic" all appear on the rendered run page.
   This is the design spec's completion criterion 4.
3. **Stub is honest** — `targets/page.test.tsx`. With a fixture that has one
   available target and two `not_implemented` stubs, assert each stub shows its
   reason and no "Evaluate" link, and the available target shows an "Evaluate"
   link to `/runs/new?target=…`.
4. **not_implemented run** — a run with `status: "not_implemented"` renders the
   reason and none of the evidence panels (no scorecard, no gallery).
5. **Accessibility** — `runs/[id]/page.a11y.test.tsx`. Run `axe` on the
   rendered run page and assert `results.violations` is empty, as the layout
   a11y test does.
6. **Component units** — `mri-scorecard.test.tsx` (score, grade, five bars, and
   the renormalized `S_expl` case) and `observation-gallery.test.tsx` (image
   count, `artifactUrl` src, heuristic label).

Run `npm --prefix web test` and `npm --prefix web run typecheck`. Both must
pass. `vitest` is the only frontend gate the project runs.

## 8. Acceptance criteria (definition of done)

1. All four routes render real content, no "Not implemented yet" placeholder
   remains.
2. `/targets` lists targets with status, shows the reason for stubs, and links
   available targets to `/runs/new?target=id`.
3. `/runs/new` builds its fields from `params_schema`, POSTs a valid
   `RunConfig`, and redirects to `/runs/{run_id}` on 202. It surfaces 422 and
   501 honestly.
4. `/runs` polls every 5 seconds and shows `RunStatusBadge` per row.
5. `/runs/[id]` renders the two-column screen from the fixture before P4 is
   live: header with `StageTimeline`, left Evidence (scorecard, measurements,
   gallery), right Interpretation (statements, candidates, limitations,
   reviewer notes, report links). `useRun` stops polling at a terminal status.
6. Every honesty label is present: candidates read "candidate / not evaluated",
   heuristics read "heuristic", inferred statements read "inferred", stubs show
   a reason, and no panel is fabricated.
7. Images load through `artifactUrl`; report links use `reportUrl`.
8. The vitest suites in section 7 pass, including the axe check. `typecheck`
   passes.
9. When `NEXT_PUBLIC_REDSIM_API_URL` points at the live P4 API, the same pages
   drive a real run end to end with no code change.

## 9. Effort estimate and special considerations

Estimate: about 3 to 4 developer-days. Roughly one day for the wire types and
hooks, one day for `/targets`, `/runs`, and `/runs/new`, one to one and a half
days for the run page with the scorecard and gallery, and half a day for tests.

Considerations:

- **SWR polling.** Give `useRun` a function-form `refreshInterval` that returns
  `0` at a terminal status so a finished run stops fetching. Keep `useRuns` at a
  flat 5000. Use a stable key so SWR dedupes.
- **Image rendering via `artifactUrl`.** Pass `Observation.artifacts` paths
  straight to `artifactUrl`. Do not use `next/image` for these; they are
  cross-origin API bytes, so a plain `<img>` with width and `alt` is simpler and
  avoids the loader config. Handle a missing artifact with an `onError`
  fallback rather than a broken image.
- **Dark mode.** Use the existing CSS tokens (`bg-card`, `text-muted-foreground`,
  `border-border`, and the design-system variants). Do not hard-code colors, so
  the scorecard bars and severity chips read in both themes.
- **Stay on the primitives.** Build the scorecard bars and the gallery layout
  from `Card`, `Table`, and plain flex/grid divs with tokens. Do not add a chart
  or icon library; the master plan freezes the design-system surface.
- **Honesty is a test, not a convention.** The label strings are asserted in
  section 7, so define them once in `honesty-label.tsx` and reuse them.
- **Fixture drift.** If P0 revises the schema, re-copy
  `tests/fixtures/run_record.json` and update the wire types in the same change.
- **P6 seam.** Leave room on the run page for a future "Publish dataset" action
  (P6), but do not build it now.
