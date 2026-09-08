# Frontend development

This doc covers the Next.js app, the design-system workspace and Storybook.
For the auth flow (NextAuth plus the redsim-signed cookie) see
[`docs/architecture/auth.md`](../architecture/auth.md). For the API surface
the app consumes see [`docs/api/v1.md`](../api/v1.md). The target ML pages
are section 18 of the
[product spec](../superpowers/specs/2026-09-08-adversarial-ml-redteam-spec.md).

## Workspace layout

```
pnpm-workspace.yaml             # root manifest: web, packages/design-system
pnpm-lock.yaml                  # the single lockfile, at the repo root
web/                            # @redsim/web, Next.js 14 app
  src/
    app/                        # App Router pages
    components/                 # app-level compositions
    lib/                        # api(), auth helpers (+ tests)
    hooks/                      # useRoles, useRequireAuth, useRunEvents (+ tests)
    server/                     # server-only modules (RSA cookie mint)
  .storybook/                   # main.ts, preview.ts
  tests/                        # Playwright stack E2E (workflow_dispatch only in CI)
  components.json               # shadcn config (aliases point at the design system)
packages/design-system/         # @redsim/design-system
  src/
    components/                 # redsim compositions + .stories.tsx
    primitives/                 # shadcn leaves: table, card, skeleton, alert, input, textarea, alert-dialog, tooltip, command
    lib/utils.ts                # cn(...)
    index.ts                    # public surface
  tsconfig.build.json           # typecheck without stories (the CI gate)
```

Everything is one workspace. From the repo root:

```bash
pnpm install --frozen-lockfile
pnpm --filter @redsim/web dev              # next dev -p 3000
pnpm --filter @redsim/web typecheck
pnpm --filter @redsim/web test             # vitest
pnpm --filter @redsim/web build
pnpm --filter @redsim/web storybook
pnpm --filter @redsim/design-system typecheck
```

The web tsconfig `paths` resolve `@redsim/design-system` to the source
folder, so a `next dev` hot reload picks up design-system edits without a
build step. `web/components.json` still names a `registry` under the deleted
`project_repos/shadcn-ui`, so `shadcn add` needs a registry override until
that entry is updated. The web app reads
`NEXT_PUBLIC_REDSIM_API_URL` (default `http://localhost:8000`) and the
`NEXT_PUBLIC_REDSIM_*` cookie names.

## Design-system principles

- **Composed, not imported.** shadcn primitives live in
  `packages/design-system/src/primitives/` and are wrapped by redsim
  compositions in `src/components/`. The web app imports only from the public
  surface (`src/index.ts`).
- **Primitive set.** The dependency-free leaves (`table`, `card`, `skeleton`,
  `alert`, `input`, `textarea`) plus the Radix and `cmdk` leaves
  (`alert-dialog`, `tooltip`, `command`) are re-exported from `index.ts`
  alongside `ComponentProps<…>` type aliases.
- **Storybook is the spec.** Every component exported from `index.ts` has a
  co-located `*.stories.tsx`. CI runs a blocking `@redsim/design-system`
  typecheck (`tsconfig.build.json`, stories excluded) plus the `@redsim/web`
  vitest suite.
- **CSP-friendly.** No inline scripts in components. CSS-only badges and
  visual states pair with the report CSP that disallows script sources.

## Component inventory

| Component | Where it appears |
|---|---|
| `SeverityChip` | dashboard, runs, findings |
| `RunStatusBadge` | dashboard, runs |
| `AuditChainBadge` | audit |
| `FindingCard` | findings detail |
| `StageTimeline` | runs detail (driven by the WS event stream) |
| `EvidenceDiff` | findings detail |
| `RoleGated` | every mutating control |
| `ToastList` | global transient notifications |
| `AlertDialog` | confirm dialogs on destructive actions (cancel run, delete target) |
| `Tooltip` | header controls, gated-button affordances |
| `Command` | the Cmd/Ctrl-K command palette |

The ML pages add `MriScorecard`, `DimensionBars`, `RobustnessCurve`,
`MeasurementTable` and `ObservationCard` (master plan WS5, spec section 18).
None of them is on `main`.

## Page inventory (on `main`)

| Page | Surfaces |
|---|---|
| `/`, `/login` | landing and sign-in |
| `/dashboard` | run and finding overview |
| `/runs`, `/runs/[id]` | run list and detail, **Cancel run** (`POST /v1/runs/{id}/cancel`, `remediator`), `report.json` / `report.md` / `report.html` links, stage timeline from `WS /v1/runs/{id}/events` |
| `/findings`, `/findings/[id]` | finding list and detail, **Verify** (`POST /v1/findings/{id}/verify`, `remediator`) |
| `/targets` | target list, **Delete target** (`DELETE /v1/targets/{id}`, `admin`, confirm dialog). The Start scan control is disabled behind a notice because no adapter is registered. |
| `/auth-profiles` | auth-profile list, create and delete (`admin`) |
| `/audit` | audit-chain visualization, each chain as linked blocks with valid / broken status and per-event hashes |
| `/projects`, `/projects/[slug]/settings` | project list and per-project settings (daily LLM budget) |
| `/logs` | terminal-style log viewer over `/v1/logs` |
| `/cost` | per-org LLM cost dashboard over `/v1/orgs/{id}/cost` |

Planned for the ML vertical (WS5, PR #16 is open): `/models` with
the Add model dialog (bundled picker, ONNX / `state_dict` upload with the
refusal rules shown before a file is chosen, endpoint tab disabled with the
Phase B reason), `/models/[id]` with the campaign launcher rendered from
`GET /v1/attacks` `params_schema`, the 13-panel `/runs/[id]` (MRI scorecard
with subscores, per-family table with denominators, ε curve, observations,
interpretation, candidate recommendations, limitations, provenance), the
three-pane `/findings/[id]`, and a `/targets` redirect. Every ML page reads
`GET /v1/ml/capabilities` once per session to render honest disabled states.

Two cross-cutting affordances live in the app shell: a header dark-mode
toggle (class-strategy Tailwind, persisted to `localStorage`) and the
Cmd/Ctrl-K palette. Destructive actions confirm through `AlertDialog`, are
wrapped in `<RoleGated>`, and the server re-checks RBAC. The client gate is
cosmetic.

## `api()` helper

`web/src/lib/api.ts` is the single fetch wrapper every page uses.

```ts
api<T>(path, init?)         // GET by default
api<T>(path, { method: "POST", body: JSON.stringify(...), headers: {…} })
```

- Attaches `X-Redsim-Request-ID` per call.
- Bearer wins: when `localStorage.redsim_token` (or `init.token`) is set,
  `Authorization: Bearer …` is sent with `credentials: omit`.
- Otherwise `credentials: include` so the cookie rides, and on mutating
  methods the `X-Redsim-CSRF` header is attached from the `redsim_csrf`
  cookie.
- Non-2xx surfaces as `ApiError(status, body)`. Pages render the detail.

`useRoles()` wraps SWR around `/v1/projects` and returns `{roles, projects}`.
`<RoleGated minRole="approver" callerRole={roles[projectId]}>` is the
canonical gate. `useRunEvents()` subscribes to the run WebSocket.

## NextAuth

The Keycloak code flow lives at `web/src/app/api/auth/[...nextauth]/route.ts`.
The session callback mints two cookies via the server-only
`web/src/server/redsim-session.ts`:

- `redsim_api_session`: httpOnly, secure in prod, sameSite=Lax, RS256-signed
  via `jose`.
- `redsim_csrf`: not httpOnly so the SPA can read it.

`/api/auth/refresh-api-session` (POST) re-mints without bouncing through
Keycloak, and `/api/auth/signout-redsim` (POST) clears both cookies on logout.

## Adding a new page

1. Add `web/src/app/<route>/page.tsx`. Mark it `"use client"` if it uses
   hooks.
2. Use `useRequireAuth()` at the top to bounce unauthenticated visitors to
   `/login`.
3. Fetch via `useSWR(authed ? "/v1/…" : null, fetcher)`.
4. Compose UI from `@redsim/design-system`. Do not write a one-off badge
   inline.
5. Wrap any mutating control in `<RoleGated minRole=… callerRole={roles[projectId]}>`.
6. Render unimplemented server paths as unavailable with the reason from the
   API. Never fake a result on the client.

## Adding a design-system component

1. If it is a primitive shadcn ships, generate it under `src/primitives/`
   with `pnpm --filter @redsim/design-system exec shadcn add <component>`
   (pass a registry, see above). If the primitive pulls a runtime dependency,
   add the package to the workspace first: CI installs with
   `--frozen-lockfile` and cannot fetch anything the lockfile is missing.
2. Compose the redsim wrapper under `src/components/`, export it from
   `src/index.ts`, co-locate a `*.stories.tsx`.
3. Update the table in this doc.
4. `pnpm --filter @redsim/design-system typecheck` (the blocking CI gate).
5. `pnpm --filter @redsim/web storybook` to preview.

## Lock-file discipline

The root `pnpm-lock.yaml` is committed. CI installs with
`pnpm install --frozen-lockfile`, and drift fails the `Next.js build` job.
When you change any `package.json`, regenerate the lockfile in the same
commit:

```bash
pnpm --filter @redsim/web add <pkg>
git add pnpm-lock.yaml web/package.json
```

On 2026-09-08 that job is red on `main` for exactly this reason: dependabot
#15 bumped `web/package.json` without the lockfile. The web image build is
also red because `deploy/Dockerfile.web` runs `corepack prepare pnpm` on the
`node:26` base image that dependabot #13 introduced, which no longer ships
corepack. Both fixes belong to the web workstream.

## What's deferred

- Per-finding HTML report (smaller than the run-level).
- Storybook test-runner CI gate and the a11y "serious-or-worse" gate.
- ESLint in `web/` (`make lint-web` prints a skip line until a config and
  `eslint-config-next` land).
