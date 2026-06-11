# Multi-tenancy

Aegis is multi-tenant on the **Organization**. An org is the top entity
in the data model; every `Project` carries an `org_id`, and every
project-scoped row (runs, findings, jobs, …) belongs to exactly one org
through its project. The tenant boundary *is* the org boundary.

Isolation is **layered**. The app layer already scopes every read to the
caller's project memberships (`ensure_project_access` / `ensure_run_access`
in `aegis/api/policy.py`). The database layer adds **Postgres Row-Level
Security (RLS)** keyed on `org_id` as defense-in-depth: a single forgotten
`WHERE` clause can no longer leak rows across tenants, because the database
itself refuses to return another org's rows.

```
caller → route auth dependency (project membership)   ← app layer
       → tenant middleware sets app.current_tenants    ← seam
       → Postgres RLS filters on org_id                ← DB layer
```

The DB layer is **belt-and-suspenders behind** the route auth, not a
replacement for it. Both filter on the same `org_id`, so they agree.

---

## The tenancy model

```mermaid
flowchart TD
  org["Organization<br/>(the tenant)"]
  org --> projA["Project A"]
  org --> projB["Project B"]
  projA --> runsA["runs · jobs · findings<br/>targets · llm_usage · artifacts<br/>remediation_attempts · application_logs"]
  projB --> runsB["runs · jobs · findings<br/>…"]
```

- **Organization = tenant.** It is the tenant root, not itself a
  project-scoped table.
- **Project belongs to one org** (`Project.org_id`).
- **Every project-scoped row belongs to one org** through its project,
  and now carries a denormalized `org_id` of its own (see below).

---

## DB-enforced org isolation (migration `0005_tenant_rls`)

Migration `0005` makes the database enforce the org boundary. It touches
`projects` (which already carries `org_id`) plus the eight project-scoped
tables: `targets`, `runs`, `jobs`, `findings`, `llm_usage`, `artifacts`,
`remediation_attempts`, `application_logs`.

### 1. Denormalized `org_id` + a backfill trigger

Each scoped table gains a denormalized `org_id VARCHAR(64) REFERENCES
organizations(id)` column (indexed). A join-free *local* column is what
lets the RLS policy be a simple column comparison — a policy that
subqueried `projects` would recurse through that table's own RLS.

- **Existing rows** are backfilled from `projects.org_id`.
- **New rows** need no insert-code changes: a per-table `BEFORE INSERT`
  trigger resolves `org_id` from the row's `project_id` when it is `NULL`.
  `project_id` is `NOT NULL` on every scoped table, so the lookup always
  resolves.

### 2. `ENABLE` + `FORCE ROW LEVEL SECURITY` + one policy

Each of the nine tables gets RLS **enabled and forced**, plus a single
policy `aegis_tenant_isolation`:

```sql
ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <t> FORCE  ROW LEVEL SECURITY;   -- binds the owner / superuser too

CREATE POLICY aegis_tenant_isolation ON <t>
  USING (
    coalesce(current_setting('app.current_tenants', true), '') = ''
    OR org_id = ANY (string_to_array(current_setting('app.current_tenants', true), ','))
  )
  WITH CHECK ( … same predicate … );
```

The policy reads a per-transaction GUC `app.current_tenants` — a
comma-separated list of org ids the caller may see:

- **Empty / unset GUC ⇒ full access.** This is the **system / worker**
  path. `current_setting(…, true)` returns `NULL` when unset; it is
  coalesced to `''`, and the explicit `= ''` short-circuits before the
  `ANY()`.
- **Otherwise** the row's `org_id` must appear in the list.

`FORCE` is load-bearing. Without it, the table owner (and a superuser)
bypasses policies — which would make the Postgres CI test a no-op. With
`FORCE`, even a superuser connection is bound by the policy, so the
isolation is real and the CI test exercises it.

!!! note "Why `organizations` itself isn't in the RLS set"
    `organizations` is the tenant *root*, not a project-scoped table, so
    `0005` does not force RLS on it (and `0006`, which adds org columns,
    needs no RLS change). The eight scoped tables plus `projects` are the
    rows that carry a tenant key.

---

## The session / middleware seam

The GUC is set per request and cleared after.

- **`aegis/db/session.py`** — `set_current_tenants(org_ids)` pins a
  request-scoped `ContextVar`; `get_session()` issues
  `SELECT set_config('app.current_tenants', :v, is_local => true)` at the
  start of the transaction so the value is scoped to that transaction and
  reset on commit/rollback (no leakage across pooled connections). The
  value is **bound as a parameter**, never interpolated. `None` / empty
  list ⇒ `''` ⇒ system (full access). This is **Postgres-only** —
  `set_config` doesn't exist on sqlite, so unit tests are unaffected.
- **`aegis/api/middleware/tenant.py`** — after auth resolves the caller,
  it computes the distinct org ids of the caller's *member projects* and
  pins them for the request, resetting in a `finally`. System principals
  (`is_system` — workers, service accounts) and callers with no
  memberships get `None` (system scope), so the route's own auth
  dependency decides. The membership lookup itself runs as *system* (the
  scope is set only after it returns), avoiding a chicken-and-egg query.
  If the DB is unavailable the middleware falls back to system scope
  rather than failing the request — RLS is defense-in-depth *behind* the
  route auth, which still gates access.

```mermaid
sequenceDiagram
    autonumber
    participant U as Caller
    participant MW as tenant_middleware
    participant CV as ContextVar
    participant S as get_session
    participant PG as Postgres (RLS)

    U->>MW: request (after auth resolves CurrentUser)
    MW->>MW: distinct org_ids of member projects (system lookup)
    MW->>CV: set_current_tenants([org-1, org-2])
    U->>S: route opens a session
    S->>PG: set_config app.current_tenants 'org-1,org-2' (local)
    PG-->>S: rows filtered to org-1, org-2
    MW->>CV: reset (finally)
```

Workers and migrations never set the GUC, so they run with full access —
exactly what background execution and `alembic upgrade` need.

---

## Per-tenant cost + LLM routing (migration `0006_org_cost_routing`)

Cost accounting and model routing, previously per-project, lift one tier
to the Organization.

### Schema

Migration `0006` adds two nullable columns to `organizations`:

- **`monthly_llm_budget_cents`** (`INTEGER`) — the org's monthly LLM spend
  cap in cents. `NULL` ⇒ uncapped.
- **`llm_model_overrides`** (`JSONB`) — a `{task: model}` map of
  per-tenant routing overrides that win over the config default.

### Budget enforcement

`DbBudgetChecker` (`aegis/llm/budget.py`) gains:

- **`remaining_org(org_id)`** — `monthly_llm_budget_cents` minus this UTC
  calendar month's `llm_usage.cost_cents` for the org (matched on the
  denormalized `LLMUsage.org_id`, falling back to the owning project's
  `org_id` for legacy rows). `None` when uncapped/absent.
- **`model_override(org_id, task)`** — reads
  `organizations.llm_model_overrides[task]`.

`route(..., org_id=…)` (`aegis/llm/router.py`) then:

1. **Model selection** — a per-tenant override
   (`llm_model_overrides[task]`) wins; otherwise the `AegisConfig`
   default. The override is consulted only when both `org_id` and a
   checker exposing `model_override` are supplied, so it degrades to the
   config default absent a DB.
2. **Budget gate** — enforces **both** the project's daily cap **and** the
   org's monthly cap. `BudgetExceeded` is raised if *either* tier is
   exhausted, and the message **names the tier** (project-daily vs
   org-monthly) without leaking spend figures. The reported
   `budget_remaining_cents` is the tighter (smaller) of the two.

### The cost endpoint + dashboard

`GET /v1/orgs/{org_id}/cost?days=30` (`aegis/api/v1/org_cost.py`)
aggregates `llm_usage` for the org into a chargeback view: `total_cents`,
`call_count`, and `by_day` / `by_model` / `by_task` breakdowns over the
trailing `days` window, plus a month-to-date budget block (cap, spent,
remaining). It is gated to **org members** via `ensure_org_access` (a
member of at least one project in the org) — cost visibility is something
a tenant sees for its *own* org, not a cross-tenant forensic surface. The
aggregation filters on `LLMUsage.org_id`, the same column RLS uses, so the
app-layer filter and the DB policy agree.

A **/cost** dashboard page in the web UI renders this endpoint (totals,
per-day/model/task breakdowns, and the monthly budget) with a
7 / 30 / 90-day window selector.

See the [API reference](../api/v1.md#orgs-cost) for the full request /
response shape and the [deployment runbook](../ops/deploy.md) for the
operational notes.
