# Integrations & workflow

Aegis closes the loop from finding to fix; this section covers the seams
that connect that loop to the systems a team already runs — the issue
tracker, the DNS / GitHub control plane that proves who owns a target, and
the release branches a generated fix PR should land against.

Three integration surfaces ship here. All three are **additive and
default-off**: nothing reaches an external tracker, no target's `verified`
flag flips, and no fix PR changes its base branch unless an operator has
explicitly configured them.

| Surface | What it connects | Default |
|---|---|---|
| [Ticket sync](#bidirectional-ticket-sync) | Jira / ServiceNow / Linear | `none` (no-op) |
| [Ownership verification](#cloud-target-ownership-verification) | DNS TXT / GitHub App | targets stay unverified |
| [Backport awareness](#backport-release-train-awareness) | release-train → PR base | `main` |

---

## Bidirectional ticket sync

A finding can be pushed into an external tracker as an issue, and that
issue's status can be pulled back in — a bidirectional sync. The provider
is a pluggable `TicketProvider`
(`aegis/integrations/ticket_provider.py`); one of three backends is
selected at process start from `AEGIS_TICKET_PROVIDER`, and the default
(`none`) is a no-op that refuses every operation with a clear error. So
nothing leaves the platform until an operator both selects a provider
**and** supplies the matching credentials.

### Providers and configuration

Selection: `AEGIS_TICKET_PROVIDER=none|jira|servicenow|linear` (default
`none`). The resolver reads the env var first, then falls back to
`config.ticket_provider`, then to `none`. Credentials are read from the
environment — never from the API body, never persisted, never logged.

=== "Jira"

    Jira Cloud / Server REST v2. Auth is HTTP Basic (user + API token).

    | Var | Notes |
    |---|---|
    | `AEGIS_JIRA_URL` | Base URL, e.g. `https://acme.atlassian.net` |
    | `AEGIS_JIRA_USER` | Account email / username |
    | `AEGIS_JIRA_TOKEN` | API token |
    | `AEGIS_JIRA_PROJECT_KEY` | Project key the issue is created under (e.g. `SEC`) |

    A sync creates a `Bug` issue; the ticket URL is `{base}/browse/{key}`.

=== "ServiceNow"

    ServiceNow Table API (`incident` table). Auth is a Bearer (OAuth) token.

    | Var | Notes |
    |---|---|
    | `AEGIS_SERVICENOW_INSTANCE` | Instance URL, e.g. `https://acme.service-now.com` |
    | `AEGIS_SERVICENOW_TOKEN` | OAuth bearer token |

=== "Linear"

    Linear GraphQL API. Auth is the API key in the `Authorization` header.

    | Var | Notes |
    |---|---|
    | `AEGIS_LINEAR_API_KEY` | Personal / workspace API key |
    | `AEGIS_LINEAR_TEAM_ID` | Team the issue is created in |

Every outbound call uses a short-timeout HTTP client. On failure the error
is wrapped so the message carries only the provider name and (for HTTP
errors) the status code — never the response body or the auth header, so a
stack trace can't leak a token.

### Endpoints

All three live under the findings router. Sync and refresh are gated at the
**`remediator+`** tier (the same bar as `fix.generate` / `verify.replay`);
the list is a read gated by project membership. Each successful sync emits a
secret-free `ticket.sync` audit event (provider + external id only).

| Method & path | What it does | RBAC |
|---|---|---|
| `POST /v1/findings/{id}/ticket` | Push (create-or-update) the finding's ticket | `remediator+` |
| `GET /v1/findings/{id}/tickets` | List tickets recorded for the finding | project member |
| `POST /v1/findings/{id}/tickets/{ticket_id}/refresh` | Pull the external status into the row | `remediator+` |

A sync **upserts** a `FindingTicket` row keyed on `(finding_id,
provider)`, so re-syncing the same finding is idempotent — the first sync
returns `201 Created`, a later sync returns `200 OK` and updates the
existing row. When no provider is configured (the default), sync returns
`409 Conflict` with a clear message rather than inventing a phantom
ticket. The `refresh` endpoint re-queries the tracker and writes the
current status back onto the row — the inbound half of the bidirectional
sync.

The `FindingTicket` table is added by migration `0005_finding_tickets`:
one row per `(finding, provider)` recording `provider` / `external_id` /
`url` / `status` / `synced_at`. **No credential is stored on the row.**

---

## Cloud-target ownership verification

Before a target's `verified` flag is set to `true`, Aegis requires the
operator to prove they actually control it. This gates the `verified`
column on `Target`: an unverified target is registered but unproven.

The verification method is chosen by `Target.kind`
(`aegis/services/target_verify.py`):

- **`url` targets → DNS TXT.** The operator publishes a TXT record on the
  target's host carrying a deterministic per-target token
  (`aegis-site-verification=<digest>`). The token is
  `sha256(project_id:value:secret)[:32]`, where `secret` comes from
  `AEGIS_VERIFY_SECRET` (a dev default is used when unset). Because the
  secret is server-side, an operator can't forge a token for a host they
  don't own; because it's deterministic, the same `(project, target)`
  always yields the same value.
- **`github_repo` targets → GitHub App linkage.** The configured Aegis
  GitHub App installation must be able to access the repo. A `2xx` from
  `GET /repos/{owner}/{name}` through the installation token proves the App
  is installed on (and can see) the repo.
- **`image` targets → unsupported.** A container image has no DNS / GitHub
  ownership channel, so verification returns a clear error.

DNS resolution uses `dnspython`, added to the `api` extra. When it isn't
installed the check degrades to a clear error rather than failing at import
time; NXDOMAIN, no TXT records, and timeouts all surface as a readable
reason, never an exception.

### Endpoints

Both live under the targets router.

| Method & path | What it does | RBAC | Status |
|---|---|---|---|
| `GET /v1/targets/{id}/verification` | Return the TXT record (name + value) or the GitHub-linkage instructions | project member | `200` |
| `POST /v1/targets/{id}/verify` | Run the check; mark `verified=true` on success | `admin` (`TARGET_MANAGE`) | `200` pass / `422` not-yet-proven |

`GET …/verification` is read-only: for a `url` target it returns the exact
TXT `record_name` (the host) and `record_value` (the per-target token) to
publish; for a `github_repo` target it states the installation linkage
required. It never exposes the verification secret.

`POST …/verify` runs the check. On success it sets `verified=true` and
returns `{verified, method, detail, target_id}`; when the request is
well-formed but the operator hasn't yet proven control it returns
`422 Unprocessable Entity` with the reason and leaves `verified`
untouched. An unknown target is `404`. Either outcome emits a secret-free
`target.verify` audit event recording the kind, method, and matched
boolean — never the token or the secret.

---

## Backport / release-train awareness

A generated fix PR can target a release branch other than `main`.
`select_base_branch()` (`aegis/remediate/patch_workflow.py`) resolves the
base from a release-train map sourced from `AEGIS_RELEASE_TRAINS` (or
`config.release_trains`):

- JSON object — `{"2024.1": "release/2024.1"}`, or
- compact form — `2024.1=release/2024.1,2024.2=release/2024.2`.

A hint that matches a train **name** returns its branch; a hint already
shaped like a branch (a known mapping value, or any value when no map is
configured) is used verbatim; an unknown hint or no hint at all falls back
to `main`. The resolution is pure — no git or gh is invoked — and is wired
into `open_pull_request()` via an optional `base_hint`. **Every existing
caller is unchanged:** callers that pass no hint keep targeting `main`
exactly as before.

---

## Not yet shipped

**Iterative agent loops with test execution** — running a generated patch
through the project's test suite and looping the agent on failures — remains
the deferred sub-item of this roadmap line. See the
[Roadmap](../roadmap.md#integrations-workflow).
