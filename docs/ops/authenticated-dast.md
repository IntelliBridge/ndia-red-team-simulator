# Authenticated DAST

This doc is the operator runbook for **authenticated DAST flows**:
scanning the part of an application that lives behind a login. For the
deployment basics (env vars, topology, rotation) see
[`docs/ops/deploy.md`](deploy.md); for the endpoint reference see
[`docs/api/v1.md`](../api/v1.md#auth-profiles).

---

## What auth profiles are

An **auth profile** is a stored credential a DAST scanner replays while
crawling a target — a session cookie, a bearer token, a custom API
header, or a form login. Profiles live in the `auth_profiles` table
(migration `0005_auth_profiles`); the secret half is **Fernet-encrypted
at rest** and the API **never** returns it. Four kinds:

| Kind     | Non-secret `config` keys                                          | The `secret` is        |
|----------|-------------------------------------------------------------------|------------------------|
| `form`   | `login_url`, `username_field`, `password_field`, `username`       | the password           |
| `bearer` | *(none)*                                                          | the bearer token       |
| `header` | `header_name`                                                     | the header value       |
| `cookie` | `cookie_name`                                                     | the cookie value       |

At scan time the worker resolves the profile, decrypts the secret, and
hands the adapter a single header to replay on every request:

- **`bearer`** → `Authorization: Bearer <secret>`.
- **`header`** → `<header_name>: <secret>`.
- **`cookie`** → `Cookie: <cookie_name>=<secret>`.
- **`form`** → a pre-flight `POST` to `login_url` with the configured
  username/password fields; the session cookies the login response sets
  are forwarded as the `Cookie` header. A failed login (HTTP error, no
  cookies set) fails the scan with a secret-free error.

Two adapters consume profiles today: **`zap`** (header via the
`ZAP_AUTH_HEADER` / `ZAP_AUTH_HEADER_VALUE` subprocess env vars — the
secret never appears in argv) and **`nuclei`** (native `-H` flag).
Other scanners ignore `auth_profile_id`.

---

## Setting up the encryption key

Profiles cannot be created — and authenticated scans cannot run —
without the Fernet key. Generate one:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set it as `AEGIS_AUTH_PROFILES_KEY` on **both** the API (encrypts on
create) and the worker (decrypts at scan time):

| Var                       | Where set   | Value                                   |
|---------------------------|-------------|------------------------------------------|
| `AEGIS_AUTH_PROFILES_KEY` | api, worker | Fernet key (32 url-safe base64 bytes)   |

Keep it in the same secret store as the other key material from the
[deploy doc](deploy.md#required-env-vars) — never in `aegis.yaml`.
A missing or malformed key **fails closed** with a clear error
(`AuthProfilesKeyError`); there is no plaintext fallback. On create the
encryption happens *before* the audit row and the DB insert, so a
missing key can't leave a half-state.

### Key rotation

There is no dual-key decryption window (unlike the
[worker SA key](deploy.md#rotation-runbook)). Ciphertexts written under
the old key **cannot be decrypted** after a rotation — an authenticated
scan against a stale profile fails with `InvalidToken`. The runbook is:

```
Step 1:  generate the new key; set AEGIS_AUTH_PROFILES_KEY on api +
         worker; rolling restart.
Step 2:  re-create every auth profile (delete + create via UI or API).
         Each create/delete lands on the audit chain, so the rotation
         itself is forensically visible.
```

Profiles are cheap to re-create by design — treat them as cattle, not
pets.

---

## Creating profiles

Writes are **admin-gated** (policy action `auth_profile.manage`,
mirroring target management) and every create/delete emits a chained
`auth_profile.create` / `auth_profile.delete` audit event **before**
the row is touched.

**UI**: the `/auth-profiles` page in `@aegis/web` lists a project's
profiles and (for admins) offers the create/delete form with per-kind
fields.

**API** — one example per kind:

```bash
# form: pre-flight login POST; the secret is the password
curl -X POST "$AEGIS_API/v1/auth-profiles" \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "project_id": "proj-a",
    "name": "juice-shop-login",
    "kind": "form",
    "config": {
      "login_url": "http://localhost:3000/rest/user/login",
      "username_field": "email",
      "password_field": "password",
      "username": "scanner@aegis.local"
    },
    "secret": "the-password"
  }'

# bearer: no config; the secret is the token
curl -X POST "$AEGIS_API/v1/auth-profiles" \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{"project_id": "proj-a", "name": "api-token", "kind": "bearer",
       "config": {}, "secret": "eyJhbGciOi…"}'

# header: named header; the secret is its value
curl -X POST "$AEGIS_API/v1/auth-profiles" \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{"project_id": "proj-a", "name": "x-api-key", "kind": "header",
       "config": {"header_name": "X-API-Key"}, "secret": "k-123…"}'

# cookie: named cookie; the secret is its value
curl -X POST "$AEGIS_API/v1/auth-profiles" \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{"project_id": "proj-a", "name": "session-cookie", "kind": "cookie",
       "config": {"cookie_name": "session"}, "secret": "s%3A…"}'
```

Each returns `201` with the profile's non-secret fields (`id`,
`project_id`, `name`, `kind`, `config`, `created_at`) — the secret is
gone the moment it's encrypted. A duplicate `(project_id, name)` is
`409`. Listing (`GET /v1/auth-profiles?project=proj-a`) needs only
project membership; deleting (`DELETE /v1/auth-profiles/{id}` → `204`)
is admin-gated like create.

---

## Attaching a profile to a scan

Pass the profile **id** (never the secret) as `auth_profile_id` on
[`POST /v1/scans`](../api/v1.md#scans):

```bash
curl -X POST "$AEGIS_API/v1/scans" \
  -H "Authorization: Bearer $AEGIS_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "project_id": "proj-a",
    "scanner": "zap",
    "auth_profile_id": "authprof-1a2b3c4d5e6f"
  }'
```

In the UI, the Targets-page scan form shows an optional auth-profile
picker when the selected scanner is `zap` or `nuclei`. Only the id
travels through admission and `Job.detail`; the worker decrypts at
execution time. If the profile is unknown — or the worker is missing
the key — the job fails with a secret-free error naming the profile id
and the failure class.

---

## Security properties

- **Encrypted at rest** — only `secret_ciphertext` (Fernet) is
  persisted; the plaintext is never stored or logged.
- **Never returned** — no endpoint includes the secret (or anything
  derived from the ciphertext) in a response.
- **Redacted command trail** — recorded command strings replace the
  secret with `***`; ZAP receives it via subprocess env, never argv.
  Audit `detail` payloads carry only non-secret metadata (profile id,
  name, kind).
- **Admin-gated** — create/delete require the `admin` role on the
  project (`auth_profile.manage`), exactly like target management.
- **Audited** — every create/delete lands a chained
  `auth_profile.create` / `auth_profile.delete` event before the DB
  mutation, so `aegis audit verify` covers credential lifecycle too.
- **Fails closed** — a missing/invalid `AEGIS_AUTH_PROFILES_KEY`
  raises a clear error; there is no silent plaintext path.
