# Concepts

Shared domain vocabulary for this project — entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound and ce-compound-refresh process learnings; direct edits are fine. Glossary only, not a spec or catch-all.

## Web session and access

### Redsim session pair
The two cookies a signed-in browser presents to the Redsim API: a signed session cookie the API verifies, and a companion CSRF cookie the browser reads and echoes back as a header on any mutating call.

The pair is minted together and cleared together. One without the other is not a usable credential, because the API compares the echoed header against the cookie on the same request and refuses a mutation that carries only one.

### Dev token
A stand-in credential naming a user directly, which the API accepts only in a development or test environment. It exists so the app can be driven without an identity provider, and any environment outside that allowlist refuses it.

### Hop token
A short-lived token authorising one redirect through the Sign-out hop, bound by HMAC to the particular credential that was just rejected.

The binding is what stops a link from another site logging someone out: a token minted against one credential value cannot clear a different one. Because the token is bound to a credential, a request arriving with no credential at all has nothing to verify against. That state means the sign-out has already happened, not that the request is hostile, so it lands on the login screen rather than being refused.

### Sign-out hop
The redirect leg that clears the Redsim session pair before the login screen renders. It exists because a page rendered on the server discovers a rejected credential but cannot write cookies itself, so it sends the browser through a route that can. See Hop token.

## Data access

### Upstream
The Redsim API as seen from the web process.

The web server holds no service credential of its own. It forwards the browser's own credential on every upstream call, so the API's per-user rate limits and tenant isolation keep applying to the person actually browsing.

### Honest state
A rendered state that reports exactly what the system knows, chosen from a structured refusal code rather than from parsed message text.

An empty result, a refusal, and an unreachable service each read differently. A value that has not been measured says so rather than showing a plausible substitute, which is the rule that keeps a reader from mistaking absence for a result.

### Fixture mode
A development-only mode in which browser data calls are answered from recorded illustrative rows instead of the Upstream.

Every page says so while it is on, because illustrative rows must never be mistaken for measurements. The mode cannot be enabled outside a development or test environment: the configuration is refused at startup rather than ignored.
