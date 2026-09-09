# Concepts

Shared domain vocabulary for this project — entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound and ce-compound-refresh process learnings; direct edits are fine. Glossary only, not a spec or catch-all.

## Web session and access

### Redsim session pair
The two cookies a signed-in browser presents to the Redsim API: a signed session cookie the API verifies, and a companion CSRF cookie the browser reads and echoes back as a header on any mutating call.

The pair is minted together and cleared together. For a mutation authenticated by the session cookie, the API compares the echoed header against the cookie on the same request and refuses when they are missing or disagree, so one half without the other is not usable. That comparison applies only to cookie-authenticated mutations: a caller presenting a bearer token is exempt, and reads are never checked.

### Dev token
A stand-in credential naming a user directly, so the app can be driven without an identity provider.

Two independent gates govern it, and they are not the same rule. The API accepts one only when it is running in dev auth mode, and refuses it outright in production. The web layer is stricter about forwarding: it passes a dev token upstream only when its own environment is development or test, so a staging web deployment forwards nothing even where the API would have accepted it.

### Hop token
A token authorising a redirect through the Sign-out hop, bound by HMAC to the particular credential that was just rejected, and valid only for a short window after it is minted.

The binding is what stops a link from another site logging someone out: a token minted against one credential value cannot clear a different one. It is time-bounded rather than single-use, so within its window it can be presented more than once against the same credential. Because the token is bound to a credential, a request arriving with no credential at all has nothing to verify against. That state means the sign-out has already happened, not that the request is hostile, so it lands on the login screen rather than being refused.

### Sign-out hop
The redirect leg that clears the Redsim session pair before the login screen renders. It exists because a page rendered on the server discovers a rejected credential but cannot write cookies itself, so it sends the browser through a route that can. See Hop token.

## Data access

### Upstream
The Redsim API as seen from the web process.

The web server has no caller credential of its own. Every upstream call carries the browser's own credential and nothing else, so the API's per-user rate limits and tenant isolation keep applying to the person actually browsing, and a request that arrives with no credential is refused rather than upgraded. This is about who the call is made as: the web process does separately hold the key that mints session cookies, which is minting authority, not a credential it can call with.

### Honest state
A rendered state that reports exactly what the system knows, chosen from a structured refusal code rather than from parsed message text.

An empty result, a refusal, and an unreachable service each read differently. A value that has not been measured says so rather than showing a plausible substitute, which is the rule that keeps a reader from mistaking absence for a result.

### Fixture mode
A development-only mode in which browser data calls are answered from recorded illustrative rows instead of the Upstream.

Every page says so while it is on, because illustrative rows must never be mistaken for measurements. The mode cannot be enabled outside a development or test environment: the configuration is refused at startup rather than ignored.
