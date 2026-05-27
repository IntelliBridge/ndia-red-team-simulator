# Starter rules bundled with `stig-check`

Thirteen rules ship in the engine at
`packages/stig-check/src/stig_check/starters/`, split across two
benchmarks:

- **8 ASD STIG rules** -- prefix `APSC_DV_*`, `benchmark_id = "asd"`.
- **5 Web Server SRG rules** -- prefix `SRG_APP_WSR_*`,
  `benchmark_id = "websrg"`.

The runner loads them automatically and scopes which apply to a given
`(asset, benchmark)` pair. Consumers can override any one by dropping
`stig/rules/V_NNNNNN.py` with the same `vuln_id` (last registration
wins; the override inherits the same `benchmark_id` unless redeclared).

Use this reference to answer "why is rule X firing as Open / Not
Applicable on asset Y?" without reading the rule source.

## V-222596 / APSC-DV-002440 -- TLS in transit

- **Stacks required:** `fastapi`
- **Paths required:** `backend_config`
- **Passes when:** the backend config file declares `TLS_CERT_PATH`
  and `TLS_KEY_PATH`, AND has a fail-fast gate (`raise SystemExit`,
  `sys.exit(`, or `raise *Error`) that refuses to start in production
  without them.
- **Fails when:** the config doesn't reference those env vars, or
  references them but doesn't enforce.
- **Skipped (`not_applicable`) when:** asset is non-fastapi, or has no
  `backend_config` path key.

## V-222603 / APSC-DV-002500 -- CSRF protection

- **Stacks required:** `fastapi`
- **Paths required:** none (uses `backend_auth` and / or
  `backend_middleware` if either is present)
- **Passes when:** an auth or middleware module references `csrf`
  AND enforces it on POST/PUT/PATCH/DELETE (looks for
  `_validate_session_csrf`, `X-CSRF-Token`, or `HTTPException 403`).
- **Fails when:** csrf is mentioned but not enforced on unsafe
  methods, or absent entirely.

## V-222602 / APSC-DV-002490 -- XSS protection

- **Stacks required:** none (rule self-checks for either
  `backend_middleware` or `frontend_src`)
- **Passes when:** the backend middleware emits
  `Content-Security-Policy` and `X-Content-Type-Options` headers, AND
  the frontend source has no `dangerouslySetInnerHTML`.
- **Fails when:** middleware lacks those headers, or frontend uses
  dangerouslySetInnerHTML.
- **Common confusion:** if the asset is a backend that's fronted by a
  reverse proxy (e.g., DSA backend + PSP7 gateway), the rule
  legitimately fires Open on the backend because the backend doesn't
  emit CSP itself. Either emit it in the backend (defense in depth,
  the right answer) or mark it Not Applicable in STIG Manager with a
  comment naming the gateway as the upstream control.

## V-222526 / APSC-DV-001580 -- MFA in keycloak realm

- **Stacks required:** `keycloak`
- **Paths required:** `keycloak_realm`
- **Passes when:** the realm export's `browser` flow includes an
  `auth-otp-form`, `webauthn`, or `x509` execution.
- **Fails when:** the realm relies on Keycloak's default password-only
  browser flow (most common case for DoD-bound apps that haven't
  wired CAC/PIV yet).
- **Skipped when:** asset doesn't have the keycloak stack.

## V-222389 / APSC-DV-000070 -- Session idle timeout

- **Stacks required:** none (uses `backend_config`, `backend_auth`,
  `keycloak_realm`)
- **Passes when:** every detected session-timeout setting is <= 15
  minutes. Rule recognizes `SESSION_TIMEOUT*`, `_SESSION_TTL`, and
  `ssoSessionIdleTimeout`. Values in seconds (TTL, ssoSessionIdle*,
  *Lifespan, *_SECONDS) are divided by 60.
- **Fails when:** max detected timeout > 15 minutes.
- **Common confusion:** STIG specifies <= 15 min for non-privileged,
  <= 10 for admin. The starter rule only checks the 15-min bound.
  Add a consumer override to check the privileged-vs-non-privileged
  split if needed.

## V-222473 / APSC-DV-000980 -- Audit timestamps

- **Stacks required:** none
- **Paths required:** none (uses `backend_logging`, `audit_events`,
  `audit_logger`)
- **Passes when:** any of those files reference structlog
  TimeStamper, `timestamp`, `isoformat`, or `datetime.now(UTC)`.
- **Fails when:** none found.

## V-222477 / APSC-DV-001020 -- Audit identity

- **Stacks required:** none
- **Paths required:** none (uses `audit_logger` or `audit_events`)
- **Passes when:** the audit module references at least one of
  `user_id`, `user_sub`, `principal`, `agent_id`, `session_id`.
- **Fails when:** none found.

## V-222515 / APSC-DV-001460 -- Vulnerability assessment

- **Stacks required:** none
- **Paths required:** none (repo-wide)
- **Passes when:** all three exist:
  `.github/workflows/trivy-weekly.yml` (with a `severity: CRITICAL`
  gate), `.github/workflows/semgrep.yml`, and
  `sonar-project.properties`.
- **Fails when:** any are missing, or Trivy doesn't gate on CRITICAL.

## Web Server SRG starter rules

These five rules cover the most-violated controls for nginx-fronted
and Fastify-based web servers. They run only on assets where the
`websrg` benchmark applies (declared via the config's `benchmarks:`
block).

### V-206434 / SRG-APP-000439-WSR-000151 -- TLS encryption

- **Stacks required:** `nginx`
- **Paths required:** `nginx_config` (file or directory; directories
  are walked recursively for `*.conf`)
- **Passes when:** every `ssl_protocols` directive lists only
  `TLSv1.2` and/or `TLSv1.3`.
- **Fails when:** any directive lists `SSLv2`, `SSLv3`, `TLSv1.0`,
  or `TLSv1.1`; or no `ssl_protocols` directive is present (we don't
  trust nginx's compiled-in default since it varies by build).

### V-206412 / SRG-APP-000266-WSR-000159 -- Server version disclosure

- **Stacks required:** `nginx`
- **Paths required:** `nginx_config`
- **Passes when:** `server_tokens off;` appears.
- **Fails when:** `server_tokens on;` or `server_tokens build;` is
  set, or no directive is present (nginx defaults to `on`, which
  exposes the version banner).
- **Common confusion:** if your nginx config files only contain
  `server { ... }` blocks (no `http {}` wrapper because the parent
  `nginx.conf` from the base image provides it), the directive needs
  to be added either to those server blocks or to a custom
  `nginx.conf` override included in the image.

### V-206357 / SRG-APP-000092-WSR-000055 -- Session logging

- **Stacks required:** `nginx`
- **Paths required:** `nginx_config`
- **Passes when:** at least one `access_log <destination> ...;`
  directive is configured.
- **Fails when:** any `access_log off;` directive appears (treated as
  a finding even if it's scoped to one location -- review and add a
  consumer override only if the off-bypass is justified, e.g. a
  /healthz endpoint).

### V-206411 / SRG-APP-000266-WSR-000142 -- Directory listing

- **Stacks required:** `nginx`
- **Paths required:** `nginx_config`
- **Passes when:** no `autoindex on;` directive is present
  (defaulting to off is fine), or it's explicitly `autoindex off;`.
- **Fails when:** `autoindex on;` appears anywhere.

### V-260898 / SRG-APP-000439-WSR-000192 -- HTTP/2 enabled

- **Stacks required:** none. The rule self-checks for either `nginx`
  or `fastify` on the asset and runs whichever apply.
- **Paths required:** `nginx_config` (for nginx) and / or
  `server_config` (for Fastify; may be a list of TS/JS files).
- **Passes when:** for nginx, every TLS server block has `http2` in
  its `listen` directive (legacy syntax) or there's a top-level
  `http2 on;` (1.25+); for Fastify, the constructor is invoked with
  `http2: <truthy>` (`true`, `hasCerts`, etc.).
- **Fails when:** the asset declares one of the two stacks but no
  HTTP/2 signal is found.
- **Skipped (`not_applicable`) when:** asset declares neither
  `nginx` nor `fastify`.

## How a consumer override looks

Drop a file at `stig/rules/V_222596.py` (note the underscore -- our
ruff convention skips `N999` for `V_*.py`):

```python
from stig_check.helpers import grep
from stig_check.rules import Rule, RuleContext, RuleResult, register


@register
class CustomTlsRule(Rule):
    vuln_id = "V-222596"  # same as the starter -> shadows it
    stig_id = "APSC-DV-002440"
    requires_stacks = ("fastapi",)
    requires_paths = ("backend_config",)

    def evaluate(self, ctx: RuleContext) -> RuleResult:
        # ... custom logic, e.g. checking a different env-var name
        return RuleResult.not_a_finding("custom TLS gate verified")
```

The runner registers starters first, then consumer rules; last
registration wins per `vuln_id`.
