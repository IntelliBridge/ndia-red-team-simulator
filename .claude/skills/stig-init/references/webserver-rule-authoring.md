# Authoring a Web Server SRG rule

This doc backs the "Authoring a new automated check rule" flow in
`SKILL.md` when the control comes from the **Web Server SRG**
(`U_Web_Server_*_SRG.zip`, benchmark id `websrg`). The general rule
contract and `RuleContext` API are shared with ASD; read
`rule-authoring.md` first if you're new to the engine.

What's *different* for Web Server SRG rules:

- **`benchmark_id = "websrg"`** must be set on the class. Defaults to
  `"asd"`, which would file the result under the wrong checklist.
- **Filename prefix** is `SRG_APP_WSR_<vuln_short>_<slug>.py` for
  starter rules in the engine, or the usual `V_NNNNNN.py` for
  consumer rules in `stig/rules/`. The prefix matters only for
  starter discovery.
- **Common stacks:** `nginx`, `fastify`, `apache` (no starters yet),
  `iis` (no starters yet). Pick the stack that *implements* the
  control, not just the one that fronts it.
- **Common path keys:** `nginx_config`, `nginx_http_config`,
  `server_config`. Use the helper at
  `stig_check.starters._webserver_paths.nginx_conf_paths(ctx, key)`
  if your rule needs to walk a directory of `.conf` files (frontends
  often point at a directory; gateways often point at a single file).

## Picking the rule shape

The same three templates from `rule-authoring.md` apply. The choice
for webserver rules is usually:

| Symptom in the XCCDF check | Template |
|---|---|
| "verify that <directive> is set in nginx.conf to <value>" | A (grep) |
| "the application server must be configured to..." (Fastify ctor / Helm values.yaml / Express middleware list) | B (structural parse) |
| "send a probe request and verify the response header / status" | C (command exec, gated on `--live`; do not use in CI by default) |

## Template A -- nginx grep

Use for directives that live verbatim in an nginx `.conf` file.

```python
from stig_check.helpers import evidence_lines, grep
from stig_check.rules import Rule, RuleContext, RuleResult, register
from stig_check.starters._webserver_paths import nginx_conf_paths


@register
class HstsRule(Rule):
    vuln_id = "V-NNNNNN"
    stig_id = "SRG-APP-XXXXXX-WSR-XXXXXX"
    benchmark_id = "websrg"
    requires_stacks = ("nginx",)
    requires_paths = ("nginx_config",)

    def evaluate(self, ctx: RuleContext) -> RuleResult:
        confs = nginx_conf_paths(ctx, "nginx_config")
        if not confs:
            return RuleResult.not_applicable(
                "no nginx .conf files found under the asset's nginx_config path"
            )
        rel = [str(p.relative_to(ctx.repo_root)) for p in confs]
        hits = grep(
            ctx,
            r'^\s*add_header\s+Strict-Transport-Security\s+"max-age=\d+',
            paths=rel,
        )
        if not hits:
            return RuleResult.open(
                "no Strict-Transport-Security header configured",
                evidence="searched: " + ", ".join(rel),
                finding_details=(
                    "Add `add_header Strict-Transport-Security \"max-age=63072000; "
                    "includeSubDomains; preload\" always;` to the TLS server block."
                ),
            )
        return RuleResult.not_a_finding(
            "HSTS header configured", evidence=evidence_lines(hits, ctx.repo_root)
        )
```

**Pitfalls:**

- `^\s*` anchors are important. Without them, `grep` will match
  commented-out directives that happen to share the keyword.
- nginx config is *line-oriented*, but a single directive can wrap
  via line-continuation. Most starters ignore that and accept the
  single-line form is what you'll see in production.
- Frontends often point at a *directory* of `.conf` files (e.g.
  `apps/<x>/frontend/nginx`). Use `nginx_conf_paths`, not
  `ctx.paths_for` directly, so directories get walked.
- A nginx config in this repo may be only a `server { ... }` block
  that gets included by the base image's `/etc/nginx/nginx.conf`.
  Top-level `http {}` directives (like `server_tokens`) won't be in
  the included file; the rule legitimately fires Open and the team
  fixes it by adding a custom `nginx.conf` override or scoping the
  directive into the server block.

## Template B -- Fastify / Express constructor parse

Use when the control lives in TypeScript / JavaScript source -- a
constructor argument, a middleware registration, an env-var gate.

```python
import re
from stig_check.rules import Rule, RuleContext, RuleResult, register


@register
class FastifyHelmetRule(Rule):
    vuln_id = "V-NNNNNN"
    stig_id = "SRG-APP-XXXXXX-WSR-XXXXXX"
    benchmark_id = "websrg"
    requires_stacks = ("fastify",)
    requires_paths = ("server_config",)

    _HELMET_REGISTER = re.compile(r"\.register\s*\(\s*helmet\b")

    def evaluate(self, ctx: RuleContext) -> RuleResult:
        for path in ctx.paths_for("server_config"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if self._HELMET_REGISTER.search(text):
                return RuleResult.not_a_finding(
                    "@fastify/helmet registered",
                    evidence=f"{path.relative_to(ctx.repo_root)}",
                )
        return RuleResult.open(
            "no @fastify/helmet plugin registration found",
            finding_details=(
                "Run `pnpm add @fastify/helmet` and call "
                "`app.register(helmet, { ... })` early in the server bootstrap."
            ),
        )
```

**Pitfalls:**

- `Fastify(...)` and `fastify(...)` are both common (default-import
  vs. named alias). Make patterns case-flexible: `[Ff]astify`.
- Production code often toggles features behind a flag
  (`http2: hasCerts`). Match `not false` instead of `== true` to
  avoid false negatives. The HTTP/2 starter uses
  `http2\s*:\s*(?!false\b)\S+`.
- Multiple TS files often share responsibility -- entrypoint
  (`index.ts`) calls a builder (`server.ts`) that calls
  `Fastify({...})`. Set `server_config` to a YAML list of both files
  so your rule sees the constructor.

## Template C -- live HTTP probe

Use sparingly. CI can't reach the deployed cluster; live checks
belong on a separate dev/cluster runner.

```python
import json
from stig_check.rules import Rule, RuleContext, RuleResult, register


@register
class TlsHandshakeRule(Rule):
    vuln_id = "V-NNNNNN"
    stig_id = "SRG-APP-XXXXXX-WSR-XXXXXX"
    benchmark_id = "websrg"
    requires_stacks = ("nginx",)
    applies_to = ()  # caller asserts this asset is reachable

    def evaluate(self, ctx: RuleContext) -> RuleResult:
        # `nginx -T -c <conf>` is offline; `openssl s_client` is online.
        # Prefer offline when both work.
        result = ctx.run(
            "nginx", "-T", "-c", str(ctx.paths_for("nginx_config")[0]),
            timeout=15,
        )
        if result.exit_code != 0:
            return RuleResult.open(
                "nginx config syntax check failed",
                evidence=result.stderr[-1500:],
            )
        return RuleResult.not_a_finding(
            "nginx config parses cleanly",
            evidence=result.stdout[-1000:],
        )
```

If you do go live (curl, openssl s_client), guard the call with an
env-var check (e.g. `if not os.environ.get("STIG_LIVE_PROBES"):
return RuleResult.not_reviewed("live probe disabled")`) so CI runs
don't try to reach an unreachable host.

## Stack-to-control cheat sheet (for the in-tree Web Server SRG)

When triaging a control by id, this maps the most common config
surfaces:

| Control family | nginx surface | Fastify surface | Helm / Ingress surface |
|---|---|---|---|
| TLS protocol floor | `ssl_protocols`, `ssl_ciphers` | https options + ALPN | `tls.minimumVersion`, `nginx.ingress.kubernetes.io/ssl-protocols` |
| Server identity disclosure | `server_tokens`, `add_header Server` | hide `X-Powered-By`, `disablePoweredByHeader` | annotation `add_header` overrides |
| Logging | `access_log`, `error_log` | logger config (pino), `requestIdHeader` | `log-format`, `enable-access-log` |
| Session / cookie hardening | `proxy_cookie_*`, `add_header Set-Cookie` | `@fastify/cookie`, `@fastify/secure-session` | n/a (per-app) |
| Directory listing | `autoindex` | static-file plugin options | n/a |
| HTTP/2 / 3 | `listen ... http2`, `http2 on;` | constructor `http2: true` | annotation `nginx.ingress.kubernetes.io/use-http2` |
| Rate limiting / DoS | `limit_req`, `limit_conn` | `@fastify/rate-limit` | annotation `nginx.ingress.kubernetes.io/limit-rps` |
| Hidden / VCS file blocking | `location ~ /\.(git\|env\|svn)` | static-file plugin filters | n/a |
| Security headers | `add_header CSP / X-Frame-Options / ...` | `@fastify/helmet` | annotation `more_set_headers` |

## When to write a consumer override instead

If a starter rule fires Open on an asset for a *justifiable* reason
specific to that deployment (e.g. `access_log off;` is correct for a
static-asset bypass), don't suppress -- write a consumer override at
`stig/rules/V_NNNNNN.py` with the same `vuln_id` and a refined
check. The runner shadows starter rules by `vuln_id`, so a consumer
override transparently replaces the bundled rule for that repo
without touching engine code.
