# `stig-check validate` advisory codes

The validate command emits one of these codes per advisory. Use this
to interpret output and propose fixes without re-reading
`packages/stig-check/src/stig_check/validate_cmd.py`.

## `missing-keycloak` (WARN)

A `realm-export.json` (with a `realm` key) exists in the repo, but no
asset declares the `keycloak` stack. Common cause: the realm sits
beside `apps/<x>/{backend, frontend}` rather than inside one of them,
and auto-detect drops parent-level detections when sub-roles take
over.

**Fix.** Add `keycloak` to the appropriate asset's `stacks` and
`keycloak_realm: <path>` to its `paths`. The advisory includes the
detected file path verbatim -- copy it.

## `keycloak-missing-path` (WARN)

The asset declares the `keycloak` stack but no `keycloak_realm` path.
The MFA rule (V-222526) will return `not_applicable`. Add the path
or remove the stack.

## `library-fan-out` (INFO)

Three or more assets are tagged `python-lib` only. Libraries usually
don't have independent deployment surfaces; STIG controls collide
across them. **Ask the user** before consolidating -- both shapes are
valid:

- **Consolidated:** one `<repo>-libs` asset with `audit_logger` /
  `audit_events` paths from the most central package. One row in
  eMASS. Simpler to review.
- **Split:** N separate assets, one per package. N rows in eMASS.
  Useful when libraries ship to different consumers.

If unsure, default to consolidation -- it's the easier-to-review
shape, and STIG Manager isn't great at managing many tiny assets.

## `stack-path-mismatch` (INFO)

Asset declares a stack but no related path keys. Example:
`stacks: [fastapi]` but no `backend_config` / `backend_auth` /
`backend_middleware` / `backend_logging`. Rules requiring those paths
will return `not_applicable` for the asset, which is technically
correct but loses signal.

**Fix.** Either add the path keys, or remove the stack if it isn't
really part of this asset.

## `orphan-path` (INFO)

A path key exists on the asset, but none of its justifying stacks
are declared. Example: `paths: { backend_config: ... }` on an asset
with `stacks: [react]`. Almost always a typo or a copy-paste from
another asset.

**Fix.** Either remove the path key, or add the appropriate stack.
The advisory message lists which stacks would justify the key.

## `dockerfile-not-pinned` (INFO)

Dockerfiles exist in the repo but no asset has them pinned in its
`dockerfile` path key. No starter rule consumes `dockerfile` yet, so
this is purely advisory -- but new container-related starter rules
will skip these assets.

**Fix.** Add `dockerfile: <path>` to the asset whose runtime image
that Dockerfile builds. Often there's a 1:1 mapping
(`apps/<x>/backend/Dockerfile` -> `<x>-backend`).

## `undeclared-stack` (INFO)

The detector found stacks in the repo but no asset declares them.
Common after consolidation -- e.g., consolidating sub-role splits
drops `nginx` because the parent asset didn't declare it.

**Fix.** Often intentional after manual edits; verify with the user
before changing anything. If it's a real miss, add the stack to the
appropriate asset.

## Web Server SRG context

These advisory codes apply to ASD-flavored detections. The Web Server
SRG flow uses the same machinery, so a few of the codes appear in
webserver contexts too:

- **`undeclared-stack`** -- the detector found `nginx` config files
  in the repo but no asset declares the `nginx` stack. Common cause:
  the asset proposal collapsed an nginx-fronted frontend into a
  combined asset that didn't carry the stack forward. Fix by adding
  `nginx` to that asset's `stacks` and an `nginx_config` path key.
- **`orphan-path`** -- an asset declares `nginx_config` but no
  `nginx` stack (or `server_config` but no `fastify` stack). The
  Web Server SRG starter rules will skip the asset. Fix by adding
  the missing stack.
- **`dockerfile-not-pinned`** -- nginx + Fastify assets often have
  Dockerfiles in the repo that aren't pinned to any asset. Pin them
  to enable future container-related starter rules.

Web-server-specific advisories (e.g. "asset declares `nginx` but no
TLS conf was found", "Fastify constructor missing the
`TLS_CERT_PATH` gate") are **not yet** emitted by the validator. Open
findings on the corresponding starter rules are the canonical signal
today; add a consumer rule at `stig/rules/V_NNNNNN.py` to refine the
check on a per-asset basis.

## Severity meanings

- **ERROR** (currently unused): hard config error, exits non-zero.
- **WARN**: real correctness issue, but doesn't block running rules.
  The user should fix before considering the config "clean."
- **INFO**: hint or coverage gap. Worth thinking about, doesn't have
  to block.

`stig-check validate --strict` exits non-zero on WARN-or-higher,
useful as a CI gate.
