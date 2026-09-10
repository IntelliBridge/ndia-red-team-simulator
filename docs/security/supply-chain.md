# Supply-chain integrity

Redsim ships two complementary supply-chain controls so that the code you
run can be tied back to the author who vouched for it:

1. **Signed third-party plugins**, opt-in Ed25519 verification of the
   third-party scanner and attack adapters discovered through the
   [marketplace seam](../dev/extending.md#third-party-plugins-marketplace).
2. **Signed + attested release images**, keyless [cosign](https://docs.sigstore.dev/cosign/overview/)
   signatures, a CycloneDX SBOM, and SLSA provenance on the four service
   images, all produced in CI at release time.

Both are layered on top of existing behaviour: plugin enforcement is
**off by default** (the marketplace works exactly as before until you
opt in), and image signing runs only on `v*` release tags, it never
touches a PR build.

---

## Signed third-party plugins

### Why

Loading a marketplace plugin runs its code **in-process** inside the API
and worker, same privileges, same secrets, same network (see the
[allowlist danger note](../dev/extending.md#security-the-redsim_plugins_allow-allowlist)).
The `REDSIM_PLUGINS_ALLOW` distribution allowlist plus a pinned lockfile
bound *which* distributions load; signature verification adds the missing
piece, **cryptographic proof of authorship**, bound to the exact code
that will run.

### The trust model

A plugin signature covers a deterministic payload built by
`redsim.supply_chain.signing.canonical_plugin_payload`:

```text
redsim-plugin\n<dist_name>\n<version>\n<sha256-of-factory-module-source>
```

The trailing field is the SHA-256 of the *source file* that defines the
plugin's factory. Because the signature binds to the factory module's
source, a signature can only authorise the code that actually runs, swap
the implementation and the digest (and therefore the required signature)
changes, invalidating any prior signature.

- **Signature file**, a *detached* raw Ed25519 signature (64 bytes),
  stored **hex-encoded** in a file named `<dist_name>-<version>.sig`
  (`<dist_name>.sig` when the version is unknown).
- **Trusted keys**, Ed25519 **public** keys in PEM form. The signature
  must verify under at least one of them.
- **`key_id`**, the SHA-256 (hex) of the matching public key's raw
  bytes. A verified plugin carries its `key_id` so an operator can tell
  *which* trusted key vouched for it. Key bytes and signature bytes are
  never logged, only `key_id` digests and concise reasons.

### Enabling enforcement

Enforcement is opt-in via three environment variables (read at process
start; set them on the **API**, **worker**, and **CLI** alike, exactly as
with `REDSIM_PLUGINS`):

| Var | Purpose |
|-----|---------|
| `REDSIM_PLUGINS_REQUIRE_SIGNATURE` | Set to `1` (or `true`/`yes`/`on`) to require a valid signature before any third-party plugin loads. Unset/`0` = today's behaviour (no signature check). |
| `REDSIM_PLUGINS_TRUSTED_KEYS` | Colon/comma-separated list of `*.pem` **public-key** files and/or directories of them. The signature must verify under one of these. |
| `REDSIM_PLUGINS_SIG_DIR` | Colon/comma-separated directories where the `<dist>-<version>.sig` files live. Falls back to the trusted-key directories, then the plugin's own module directory, so a self-contained key+sig directory works with no extra config. |

```bash
export REDSIM_PLUGINS=1                       # marketplace discovery on
export REDSIM_PLUGINS_REQUIRE_SIGNATURE=1     # require signatures
export REDSIM_PLUGINS_TRUSTED_KEYS=/etc/redsim/trusted-keys
export REDSIM_PLUGINS_SIG_DIR=/etc/redsim/plugin-sigs
```

!!! note "Enforcement is independent of the allowlist"
    `REDSIM_PLUGINS_ALLOW` and signature enforcement are separate gates and
    compose: a plugin can be skipped for not being in the allowlist *and*
    a plugin in the allowlist can still be rejected for a missing or
    invalid signature. For a hardened production posture, pin the
    distributions **and** require signatures.

### Verification behaviour

When enforcement is on, each discovered plugin's distribution signature is
checked **before** the plugin is registered:

- A plugin with a **valid** signature loads normally and carries its
  `key_id`, `redsim plugins list` shows `yes:<first-12-of-key_id>` in the
  **SIGNED** column.
- A plugin that is **unsigned or whose signature does not verify** is
  **rejected** (not loaded) with a concise reason (`no signature found`,
  `signature does not verify`, `no trusted keys`) and surfaces as
  `rejected` in `redsim plugins list`.
- One bad plugin never crashes discovery or sidelines a healthy one, the
  same resilience guarantee as Protocol-conformance validation.

When enforcement is **off** (the default) the SIGNED column shows `-` for
every plugin and no signature is checked.

```text
$ REDSIM_PLUGINS=1 REDSIM_PLUGINS_REQUIRE_SIGNATURE=1 \
  REDSIM_PLUGINS_TRUSTED_KEYS=/etc/redsim/trusted-keys redsim plugins list
NAME       KIND     DISTRIBUTION          VERSION  STATUS    SIGNED         DETAIL
my-attack  scanner  my-redsim-plugin       0.1.0    loaded    yes:1f3c9a02b1
acme-dast  scanner  acme-scanners         2.3.0    rejected  -              signature rejected: no signature found
```

### Signing a plugin (authoring)

A plugin author signs their own distribution with the CLI. It resolves the
`GROUP:NAME` entry point to its factory, digests the factory module's
source, signs the canonical payload with an Ed25519 **private** key, and
writes the detached `<dist>-<version>.sig`:

```bash
redsim plugins sign \
  --dist my-redsim-plugin --version 0.1.0 \
  --entry-point redsim.scanners:my_attack \
  --key your-ed25519-private-key.pem \
  --out ./signing            # optional; defaults to the current directory
```

It prints the signature path and the `key_id` operators must trust. Ship
the **public** key to operators (it is safe to publish); the private key
stays with the author. Re-run `sign` whenever the factory module's source
changes, the digest, and therefore the signature, moves with it.

!!! tip "Generate a keypair"
    Any Ed25519 keypair works (e.g. `openssl genpkey -algorithm ed25519`).
    Redsim only needs the **public** half as a trusted key; the private half
    is the author's signing secret and is never read by the platform at
    verification time.

### Trying it out

The upstream aegis reference plugin bundle (`examples/aegis-plugin-example/`)
is not carried in this fork, so there is no committed signed example. To
exercise enforcement end to end: generate an Ed25519 keypair, install a
plugin distribution that exposes a `redsim.scanners` entry point, sign it
with `redsim plugins sign`, and point the three variables at the output:

```bash
REDSIM_PLUGINS=1 \
REDSIM_PLUGINS_REQUIRE_SIGNATURE=1 \
REDSIM_PLUGINS_TRUSTED_KEYS=./signing/keys \
REDSIM_PLUGINS_SIG_DIR=./signing \
  redsim plugins list
```

A verified plugin shows `status=loaded` with a `yes:<key_id>` SIGNED
cell. An unsigned plugin is `rejected` ("no signature found") and never
registered. The ML attack adapters under `redsim/ml/attacks/` will
register through the same generic registry (entry-point group
`redsim.ml.attacks`), so the same allowlist and
signature gates apply to third-party attacks.

---

## Signed + attested release images

The four service images (`api`, `worker`, `web`, `log_ingest`) are signed
and attested at release time by
[`.github/workflows/release-sign.yml`](https://github.com/IntelliBridge/ndia-red-team-simulator/blob/main/.github/workflows/release-sign.yml),
which runs **only on `v*` tags**, it is the release-only, push-and-sign
counterpart to the no-push PR `docker-images` build. Everything executes in
GitHub Actions; it cannot be run locally.

For each image the workflow:

1. **Builds and pushes** the image to GHCR (`ghcr.io/<owner>/ndia-red-team-simulator/<service>`)
   and captures the pushed **digest**.
2. **Keyless-signs** the image **by digest** with cosign using the ambient
   GitHub OIDC token (`id-token: write`). No private keys are stored
   anywhere, the signing identity is the workflow itself, recorded in a
   Fulcio-issued certificate and logged to the Rekor transparency log.
3. **Generates a CycloneDX SBOM** with Syft and attaches it as a cosign
   **attestation** (`--type cyclonedx`).
4. **Generates SLSA-3 build provenance** via the official
   `slsa-framework/slsa-github-generator` reusable workflow, which produces
   signed, non-falsifiable provenance from an isolated builder and attaches
   it to the image in GHCR.

### Operator verification (before deploy)

Verify each image **by digest** before you deploy it. The signing identity
is this repo's release workflow on a tag; the OIDC issuer is GitHub's
Actions token service. Replace `<service>` with `api | worker | web |
log_ingest` and `<DIGEST>` with the image's `sha256:…` digest. A helper
lives at `scripts/verify-release.sh`.

```bash
IMAGE="ghcr.io/intellibridge/ndia-red-team-simulator/<service>@<DIGEST>"
IDENTITY='^https://github.com/IntelliBridge/ndia-red-team-simulator/.github/workflows/release-sign.yml@refs/tags/v.*$'
ISSUER='https://token.actions.githubusercontent.com'

# 1. Verify the keyless image signature.
cosign verify \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"

# 2. Verify the SBOM attestation (CycloneDX).
cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"

# 3. Verify the SLSA provenance attestation. The provenance is signed by
#    the slsa-github-generator reusable workflow, so its identity differs
#    from this repo's workflow:
cosign verify-attestation --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/slsa-framework/slsa-github-generator/.*$' \
  --certificate-oidc-issuer "$ISSUER" \
  "$IMAGE"
```

The simplified operator command (matching any release identity under this
repo) is:

```bash
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/IntelliBridge/ndia-red-team-simulator/' \
  <image>@<digest>
```

Wire these into your deploy pipeline so a tampered or unsigned image fails
the gate before `docker compose up` / `kubectl apply`, see the
[pre-deploy verification step](../ops/deploy.md#verify-release-images-before-deploy).

!!! note "Verify by digest, not tag"
    cosign signs the image **digest**, so always verify (and deploy) the
    `@sha256:…` pinned reference. A floating tag can be re-pointed after
    verification; a digest cannot.

---

## garak and the LLM probe domain

The LLM red-teaming track (`redsim/ml/llm/`) drives
NVIDIA garak 0.16 through its OpenAI-compatible generator pointed at the
Pythia gateway. The `garak` extra (`pyproject.toml`, pinned `garak>=0.16,<0.17`)
pulls in the `openai` and `litellm` client libraries and their own transitive
tree. What that means for the supply chain, and how it is bounded:

- **Where the extra is installed.** No deploy image installs it:
  `deploy/Dockerfile.worker` installs `.[worker,ml]` and `Dockerfile.api`
  `.[api,worker]`. It is installed in two CI lanes (`garak offline`, and
  `e2e-python` for the e2e-gated `tests/e2e/test_ml_llm.py`) and on a
  developer venv that opts in. An operator who wants probe runs installs it
  on the worker's `default` pool, the only pool with egress; the transitive
  provider SDKs then exist there and nowhere else.
- **No configuration path reaches those SDKs.** No provider key variable
  exists anywhere (`.env.example` names `PYTHIA_API_KEY` as the only LLM
  credential, and the probe key lives encrypted in a bearer `AuthProfile`,
  never in the environment). `redsim/ml/llm/generator.py::PythiaGenerator`
  posts `model`, `messages`, `temperature` and `max_tokens` only to the
  configured gateway with the caller-supplied key and `max_retries=0`;
  `assert_no_litellm` checks that litellm never enters the generator's class
  hierarchy; the probe child (`python -m redsim.ml.llm.probe_child`) runs
  under the plugin sandbox's interpreter allowlist with every `PYTHIA_*`,
  `AWS_*`, `KAGGLE*`, `OPENAI*`, `HF_TOKEN` and `REDSIM_*` secret swept, reads
  the key from a 0600 file it deletes at once, pins the garak version before
  garak imports and configures garak through a written `garak.yaml`, never
  argv; `redsim/llm/pricing.py` snapshots the environment around its own
  `litellm` import so a cost lookup can never seed the process from a
  developer's `.env`; and `tests/test_api_process_has_no_ml.py` builds the
  API with `garak`, `openai` and `litellm` blocked.
- **Offline by construction in CI.** The two lanes export no gateway
  variable and the tests point the generator at
  `tests/ml/fake_openai_server.py` on the loopback interface with a
  low-entropy fake token. The `garak offline` job fails when nothing was
  collected, when no test passed or when the extra is missing, so an absent
  dependency can never read as a green lane.
- **What garak ships.** garak loads its bundled probe corpora from the
  installed package; redsim re-packages none of them and commits no prompt
  text. The public data repository carries a copy of that directory with the
  licence recorded per subset. Prompts are untrusted data sent only to an explicitly
  entitled Pythia persona under the permission-gate-only guardrail default.
- **Scanning.** `pip-audit` audits the resolved `api,worker,security`
  environment, which excludes the `garak` and `ml` extras; the release
  workflow's Syft SBOM covers the shipped worker image, which carries neither.
  An operator who installs the extra on a worker should audit that
  environment separately.

## Signed release images: what's still deferred

**Nix reproducible builds** remain deferred as the last remaining piece of supply-chain hardening, bit-for-bit
reproducible builds so the published image can be independently rebuilt and
compared. Signed plugins, sigstore image signing, the SBOM attestation, and
SLSA provenance have all shipped.
