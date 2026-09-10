# Architecture diagrams

Three explorable diagrams of redsim, generated with
[Archify](https://github.com/tt-a1i/archify) from the JSON sources in this
directory. Each `.html` is self-contained (inline SVG, light and dark themes,
pan and zoom, search, focus, PNG/SVG export). Open it in a browser. The JSON
next to it is the source of truth: edit the JSON, regenerate the HTML, never
hand-edit the HTML.

Evidence date: 2026-09-08. Repository state: `main` at commit `4320740`
(`432074035709487011fc01bace56162dc05b1c35`). Node cards cite the files that
back each component. Components and steps that are not on `main` are marked
"planned" (dashed relationships) or attributed to the open draft PR that
carries them (#8 `feat/ml-core`, #9 `feat/ml-assets`).

## The diagrams

### `redsim-platform.architecture.html`

Component map of the platform with four trust boundaries: identity
(Keycloak OIDC), browser and edge (`@redsim/web`), the redsim platform
(FastAPI API, Redis, Celery workers, Postgres with row-level security,
S3/MinIO with the WORM bucket, opt-in observability, the planned model
sandbox child), and external services (the Pythia gateway as the only LLM
egress, HuggingFace and Kaggle as build-time dataset sources). The
emphasised path is the campaign path: browser to API, chained audit row,
then `Run` and `Job` rows, then `task.delay`, worker execution, artifacts
to the blob store and records to Postgres, and the WebSocket relay of
`run:{run_id}:events` back to the UI. Every node carries source references
(`sources`) that Archify verifies against the checkout pinned by
`meta.repository`.

Source: `redsim-platform.architecture.json`.

### `attack-campaign.sequence.html`

The attack campaign: analyst to web to `POST /v1/models/{id}/attacks`, RBAC
`attack.run`, the audit row appended before any row or enqueue, the
`attack.run` chain (sample, clean_eval, attack per epsilon, control), then
`explain.run` (SHAP), the score stage (MRI), `harden.recommend` (rules
first, optional text-only Pythia narrative through `redsim/llm/pythia.py`),
report render, and the events back to the UI. Every message says whether
it exists on `main`, sits in an open PR, or is planned.

Source: `attack-campaign.sequence.json`.

### `campaign-run.lifecycle.html`

The job state machine from `redsim/workers/job_state.py`. `ALLOWED` lets
`queued` move to `running` or `cancelled`, lets `running` move to
`succeeded`, `failed`, `cancelled` or back to `queued`, and makes the three
terminal states sinks. The campaign `STAGES` from `redsim/ml/schema.py` are
grouped by the chained job that runs them, with the transient-retry requeue
(`task_acks_late` plus the redelivery guard in `redsim/workers/bootstrap.py`),
the reaper, and the cancel and failure paths.

Source: `campaign-run.lifecycle.json`.

## Receipts (2026-09-08)

Each delivery froze the JSON source, rendered it, ran the nine artifact
checks at the `showcase` profile (0 errors, 0 warnings) and committed the
HTML. `visual-check` then measured the delivered HTML in Chrome at
1440x900, 1600x1000, 1920x1080 and 2048x1320 (light containment, light and
dark captures) and passed for all three. The `*.visual-check.json` files are
those receipts. The PNG and contact-sheet sidecars are not kept in the
repository, rerun `visual-check` to regenerate them.

| Diagram | Source SHA-256 (bytes) | HTML SHA-256 (bytes) |
|---|---|---|
| `redsim-platform.architecture` | `1c76dd821a634e1af7a82b5a0bbef1f336721e0bc9f76e59ac7bfcc583e84751` (10690) | `efe7f42b23e95cd41fb5d0fc6e596d83ef776993fb6d18e6c4cda480c74319c8` (822575) |
| `attack-campaign.sequence` | `f471e740e6bc75c60a1df212b0b2085c85d9f816e0049fd636344847bc4eb462` (6046) | `bf78bfcc958533ee8ce098cae4ef309639a58fb59b5ab28c31f5102311a2a6cc` (814003) |
| `campaign-run.lifecycle` | `dc17b612435a7d71c8fae4b600b6c009124646b8532988997abe68ef466e30f8` (3548) | `36cb473fb59c171a177cdf2259ac9b1225ccc3304123c3752ac3c3efeb95578b` (804803) |

The architecture receipt also records 26 verified repository references at
revision `4320740`.

## Regenerating

Archify is a Node.js skill package. The commands below assume it is
installed at `~/.claude/skills/archify` and are run from that directory.
`DIAGRAMS` is the absolute path of this directory and `REPO` the absolute
path of the repository checkout (needed only for the architecture diagram,
whose node cards cite source files that Archify verifies before rendering).

```bash
cd ~/.claude/skills/archify
DIAGRAMS="/path/to/ndia-red-team-simulator/docs/architecture/diagrams"
REPO="/path/to/ndia-red-team-simulator"

# 1. Validate (a showcase pass reports 9 artifact checks, 0 errors, 0 warnings)
node bin/archify.mjs validate architecture "$DIAGRAMS/redsim-platform.architecture.json" --quality showcase --repo-root "$REPO" --json
node bin/archify.mjs validate sequence     "$DIAGRAMS/attack-campaign.sequence.json"      --quality showcase --json
node bin/archify.mjs validate lifecycle    "$DIAGRAMS/campaign-run.lifecycle.json"        --quality showcase --json

# 2. Deliver (renders, checks, commits the HTML, reports SHA-256 and byte counts)
node bin/archify.mjs deliver architecture "$DIAGRAMS/redsim-platform.architecture.json" "$DIAGRAMS/redsim-platform.architecture.html" --quality showcase --repo-root "$REPO" --json
node bin/archify.mjs deliver sequence     "$DIAGRAMS/attack-campaign.sequence.json"      "$DIAGRAMS/attack-campaign.sequence.html"      --quality showcase --json
node bin/archify.mjs deliver lifecycle    "$DIAGRAMS/campaign-run.lifecycle.json"        "$DIAGRAMS/campaign-run.lifecycle.html"        --quality showcase --json

# 3. Browser evidence on the delivered HTML (does not modify it, writes sidecars beside it)
node bin/archify.mjs visual-check "$DIAGRAMS/redsim-platform.architecture.html" --json
node bin/archify.mjs visual-check "$DIAGRAMS/attack-campaign.sequence.html" --json
node bin/archify.mjs visual-check "$DIAGRAMS/campaign-run.lifecycle.html" --json
```

Two viewer constraints shape the sources. The standalone viewer never
renders a diagram narrower than about 930px or its node text below 6px, so
a page only fits a 1440x900 desktop when the viewBox height stays near 550
to 650 units, node sublabels stay short enough to keep the 7px font, and
the cards stay at two short items each. When the code changes, update the
JSON first (node cards, `sources` paths and lines, the "on main / PR /
planned" wording, and `meta.repository.revision` in the architecture
source), then rerun the three steps. `mkdocs --strict` does not process
these HTML files. They are linked, not rendered, from the architecture docs.
