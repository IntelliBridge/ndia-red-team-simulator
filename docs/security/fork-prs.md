# Fork PR safety

GitHub Actions and PR-scoped scanners face a recurring threat: a fork's
PR carries arbitrary code that the build / scanner / fix loop will
execute against the upstream repo's credentials. Aegis treats every
fork-PR as untrusted and engages **restricted mode** before any code
from the fork is materialised on the worker.

## What "fork" means here

A PR is a fork PR when
``payload.pull_request.head.repo.full_name`` differs from
``payload.pull_request.base.repo.full_name``. GitHub also exposes
``head.repo.fork`` but that flag isn't reliable on cross-fork PRs
through forks of forks; the `head` vs `base` full-name comparison is.

## Restricted mode

`aegis.integrations.github_handlers.restricted_mode_for(scope)`
returns the policy applied to a fork PR:

| Policy          | Default (trusted) | Fork (restricted) |
|-----------------|-------------------|-------------------|
| `apply`         | false (opt-in)    | **false**, hard-no |
| `open_pr`       | false (opt-in)    | **false**, hard-no |
| `clone_depth`   | 0 (full)          | **1** — head SHA only |
| `mount_secrets` | true              | **false** — no API keys reach the worker |
| `path_allowlist`| `[]` (no restriction) | `scope.changed_files` only |
| Audit detail    | `restricted_mode=trusted` | `restricted_mode.reason="fork.restricted=true"` |

## What still works for fork PRs

- The scanner still runs against the depth-1 clone of `head_sha`.
- Findings are reported back as a **Check Run** posted via the
  installation token. Maintainers of the upstream repo see the same
  context they'd see for an in-org PR.
- The audit chain records that this was a restricted run, with the
  reason field, the change-set size, and the head SHA — so a forensic
  review can prove no write action was attempted.

## What is **not** possible for fork PRs

- `--apply` is rejected at admission time. The job carries
  `apply=false` regardless of UI / webhook payload, and the worker
  re-asserts this before invoking the patch workflow.
- `--open-pr` is similarly rejected.
- The worker bootstrap does not mount LLM provider keys, registry
  credentials, or any other secret into the scanner subprocess.
- Path traversal: scanners that respect `scope.path_allowlist` (Strix,
  Trivy fs, Semgrep) operate only on the files in the PR's change-set;
  out-of-scope findings are dropped at the scope-filter boundary.

## What still requires care

- A fork PR can still inject artefacts via the *fixtures* it commits
  (e.g. a malicious `package.json` script). The scanner runs in a
  container; do not relax that boundary even under "trusted" mode.
- Custom GitHub Actions in the fork are out of scope here — that's the
  upstream repo's CI design problem, not Aegis's.
