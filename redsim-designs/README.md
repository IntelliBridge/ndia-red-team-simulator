# redsim-designs (reference only)

This directory is a [v0.dev](https://v0.dev) export of an alternative
`@redsim/web` UI, kept here as a design reference. It is **not** the shipped
web app, which stays at `web/` (`@redsim/web`) and `packages/design-system`
(`@redsim/design-system`) per `pnpm-workspace.yaml`.

- Not a pnpm workspace member. It carries its own `pnpm-workspace.yaml` and
  `pnpm-lock.yaml` so it can be installed and run in isolation
  (`cd redsim-designs && pnpm install && pnpm dev`), but the repo root
  `pnpm-workspace.yaml` does not list it and no CI job builds, lints, types
  or tests it.
- Its `package.json` name (`@redsim/web`) intentionally matches the real
  app's, which is fine only because it is excluded from the workspace;
  do not add this directory to `pnpm-workspace.yaml`'s `packages` list, or
  the two would collide.
- Excluded from the CI dependency-CVE scan (`--skip-dirs redsim-designs` in
  `.github/workflows/redsim-ci.yml`) since its pinned `next@14.2.15` is not
  shipped and is not baselined in `.trivyignore`.
- Temporary. This directory is a reference for an in-progress web redesign
  discussion and is expected to be removed once that work either lands in
  `web/` or is abandoned.
