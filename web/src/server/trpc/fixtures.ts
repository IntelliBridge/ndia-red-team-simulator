import "server-only";

import { runFixtures } from "@/__fixtures__/typed";

/**
 * Fixture answers, keyed by the real route paths (KTD13).
 *
 * The sentinel below is what the U14 image-build assertion greps for. It is a
 * literal in this module and nowhere else, so a match means the module reached
 * the build output.
 */
export const FIXTURE_MODULE_SENTINEL = "redsim-dev-fixtures-module";

type FixtureKey = `${string} /${string}`;

/**
 * Illustrative rows only. Nothing here is a measurement, and the ribbon says
 * so on every page (R27).
 */
const FIXTURES: Readonly<Record<FixtureKey, unknown>> = {
  "GET /v1/runs": { runs: runFixtures, count: runFixtures.length },
};

/** Resolve one route, or undefined when fixture mode has no answer for it. */
export function resolveFixture(method: string, path: string): unknown {
  const exact = FIXTURES[`${method} ${path}` as FixtureKey];
  if (exact !== undefined) return exact;
  if (method === "GET" && path.startsWith("/v1/runs/")) {
    const id = path.slice("/v1/runs/".length);
    const run = runFixtures.find((entry) => entry.id === id);
    if (run === undefined) return undefined;
    // The same projection `_run_to_dict` makes in redsim/api/v1/runs.py: the
    // detail route drops created_by and adds completed_at and stage_table.
    // Recorded rows are the list shape, so returning one unchanged would fail
    // the detail schema and answer 502 where the real API answers 200. The
    // two added values are empty rather than invented: nothing here is a
    // measurement, and a fixture stage table would read like one.
    return {
      id: run.id,
      project_id: run.project_id,
      status: run.status,
      scanner: run.scanner,
      mode: run.mode,
      created_at: run.created_at,
      completed_at: null,
      stage_table: {},
    };
  }
  return undefined;
}
