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
    return runFixtures.find((run) => run.id === id);
  }
  return undefined;
}
