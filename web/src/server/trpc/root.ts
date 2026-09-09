import "server-only";

import { router } from "./init";
import { runsRouter } from "./routers/runs";

/**
 * The app router.
 *
 * One sub-router per row group of the plan's route-to-procedure mapping. U1
 * lands `runs` as the proof of the layer. U8 adds the rest.
 */
export const appRouter = router({
  runs: runsRouter,
});

export type AppRouter = typeof appRouter;
