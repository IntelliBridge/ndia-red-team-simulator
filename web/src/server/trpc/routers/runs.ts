import "server-only";

import { z } from "zod";

import type { Run } from "@/lib/api";

import { mutationProcedure, publicProcedure, router } from "../init";
import { upstreamFetch } from "../upstream";

/**
 * An id that can never rewrite the upstream path.
 *
 * `upstreamFetch` encodes each segment, so a slash would survive as `%2F` and
 * hit a route that does not exist rather than a route the caller chose. The
 * schema refuses it anyway, so the refusal is a named field error the form can
 * render rather than an upstream 404.
 */
export const idSchema = z
  .string()
  .min(1, "an id is required")
  .max(200)
  .refine((v) => !v.includes("/"), "an id cannot contain a slash");

/**
 * One run row, as `GET /v1/runs` and `GET /v1/runs/{id}` return it.
 *
 * `looseObject` rather than `object`: zod strips unknown keys, and the API
 * adding a field it means a page to read is not a reason to hide that field
 * from the page. Annotated `z.ZodType<Run>` so the type in `@/lib/api` stays
 * the one `RouterOutputs` reports, and so a schema that drifts from it fails
 * the typecheck rather than quietly narrowing what a component receives.
 */
const runSchema: z.ZodType<Run> = z.looseObject({
  id: z.string(),
  project_id: z.string(),
  status: z.string(),
  scanner: z.string().nullable(),
  mode: z.string(),
  created_at: z.string(),
  created_by: z.string().nullable(),
});

const runsListSchema: z.ZodType<{ runs: Run[]; count: number }> = z.looseObject({
  runs: z.array(runSchema),
  count: z.number(),
});

const cancelSchema: z.ZodType<{ run_id: string; status: string; jobs_cancelled: number }> =
  z.looseObject({
    run_id: z.string(),
    status: z.string(),
    jobs_cancelled: z.number(),
  });

export const runsRouter = router({
  list: publicProcedure
    .input(z.object({ project: z.string().optional(), limit: z.number().int().positive().max(500).optional() }).optional())
    .query(({ ctx, input }) =>
      upstreamFetch(
        ctx,
        {
          method: "GET",
          segments: ["v1", "runs"],
          query: { project: input?.project, limit: input?.limit },
        },
        runsListSchema,
      ),
    ),

  get: publicProcedure
    .input(z.object({ id: idSchema }))
    .query(({ ctx, input }) =>
      upstreamFetch(ctx, { method: "GET", segments: ["v1", "runs", input.id] }, runSchema),
    ),

  cancel: mutationProcedure
    .input(z.object({ id: idSchema }))
    .mutation(({ ctx, input }) =>
      upstreamFetch(
        ctx,
        { method: "POST", segments: ["v1", "runs", input.id, "cancel"] },
        cancelSchema,
      ),
    ),
});
