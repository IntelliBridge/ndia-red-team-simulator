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

export const runsRouter = router({
  list: publicProcedure
    .input(z.object({ project: z.string().optional(), limit: z.number().int().positive().max(500).optional() }).optional())
    .query(({ ctx, input }) =>
      upstreamFetch<{ runs: Run[]; count: number }>(ctx, {
        method: "GET",
        segments: ["v1", "runs"],
        query: { project: input?.project, limit: input?.limit },
      }),
    ),

  get: publicProcedure
    .input(z.object({ id: idSchema }))
    .query(({ ctx, input }) =>
      upstreamFetch<Run>(ctx, { method: "GET", segments: ["v1", "runs", input.id] }),
    ),

  cancel: mutationProcedure
    .input(z.object({ id: idSchema }))
    .mutation(({ ctx, input }) =>
      upstreamFetch<{ run_id: string; status: string; jobs_cancelled: number }>(ctx, {
        method: "POST",
        segments: ["v1", "runs", input.id, "cancel"],
      }),
    ),
});
