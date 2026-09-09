import "server-only";

import { z } from "zod";

import type { ExportRow, ExportsList } from "@/lib/api";

import { mutationProcedure, publicProcedure, router } from "../init";
import { upstreamFetch } from "../upstream";
import { idSchema } from "./runs";

/**
 * One export inventory row, as `GET /v1/exports` returns it.
 *
 * `looseObject` for the same reason the runs schemas are: the API adding a
 * field it means the page to read is not a reason to hide it. The nested
 * blocks are checked for the keys the table renders from, so a body that has
 * drifted fails the parse as a 502 rather than rendering `undefined`.
 */
const artifactRefSchema = z.looseObject({
  artifact_id: z.string(),
  kind: z.string(),
  sha256: z.string(),
  size_bytes: z.number(),
  source: z.enum(["snapshot", "artifact"]),
  snapshot_version: z.number().optional(),
});

const reportExtSchema = z.enum(["md", "json", "html", "pdf"]);

const exportRowSchema: z.ZodType<ExportRow> = z.looseObject({
  run_id: z.string(),
  project_id: z.string(),
  kind: z.enum(["campaign", "verify"]),
  status: z.string(),
  terminal: z.boolean(),
  created_at: z.string().nullable(),
  completed_at: z.string().nullable(),
  model: z.looseObject({
    target_id: z.string().nullable(),
    name: z.string().nullable(),
    value: z.string().nullable(),
    modality: z.string().nullable(),
    fixture: z.boolean(),
  }),
  reports: z.looseObject({
    run_id: z.string(),
    formats: z.object({
      md: artifactRefSchema.nullable(),
      json: artifactRefSchema.nullable(),
      html: artifactRefSchema.nullable(),
      pdf: artifactRefSchema.nullable(),
    }),
    available: z.array(reportExtSchema),
    missing: z.array(reportExtSchema),
    snapshot_count: z.number(),
    latest_snapshot: z
      .looseObject({
        id: z.string(),
        version: z.number(),
        rendered_at: z.string().nullable(),
        archived: z.boolean(),
      })
      .nullable(),
    render_in_flight: z.boolean(),
  }),
  dataset: z.looseObject({
    format: z.string(),
    status: z.enum(["not_exported", "queued", "running", "exported", "failed"]),
    manifest_artifact_id: z.string().nullable(),
    manifest_sha256: z.string().nullable(),
    files: z.number(),
    bytes: z.number(),
    card: z.boolean(),
    job_id: z.string().nullable(),
    follow_up_run_id: z.string().nullable(),
    error: z.string().nullable(),
    blockers: z.array(z.enum(["not_terminal", "run_failed", "fixture_target", "no_slices"])),
  }),
});

const exportsListSchema: z.ZodType<ExportsList> = z.looseObject({
  exports: z.array(exportRowSchema),
  count: z.number(),
  report_formats: z.array(z.string()),
  dataset_format: z.string(),
  limit: z.number(),
});

/** `202` from `POST /v1/runs/{id}/dataset`: a fresh job, or the existing export (`status: exists`). */
const datasetExportSchema = z.looseObject({
  dataset_id: z.string(),
  status: z.string(),
  type: z.string(),
  run_id: z.string().optional(),
  job_id: z.string().optional(),
  manifest_sha256: z.string().optional(),
});

/** `202` from `POST /v1/runs/{id}/report.render`. */
const renderSchema = z.looseObject({
  run_id: z.string(),
  job_id: z.string(),
  formats: z.array(z.string()),
  status: z.string(),
});

export const exportsRouter = router({
  list: publicProcedure
    .input(
      z
        .object({
          project: z.string().optional(),
          kind: z.enum(["campaign", "verify"]).optional(),
          limit: z.number().int().positive().max(500).optional(),
        })
        .optional(),
    )
    .query(({ ctx, input }) =>
      upstreamFetch(
        ctx,
        {
          method: "GET",
          segments: ["v1", "exports"],
          query: { project: input?.project, kind: input?.kind, limit: input?.limit },
        },
        exportsListSchema,
      ),
    ),

  /** Start the Croissant/Parquet export of a run (`dataset.export`, remediator). */
  exportDataset: mutationProcedure
    .input(z.object({ runId: idSchema }))
    .mutation(({ ctx, input }) =>
      upstreamFetch(
        ctx,
        { method: "POST", segments: ["v1", "runs", input.runId, "dataset"], timeoutMs: 120_000 },
        datasetExportSchema,
      ),
    ),

  /** Re-render the run's reports as a new immutable snapshot (`report.render`, scanner). */
  renderReport: mutationProcedure
    .input(z.object({ runId: idSchema, formats: z.array(reportExtSchema).optional() }))
    .mutation(({ ctx, input }) =>
      upstreamFetch(
        ctx,
        {
          method: "POST",
          segments: ["v1", "runs", input.runId, "report.render"],
          body: input.formats ? { formats: input.formats } : {},
        },
        renderSchema,
      ),
    ),
});
