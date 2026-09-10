import "server-only";

import { z } from "zod";

import type { AuthProfile, ExportRow, ExportsList, FoundryProjectSettings } from "@/lib/api";

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
  kind: z.literal("campaign"),
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
  foundry: z.looseObject({
    status: z.enum(["not_configured", "not_pushed", "queued", "running", "pushed", "failed"]),
    auto_push: z.boolean(),
    push_run_id: z.string().nullable(),
    transaction_rid: z.string().nullable(),
    pushed_at: z.string().nullable(),
    error: z.string().nullable(),
    blockers: z.array(z.enum(["not_terminal", "run_failed", "fixture_target", "score_unavailable"])),
  }),
  evidence: z.looseObject({
    available: z.boolean(),
    path: z.string().nullable(),
  }),
});

const exportsListSchema: z.ZodType<ExportsList> = z.looseObject({
  exports: z.array(exportRowSchema),
  count: z.number(),
  report_formats: z.array(z.string()),
  dataset_format: z.string(),
  limit: z.number(),
  evidence_signing: z.looseObject({
    configured: z.boolean(),
    algorithm: z.literal("ed25519").nullable(),
    key_id: z.string().nullable(),
    reason: z.string().optional(),
  }),
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

/**
 * `GET`/`PUT /v1/projects/{slug}/integrations/foundry` (spec 27.3): the operator's
 * deployment block, the admin's per-project settings and what a push would use.
 */
const foundrySettingsSchema: z.ZodType<FoundryProjectSettings> = z.looseObject({
  project_id: z.string(),
  project: z.string(),
  deployment: z.looseObject({
    status: z.enum(["disabled", "misconfigured", "configured"]),
    host: z.string().nullable(),
    reason: z.string().nullable(),
    attested: z.boolean(),
    default_dataset_rid: z.string().nullable(),
  }),
  settings: z.looseObject({
    dataset_rid: z.string().nullable(),
    auth_profile_id: z.string().nullable(),
    auth_profile_name: z.string().nullable(),
    auto_push: z.boolean(),
    updated_at: z.string().nullable(),
    updated_by: z.string().nullable(),
  }),
  effective: z.looseObject({
    dataset_rid: z.string().nullable(),
    ready: z.boolean(),
    blockers: z.array(
      z.enum([
        "integration_disabled",
        "integration_misconfigured",
        "auth_profile_missing",
        "auth_profile_deleted",
        "auth_profile_kind_unsupported",
        "dataset_rid_missing",
      ]),
    ),
  }),
});

const authProfileSchema: z.ZodType<AuthProfile> = z.looseObject({
  id: z.string(),
  project_id: z.string(),
  name: z.string(),
  kind: z.enum(["form", "bearer", "header", "cookie"]),
  config: z.record(z.string(), z.string()),
  created_at: z.string(),
});

/** `GET /v1/auth-profiles?project=`: a bare array, or the `{auth_profiles}` envelope the API also emits. */
const authProfilesSchema = z
  .union([z.array(authProfileSchema), z.looseObject({ auth_profiles: z.array(authProfileSchema).optional() })])
  .transform((out): AuthProfile[] => (Array.isArray(out) ? out : (out.auth_profiles ?? [])));

/** `202` from `POST /v1/runs/{id}/integrations/foundry`: the follow-up push run's handle. */
const foundryPushSchema = z.looseObject({
  run_id: z.string(),
  job_ids: z.array(z.string()),
  status_url: z.string().optional(),
  integration: z.string(),
  campaign_run_id: z.string(),
  target_ref: z.string(),
  kind: z.string().optional(),
});

/** A project slug or id as a path segment. */
const projectSchema = z.string().min(1, "a project is required").max(200);

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
          query: { project: input?.project, limit: input?.limit },
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

  /** The project's Foundry settings and the deployment's roster state (membership). */
  foundrySettings: publicProcedure
    .input(z.object({ project: projectSchema }))
    .query(({ ctx, input }) =>
      upstreamFetch(
        ctx,
        { method: "GET", segments: ["v1", "projects", input.project, "integrations", "foundry"] },
        foundrySettingsSchema,
      ),
    ),

  /** Set the dataset rid, the bearer profile or the auto-push toggle (`target.manage`, admin; audited). */
  updateFoundrySettings: mutationProcedure
    .input(
      z.object({
        project: projectSchema,
        dataset_rid: z.string().max(256).nullable().optional(),
        auth_profile_id: z.string().max(64).nullable().optional(),
        auto_push: z.boolean().optional(),
      }),
    )
    .mutation(({ ctx, input }) => {
      const { project, ...body } = input;
      return upstreamFetch(
        ctx,
        { method: "PUT", segments: ["v1", "projects", project, "integrations", "foundry"], body },
        foundrySettingsSchema,
      );
    }),

  /** The project's auth profiles (credential-free rows), to pick the bearer profile from. */
  authProfiles: publicProcedure
    .input(z.object({ project: projectSchema }))
    .query(({ ctx, input }) =>
      upstreamFetch(
        ctx,
        { method: "GET", segments: ["v1", "auth-profiles"], query: { project: input.project } },
        authProfilesSchema,
      ),
    ),

  /** Push one finished run's scorecard with the project's settings (`integration.push`, admin). */
  pushFoundry: mutationProcedure
    .input(z.object({ runId: idSchema }))
    .mutation(({ ctx, input }) =>
      upstreamFetch(
        ctx,
        { method: "POST", segments: ["v1", "runs", input.runId, "integrations", "foundry"], body: {} },
        foundryPushSchema,
      ),
    ),
});
