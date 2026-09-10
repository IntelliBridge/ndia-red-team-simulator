"use client";

// The Palantir Foundry section of /exports (spec 27.3).
//
// One project at a time: the operator's deployment block (read from the API
// environment, never editable here), the admin's per-project settings (the
// dataset rid, the bearer auth profile holding the token, the auto-push
// toggle) and what a push would use. The API is the authorization boundary;
// the role gate here is presentation only (spec 7.9). Refusals are shown as
// the API's `code: message`, never rewritten.

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { RoleGated } from "@redsim/design-system";
import { upstreamError, type FoundryBlocker, type FoundryProjectSettings } from "@/lib/api";
import { formatDateTime } from "@/lib/format-datetime";
import { useTRPC } from "@/lib/trpc/client";
import { useRoles } from "@/hooks/useRoles";

export type FoundryPanelProps = {
  /** The project slug from the page's `?project=`; without it the panel offers a selector. */
  project?: string;
};

/** What each effective blocker means to a reader. */
export const FOUNDRY_BLOCKER_TEXT: Record<FoundryBlocker, string> = {
  integration_disabled: "Foundry is not configured on this deployment.",
  integration_misconfigured: "The deployment's Foundry setting was refused; see the reason above.",
  auth_profile_missing: "No bearer auth profile is selected for the token.",
  auth_profile_deleted: "The selected auth profile was deleted.",
  auth_profile_kind_unsupported: "The selected auth profile is not a bearer profile.",
  dataset_rid_missing: "No Foundry dataset rid is set and the deployment has no default.",
};

const ENV_HINT =
  "An operator sets REDSIM_INTEGRATION_FOUNDRY_URL, the non-operational attestation and the allowlist on the API and worker.";

function refusalText(error: unknown): string {
  const upstream = upstreamError(error);
  if (upstream) return `${upstream.code}: ${upstream.message}`;
  return error instanceof Error ? error.message : "request failed";
}

function DeploymentLine({ deployment }: { deployment: FoundryProjectSettings["deployment"] }) {
  if (deployment.status === "configured") {
    return (
      <p className="text-sm">
        <span className="text-muted-foreground">Deployment </span>
        <span className="text-success">configured</span>
        {deployment.host ? (
          <>
            <span className="text-muted-foreground"> · </span>
            <span className="font-mono text-xs">{deployment.host}</span>
          </>
        ) : null}
        {deployment.attested ? <span className="text-muted-foreground"> · attested non-operational</span> : null}
      </p>
    );
  }
  return (
    <div className="space-y-1 text-sm">
      <p>
        <span className="text-muted-foreground">Deployment </span>
        <span className="text-warning">{deployment.status}</span>
        {deployment.reason ? <span className="text-muted-foreground"> · {deployment.reason}</span> : null}
      </p>
      <p className="text-xs text-muted-foreground">{ENV_HINT}</p>
    </div>
  );
}

export function FoundryPanel({ project }: FoundryPanelProps) {
  const trpc = useTRPC();
  const { roles, projects, isLoading: rolesLoading } = useRoles();

  // The project in view: the page's `?project=` wins; otherwise the first
  // project the caller administers, else the first membership.
  const [chosen, setChosen] = useState<string | undefined>(project);
  const slug = useMemo(() => {
    if (project) return project;
    if (chosen) return chosen;
    const admin = projects.find((p) => p.role === "admin");
    return (admin ?? projects[0])?.slug;
  }, [project, chosen, projects]);

  const settingsQuery = useQuery({
    ...trpc.exports.foundrySettings.queryOptions({ project: slug ?? "" }),
    enabled: Boolean(slug),
  });
  const data = settingsQuery.data;
  const projectId = data?.project_id ?? projects.find((p) => p.slug === slug)?.id;
  const role = projectId ? roles[projectId] : undefined;

  const profilesQuery = useQuery({
    ...trpc.exports.authProfiles.queryOptions({ project: projectId ?? "" }),
    enabled: Boolean(projectId),
  });
  const bearerProfiles = (profilesQuery.data ?? []).filter((p) => p.kind === "bearer");

  // Form state, reset from the API each time the settings load or change.
  const [rid, setRid] = useState("");
  const [profileId, setProfileId] = useState("");
  const [autoPush, setAutoPush] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    if (!data) return;
    setRid(data.settings.dataset_rid ?? "");
    setProfileId(data.settings.auth_profile_id ?? "");
    setAutoPush(data.settings.auto_push);
  }, [data]);

  const update = useMutation(trpc.exports.updateFoundrySettings.mutationOptions());

  const save = () => {
    if (!slug) return;
    setRefusal(null);
    setSaved(false);
    update.mutate(
      {
        project: slug,
        dataset_rid: rid.trim() === "" ? null : rid.trim(),
        auth_profile_id: profileId === "" ? null : profileId,
        auto_push: autoPush,
      },
      {
        onSuccess: () => {
          setSaved(true);
          void settingsQuery.refetch();
        },
        onError: (error) => setRefusal(refusalText(error)),
      },
    );
  };

  const upstream = upstreamError(settingsQuery.error);
  const canEdit = role === "admin";

  return (
    <section className="redsim-panel space-y-4 p-4" aria-labelledby="foundry-heading">
      <header className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <div className="redsim-kicker">integration</div>
          <h2 id="foundry-heading" className="text-lg font-semibold">
            Palantir Foundry
          </h2>
        </div>
        {project ? (
          <span className="font-mono text-xs text-muted-foreground">{project}</span>
        ) : projects.length > 1 ? (
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            Project
            <select
              className="rounded-md border border-border bg-background px-2 py-1 font-mono text-xs text-foreground"
              value={slug ?? ""}
              onChange={(event) => setChosen(event.target.value)}
              aria-label="Project"
            >
              {projects.map((p) => (
                <option key={p.id} value={p.slug}>
                  {p.slug}
                </option>
              ))}
            </select>
          </label>
        ) : slug ? (
          <span className="font-mono text-xs text-muted-foreground">{slug}</span>
        ) : null}
      </header>

      {!slug ? (
        <p className="text-sm text-muted-foreground">
          {rolesLoading ? "Loading projects…" : "No project membership; nothing to configure."}
        </p>
      ) : settingsQuery.error && data === undefined ? (
        <div role="alert" className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          <p>
            Foundry settings are unavailable: <code>{upstream?.code ?? "unknown_error"}</code>
          </p>
          {upstream?.message ? <p className="mt-1">{upstream.message}</p> : null}
          <button type="button" className="mt-2 underline" onClick={() => void settingsQuery.refetch()}>
            Retry
          </button>
        </div>
      ) : data === undefined ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : (
        <>
          <DeploymentLine deployment={data.deployment} />

          <form
            className="grid gap-4 md:grid-cols-2"
            onSubmit={(event) => {
              event.preventDefault();
              save();
            }}
          >
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted-foreground">Dataset rid</span>
              <input
                name="dataset_rid"
                className="rounded-md border border-border bg-background px-2 py-1 font-mono text-xs text-foreground disabled:opacity-70"
                value={rid}
                placeholder={data.deployment.default_dataset_rid ?? "ri.foundry.main.dataset.<uuid>"}
                onChange={(event) => setRid(event.target.value)}
                disabled={!canEdit}
                spellCheck={false}
              />
              {rid.trim() === "" && data.deployment.default_dataset_rid ? (
                <span className="text-xs text-muted-foreground">Empty uses the deployment default.</span>
              ) : null}
            </label>

            <label className="flex flex-col gap-1 text-sm">
              <span className="text-muted-foreground">Bearer auth profile (holds the token)</span>
              <select
                name="auth_profile_id"
                className="rounded-md border border-border bg-background px-2 py-1 font-mono text-xs text-foreground disabled:opacity-70"
                value={profileId}
                onChange={(event) => setProfileId(event.target.value)}
                disabled={!canEdit}
              >
                <option value="">none selected</option>
                {bearerProfiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
                {profileId !== "" && !bearerProfiles.some((p) => p.id === profileId) ? (
                  <option value={profileId}>{data.settings.auth_profile_name ?? profileId}</option>
                ) : null}
              </select>
              <span className="text-xs text-muted-foreground">
                {bearerProfiles.length === 0 ? "No bearer profile in this project. " : null}
                <Link className="text-primary underline" href="/auth-profiles">
                  Manage auth profiles
                </Link>
              </span>
            </label>

            <label className="flex items-center gap-3 text-sm md:col-span-2">
              <span className="relative inline-flex h-5 w-9 shrink-0 items-center">
                <input
                  type="checkbox"
                  name="auto_push"
                  className="peer sr-only"
                  checked={autoPush}
                  onChange={(event) => setAutoPush(event.target.checked)}
                  disabled={!canEdit}
                />
                <span
                  aria-hidden="true"
                  className="absolute inset-0 rounded-full bg-muted transition-colors peer-checked:bg-primary peer-disabled:opacity-70"
                />
                <span
                  aria-hidden="true"
                  className="absolute left-0.5 h-4 w-4 rounded-full bg-background transition-transform peer-checked:translate-x-4"
                />
              </span>
              <span>
                Auto-push finished campaigns
                <span className="block text-xs text-muted-foreground">
                  Every campaign that succeeds with a complete score pushes its scorecard. Failed pushes are recorded
                  on their own run and never retried.
                </span>
              </span>
            </label>

            <div className="space-y-1 text-xs md:col-span-2">
              <p className={data.effective.ready ? "text-success" : "text-muted-foreground"}>
                {data.effective.ready
                  ? `Ready · pushes write to ${data.effective.dataset_rid ?? "the dataset"}`
                  : "Not ready"}
                {data.settings.auto_push ? " · auto-push on" : " · auto-push off"}
              </p>
              {data.effective.blockers.length > 0 ? (
                <ul className="list-disc space-y-0.5 pl-4 text-muted-foreground">
                  {data.effective.blockers.map((blocker) => (
                    <li key={blocker}>{FOUNDRY_BLOCKER_TEXT[blocker]}</li>
                  ))}
                </ul>
              ) : null}
              {data.settings.updated_at ? (
                <p className="text-muted-foreground">
                  Updated {formatDateTime(data.settings.updated_at)}
                  {data.settings.updated_by ? ` by ${data.settings.updated_by}` : ""}
                </p>
              ) : null}
            </div>

            <div className="flex flex-wrap items-center gap-3 md:col-span-2">
              <RoleGated
                minRole="admin"
                callerRole={role}
                fallback={<span className="text-xs text-muted-foreground">Admins of this project can change these.</span>}
              >
                <button type="submit" className="redsim-cta px-3 py-1 text-xs" disabled={update.isPending}>
                  {update.isPending ? "Saving…" : "Save"}
                </button>
              </RoleGated>
              {saved && !refusal ? (
                <span role="status" className="text-xs text-success">
                  Saved
                </span>
              ) : null}
              {refusal ? (
                <span role="alert" className="text-xs text-warning">
                  {refusal}
                </span>
              ) : null}
            </div>
          </form>
        </>
      )}
    </section>
  );
}
