"use client";

import { useEffect, useState } from "react";
import useSWR from "swr";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
  RoleGated,
  SeverityChip,
  StageTimeline,
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
  type StageEntry,
} from "@aegis/design-system";
import {
  api,
  apiWsBase,
  cancelRun,
  exportVulnfixerUrl,
  isCancellable,
  reportUrl,
  type Finding,
  type Run,
} from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";
import { useRunEvents } from "@/hooks/useRunEvents";

const findingsFetcher = (path: string) =>
  api<{ findings: Finding[]; count: number }>(path);
const runFetcher = (path: string) => api<Run>(path);

// Live job-lifecycle events (useRunEvents) drive freshness; this poll is the
// fallback for when the WebSocket can't connect. Kept slow on purpose so it's
// a safety net rather than the primary update path.
const FALLBACK_POLL_MS = 30_000;

const VALIDATION_TONES: Record<string, string> = {
  poc_passed: "bg-emerald-100 text-emerald-900",
  poc_failed: "bg-red-100 text-red-900",
  inconclusive: "bg-amber-100 text-amber-900",
  unvalidated: "bg-slate-100 text-slate-500",
};

export default function RunPage({ params }: { params: { id: string } }) {
  const authed = useRequireAuth();

  const { data, error, isLoading, mutate } = useSWR(
    authed ? `/v1/findings?run=${params.id}` : null,
    findingsFetcher,
    { refreshInterval: FALLBACK_POLL_MS },
  );
  const {
    data: run,
    mutate: mutateRun,
  } = useSWR(authed ? `/v1/runs/${params.id}` : null, runFetcher);
  const { roles } = useRoles();
  const [stages, setStages] = useState<StageEntry[]>([]);
  const [cancelBusy, setCancelBusy] = useState(false);
  const [cancelErr, setCancelErr] = useState<string | null>(null);

  // Hybrid liveness: each job transition revalidates the findings query so the
  // view tracks the run without leaning on the slow fallback poll above.
  useRunEvents(authed ? params.id : null, () => {
    void mutate();
  });

  useEffect(() => {
    if (!authed) return;
    const wsUrl = `${apiWsBase}/v1/runs/${params.id}/events`;
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (msg) => {
      try {
        const evt = JSON.parse(msg.data);
        if (evt?.name) {
          setStages((s) => [
            ...s,
            {
              name: String(evt.name),
              mode: String(evt.mode ?? "live"),
              success: evt.success !== false,
              detail: evt.detail ? String(evt.detail) : undefined,
            },
          ]);
        }
      } catch {
        /* heartbeat */
      }
    };
    return () => ws.close();
  }, [params.id, authed]);

  if (!authed) return <p className="text-slate-500">Redirecting to sign in…</p>;
  if (isLoading) return <p className="text-slate-500">Loading…</p>;
  if (error)
    return (
      <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
        Failed to load: {String(error)}
      </p>
    );

  const callerRole = run ? roles[run.project_id] : undefined;
  const showCancel = isCancellable(run?.status);

  const doCancel = async () => {
    setCancelBusy(true);
    setCancelErr(null);
    try {
      await cancelRun(params.id);
      mutateRun();
    } catch (e) {
      setCancelErr(String(e));
    } finally {
      setCancelBusy(false);
    }
  };

  return (
    <TooltipProvider>
      <div className="space-y-8">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <h1 className="font-mono text-xl">{params.id}</h1>
            {run?.status && (
              <span className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                {run.status}
              </span>
            )}
          </div>
          <div className="flex items-center gap-4">
            <ReportLinks runId={params.id} />
            {showCancel && (
              <RoleGated minRole="remediator" callerRole={callerRole}>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <button
                      disabled={cancelBusy}
                      className="rounded-md bg-destructive px-3 py-1.5 text-sm text-white hover:opacity-90 disabled:opacity-50"
                    >
                      Cancel run
                    </button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Cancel this run?</AlertDialogTitle>
                      <AlertDialogDescription>
                        Cancelling revokes all queued and running jobs for{" "}
                        <span className="font-mono">{params.id}</span>. This
                        cannot be undone.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Keep running</AlertDialogCancel>
                      <AlertDialogAction
                        variant="destructive"
                        onClick={doCancel}
                      >
                        Cancel run
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </RoleGated>
            )}
          </div>
        </header>

        {cancelErr && (
          <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
            {cancelErr}
          </p>
        )}

        <section className="space-y-3">
          <h2 className="text-sm uppercase tracking-wide text-slate-500">
            Live stage events
          </h2>
          {stages.length === 0 ? (
            <p className="text-sm text-slate-500">
              Waiting for the worker to emit stage events…
            </p>
          ) : (
            <StageTimeline stages={stages} />
          )}
        </section>

        <section className="space-y-3">
          <h2 className="text-sm uppercase tracking-wide text-slate-500">
            Findings ({data?.count ?? 0})
          </h2>
          <div className="overflow-hidden rounded-md border border-slate-200 bg-white">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2">ID</th>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Title</th>
                  <th className="px-3 py-2">Validation</th>
                  <th className="px-3 py-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {(data?.findings ?? []).map((f) => {
                  const blob = f.schema_blob;
                  const tone =
                    VALIDATION_TONES[f.validation_state] ??
                    "bg-slate-100 text-slate-500";
                  return (
                    <tr key={f.id} className="border-t border-slate-100">
                      <td className="px-3 py-2 font-mono text-xs">
                        <a
                          className="text-sky-700 underline"
                          href={`/findings/${f.id}`}
                        >
                          {f.id}
                        </a>
                      </td>
                      <td className="px-3 py-2">
                        <SeverityChip level={f.severity} />
                      </td>
                      <td className="px-3 py-2">{blob.title ?? "—"}</td>
                      <td className="px-3 py-2">
                        <span
                          className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs ${tone}`}
                        >
                          {f.validation_state.replace("_", " ")}
                        </span>
                      </td>
                      <td className="px-3 py-2">{f.status}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </TooltipProvider>
  );
}

function ReportLinks({ runId }: { runId: string }) {
  const links: Array<{ ext: "html" | "json" | "md"; label: string; tip: string }> = [
    {
      ext: "html",
      label: "HTML report ↗",
      tip: "Rendered, CSP-hardened report — opens in a new tab for reading.",
    },
    {
      ext: "json",
      label: "JSON",
      tip: "Machine-readable report payload — downloads for tooling / ingestion.",
    },
    {
      ext: "md",
      label: "Markdown",
      tip: "Markdown report — downloads for tickets, PRs, and docs.",
    },
  ];
  return (
    <div className="flex items-center gap-3 text-sm">
      {links.map((l) => (
        <Tooltip key={l.ext}>
          <TooltipTrigger asChild>
            <a
              href={reportUrl(runId, l.ext)}
              target="_blank"
              rel="noreferrer"
              className="text-sky-700 underline"
            >
              {l.label}
            </a>
          </TooltipTrigger>
          <TooltipContent>{l.tip}</TooltipContent>
        </Tooltip>
      ))}
      <Tooltip>
        <TooltipTrigger asChild>
          <a
            href={exportVulnfixerUrl(runId)}
            target="_blank"
            rel="noreferrer"
            className="text-sky-700 underline"
          >
            Vulnfixer export
          </a>
        </TooltipTrigger>
        <TooltipContent>
          Structured JSON for the Vulnfixer remediation pipeline.
        </TooltipContent>
      </Tooltip>
    </div>
  );
}
