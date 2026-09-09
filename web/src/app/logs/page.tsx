"use client";

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import useSWR from "swr";

import { api } from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { buildLogsQuery } from "./query";

interface LogRow {
  id: number;
  ts: string;
  severity: string;
  service: string;
  message: string;
  run_id: string | null;
  project_id: string | null;
  request_id: string | null;
  trace_id: string | null;
  span_id: string | null;
  actor: string | null;
}

interface LogsResponse {
  logs: LogRow[];
  next_cursor: number | null;
  count: number;
}

const fetcher = (path: string) => api<LogsResponse>(path);

const SEV_TONE: Record<string, string> = {
  trace: "text-muted-foreground",
  debug: "text-muted-foreground",
  info: "text-foreground",
  // Amber and orange, never red: red is the brand accent in this UI.
  warn: "text-amber-300",
  error: "text-orange-400",
  fatal: "font-semibold text-orange-300",
};

function LogTableRow({ row }: { row: LogRow }) {
  return (
    <tr className="border-t border-border">
      <td className="px-2 py-1 font-mono text-muted-foreground">
        {new Date(row.ts).toLocaleTimeString()}
      </td>
      <td
        className={`px-2 py-1 font-mono uppercase ${
          SEV_TONE[row.severity] ?? "text-foreground"
        }`}
      >
        {row.severity}
      </td>
      <td className="px-2 py-1">{row.service}</td>
      <td className="px-2 py-1 font-mono">{row.message}</td>
      <td className="px-2 py-1 font-mono text-muted-foreground">{row.run_id ?? "—"}</td>
      <td className="px-2 py-1 font-mono text-muted-foreground">
        {row.request_id ?? "—"}
      </td>
    </tr>
  );
}

// Next.js 14 requires useSearchParams() to live inside a Suspense
// boundary so the page can prerender (CSR-bailout). LogsView reads
// the params; the default export wraps it.
function LogsView() {
  const params = useSearchParams();
  const authed = useRequireAuth();

  const runFilter = params.get("run") ?? "";

  const { data, error, isLoading } = useSWR<LogsResponse>(
    authed ? `/v1/logs?${buildLogsQuery(params)}` : null,
    fetcher,
  );

  if (!authed)
    return <p className="text-muted-foreground">Redirecting to sign in…</p>;
  if (isLoading) return <p className="text-muted-foreground">Loading…</p>;
  if (error)
    return (
      <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
        Failed to load: {String(error)}
      </p>
    );

  const rows = data?.logs ?? [];

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Logs</h1>
          <p className="text-sm text-muted-foreground">
            Newest first.{" "}
            {runFilter ? `Filtered to run ${runFilter}.` : "Across all runs."}
          </p>
        </div>
      </header>

      <div className="overflow-hidden rounded-md border border-border bg-card">
        <table className="w-full text-xs">
          <thead className="bg-muted text-left text-[10px] uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="px-2 py-1">ts</th>
              <th className="px-2 py-1">sev</th>
              <th className="px-2 py-1">service</th>
              <th className="px-2 py-1">message</th>
              <th className="px-2 py-1">run</th>
              <th className="px-2 py-1">request</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-4 text-center text-muted-foreground">
                  No log rows match these filters.
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <LogTableRow key={r.id} row={r} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function LogsPage() {
  return (
    <Suspense fallback={<p className="text-muted-foreground">Loading…</p>}>
      <LogsView />
    </Suspense>
  );
}
