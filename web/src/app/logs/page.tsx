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
  trace: "text-ink-3",
  debug: "text-ink-3",
  info: "text-ink-2",
  // Amber and orange, never red: red is the brand accent in this UI.
  warn: "border-amber-400/50 text-amber-300",
  error: "border-orange-400/50 text-orange-400",
  fatal: "border-orange-400/50 font-semibold text-orange-300",
};

function LogTableRow({ row }: { row: LogRow }) {
  return (
    <tr className="border-b border-line last:border-0">
      <td className="px-3 py-2 font-mono tabular-nums text-ink-3">
        {new Date(row.ts).toLocaleTimeString()}
      </td>
      <td className="px-3 py-2">
        <span
          className={`redsim-chip font-mono ${
            SEV_TONE[row.severity] ?? "text-ink-2"
          }`}
        >
          {row.severity}
        </span>
      </td>
      <td className="px-3 py-2 text-ink-2">{row.service}</td>
      <td className="px-3 py-2 font-mono text-ink-1">{row.message}</td>
      <td className="px-3 py-2 font-mono text-ink-3">{row.run_id ?? "—"}</td>
      <td className="px-3 py-2 font-mono text-ink-3">
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
    return <p className="text-ink-3">Signing in…</p>;
  if (isLoading) return <p className="text-ink-3">Loading…</p>;
  if (error)
    return (
      <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
        Failed to load: {String(error)}
      </p>
    );

  const rows = data?.logs ?? [];

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <h1>Logs</h1>
          <p className="mt-1 text-sm text-ink-3">
            Newest first.{" "}
            {runFilter ? `Filtered to run ${runFilter}.` : "Across all runs."}
          </p>
        </div>
      </header>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="text-left">
            <tr className="border-b border-line-strong">
              <th className="px-3 py-2">ts</th>
              <th className="px-3 py-2">sev</th>
              <th className="px-3 py-2">service</th>
              <th className="px-3 py-2">message</th>
              <th className="px-3 py-2">run</th>
              <th className="px-3 py-2">request</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-4 text-center text-ink-3">
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
    <Suspense fallback={<p className="text-ink-3">Loading…</p>}>
      <LogsView />
    </Suspense>
  );
}
