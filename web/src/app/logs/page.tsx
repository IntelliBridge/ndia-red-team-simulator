"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import useSWR from "swr";

import { api } from "@/lib/api";
import { requireAuth } from "@/lib/auth";

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
  trace: "text-slate-500",
  debug: "text-slate-500",
  info: "text-slate-700",
  warn: "text-amber-700",
  error: "text-red-700",
  fatal: "text-red-900",
};

export default function LogsPage() {
  const router = useRouter();
  const params = useSearchParams();
  const [authed, setAuthed] = useState(false);
  useEffect(() => {
    if (requireAuth(router)) setAuthed(true);
  }, [router]);

  const runFilter = params.get("run") ?? "";
  const severityFilter = params.get("severity") ?? "";
  const serviceFilter = params.get("service") ?? "";

  const qs = new URLSearchParams();
  if (runFilter) qs.set("run", runFilter);
  if (severityFilter) qs.set("severity", severityFilter);
  if (serviceFilter) qs.set("service", serviceFilter);

  const { data, error, isLoading } = useSWR<LogsResponse>(
    authed ? `/v1/logs?${qs.toString()}` : null,
    fetcher,
  );

  if (!authed) return <p className="text-slate-500">Redirecting to sign in…</p>;
  if (isLoading) return <p className="text-slate-500">Loading…</p>;
  if (error)
    return (
      <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
        Failed to load: {String(error)}
      </p>
    );

  const rows = data?.logs ?? [];

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Logs</h1>
          <p className="text-sm text-slate-600">
            Newest first.{" "}
            {runFilter ? `Filtered to run ${runFilter}.` : "Across all runs."}
          </p>
        </div>
      </header>

      <div className="overflow-hidden rounded-md border border-slate-200 bg-white">
        <table className="w-full text-xs">
          <thead className="bg-slate-50 text-left text-[10px] uppercase tracking-wide text-slate-500">
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
                <td colSpan={6} className="px-3 py-4 text-center text-slate-500">
                  No log rows match these filters.
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr key={r.id} className="border-t border-slate-100">
                <td className="px-2 py-1 font-mono text-slate-500">
                  {new Date(r.ts).toLocaleTimeString()}
                </td>
                <td
                  className={`px-2 py-1 font-mono uppercase ${
                    SEV_TONE[r.severity] ?? "text-slate-700"
                  }`}
                >
                  {r.severity}
                </td>
                <td className="px-2 py-1">{r.service}</td>
                <td className="px-2 py-1 font-mono">{r.message}</td>
                <td className="px-2 py-1 font-mono text-slate-500">
                  {r.run_id ?? "—"}
                </td>
                <td className="px-2 py-1 font-mono text-slate-500">
                  {r.request_id ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
