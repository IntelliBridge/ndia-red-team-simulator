"use client";

import { useRouter } from "next/navigation";
import useSWR from "swr";

import { RunStatusBadge } from "@aegis/design-system";
import { api, type Run } from "@/lib/api";
import { getEmail, logout } from "@/lib/auth";
import { useRequireAuth } from "@/hooks/useRequireAuth";

const fetcher = (path: string) => api<{ runs: Run[]; count: number }>(path);

export default function DashboardPage() {
  const router = useRouter();
  const authed = useRequireAuth();

  const { data, error, isLoading } = useSWR(authed ? "/v1/runs" : null, fetcher);

  if (!authed) return <p className="text-slate-500">Redirecting to sign in…</p>;

  const signOut = () => {
    logout();
    router.push("/login");
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Recent runs</h1>
        <div className="flex items-center gap-3 text-sm">
          <span className="text-slate-500">{getEmail() ?? "(session)"}</span>
          <button
            onClick={signOut}
            className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-sm hover:bg-slate-100"
          >
            Sign out
          </button>
        </div>
      </div>

      {isLoading && <p className="text-slate-500">Loading…</p>}
      {error && (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
          Failed to load runs: {String(error)}
        </p>
      )}
      {!isLoading && !error && (!data || data.runs.length === 0) && (
        <p className="text-slate-600">
          No runs yet. Head to{" "}
          <a className="text-sky-700 underline" href="/targets">/targets</a> to
          register a target and start one.
        </p>
      )}
      {data && data.runs.length > 0 && (
        <div className="overflow-hidden rounded-md border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-3 py-2">Run</th>
                <th className="px-3 py-2">Project</th>
                <th className="px-3 py-2">Scanner</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Created</th>
              </tr>
            </thead>
            <tbody>
              {data.runs.map((r) => (
                <tr key={r.id} className="border-t border-slate-100">
                  <td className="px-3 py-2 font-mono text-xs">
                    <a className="text-sky-700 underline" href={`/runs/${r.id}`}>
                      {r.id}
                    </a>
                  </td>
                  <td className="px-3 py-2">{r.project_id}</td>
                  <td className="px-3 py-2">{r.scanner ?? "—"}</td>
                  <td className="px-3 py-2">
                    <RunStatusBadge status={r.status} />
                  </td>
                  <td className="px-3 py-2 text-slate-600">
                    {new Date(r.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
