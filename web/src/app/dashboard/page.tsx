"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import useSWR from "swr";

import { RunStatusBadge } from "@redsim/design-system";
import { api, type Run } from "@/lib/api";
import { getEmail, logout } from "@/lib/auth";
import { useRequireAuth } from "@/hooks/useRequireAuth";

const fetcher = (path: string) => api<{ runs: Run[]; count: number }>(path);

export default function DashboardPage() {
  const router = useRouter();
  const authed = useRequireAuth();

  // Poll every 15s so the dashboard tracks newly queued/finished runs
  // without a manual refresh (the run-detail view has its own live feed).
  const { data, error, isLoading } = useSWR(
    authed ? "/v1/runs" : null,
    fetcher,
    { refreshInterval: 15000 },
  );

  if (!authed)
    return <p className="text-muted-foreground">Signing in…</p>;

  // Awaited, so the redirect follows both the Better Auth sign-out and the
  // redsim cookie clear rather than racing them.
  const signOut = async () => {
    await logout();
    router.push("/login");
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Recent runs</h1>
        <div className="flex items-center gap-3 text-sm">
          <span className="text-muted-foreground">{getEmail() ?? "(session)"}</span>
          <button
            onClick={signOut}
            className="rounded-md border border-border bg-card px-3 py-1.5 text-sm hover:bg-muted"
          >
            Sign out
          </button>
        </div>
      </div>

      {isLoading && <p className="text-muted-foreground">Loading…</p>}
      {error && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          Failed to load runs: {String(error)}
        </p>
      )}
      {!isLoading && !error && (!data || data.runs.length === 0) && (
        <p className="text-muted-foreground">
           No runs yet. Head to{" "}
           <Link className="text-primary underline" href="/models">
             /models
           </Link>{" "}
           to
          register a target and start one.
        </p>
      )}
      {data && data.runs.length > 0 && (
        <div className="overflow-hidden rounded-md border border-border bg-card">
          <table className="w-full text-sm">
            <thead className="bg-muted text-left text-xs uppercase tracking-wide text-muted-foreground">
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
                <tr key={r.id} className="border-t border-border">
                  <td className="px-3 py-2 font-mono text-xs">
                    <a className="text-primary underline" href={`/runs/${r.id}`}>
                      {r.id}
                    </a>
                  </td>
                  <td className="px-3 py-2">{r.project_id}</td>
                  <td className="px-3 py-2">{r.scanner ?? "—"}</td>
                  <td className="px-3 py-2">
                    <RunStatusBadge status={r.status} />
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">
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
