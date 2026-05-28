"use client";

import useSWR from "swr";
import { api, Run } from "@/lib/api";

const fetcher = (path: string) =>
  api<{ runs: Run[]; count: number }>(path, {
    token: typeof window !== "undefined"
      ? localStorage.getItem("aegis_token") ?? undefined
      : undefined,
  });

export default function DashboardPage() {
  const { data, error, isLoading } = useSWR("/v1/runs", fetcher);

  if (isLoading) return <p>Loading…</p>;
  if (error) return <p>Failed to load runs: {String(error)}</p>;
  if (!data || data.runs.length === 0) {
    return <p>No runs yet. Trigger a scan from the targets page.</p>;
  }

  return (
    <div>
      <h1>Recent runs</h1>
      <table className="table">
        <thead>
          <tr>
            <th>Run</th><th>Project</th><th>Scanner</th>
            <th>Status</th><th>Created</th>
          </tr>
        </thead>
        <tbody>
          {data.runs.map((r) => (
            <tr key={r.id}>
              <td><a href={`/runs/${r.id}`}>{r.id}</a></td>
              <td>{r.project_id}</td>
              <td>{r.scanner ?? "—"}</td>
              <td>{r.status}</td>
              <td>{new Date(r.created_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
