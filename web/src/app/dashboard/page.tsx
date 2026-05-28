"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { api, Run } from "@/lib/api";
import { getEmail, logout, requireAuth } from "@/lib/auth";

const fetcher = (path: string) => api<{ runs: Run[]; count: number }>(path);

export default function DashboardPage() {
  const router = useRouter();
  const [authed, setAuthed] = useState(false);
  useEffect(() => {
    if (requireAuth(router)) setAuthed(true);
  }, [router]);

  const { data, error, isLoading } = useSWR(authed ? "/v1/runs" : null, fetcher);

  if (!authed) return <p>Redirecting to sign in…</p>;

  const signOut = () => { logout(); router.push("/login"); };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between",
                     alignItems: "center" }}>
        <h1>Recent runs</h1>
        <div>
          <small style={{ marginRight: "1rem" }}>{getEmail()}</small>
          <button className="primary" onClick={signOut}>Sign out</button>
        </div>
      </div>
      {isLoading && <p>Loading…</p>}
      {error && (
        <p style={{ color: "#b00020" }}>Failed to load runs: {String(error)}</p>
      )}
      {!isLoading && !error && (!data || data.runs.length === 0) && (
        <p>
          No runs yet. Head to <a href="/targets">/targets</a> to register a
          target and start one.
        </p>
      )}
      {data && data.runs.length > 0 && (
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
      )}
    </div>
  );
}
