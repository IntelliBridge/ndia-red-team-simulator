"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";
import { api } from "@/lib/api";
import { requireAuth } from "@/lib/auth";

type Target = {
  id: string; kind: string; value: string; verified: boolean; project_id: string;
};

const fetcher = (path: string) => api<{ targets: Target[] }>(path);

export default function TargetsPage() {
  const router = useRouter();
  const [authed, setAuthed] = useState(false);
  useEffect(() => {
    if (requireAuth(router)) setAuthed(true);
  }, [router]);

  const { data, error, mutate } = useSWR(
    authed ? "/v1/targets?project=default" : null, fetcher,
  );
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);

  if (!authed) return <p>Redirecting to sign in…</p>;
  if (error) return <p>Failed to load.</p>;

  const create = async () => {
    if (!value) return;
    setBusy(true);
    try {
      await api("/v1/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "url", value, project_id: "default" }),
      });
      setValue("");
      mutate();
    } finally {
      setBusy(false);
    }
  };

  const startScan = async (target: Target) => {
    setBusy(true);
    try {
      const out = await api<{ run_id: string }>("/v1/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: target.value, scanner: "trivy",
          project_id: target.project_id,
        }),
      });
      router.push(`/runs/${out.run_id}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1>Targets</h1>
      <table className="table">
        <thead>
          <tr>
            <th>ID</th><th>Kind</th><th>Value</th>
            <th>Verified</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {(data?.targets ?? []).map((t) => (
            <tr key={t.id}>
              <td>{t.id}</td><td>{t.kind}</td>
              <td>{t.value}</td><td>{t.verified ? "yes" : "no"}</td>
              <td>
                <button className="primary" disabled={busy}
                        onClick={() => startScan(t)}>
                  Start scan
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2>Register target</h2>
      <input value={value} onChange={(e) => setValue(e.target.value)}
             placeholder="https://target.example" style={{ width: "320px" }} />
      <button className="primary" onClick={create} disabled={busy}>Add</button>
    </div>
  );
}
