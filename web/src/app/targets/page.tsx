"use client";

import { useState } from "react";
import useSWR from "swr";
import { api } from "@/lib/api";

type Target = {
  id: string; kind: string; value: string; verified: boolean; project_id: string;
};

const fetcher = (path: string) => api<{ targets: Target[] }>(path);

export default function TargetsPage() {
  const { data, error, mutate } = useSWR("/v1/targets?project=default", fetcher);
  const [value, setValue] = useState("");

  if (error) return <p>Failed to load.</p>;

  const create = async () => {
    if (!value) return;
    await api("/v1/targets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: "url", value, project_id: "default" }),
    });
    setValue("");
    mutate();
  };

  return (
    <div>
      <h1>Targets</h1>
      <table className="table">
        <thead>
          <tr><th>ID</th><th>Kind</th><th>Value</th><th>Verified</th></tr>
        </thead>
        <tbody>
          {(data?.targets ?? []).map((t) => (
            <tr key={t.id}>
              <td>{t.id}</td><td>{t.kind}</td>
              <td>{t.value}</td><td>{t.verified ? "yes" : "no"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2>Register target</h2>
      <input value={value} onChange={(e) => setValue(e.target.value)}
             placeholder="https://target.example" style={{ width: "320px" }} />
      <button className="primary" onClick={create}>Add</button>
    </div>
  );
}
