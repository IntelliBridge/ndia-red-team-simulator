"use client";

import { useEffect, useState } from "react";
import useSWR from "swr";
import { api, Finding } from "@/lib/api";

const fetcher = (path: string) => api<{ findings: Finding[]; count: number }>(path);

export default function RunPage({ params }: { params: { id: string } }) {
  const { data, error, isLoading } = useSWR(`/v1/findings?run=${params.id}`, fetcher);
  const [events, setEvents] = useState<{ name: string; mode: string }[]>([]);

  useEffect(() => {
    const base = process.env.NEXT_PUBLIC_AEGIS_API_URL ?? "http://localhost:8000";
    const wsUrl = base.replace(/^http/, "ws") + `/v1/runs/${params.id}/events`;
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (msg) => {
      try {
        const evt = JSON.parse(msg.data);
        if (evt?.name) setEvents((e) => [...e, evt]);
      } catch {
        // ignore
      }
    };
    return () => ws.close();
  }, [params.id]);

  if (isLoading) return <p>Loading…</p>;
  if (error) return <p>Failed to load: {String(error)}</p>;
  return (
    <div>
      <h1>Run {params.id}</h1>
      <h2>Live stage events</h2>
      <ul>
        {events.map((e, idx) => (
          <li key={idx}><code>{e.name}</code> — {e.mode}</li>
        ))}
      </ul>
      <h2>Findings ({data?.count ?? 0})</h2>
      <table className="table">
        <thead>
          <tr>
            <th>ID</th><th>Severity</th><th>Title</th>
            <th>Validation</th><th>Status</th>
          </tr>
        </thead>
        <tbody>
          {(data?.findings ?? []).map((f) => {
            const blob = f.schema_blob as { title?: string };
            return (
              <tr key={f.id}>
                <td><a href={`/findings/${f.id}`}>{f.id}</a></td>
                <td className={`sev-${f.severity}`}>{f.severity.toUpperCase()}</td>
                <td>{blob.title ?? "—"}</td>
                <td>
                  <span className={`badge badge-${f.validation_state === "poc_passed"
                    ? "verified"
                    : f.validation_state === "poc_failed"
                      ? "still_vulnerable"
                      : "inconclusive"}`}>
                    {f.validation_state}
                  </span>
                </td>
                <td>{f.status}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p>
        <a href={`${process.env.NEXT_PUBLIC_AEGIS_API_URL ?? ""}/v1/runs/${params.id}/report.html`}
           target="_blank" rel="noreferrer">
          Open HTML report ↗
        </a>
      </p>
    </div>
  );
}
