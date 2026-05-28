"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import useSWR from "swr";

import {
  SeverityChip,
  StageTimeline,
  type StageEntry,
} from "@aegis/design-system";
import { api, type Finding } from "@/lib/api";
import { requireAuth } from "@/lib/auth";

const fetcher = (path: string) =>
  api<{ findings: Finding[]; count: number }>(path);

const VALIDATION_TONES: Record<string, string> = {
  poc_passed: "bg-emerald-100 text-emerald-900",
  poc_failed: "bg-red-100 text-red-900",
  inconclusive: "bg-amber-100 text-amber-900",
  unvalidated: "bg-slate-100 text-slate-500",
};

export default function RunPage({ params }: { params: { id: string } }) {
  const router = useRouter();
  const [authed, setAuthed] = useState(false);
  useEffect(() => {
    if (requireAuth(router)) setAuthed(true);
  }, [router]);

  const { data, error, isLoading } = useSWR(
    authed ? `/v1/findings?run=${params.id}` : null,
    fetcher,
  );
  const [stages, setStages] = useState<StageEntry[]>([]);

  useEffect(() => {
    if (!authed) return;
    const base = process.env.NEXT_PUBLIC_AEGIS_API_URL ?? "http://localhost:8000";
    const wsUrl =
      base.replace(/^http/, "ws") + `/v1/runs/${params.id}/events`;
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (msg) => {
      try {
        const evt = JSON.parse(msg.data);
        if (evt?.name) {
          setStages((s) => [
            ...s,
            {
              name: String(evt.name),
              mode: String(evt.mode ?? "live"),
              success: evt.success !== false,
              detail: evt.detail ? String(evt.detail) : undefined,
            },
          ]);
        }
      } catch {
        /* heartbeat */
      }
    };
    return () => ws.close();
  }, [params.id, authed]);

  if (!authed) return <p className="text-slate-500">Redirecting to sign in…</p>;
  if (isLoading) return <p className="text-slate-500">Loading…</p>;
  if (error)
    return (
      <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
        Failed to load: {String(error)}
      </p>
    );

  const reportBase = process.env.NEXT_PUBLIC_AEGIS_API_URL ?? "";
  return (
    <div className="space-y-8">
      <header className="flex items-center justify-between">
        <h1 className="font-mono text-xl">{params.id}</h1>
        <a
          href={`${reportBase}/v1/runs/${params.id}/report.html`}
          target="_blank"
          rel="noreferrer"
          className="text-sm text-sky-700 underline"
        >
          Open HTML report ↗
        </a>
      </header>

      <section className="space-y-3">
        <h2 className="text-sm uppercase tracking-wide text-slate-500">
          Live stage events
        </h2>
        {stages.length === 0 ? (
          <p className="text-sm text-slate-500">
            Waiting for the worker to emit stage events…
          </p>
        ) : (
          <StageTimeline stages={stages} />
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-sm uppercase tracking-wide text-slate-500">
          Findings ({data?.count ?? 0})
        </h2>
        <div className="overflow-hidden rounded-md border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-3 py-2">ID</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Title</th>
                <th className="px-3 py-2">Validation</th>
                <th className="px-3 py-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {(data?.findings ?? []).map((f) => {
                const blob = f.schema_blob as { title?: string };
                const tone =
                  VALIDATION_TONES[f.validation_state] ??
                  "bg-slate-100 text-slate-500";
                return (
                  <tr key={f.id} className="border-t border-slate-100">
                    <td className="px-3 py-2 font-mono text-xs">
                      <a
                        className="text-sky-700 underline"
                        href={`/findings/${f.id}`}
                      >
                        {f.id}
                      </a>
                    </td>
                    <td className="px-3 py-2">
                      <SeverityChip level={f.severity} />
                    </td>
                    <td className="px-3 py-2">{blob.title ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span
                        className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs ${tone}`}
                      >
                        {f.validation_state.replace("_", " ")}
                      </span>
                    </td>
                    <td className="px-3 py-2">{f.status}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
