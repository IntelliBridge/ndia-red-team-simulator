"use client";

import { useEffect, useState } from "react";
import useSWR from "swr";

import { RoleGated } from "@redsim/design-system";
import { api } from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

interface MembershipResponse {
  project: {
    id: string;
    slug: string;
    name: string;
    daily_llm_budget_cents: number | null;
  };
  members: { sub: string; email: string; display_name: string; role: string }[];
}

const fetcher = (path: string) => api<MembershipResponse>(path);

export default function ProjectSettingsPage({
  params,
}: {
  params: { slug: string };
}) {
  const authed = useRequireAuth();

  const { data, error, isLoading, mutate } = useSWR(
    authed ? `/v1/projects/${params.slug}/membership` : null,
    fetcher,
  );
  const { roles } = useRoles();
  const [budget, setBudget] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (data?.project.daily_llm_budget_cents != null) {
      setBudget(String(data.project.daily_llm_budget_cents));
    }
  }, [data]);

  if (!authed)
    return <p className="text-ink-3">Signing in…</p>;
  if (isLoading) return <p className="text-ink-3">Loading…</p>;
  if (error)
    return (
      <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
        Failed to load: {String(error)}
      </p>
    );
  if (!data) return null;

  const callerRole = roles[data.project.id] ?? roles[data.project.slug];

  const saveBudget = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api(`/v1/projects/${params.slug}/settings`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          daily_llm_budget_cents:
            budget.trim() === "" ? null : Number(budget),
        }),
      });
      await mutate();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <header>
        <h1>{data.project.name}</h1>
        <p className="mt-1 font-mono text-xs text-ink-3">{data.project.slug}</p>
      </header>

      <section className="redsim-sheet">
        <h2 className="redsim-sheet-label">Members</h2>
        <div className="redsim-sheet-body overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left">
              <tr className="border-b border-line-strong">
                <th className="px-3 py-2">Email</th>
                <th className="px-3 py-2">Role</th>
              </tr>
            </thead>
            <tbody>
              {data.members.map((m) => (
                <tr key={m.sub} className="border-b border-line last:border-0">
                  <td className="px-3 py-2.5 text-ink-1">{m.email}</td>
                  <td className="px-3 py-2.5">
                    <span className="redsim-chip">{m.role}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <RoleGated minRole="admin" callerRole={callerRole}>
        <section className="redsim-sheet">
          <h2 className="redsim-sheet-label">LLM budget</h2>
          <div className="redsim-sheet-body">
            <div className="redsim-panel space-y-4 p-5">
              <div className="flex flex-wrap items-end gap-3">
                <label className="block text-sm">
                  <span className="redsim-kicker mb-1 block">Daily limit (cents)</span>
                  <input
                    type="number"
                    min="0"
                    value={budget}
                    onChange={(e) => setBudget(e.target.value)}
                    className="redsim-input w-48"
                  />
                </label>
                <button
                  onClick={saveBudget}
                  disabled={busy}
                  className="redsim-cta"
                >
                  Save
                </button>
              </div>
              {err && (
                <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
                  {err}
                </p>
              )}
            </div>
          </div>
        </section>
      </RoleGated>
    </div>
  );
}
