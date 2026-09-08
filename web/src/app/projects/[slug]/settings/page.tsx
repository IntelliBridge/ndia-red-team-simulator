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
    return <p className="text-muted-foreground">Redirecting to sign in…</p>;
  if (isLoading) return <p className="text-muted-foreground">Loading…</p>;
  if (error)
    return (
      <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
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
        <h1 className="text-2xl font-semibold">{data.project.name}</h1>
        <p className="font-mono text-xs text-muted-foreground">{data.project.slug}</p>
      </header>

      <section className="space-y-3">
        <h2 className="text-sm uppercase tracking-wide text-muted-foreground">
          Members
        </h2>
        <div className="overflow-hidden rounded-md border border-border bg-card">
          <table className="w-full text-sm">
            <thead className="bg-muted text-left text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-3 py-2">Email</th>
                <th className="px-3 py-2">Role</th>
              </tr>
            </thead>
            <tbody>
              {data.members.map((m) => (
                <tr key={m.sub} className="border-t border-border">
                  <td className="px-3 py-2">{m.email}</td>
                  <td className="px-3 py-2">{m.role}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <RoleGated minRole="admin" callerRole={callerRole}>
        <section className="space-y-3">
          <h2 className="text-sm uppercase tracking-wide text-muted-foreground">
            LLM budget
          </h2>
          <div className="flex items-end gap-3">
            <label className="flex flex-col text-sm">
              <span className="mb-1">Daily limit (cents)</span>
              <input
                type="number"
                min="0"
                value={budget}
                onChange={(e) => setBudget(e.target.value)}
                className="rounded-md border border-input bg-background px-2 py-1.5"
              />
            </label>
            <button
              onClick={saveBudget}
              disabled={busy}
              className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90 disabled:opacity-50"
            >
              Save
            </button>
          </div>
          {err && (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {err}
            </p>
          )}
        </section>
      </RoleGated>
    </div>
  );
}
