"use client";

import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

export default function ProjectsPage() {
  const authed = useRequireAuth();
  const { projects, isLoading, error } = useRoles();

  if (!authed)
    return <p className="text-ink-3">Signing in…</p>;
  if (isLoading) return <p className="text-ink-3">Loading…</p>;
  if (error)
    return (
      <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
        Failed to load projects: {String(error)}
      </p>
    );

  return (
    <div className="space-y-6">
      <h1>Projects</h1>
      {projects.length === 0 ? (
        <p className="text-ink-3">You don&apos;t belong to any projects yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left">
              <tr className="border-b border-line-strong">
                <th className="px-3 py-2">Slug</th>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Role</th>
                <th className="px-3 py-2">Daily budget</th>
              </tr>
            </thead>
            <tbody>
              {projects.map((p) => (
                <tr key={p.id} className="border-b border-line last:border-0">
                  <td className="px-3 py-2.5 font-mono text-xs">
                    <a
                      className="redsim-link"
                      href={`/projects/${p.slug}/settings`}
                    >
                      {p.slug}
                    </a>
                  </td>
                  <td className="px-3 py-2.5 text-ink-1">{p.name}</td>
                  <td className="px-3 py-2.5">
                    <span className="redsim-chip">{p.role}</span>
                  </td>
                  <td className="px-3 py-2.5 tabular-nums text-ink-3">
                    {p.daily_llm_budget_cents == null
                      ? "—"
                      : `$${(p.daily_llm_budget_cents / 100).toFixed(2)}`}
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
