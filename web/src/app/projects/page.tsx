"use client";

import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

export default function ProjectsPage() {
  const authed = useRequireAuth();
  const { projects, isLoading, error } = useRoles();

  if (!authed)
    return <p className="text-muted-foreground">Signing in…</p>;
  if (isLoading) return <p className="text-muted-foreground">Loading…</p>;
  if (error)
    return (
      <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
        Failed to load projects: {String(error)}
      </p>
    );

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Projects</h1>
      {projects.length === 0 ? (
        <p className="text-muted-foreground">You don&apos;t belong to any projects yet.</p>
      ) : (
        <div className="overflow-hidden rounded-md border border-border bg-card">
          <table className="w-full text-sm">
            <thead className="bg-muted text-left text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-3 py-2">Slug</th>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Role</th>
                <th className="px-3 py-2">Daily budget</th>
              </tr>
            </thead>
            <tbody>
              {projects.map((p) => (
                <tr key={p.id} className="border-t border-border">
                  <td className="px-3 py-2 font-mono text-xs">
                    <a
                      className="text-primary underline"
                      href={`/projects/${p.slug}/settings`}
                    >
                      {p.slug}
                    </a>
                  </td>
                  <td className="px-3 py-2">{p.name}</td>
                  <td className="px-3 py-2">{p.role}</td>
                  <td className="px-3 py-2 text-muted-foreground">
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
