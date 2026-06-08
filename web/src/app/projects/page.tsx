"use client";

import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

export default function ProjectsPage() {
  const authed = useRequireAuth();
  const { projects, isLoading, error } = useRoles();

  if (!authed) return <p className="text-slate-500">Redirecting to sign in…</p>;
  if (isLoading) return <p className="text-slate-500">Loading…</p>;
  if (error)
    return (
      <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
        Failed to load projects: {String(error)}
      </p>
    );

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Projects</h1>
      {projects.length === 0 ? (
        <p className="text-slate-600">You don&apos;t belong to any projects yet.</p>
      ) : (
        <div className="overflow-hidden rounded-md border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-3 py-2">Slug</th>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Role</th>
                <th className="px-3 py-2">Daily budget</th>
              </tr>
            </thead>
            <tbody>
              {projects.map((p) => (
                <tr key={p.id} className="border-t border-slate-100">
                  <td className="px-3 py-2 font-mono text-xs">
                    <a
                      className="text-sky-700 underline"
                      href={`/projects/${p.slug}/settings`}
                    >
                      {p.slug}
                    </a>
                  </td>
                  <td className="px-3 py-2">{p.name}</td>
                  <td className="px-3 py-2">{p.role}</td>
                  <td className="px-3 py-2 text-slate-600">
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
