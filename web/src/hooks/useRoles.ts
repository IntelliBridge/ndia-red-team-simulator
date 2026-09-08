"use client";

// useRoles — fetch the calling user's per-project roles.
//
// Backs <RoleGated callerRole={…}/> and any page-level conditional
// rendering. The API enforces the same role checks server side
// (redsim/api/policy.py); this hook is presentation only.

import useSWR from "swr";
import { api, type ProjectMembership } from "@/lib/api";

const fetcher = (path: string) =>
  api<{ projects: ProjectMembership[] }>(path);

export interface UseRolesResult {
  /** Map of project_id -> role. Stable identity per render when ready. */
  roles: Record<string, string>;
  /** Full project list as returned by /v1/projects (for selectors). */
  projects: ProjectMembership[];
  isLoading: boolean;
  error: unknown;
}

export function useRoles(): UseRolesResult {
  const { data, error, isLoading } = useSWR<{ projects: ProjectMembership[] }>(
    "/v1/projects",
    fetcher,
    { revalidateOnFocus: false },
  );

  const projects = data?.projects ?? [];
  const roles: Record<string, string> = {};
  for (const p of projects) {
    roles[p.id] = p.role;
    if (p.slug && p.slug !== p.id) roles[p.slug] = p.role;
  }
  return { roles, projects, isLoading: !!isLoading, error };
}
