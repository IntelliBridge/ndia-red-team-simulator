// <RoleGated action=... projectId=... /> — UX-only gating.
//
// The API enforces the same RBAC server-side; this component just
// hides controls the caller can't use anyway so the UI doesn't show
// dead buttons. Real authorization is the API's responsibility.

import { type ReactNode } from "react";

export const ROLES = ["scanner", "remediator", "approver", "admin"] as const;
export type Role = (typeof ROLES)[number];

export interface RoleGatedProps {
  /** Role this action requires on the given project. */
  minRole: Role;
  /** The caller's role on the project, or undefined when no membership. */
  callerRole: string | undefined;
  /** Children shown when the caller's role meets/exceeds minRole. */
  children: ReactNode;
  /** Optional fallback rendered when access is denied. */
  fallback?: ReactNode;
}

const RANK: Record<Role, number> = Object.fromEntries(
  ROLES.map((r, i) => [r, i + 1]),
) as Record<Role, number>;

function rankOf(role: string | undefined): number {
  if (!role) return 0;
  return RANK[role as keyof typeof RANK] ?? 0;
}

export function RoleGated({
  minRole,
  callerRole,
  children,
  fallback = null,
}: RoleGatedProps) {
  return rankOf(callerRole) >= RANK[minRole] ? <>{children}</> : <>{fallback}</>;
}
