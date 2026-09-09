"use client"

import type { ReactNode } from "react"
import type { Role } from "@/lib/api-types"
import { roleAtLeast, useSession } from "@/lib/session"

/**
 * UX convenience only. The API is the authorization boundary; every gated
 * action must still handle a 403 from the server. Roles tuple includes viewer.
 * [spec §7.2, §7.9]
 */
export const ROLES: readonly Role[] = ["viewer", "scanner", "remediator", "approver", "admin"]

export function RoleGated({ min, children, fallback = null }: { min: Role; children: ReactNode; fallback?: ReactNode }) {
  const { session } = useSession()
  if (!roleAtLeast(session?.role, min)) return <>{fallback}</>
  return <>{children}</>
}
