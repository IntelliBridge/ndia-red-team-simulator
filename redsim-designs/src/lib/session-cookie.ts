import type { Role } from "./api-types"

export interface Session {
  user: string
  role: Role
  /** dev-token path; a real deployment uses NextAuth + Keycloak cookies. */
  dev: boolean
}

/** Non-httpOnly so the client can set it and middleware/RSC can read it. */
export const SESSION_COOKIE = "redsim_session"

/** Isomorphic parse — runs on the server (RSC, middleware) and on the client. */
export function parseSession(raw: string | undefined | null): Session | null {
  if (!raw) return null
  try {
    const s = JSON.parse(decodeURIComponent(raw))
    if (s && typeof s.user === "string" && typeof s.role === "string") return s as Session
  } catch {
    /* malformed cookie → treated as signed out */
  }
  return null
}

export function serializeSession(s: Session): string {
  return encodeURIComponent(JSON.stringify(s))
}
