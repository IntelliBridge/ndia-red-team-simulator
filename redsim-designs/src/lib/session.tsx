"use client"

import { createContext, useCallback, useContext, useState, type ReactNode } from "react"
import type { Role } from "./api-types"
import { IS_PROD } from "./env"
import { SESSION_COOKIE, serializeSession, type Session } from "./session-cookie"

export type { Session } from "./session-cookie"

interface SessionCtx {
  session: Session | null
  signInDevAdmin: () => void
  signOut: () => void
  setRole: (role: Role) => void
}

const Ctx = createContext<SessionCtx | null>(null)

function writeCookie(s: Session | null) {
  if (typeof document === "undefined") return
  document.cookie = s
    ? `${SESSION_COOKIE}=${serializeSession(s)}; path=/; max-age=86400; samesite=lax`
    : `${SESSION_COOKIE}=; path=/; max-age=0; samesite=lax`
}

/**
 * The session is seeded from the cookie the RSC layout read, so the very first
 * client paint already knows who is signed in — no hydration flash, no gate.
 * The cookie stays the source of truth so middleware can guard routes too.
 */
export function SessionProvider({ initialSession, children }: { initialSession: Session | null; children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(initialSession)

  const persist = useCallback((s: Session | null) => {
    setSession(s)
    writeCookie(s)
  }, [])

  const signInDevAdmin = useCallback(() => {
    if (IS_PROD) return // dev-token path hidden in prod [spec §3]
    persist({ user: "dev-admin", role: "admin", dev: true })
  }, [persist])

  const signOut = useCallback(() => persist(null), [persist])

  const setRole = useCallback(
    (role: Role) =>
      setSession((prev) => {
        if (!prev) return prev
        const next = { ...prev, role }
        writeCookie(next)
        return next
      }),
    [],
  )

  return <Ctx.Provider value={{ session, signInDevAdmin, signOut, setRole }}>{children}</Ctx.Provider>
}

export function useSession() {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error("useSession must be used within SessionProvider")
  return ctx
}

const ORDER: Role[] = ["viewer", "scanner", "remediator", "approver", "admin"]

/** True when the session role is at least `min`. `viewer` is the floor. [spec §7.2] */
export function roleAtLeast(role: Role | undefined, min: Role): boolean {
  if (!role) return false
  return ORDER.indexOf(role) >= ORDER.indexOf(min)
}
