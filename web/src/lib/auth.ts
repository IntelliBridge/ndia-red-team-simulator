// Tiny client-side auth helpers shared by every page.

"use client";

import { env } from "@/env";

import { hasCookie } from "./api";

export function getToken(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return localStorage.getItem("redsim_token") ?? undefined;
}

export function getEmail(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return localStorage.getItem("redsim_email") ?? undefined;
}

export function logout(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem("redsim_token");
  localStorage.removeItem("redsim_email");
  // Also tell the NextAuth callback to clear the Redsim cookies.
  // Fire-and-forget; the redirect to /login happens regardless.
  void fetch("/api/auth/signout-redsim", { method: "POST" }).catch(() => {});
}

/**
 * Bounce to /login when no token is present. Returns the token (or undefined
 * during the brief server-render pass; the redirect fires on hydration).
 *
 * F18: cookie-authed users have no localStorage token but do have an
 * httpOnly redsim_api_session cookie. We can't read that from JS, so we
 * additionally check for the non-httpOnly redsim_csrf cookie that the
 * NextAuth callback (F13) sets alongside it.
 */
export function requireAuth(router: { push: (path: string) => void }): string | undefined {
  const token = getToken();
  if (token) return token;
  if (hasCookie(env.NEXT_PUBLIC_REDSIM_CSRF_COOKIE)) return "(cookie)";
  if (typeof window !== "undefined") {
    router.push("/login");
  }
  return undefined;
}
