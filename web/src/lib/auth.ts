// Tiny client-side auth helpers shared by every page.

"use client";

import { hasCookie } from "./api";

export function getToken(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return localStorage.getItem("aegis_token") ?? undefined;
}

export function getEmail(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return localStorage.getItem("aegis_email") ?? undefined;
}

export function logout(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem("aegis_token");
  localStorage.removeItem("aegis_email");
  // Also tell the NextAuth callback to clear the Aegis cookies.
  // Fire-and-forget; the redirect to /login happens regardless.
  void fetch("/api/auth/signout-aegis", { method: "POST" }).catch(() => {});
}

/**
 * Bounce to /login when no token is present. Returns the token (or undefined
 * during the brief server-render pass; the redirect fires on hydration).
 *
 * F18: cookie-authed users have no localStorage token but do have an
 * httpOnly aegis_api_session cookie. We can't read that from JS, so we
 * additionally check for the non-httpOnly aegis_csrf cookie that the
 * NextAuth callback (F13) sets alongside it.
 */
export function requireAuth(router: { push: (path: string) => void }): string | undefined {
  const token = getToken();
  if (token) return token;
  if (hasCookie(process.env.NEXT_PUBLIC_AEGIS_CSRF_COOKIE ?? "aegis_csrf")) return "(cookie)";
  if (typeof window !== "undefined") {
    router.push("/login");
  }
  return undefined;
}
