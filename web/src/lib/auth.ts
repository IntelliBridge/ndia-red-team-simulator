// Tiny client-side auth helpers shared by every page.

"use client";

import { env } from "@/env";

import { hasCookie } from "./api";
import { signOut } from "./auth-client";

export function getToken(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return localStorage.getItem("redsim_token") ?? undefined;
}

export function getEmail(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return localStorage.getItem("redsim_email") ?? undefined;
}

/**
 * End every session this browser holds, then resolve.
 *
 * There are three, not one. Better Auth's own session cookie and the Keycloak
 * SSO session behind it are ended by signOut(), which reaches Keycloak's
 * end_session_endpoint through the issuer discovery the provider already does.
 * The redsim pair minted by the login after-hook is cleared by the POST.
 * Dropping the first leaves the upstream SSO session alive, so one click on
 * "Continue with Keycloak" signs the same user straight back in.
 *
 * Neither call is allowed to strand the user on an authenticated page, so both
 * settle rather than reject and the caller redirects either way.
 */
export async function logout(): Promise<void> {
  if (typeof window === "undefined") return;
  localStorage.removeItem("redsim_token");
  localStorage.removeItem("redsim_email");
  await Promise.allSettled([
    signOut(),
    fetch("/api/auth/signout-redsim", { method: "POST" }),
  ]);
}

/**
 * Bounce to /login when no token is present. Returns the token (or undefined
 * during the brief server-render pass; the redirect fires on hydration).
 *
 * Cookie-authed users have no localStorage token but do have an httpOnly
 * redsim_api_session cookie. We can't read that from JS, so we additionally
 * check for the non-httpOnly redsim_csrf cookie that the login after-hook
 * sets alongside it.
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
