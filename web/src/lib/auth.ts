// Tiny client-side auth helpers shared by every page.
//
// The browser holds no token. It holds the httpOnly redsim_api_session cookie
// the login route minted, which JavaScript cannot read, and the readable
// redsim_csrf cookie that sits beside it for exactly as long. Presence of the
// csrf cookie is therefore the client's whole view of "signed in".

"use client";

import { env } from "@/env";

import { hasCookie } from "./api";
import { type LoginFailure } from "./login-messages";

export type LoginOutcome = { ok: true } | { ok: false; code: LoginFailure };

/**
 * Submit the email and password to the login route.
 *
 * Resolves rather than rejects on every path: the page shows the code's
 * sentence and the password field keeps focus. A network failure reads as the
 * service being unavailable, which is what it is from where the user sits.
 */
export async function signInWithPassword(email: string, password: string): Promise<LoginOutcome> {
  let response: Response;
  try {
    response = await fetch("/api/auth/login", {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ email, password }),
    });
  } catch {
    return { ok: false, code: "unavailable" };
  }
  if (response.ok) return { ok: true };
  let code: LoginFailure = "unknown";
  try {
    const body = (await response.json()) as { error?: unknown };
    if (typeof body.error === "string") code = body.error as LoginFailure;
  } catch {
    // A non-JSON refusal keeps the generic sentence.
  }
  return { ok: false, code };
}

/** Whether this browser holds a session, as far as the client can tell. */
export function isAuthenticated(): boolean {
  if (typeof window === "undefined") return false;
  return hasCookie(env.NEXT_PUBLIC_REDSIM_CSRF_COOKIE);
}

/**
 * The login page, carrying the current location so a successful sign-in
 * returns there. The root and the login page itself carry nothing.
 */
export function loginPath(): string {
  if (typeof window === "undefined") return "/login";
  const here = `${window.location.pathname}${window.location.search}`;
  if (here === "/" || here.startsWith("/login")) return "/login";
  return `/login?next=${encodeURIComponent(here)}`;
}

/**
 * End the session this browser holds, then resolve.
 *
 * One POST clears the three credential cookies and ends the upstream session
 * behind the refresh cookie. It settles rather than rejects, so a failing
 * sign-out cannot strand the user on an authenticated page: the caller
 * redirects either way.
 */
export async function logout(): Promise<void> {
  if (typeof window === "undefined") return;
  await Promise.allSettled([fetch("/api/auth/signout-redsim", { method: "POST" })]);
}

/**
 * Bounce to /login when no session is present. Returns whether the browser is
 * signed in (false during the brief server-render pass; the redirect fires on
 * hydration).
 */
export function requireAuth(router: { push: (path: string) => void }): boolean {
  if (isAuthenticated()) return true;
  if (typeof window !== "undefined") {
    router.push(loginPath());
  }
  return false;
}
