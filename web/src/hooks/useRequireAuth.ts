"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { requireAuth } from "@/lib/auth";

/**
 * Client-side auth gate for a page.
 *
 * Optimistic: the page renders as authenticated on the server pass and on the
 * first client paint, and only flips to the redirect state when the mount-time
 * check finds neither a dev token nor the redsim_csrf cookie. In production the
 * edge middleware (server/gate.ts) has already redirected every request that
 * carries no session cookie, so a page that reaches this hook is authenticated
 * in all but the dev-fixture cases. The previous default of `false` painted a
 * "Redirecting to sign in" placeholder into the server HTML of every page load
 * for as long as the route's JavaScript took to arrive, several seconds on the
 * dev server, which read as the app re-running auth on every tab.
 */
export function useRequireAuth(): boolean {
  const router = useRouter();
  const [authed, setAuthed] = useState(true);
  useEffect(() => {
    if (!requireAuth(router)) setAuthed(false);
  }, [router]);
  return authed;
}
