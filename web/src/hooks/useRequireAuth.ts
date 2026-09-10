"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { requireAuth } from "@/lib/auth";

/**
 * Client-side auth gate for a page.
 *
 * Optimistic: the page renders as authenticated on the server pass and on the
 * first client paint, and only flips to the redirect state when the mount-time
 * check finds no redsim_csrf cookie, the readable half of the session pair the
 * login route sets. The redirect carries the current location as `next`, so a
 * successful sign-in returns here. The previous default of `false` painted a
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
