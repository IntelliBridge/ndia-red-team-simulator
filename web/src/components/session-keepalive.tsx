"use client";

import { useEffect } from "react";
import { usePathname } from "next/navigation";

/**
 * Keep the redsim API session cookie alive while a tab is open.
 *
 * The web app mints `redsim_api_session` (httpOnly) and `redsim_csrf` at login
 * with a TTL of REDSIM_API_SESSION_TTL_SECONDS (900 by default). Nothing
 * refreshed them, so the first API call after that window was a 401 and the
 * page bounced through /login and Keycloak, which read as the app re-running
 * auth every quarter hour. POST /api/auth/refresh-api-session re-mints both
 * cookies from the caller's own verified session; it has to run before expiry,
 * so the interval is a fraction of the shortest TTL in use, and it also fires
 * when a tab becomes visible again after the laptop was asleep.
 */
const INTERVAL_MS = 5 * 60 * 1000;

export async function refreshApiSession(): Promise<boolean> {
  try {
    const resp = await fetch("/api/auth/refresh-api-session", {
      method: "POST",
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    return resp.ok;
  } catch {
    return false;
  }
}

export function SessionKeepalive() {
  const pathname = usePathname();
  useEffect(() => {
    if (pathname === "/login") return;
    let cancelled = false;
    const tick = () => {
      if (cancelled || document.visibilityState !== "visible") return;
      void refreshApiSession();
    };
    const timer = window.setInterval(tick, INTERVAL_MS);
    const onVisible = () => {
      if (document.visibilityState === "visible") tick();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [pathname]);
  return null;
}
