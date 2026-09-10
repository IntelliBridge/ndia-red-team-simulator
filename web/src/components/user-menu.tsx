"use client";

// UserMenu: the account control at the right end of the top bar. Signed out
// it is a Sign in link; signed in it is an avatar button that opens a small
// menu carrying the account and Sign out. The login page renders neither,
// because the page itself is the sign-in affordance.

import { useEffect, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import useSWR from "swr";

import { isAuthenticated, loginPath, logout } from "@/lib/auth";

/** Who the session cookie says is signed in, as the me route answers it. */
interface SessionUser {
  sub: string;
  email: string;
  name: string;
}

async function fetchMe(path: string): Promise<SessionUser | null> {
  const response = await fetch(path, { credentials: "include", headers: { accept: "application/json" } });
  if (!response.ok) return null;
  return (await response.json()) as SessionUser;
}

/**
 * One or two letters for the avatar. A display name gives its first and last
 * initials, an email its first letter, and an account with neither the same
 * fallback a missing name gets, so the circle is never empty.
 */
export function initialsFor(user: { name?: string; email?: string }): string {
  const parts = (user.name ?? "").trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return `${parts[0]![0]!}${parts[parts.length - 1]![0]!}`.toUpperCase();
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase();
  const email = (user.email ?? "").trim();
  if (email) return email[0]!.toUpperCase();
  return "?";
}

export function UserMenu() {
  const router = useRouter();
  const pathname = usePathname() ?? "";
  const [open, setOpen] = useState(false);
  // "unknown" until hydration: the server render has no browser cookies, so
  // it cannot tell the two states apart, and guessing either way flashes the
  // wrong control on the first paint of every page.
  const [session, setSession] = useState<"unknown" | "in" | "out">("unknown");
  const container = useRef<HTMLDivElement>(null);

  useEffect(() => setSession(isAuthenticated() ? "in" : "out"), [pathname]);

  const { data: user } = useSWR(session === "in" ? "/api/auth/me" : null, fetchMe, {
    revalidateOnFocus: false,
  });

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    const onPointer = (event: MouseEvent) => {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onPointer);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onPointer);
    };
  }, [open]);

  // Awaited, so the redirect follows both the upstream sign-out and the
  // cookie clear rather than racing them.
  const signOut = async () => {
    setOpen(false);
    await logout();
    router.push("/login");
  };

  if (pathname === "/login" || session === "unknown") return null;

  if (session === "out") {
    return (
      <a
        href={loginPath()}
        className="rounded-md border border-border bg-card px-3 py-1.5 text-sm hover:bg-muted"
      >
        Sign in
      </a>
    );
  }

  const label = user?.name?.trim() || user?.email || "Account";

  return (
    <div className="relative" ref={container}>
      <button
        type="button"
        onClick={() => setOpen((wasOpen) => !wasOpen)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Account: ${label}`}
        data-testid="user-menu-button"
        className="flex h-8 w-8 items-center justify-center rounded-full border border-border bg-muted font-mono text-xs font-semibold text-foreground hover:bg-navy-elevated focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {initialsFor(user ?? {})}
      </button>
      {open ? (
        <div
          role="menu"
          aria-label="Account"
          className="absolute right-0 z-50 mt-2 w-60 overflow-hidden rounded-md border border-border bg-card shadow-lg"
        >
          <div className="border-b border-border px-3 py-2">
            <div className="truncate text-sm font-medium text-foreground">{label}</div>
            {user?.email && user.email !== label ? (
              <div className="truncate text-xs text-muted-foreground">{user.email}</div>
            ) : null}
          </div>
          <button
            type="button"
            role="menuitem"
            onClick={signOut}
            className="block w-full px-3 py-2 text-left text-sm text-foreground hover:bg-muted"
          >
            Sign out
          </button>
        </div>
      ) : null}
    </div>
  );
}
