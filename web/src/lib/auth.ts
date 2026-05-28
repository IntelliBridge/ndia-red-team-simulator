// Tiny client-side auth helpers shared by every page.

"use client";

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
}

/**
 * Bounce to /login when no token is present. Returns the token (or undefined
 * during the brief server-render pass; the redirect fires on hydration).
 */
export function requireAuth(router: { push: (path: string) => void }): string | undefined {
  const token = getToken();
  if (!token && typeof window !== "undefined") {
    router.push("/login");
  }
  return token;
}
