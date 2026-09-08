// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const setSpy = vi.hoisted(() => vi.fn());
vi.mock("next/headers", () => ({ cookies: () => ({ set: setSpy }) }));

const keycloakMock = vi.hoisted(() => vi.fn(() => ({ id: "keycloak" })));
vi.mock("next-auth/providers/keycloak", () => ({ default: keycloakMock }));

const mintMock = vi.hoisted(() => vi.fn());
vi.mock("./aegis-session", () => ({
  csrfCookieName: "aegis_csrf",
  sessionCookieName: "aegis_api_session",
  sessionTtlSeconds: 900,
  mintAegisSessionJwt: mintMock,
  newCsrfToken: () => "csrf",
}));

import { authOptions } from "./auth-options";

beforeEach(() => {
  setSpy.mockClear();
  mintMock.mockReset();
});

describe("authOptions config shape", () => {
  it("uses the jwt session strategy, a /login sign-in page and one Keycloak provider", () => {
    expect(authOptions.session?.strategy).toBe("jwt");
    expect(authOptions.pages?.signIn).toBe("/login");
    expect(keycloakMock).toHaveBeenCalled();
    expect(authOptions.providers.length).toBe(1);
  });
});

describe("authOptions.callbacks.jwt", () => {
  it("merges sub/email/name and aegis_project_roles from the Keycloak profile", async () => {
    const token = await authOptions.callbacks!.jwt!({
      token: { sub: "old" },
      account: { provider: "keycloak" },
      profile: {
        sub: "u1",
        email: "u@e.com",
        name: "U",
        aegis_project_roles: { p1: "admin" },
      },
    } as any);

    expect(token.sub).toBe("u1");
    expect(token.email).toBe("u@e.com");
    expect(token.aegisProjectRoles).toEqual({ p1: "admin" });
  });

  it("returns the token unchanged when there is no account/profile", async () => {
    const token = await authOptions.callbacks!.jwt!({
      token: { sub: "x" },
    } as any);

    expect(token.sub).toBe("x");
  });
});

describe("authOptions.callbacks.session", () => {
  it("mints the jwt and sets both Aegis cookies on a session refresh", async () => {
    mintMock.mockResolvedValue("signed-jwt");

    const session = await authOptions.callbacks!.session!({
      session: { user: { email: "u@e.com" } },
      token: {
        sub: "u1",
        email: "u@e.com",
        name: "U",
        aegisProjectRoles: { p1: "admin" },
      },
    } as any);

    expect(mintMock).toHaveBeenCalled();
    expect(setSpy).toHaveBeenCalledTimes(2);
    expect(session.user!.email).toBe("u@e.com");
  });

  it("keeps the session intact and warns when minting fails", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    mintMock.mockRejectedValueOnce(new Error("no key"));

    const s = await authOptions.callbacks!.session!({
      session: { user: { email: "u@e.com" } },
      token: { sub: "u1" },
    } as any);

    expect(s).toBeTruthy();
    expect(setSpy).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });
});
