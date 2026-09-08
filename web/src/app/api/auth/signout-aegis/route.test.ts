// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const setSpy = vi.hoisted(() => vi.fn());
vi.mock("next/headers", () => ({ cookies: () => ({ set: setSpy }) }));
vi.mock("@/server/aegis-session", () => ({
  sessionCookieName: "aegis_api_session",
  csrfCookieName: "aegis_csrf",
}));

import { POST } from "./route";

beforeEach(() => {
  setSpy.mockClear();
});

describe("POST /api/auth/signout-aegis", () => {
  it("clears both the session and csrf cookies with maxAge 0", () => {
    POST();

    expect(setSpy).toHaveBeenCalledWith("aegis_api_session", "", {
      path: "/",
      maxAge: 0,
    });
    expect(setSpy).toHaveBeenCalledWith("aegis_csrf", "", {
      path: "/",
      maxAge: 0,
    });
    expect(setSpy).toHaveBeenCalledTimes(2);
  });

  it("responds 200 with { ok: true }", async () => {
    const res = POST();

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ ok: true });
  });
});
