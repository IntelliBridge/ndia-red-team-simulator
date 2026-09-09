// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const setSpy = vi.hoisted(() => vi.fn());
vi.mock("next/headers", () => ({ cookies: () => ({ set: setSpy }) }));
vi.mock("@/server/redsim-session", () => ({
  sessionCookieName: "redsim_api_session",
  csrfCookieName: "redsim_csrf",
  sessionTtlSeconds: 900,
  mintRedsimSessionJwt: vi.fn(),
  newCsrfToken: () => "csrf-token",
}));

import { POST } from "./route";

beforeEach(() => {
  setSpy.mockClear();
});

describe("POST /api/auth/signout-redsim", () => {
  it("clears both the session and csrf cookies with maxAge 0", () => {
    POST();

    // The attributes now come from the shared builder the after-hook and the
    // refresh route also use, so the three cannot drift apart.
    expect(setSpy).toHaveBeenCalledWith(
      "redsim_api_session",
      "",
      expect.objectContaining({ path: "/", maxAge: 0, httpOnly: true }),
    );
    expect(setSpy).toHaveBeenCalledWith(
      "redsim_csrf",
      "",
      expect.objectContaining({ path: "/", maxAge: 0, httpOnly: false }),
    );
    expect(setSpy).toHaveBeenCalledTimes(2);
  });

  it("responds 200 with { ok: true }", async () => {
    const res = POST();

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ ok: true });
  });
});
