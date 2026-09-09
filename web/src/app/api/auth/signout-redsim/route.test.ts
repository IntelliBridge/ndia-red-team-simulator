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

describe("GET /api/auth/signout-redsim (the server-prefetch hop)", () => {
  const FAKE_SESSION = "fake-rejected-session-cookie";

  async function hopUrl(credential: string): Promise<string> {
    const { mintHopToken } = await import("@/server/gate");
    const token = await mintHopToken(process.env.BETTER_AUTH_SECRET ?? "", credential);
    return `http://localhost:3000/api/auth/signout-redsim?hop=${encodeURIComponent(token)}`;
  }

  function withCookie(value: string | null): HeadersInit {
    return value === null ? {} : { cookie: `redsim_api_session=${value}` };
  }

  it("clears the redsim pair and lands on /login?reason=rejected", async () => {
    const { GET } = await import("./route");
    const response = await GET(
      new Request(await hopUrl(FAKE_SESSION), { headers: withCookie(FAKE_SESSION) }),
    );

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toContain("/login?reason=rejected");
    const cleared = response.cookies.getAll().map((c) => [c.name, c.value, c.maxAge]);
    expect(cleared).toEqual(
      expect.arrayContaining([
        ["redsim_api_session", "", 0],
        ["redsim_csrf", "", 0],
      ]),
    );
  });

  it("refuses a token minted for a different cookie value, clearing nothing", async () => {
    const { GET } = await import("./route");
    const response = await GET(
      new Request(await hopUrl(FAKE_SESSION), { headers: withCookie("a-different-value") }),
    );

    expect(response.status).toBe(403);
    expect(response.cookies.getAll()).toEqual([]);
  });

  it("refuses a request with no token and one with no cookie", async () => {
    const { GET } = await import("./route");
    const noToken = await GET(
      new Request("http://localhost:3000/api/auth/signout-redsim", {
        headers: withCookie(FAKE_SESSION),
      }),
    );
    expect(noToken.status).toBe(403);

    const noCookie = await GET(new Request(await hopUrl(FAKE_SESSION)));
    expect(noCookie.status).toBe(403);
  });
});
