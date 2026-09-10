// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const setSpy = vi.hoisted(() => vi.fn());
const getSpy = vi.hoisted(() => vi.fn(() => undefined));
vi.mock("next/headers", () => ({ cookies: () => ({ set: setSpy, get: getSpy }) }));

// The upstream revocation, stubbed: this file is about the cookies and the
// origin legs; identity.test.ts covers what the revocation posts.
const revokeMock = vi.hoisted(() => vi.fn(async () => true));
vi.mock("@/server/identity", () => ({ revokeRefreshToken: revokeMock }));
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
  getSpy.mockReset();
  getSpy.mockReturnValue(undefined);
  revokeMock.mockClear();
});

const SIGNOUT_URL = "http://localhost:3000/api/auth/signout-redsim";

/** The sign-out post, with whatever fetch metadata the case is about. */
function post(headers: HeadersInit = {}): Request {
  return new Request(SIGNOUT_URL, { method: "POST", headers });
}

describe("POST /api/auth/signout-redsim", () => {
  it("clears the session, csrf and refresh cookies with maxAge 0", async () => {
    await POST(post({ "sec-fetch-site": "same-origin" }));

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
    // The sealed refresh cookie lives on the auth-route path, so its clear
    // has to name that path or the browser keeps it.
    expect(setSpy).toHaveBeenCalledWith(
      "redsim_refresh",
      "",
      expect.objectContaining({ path: "/api/auth", maxAge: 0, httpOnly: true }),
    );
    expect(setSpy).toHaveBeenCalledTimes(3);
  });

  it("ends the upstream session behind the refresh cookie before clearing", async () => {
    const { sealRefreshToken } = await import("@/server/refresh-cookie");
    const sealed = await sealRefreshToken("rt-live", 600);
    getSpy.mockImplementation(((name: string) =>
      name === "redsim_refresh" ? { value: sealed } : undefined) as never);

    const res = await POST(post({ "sec-fetch-site": "same-origin" }));

    expect(res.status).toBe(200);
    expect(revokeMock).toHaveBeenCalledWith("rt-live");
    expect(setSpy).toHaveBeenCalledTimes(3);
  });

  it("skips the upstream call when there is no refresh cookie to revoke", async () => {
    await POST(post({ "sec-fetch-site": "same-origin" }));
    expect(revokeMock).not.toHaveBeenCalled();
  });

  it("responds 200 with { ok: true }", async () => {
    const res = await POST(post({ "sec-fetch-site": "same-origin" }));

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({ ok: true });
  });

  it("refuses a cross-site post and clears nothing", async () => {
    // Clearing the credential pair is a state change, and this form had no
    // gate at all: a cross-site top-level form post forced the victim's
    // logout while the sibling GET was hop-token protected.
    const res = await POST(post({ "sec-fetch-site": "cross-site" }));

    expect(res.status).toBe(403);
    expect(setSpy).not.toHaveBeenCalled();
  });

  it("refuses a same-site post too, since the cookie jar is not proof of intent", async () => {
    const res = await POST(post({ "sec-fetch-site": "same-site" }));

    expect(res.status).toBe(403);
    expect(setSpy).not.toHaveBeenCalled();
  });

  it("refuses an untrusted Origin when the browser sent no fetch metadata", async () => {
    const res = await POST(post({ origin: "https://evil.test" }));

    expect(res.status).toBe(403);
    expect(setSpy).not.toHaveBeenCalled();
  });

  it("admits the app's own bare post, which carries no Content-Type at all", async () => {
    // Both callers send fetch(url, { method: "POST" }) with no body. The full
    // mutation gate requires application/json and would refuse them, which is
    // why this route takes only the origin legs. No fetch metadata and no
    // Origin is admitted, the same call the mutation gate makes.
    const res = await POST(post());

    expect(res.status).toBe(200);
    expect(setSpy).toHaveBeenCalledTimes(3);
  });
});

describe("GET /api/auth/signout-redsim (the server-prefetch hop)", () => {
  const FAKE_SESSION = "fake-rejected-session-cookie";

  async function hopUrl(credential: string): Promise<string> {
    const { mintHopToken } = await import("@/server/gate");
    const token = await mintHopToken(process.env.REDSIM_WEB_SESSION_SECRET ?? "", credential);
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
