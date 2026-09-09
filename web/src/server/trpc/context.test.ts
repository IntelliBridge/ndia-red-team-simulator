// @vitest-environment node
//
// The credential rules of KTD2. Node rather than jsdom because the context is
// server-only, and every case re-imports the module graph so the REDSIM_ENV it
// reads through env.js is the one the case set.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const savedEnv = { ...process.env };

const BASE_ENV: Record<string, string> = {
  BETTER_AUTH_SECRET: "test-not-a-real-secret-change-me-0123456789",
  BETTER_AUTH_URL: "http://localhost:3000",
};

function setEnv(values: Record<string, string> = {}) {
  const merged: Record<string, string> = { ...BASE_ENV, ...values };
  process.env = merged as NodeJS.ProcessEnv;
}

async function loadContext() {
  vi.resetModules();
  return import("./context");
}

/** A request carrying the named cookies and headers, as the route handler sees it. */
function request(
  cookies: Record<string, string> = {},
  headers: Record<string, string> = {},
): Request {
  const cookie = Object.entries(cookies)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join("; ");
  return new Request("http://localhost:3000/api/trpc/runs.list", {
    headers: cookie ? { ...headers, cookie } : headers,
  });
}

beforeEach(() => {
  vi.resetModules();
});

afterEach(() => {
  process.env = { ...savedEnv };
});

describe("createContext credential rules", () => {
  it("forwards exactly the session and csrf cookies plus the client CSRF header", async () => {
    setEnv();
    const { createContext, requestPartsFromRequest } = await loadContext();
    const ctx = createContext(
      requestPartsFromRequest(
        request(
          {
            redsim_api_session: "session-value",
            redsim_csrf: "csrf-value",
            "better-auth.session_token": "must-not-cross",
            redsim_dev_token: "dev:someone@example.test",
          },
          { "x-redsim-csrf": "csrf-value", "x-something-else": "nope" },
        ),
      ),
    );

    expect(ctx.credential).toEqual({
      kind: "cookie",
      cookieHeader: "redsim_api_session=session-value; redsim_csrf=csrf-value",
      csrfHeader: "csrf-value",
    });
    expect(ctx.credential?.kind === "cookie" && ctx.credential.cookieHeader).not.toContain(
      "better-auth",
    );
    expect(ctx.credential?.kind === "cookie" && ctx.credential.cookieHeader).not.toContain(
      "redsim_dev_token",
    );
  });

  it("prefers the session cookie when the dev cookie is present too", async () => {
    setEnv({ REDSIM_ENV: "dev" });
    const { createContext, requestPartsFromRequest } = await loadContext();
    const ctx = createContext(
      requestPartsFromRequest(
        request({ redsim_api_session: "s", redsim_dev_token: "dev:a@b.test" }),
      ),
    );
    expect(ctx.credential?.kind).toBe("cookie");
  });

  it("turns the dev cookie into a bearer when REDSIM_ENV is dev", async () => {
    setEnv({ REDSIM_ENV: "dev" });
    const { createContext, requestPartsFromRequest } = await loadContext();
    const ctx = createContext(
      requestPartsFromRequest(request({ redsim_dev_token: "dev:a@b.test" })),
    );
    expect(ctx.credential).toEqual({ kind: "bearer", token: "dev:a@b.test" });
  });

  it("honours the dev cookie when REDSIM_ENV is unset, because the env default is dev", async () => {
    setEnv();
    const { createContext, requestPartsFromRequest } = await loadContext();
    const ctx = createContext(
      requestPartsFromRequest(request({ redsim_dev_token: "dev:a@b.test" })),
    );
    expect(ctx.credential).toEqual({ kind: "bearer", token: "dev:a@b.test" });
  });

  it("refuses the dev cookie outside the dev or test allowlist", async () => {
    for (const redsimEnv of ["prod", "staging", "anything-else"]) {
      setEnv({ REDSIM_ENV: redsimEnv });
      const { createContext, requestPartsFromRequest } = await loadContext();
      const ctx = createContext(
        requestPartsFromRequest(request({ redsim_dev_token: "dev:a@b.test" })),
      );
      expect(ctx.credential).toBeNull();
    }
  });

  it("carries the fetch metadata, origin and content type the mutation gate reads", async () => {
    setEnv();
    const { createContext, requestPartsFromRequest } = await loadContext();
    const ctx = createContext(
      requestPartsFromRequest(
        request(
          {},
          {
            "sec-fetch-site": "same-origin",
            origin: "http://localhost:3000",
            "content-type": "application/json",
          },
        ),
      ),
    );
    expect(ctx.secFetchSite).toBe("same-origin");
    expect(ctx.origin).toBe("http://localhost:3000");
    expect(ctx.contentType).toBe("application/json");
  });

  it("starts with no call ids and mints a fresh one per call, in call order", async () => {
    setEnv();
    const { beginCall, createContext, requestPartsFromRequest } = await loadContext();
    const ctx = createContext(requestPartsFromRequest(request()));
    expect(ctx.requestIds).toEqual([]);

    const first = beginCall(ctx);
    const second = beginCall(ctx);
    expect(first.requestId).toMatch(/^[0-9a-f]{32}$/);
    expect(first.requestId).not.toBe(second.requestId);
    expect(ctx.requestIds).toEqual([first.requestId, second.requestId]);
  });

  it("reports fixture mode only when the server flag and the environment agree", async () => {
    setEnv({ REDSIM_ENV: "dev", REDSIM_DEV_FIXTURES: "1" });
    const on = await loadContext();
    expect(on.createContext(on.requestPartsFromRequest(request())).fixtures).toBe(true);

    setEnv({ REDSIM_ENV: "dev" });
    const off = await loadContext();
    expect(off.createContext(off.requestPartsFromRequest(request())).fixtures).toBe(false);
  });
});
