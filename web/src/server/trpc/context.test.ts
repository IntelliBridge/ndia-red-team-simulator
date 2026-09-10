// @vitest-environment node
//
// The credential rules of KTD2. Node rather than jsdom because the context is
// server-only, and every case re-imports the module graph so the REDSIM_ENV it
// reads through env.js is the one the case set.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const savedEnv = { ...process.env };

const BASE_ENV: Record<string, string> = {
  REDSIM_WEB_SESSION_SECRET: "test-not-a-real-secret-change-me-0123456789",
  REDSIM_WEB_ORIGIN: "http://localhost:3000",
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

/** A request carrying a `Cookie` header verbatim, encoding and all. */
function rawCookieRequest(cookie: string): Request {
  return new Request("http://localhost:3000/api/trpc/runs.list", { headers: { cookie } });
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
            redsim_refresh: "must-not-cross",
            other_cookie: "must-not-cross-either",
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
      "must-not-cross",
    );
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

describe("a malformed cookie in the jar", () => {
  // `decodeURIComponent("100%")` throws a URIError, and both entry points build
  // the context synchronously outside any try/catch: the tRPC route handler
  // before `fetchRequestHandler`, and the sign-out hop before it can clear
  // anything. An unguarded decode turned one bad cookie into a raw 500 on every
  // procedure call and on the recovery hop itself.
  const MALFORMED = "junk=100%";
  const ENCODED_SESSION = "redsim_api_session=fake%2Fsession%2Bvalue";

  it("is skipped by the reader the sign-out hop uses, leaving the rest of the jar readable", async () => {
    setEnv();
    const { cookieReaderFromHeader } = await loadContext();

    const cookie = cookieReaderFromHeader(`${MALFORMED}; ${ENCODED_SESSION}`);

    expect(cookie("junk")).toBeUndefined();
    // Decoded, not raw: this reader has to agree with `cookies()` on the
    // server-component side or the hop refuses a legitimate credential.
    expect(cookie("redsim_api_session")).toBe("fake/session+value");
  });

  it("does not stop the tRPC route handler building a context", async () => {
    setEnv({ REDSIM_ENV: "dev" });
    const { createContext, requestPartsFromRequest } = await loadContext();

    const ctx = createContext(
      requestPartsFromRequest(rawCookieRequest(`${MALFORMED}; ${ENCODED_SESSION}`)),
    );

    expect(ctx.credential).toMatchObject({
      kind: "cookie",
      cookieHeader: "redsim_api_session=fake/session+value",
    });
  });

  it("does not stop the session credential being read either", async () => {
    setEnv();
    const { createContext, requestPartsFromRequest } = await loadContext();

    const ctx = createContext(
      requestPartsFromRequest(
        rawCookieRequest(`redsim_api_session=s; ${MALFORMED}; redsim_csrf=c`),
      ),
    );

    expect(ctx.credential).toEqual({
      kind: "cookie",
      cookieHeader: "redsim_api_session=s; redsim_csrf=c",
      csrfHeader: null,
    });
  });
});
