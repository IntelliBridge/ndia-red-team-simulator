// @vitest-environment node
//
// The server side of /runs: the awaited prefetch, what crosses the RSC
// boundary, and what the first HTML already contains.
//
// Node rather than jsdom, because every module under src/server/ reaches the
// env module and a server-variable read throws once a window exists. The HTML
// comes from react-dom/server, which needs no DOM.
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactElement, ReactNode } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { createTRPCClient, httpBatchLink } from "@trpc/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MockUpstream, detailBody } from "@/test/mock-upstream";
import type { AppRouter } from "@/server/trpc/root";

const API_HOST = "api.internal.invalid";
const SESSION_COOKIE = "fake-session-cookie-value";

// React 18.3.1 exports no cache(), so server.tsx falls back to identity and
// each caller in one render would get its own QueryClient. Next bundles a
// canary that has it. Supplying a single-call memo here exercises the branch
// production takes rather than the fallback.
vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    cache: <TArgs extends unknown[], TResult>(fn: (...args: TArgs) => TResult) => {
      let cached: TResult;
      let filled = false;
      return (...args: TArgs): TResult => {
        if (!filled) {
          cached = fn(...args);
          filled = true;
        }
        return cached;
      };
    },
  };
});

const jar = vi.hoisted(() => new Map<string, string>());
vi.mock("next/headers", () => ({
  cookies: () => ({ get: (name: string) => (jar.has(name) ? { value: jar.get(name) } : undefined) }),
  headers: () => new Headers({ "sec-fetch-site": "same-origin" }),
}));

const redirectMock = vi.hoisted(() =>
  vi.fn((target: string) => {
    throw new Error(`NEXT_REDIRECT:${target}`);
  }),
);
vi.mock("next/navigation", () => ({ redirect: redirectMock }));

const upstream = new MockUpstream();

/** The providers the root layout supplies around a server-rendered page. */
async function renderPage(searchParams?: Record<string, string>): Promise<{
  html: string;
  dehydrated: unknown;
}> {
  vi.resetModules();
  const { default: RunsPage } = await import("./page");
  const { makeQueryClient } = await import("@/lib/trpc/query-client");
  const { TRPCProvider } = await import("@/lib/trpc/client");
  const { dehydrate } = await import("@tanstack/react-query");
  const { getQueryClient } = await import("@/server/trpc/server");

  const element = (await RunsPage({ searchParams })) as ReactElement;

  const browserClient = makeQueryClient();
  const trpcClient = createTRPCClient<AppRouter>({
    links: [httpBatchLink({ url: "http://localhost:3000/api/trpc" })],
  });

  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={browserClient}>
        <TRPCProvider trpcClient={trpcClient} queryClient={browserClient}>
          {children}
        </TRPCProvider>
      </QueryClientProvider>
    );
  }

  const html = renderToStaticMarkup(<Wrapper>{element}</Wrapper>);
  return { html, dehydrated: dehydrate(getQueryClient()) };
}

/** The one query the page prefetches, as the dehydrated state records it. */
function dehydratedQuery(state: unknown): { state: { status: string; data?: unknown; error?: unknown } } {
  const queries = (state as { queries: Array<{ state: { status: string; data?: unknown; error?: unknown } }> }).queries;
  expect(queries).toHaveLength(1);
  return queries[0]!;
}

beforeEach(() => {
  jar.clear();
  jar.set("redsim_api_session", SESSION_COOKIE);
  upstream.json(200, { runs: [], count: 0 });
  upstream.calls.length = 0;
  redirectMock.mockClear();
  vi.stubGlobal("fetch", upstream.fetch);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("RunsPage server component", () => {
  it("awaits the prefetch and dehydrates the rows into the first HTML", async () => {
    upstream.json(200, {
      runs: [
        { id: "run-7", project_id: "default", status: "running", scanner: "ml-campaign", mode: "campaign", created_at: "2026-01-02T03:04:05.000Z", created_by: null },
        { id: "run-8", project_id: "default", status: "failed", scanner: null, mode: "campaign", created_at: "2026-01-02T03:04:05.000Z", created_by: null },
      ],
      count: 2,
    });

    const { html, dehydrated } = await renderPage();

    expect(upstream.calls).toHaveLength(1);
    expect(upstream.calls[0]?.url).toContain("/v1/runs");
    expect(html).toContain("run-7");
    expect(html).toContain("run-8");
    expect(dehydratedQuery(dehydrated).state.status).toBe("success");
  });

  it("passes the search params through to the query it prefetches", async () => {
    await renderPage({ project: "proj-alpha", limit: "25" });
    const url = upstream.calls[0]?.url ?? "";
    expect(url).toContain("project=proj-alpha");
    expect(url).toContain("limit=25");
  });

  it("renders the empty state server-side when the API has no runs", async () => {
    const { html } = await renderPage();
    expect(html).toContain("No runs yet");
    expect(html).toContain('href="/models"');
  });

  it("dehydrates a 503 with its envelope and renders the honest state in the first HTML", async () => {
    upstream.json(503, detailBody("database is unavailable"));

    const { html, dehydrated } = await renderPage();

    expect(html).toContain("Runs are unavailable");
    expect(html).toContain("db_unavailable");

    const query = dehydratedQuery(dehydrated);
    expect(query.state.status).toBe("error");
    expect(query.state.error).toMatchObject({
      data: { upstream: { status: 503, code: "db_unavailable" } },
    });
  });

  it("dehydrates the error as a plain object with no prototype, cause or stack", async () => {
    upstream.json(409, detailBody({ code: "incompatible_campaigns", message: "no", reasons: ["seed"] }));

    const { dehydrated } = await renderPage();
    const error = dehydratedQuery(dehydrated).state.error as Record<string, unknown>;

    expect(Object.getPrototypeOf(error)).toBe(Object.prototype);
    expect("stack" in error).toBe(false);
    expect("cause" in error).toBe(false);
    expect(error.data).toMatchObject({ upstream: { code: "incompatible_campaigns", reasons: ["seed"] } });
    // Survives the JSON trip the RSC boundary makes it take.
    expect(JSON.parse(JSON.stringify(error))).toEqual(error);
  });

  it("leaks neither the API host, the fetch error text nor a stack when the API is unreachable", async () => {
    upstream.networkError(`connect ECONNREFUSED ${API_HOST}:8000`);

    const { html, dehydrated } = await renderPage();
    const serialized = JSON.stringify(dehydrated);

    for (const leak of [API_HOST, "ECONNREFUSED", "at Object.", "node_modules"]) {
      expect(html).not.toContain(leak);
      expect(serialized).not.toContain(leak);
    }
    expect(dehydratedQuery(dehydrated).state.error).toMatchObject({
      data: { upstream: { status: 503, code: "service_unavailable" } },
    });
  });

  it("dehydrates a refused input as a 400 with its field issues, not a generic 500", async () => {
    // The .input() parser runs after withRequestId, so a schema failure reaches
    // toBrowserSafeError carrying only the request id. Without the shared
    // badRequestEnvelope it fell through to the 500 fallback and the user saw
    // upstream_error instead of the 400 the formatter had already computed.
    // limit is capped at 500 by the procedure's schema.
    const { html, dehydrated } = await renderPage({ limit: "99999" });

    expect(upstream.calls).toHaveLength(0);
    expect(html).toContain("bad_request");
    expect(html).not.toContain("upstream_error");

    const query = dehydratedQuery(dehydrated);
    expect(query.state.status).toBe("error");
    expect(query.state.error).toMatchObject({
      data: {
        upstream: { status: 400, code: "bad_request" },
        input: { fieldErrors: { limit: expect.arrayContaining([expect.any(String)]) } },
      },
    });
  });

  it("redirects a 401 through the sign-out hop and dehydrates nothing", async () => {
    upstream.json(401, detailBody("not authenticated"));

    await expect(renderPage()).rejects.toThrow(/NEXT_REDIRECT/);

    const target = redirectMock.mock.calls[0]?.[0] ?? "";
    expect(target).toContain("/api/auth/signout-redsim?hop=");
  });

  it("sends an anonymous request straight to /login, since there is no cookie to clear", async () => {
    // Between this unit and U7 there is no middleware, so an anonymous page
    // load reaches the prefetch with an empty jar and no credential to bind a
    // hop token to.
    jar.clear();

    await expect(renderPage()).rejects.toThrow(/NEXT_REDIRECT/);

    expect(redirectMock).toHaveBeenCalledWith("/login");
    expect(upstream.calls).toHaveLength(0);
  });
});
