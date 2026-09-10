// @vitest-environment node
//
// The server side of /exports: the awaited prefetch, what crosses the RSC
// boundary, and what the first HTML already contains. Node rather than jsdom
// for the same reason the /runs page test is.
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactElement, ReactNode } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { createTRPCClient, httpBatchLink } from "@trpc/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MockUpstream, detailBody } from "@/test/mock-upstream";
import type { AppRouter } from "@/server/trpc/root";

const SESSION_COOKIE = "fake-session-cookie-value";

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

// The client leaf reads the caller's roles through SWR; the server render
// needs neither the hook's fetch nor its result.
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: {}, projects: [], isLoading: false, error: undefined }),
}));

const upstream = new MockUpstream();

const EMPTY = { exports: [], count: 0, report_formats: ["md", "json", "html", "pdf"], dataset_format: "croissant-parquet", limit: 50 };

function exportRow(runId: string) {
  return {
    run_id: runId,
    project_id: "default",
    kind: "campaign",
    status: "succeeded",
    terminal: true,
    created_at: "2026-01-02T03:04:05+00:00",
    completed_at: null,
    model: { target_id: "tgt-1", name: "Vehicles CNN", value: "bundled:vehicles_cnn", modality: "image", fixture: false },
    reports: {
      run_id: runId,
      formats: { md: null, json: null, html: null, pdf: null },
      available: [],
      missing: ["md", "json", "html", "pdf"],
      snapshot_count: 0,
      latest_snapshot: null,
      render_in_flight: false,
    },
    dataset: {
      format: "croissant-parquet",
      status: "not_exported",
      manifest_artifact_id: null,
      manifest_sha256: null,
      files: 0,
      bytes: 0,
      card: false,
      job_id: null,
      follow_up_run_id: null,
      error: null,
      blockers: ["no_slices"],
    },
  };
}

async function renderPage(searchParams?: Record<string, string>): Promise<{ html: string; dehydrated: unknown }> {
  vi.resetModules();
  const { default: ExportsPage } = await import("./page");
  const { makeQueryClient } = await import("@/lib/trpc/query-client");
  const { TRPCProvider } = await import("@/lib/trpc/client");
  const { dehydrate } = await import("@tanstack/react-query");
  const { getQueryClient } = await import("@/server/trpc/server");

  const element = (await ExportsPage({ searchParams })) as ReactElement;

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

function dehydratedQuery(state: unknown): { state: { status: string; data?: unknown; error?: unknown } } {
  const queries = (state as { queries: Array<{ state: { status: string; data?: unknown; error?: unknown } }> }).queries;
  expect(queries).toHaveLength(1);
  return queries[0]!;
}

beforeEach(() => {
  jar.clear();
  jar.set("redsim_api_session", SESSION_COOKIE);
  upstream.json(200, EMPTY);
  upstream.calls.length = 0;
  redirectMock.mockClear();
  vi.stubGlobal("fetch", upstream.fetch);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("ExportsPage server component", () => {
  it("awaits the prefetch of /v1/exports and dehydrates the rows into the first HTML", async () => {
    upstream.json(200, { ...EMPTY, exports: [exportRow("run-7"), exportRow("run-8")], count: 2 });

    const { html, dehydrated } = await renderPage();

    expect(upstream.calls).toHaveLength(1);
    expect(upstream.calls[0]?.url).toContain("/v1/exports");
    expect(html).toContain("run-7");
    expect(html).toContain("run-8");
    expect(html).toContain("no adversarial slices retained");
    expect(dehydratedQuery(dehydrated).state.status).toBe("success");
  });

  it("passes project, kind and limit through to the query it prefetches", async () => {
    await renderPage({ project: "proj-alpha", kind: "verify", limit: "25" });
    const url = upstream.calls[0]?.url ?? "";
    expect(url).toContain("project=proj-alpha");
    expect(url).toContain("kind=verify");
    expect(url).toContain("limit=25");
  });

  it("drops a kind that is not campaign or verify rather than sending it", async () => {
    await renderPage({ kind: "probe" });
    expect(upstream.calls[0]?.url ?? "").not.toContain("kind=");
  });

  it("renders the empty state and the heading server-side", async () => {
    const { html } = await renderPage();
    expect(html).toContain("Exports");
    expect(html).toContain("Nothing to export yet");
    expect(html).toContain('href="/models"');
  });

  it("dehydrates an upstream refusal as the typed error rather than throwing", async () => {
    upstream.json(503, detailBody("database is unavailable"));
    const { html, dehydrated } = await renderPage();
    const state = dehydratedQuery(dehydrated).state;
    expect(state.status).toBe("error");
    expect(html).toContain("Exports are unavailable");
    expect(html).toContain("db_unavailable");
  });
});
