// The client leaf of /runs, mounted the way the browser mounts it.
//
// jsdom, and deliberately no server module at runtime: the env module throws
// on a server-variable read once a window exists, which is the same boundary
// the app enforces. The link is mocked at the wire, so the leaf sees exactly
// the envelope the error formatter emits.
import { act, cleanup, screen, waitFor } from "@testing-library/react";
import { QueryClient, dehydrate, type DehydratedState } from "@tanstack/react-query";
import { createTRPCClient, httpBatchLink } from "@trpc/client";
import { createTRPCOptionsProxy } from "@trpc/tanstack-react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Run } from "@/lib/api";
import { makeQueryClient } from "@/lib/trpc/query-client";
import { renderWithProviders } from "@/test/render";
import { trpcResult, trpcUpstreamError } from "@/test/mock-upstream";
import type { AppRouter } from "@/server/trpc/root";

import { RUNS_POLL_MS, RunsTable } from "./runs-table";

type RunsList = { runs: Run[]; count: number };

function run(over: Partial<Run> = {}): Run {
  return {
    id: "run-1",
    project_id: "default",
    status: "succeeded",
    scanner: "ml-campaign",
    mode: "campaign",
    created_at: "2026-01-02T03:04:05.000Z",
    created_by: null,
    ...over,
  };
}

/** A client that never reaches the network; only its key shapes are used. */
function keyProxy(queryClient: QueryClient) {
  const client = createTRPCClient<AppRouter>({
    links: [
      httpBatchLink({
        url: "http://localhost:3000/api/trpc",
        fetch: (() => Promise.reject(new Error("unused"))) as unknown as typeof fetch,
      }),
    ],
  });
  return createTRPCOptionsProxy<AppRouter>({ client, queryClient });
}

/** The dehydrated state a server prefetch of runs.list would have produced. */
async function dehydratedRunsList(
  outcome: { data: RunsList } | { error: unknown },
): Promise<DehydratedState> {
  const queryClient = makeQueryClient();
  const options = keyProxy(queryClient).runs.list.queryOptions({});
  await queryClient.prefetchQuery({
    ...options,
    retry: false,
    queryFn: () => ("data" in outcome ? Promise.resolve(outcome.data) : Promise.reject(outcome.error)),
  });
  return dehydrate(queryClient);
}

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("RunsTable hydration", () => {
  it("renders hydrated rows synchronously and issues no fetch inside the stale window", async () => {
    const dehydratedState = await dehydratedRunsList({
      data: { runs: [run({ id: "run-7", status: "running" }), run({ id: "run-8", status: "failed" })], count: 2 },
    });

    vi.useFakeTimers();
    const { trpcFetch } = renderWithProviders(<RunsTable />, { dehydratedState });

    // Synchronously, in the same tick as mount: the hydration guarantee.
    expect(screen.getByRole("link", { name: "run-7" }).getAttribute("href")).toBe("/runs/run-7");
    expect(screen.getByRole("link", { name: "run-8" }).getAttribute("href")).toBe("/runs/run-8");
    expect(trpcFetch).not.toHaveBeenCalled();

    await act(async () => {
      vi.advanceTimersByTime(RUNS_POLL_MS - 1);
    });
    expect(trpcFetch).not.toHaveBeenCalled();
  });

  it("refetches on the poll, so a running run does not go stale on screen", async () => {
    // The interval is installed when the observer settles on the hydrated
    // data, not at the first paint, so the boundary is asserted as "within one
    // further interval" rather than at an exact tick. What matters is that
    // nothing fetches inside the window and the poll is what recovers.
    const dehydratedState = await dehydratedRunsList({
      data: { runs: [run({ id: "run-9", status: "running" })], count: 1 },
    });

    vi.useFakeTimers();
    const { trpcFetch } = renderWithProviders(<RunsTable />, {
      dehydratedState,
      respond: () => [trpcResult({ runs: [run({ id: "run-9", status: "succeeded" })], count: 1 })],
    });

    await act(async () => {
      vi.advanceTimersByTime(RUNS_POLL_MS - 1);
    });
    expect(trpcFetch).not.toHaveBeenCalled();

    await act(async () => {
      vi.advanceTimersByTime(RUNS_POLL_MS + 1);
    });
    expect(trpcFetch).toHaveBeenCalledTimes(1);
  });

  it("keeps a hydrated error on screen without refetching it on mount", async () => {
    // retryOnMount, not staleTime, is what holds this: TanStack remounts an
    // errored query with no data unless the flag is off.
    const dehydratedState = await dehydratedRunsList({
      error: { data: { upstream: { status: 503, code: "db_unavailable", message: "database is unavailable" }, requestId: "r" } },
    });

    vi.useFakeTimers();
    const { trpcFetch } = renderWithProviders(<RunsTable />, { dehydratedState });

    expect(screen.getByRole("alert").textContent).toContain("db_unavailable");
    expect(trpcFetch).not.toHaveBeenCalled();

    await act(async () => {
      vi.advanceTimersByTime(RUNS_POLL_MS - 1);
    });
    expect(trpcFetch).not.toHaveBeenCalled();

    // The poll is the recovery path for a hydrated error, and it is bounded by
    // the interval rather than by staleTime.
    await act(async () => {
      vi.advanceTimersByTime(RUNS_POLL_MS + 1);
    });
    expect(trpcFetch).toHaveBeenCalledTimes(1);
  });
});

describe("RunsTable when a poll fails over hydrated rows", () => {
  it("keeps the rows and says they may be stale, rather than blanking them", async () => {
    // TanStack keeps `data` alongside `error`. With retry off and a 15 s poll,
    // branching on query.error alone replaced rows that were still in cache
    // with the blocking alert, so one transient failure emptied the page.
    const dehydratedState = await dehydratedRunsList({
      data: { runs: [run({ id: "run-7", status: "running" })], count: 1 },
    });

    vi.useFakeTimers();
    const { trpcFetch } = renderWithProviders(<RunsTable />, {
      dehydratedState,
      respond: () => [trpcUpstreamError(503, { message: "database is unavailable" })],
    });

    expect(screen.getByRole("link", { name: "run-7" })).toBeTruthy();

    await act(async () => {
      vi.advanceTimersByTime(RUNS_POLL_MS + 1);
    });
    expect(trpcFetch).toHaveBeenCalledTimes(1);
    // The interval fired the request; this settles its answer into the query.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });

    // Still on screen, in a real table.
    expect(screen.getByRole("link", { name: "run-7" })).toBeTruthy();
    expect(screen.getByRole("table")).toBeTruthy();
    // And the failure is admitted, non-blocking, next to them.
    const stale = screen.getByRole("status");
    expect(stale.textContent).toContain("out of date");
    expect(stale.textContent).toContain("db_unavailable");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("still blocks when the failure arrives with nothing in cache", async () => {
    vi.useRealTimers();
    renderWithProviders(<RunsTable />, {
      respond: () => [trpcUpstreamError(503, { message: "database is unavailable" })],
    });

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Runs are unavailable");
    expect(screen.queryByRole("status")).toBeNull();
    expect(screen.queryByRole("table")).toBeNull();
  });
});

describe("RunsTable states", () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  it("renders the empty state with a /models link and no table", async () => {
    const dehydratedState = await dehydratedRunsList({ data: { runs: [], count: 0 } });
    renderWithProviders(<RunsTable />, { dehydratedState });

    expect(screen.getByText(/No runs yet/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "/models" }).getAttribute("href")).toBe("/models");
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("names the upstream code on an unavailable API and retries on demand", async () => {
    const { trpcFetch } = renderWithProviders(<RunsTable />, {
      respond: () => [trpcUpstreamError(503, { message: "database is unavailable" })],
    });

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("db_unavailable");
    expect(alert.textContent).toContain("database is unavailable");
    expect(trpcFetch).toHaveBeenCalledTimes(1);

    screen.getByRole("button", { name: "Retry" }).click();
    await waitFor(() => expect(trpcFetch).toHaveBeenCalledTimes(2));
  });

  it("renders the spec 18.1 columns, with Model and Attacks not recorded", async () => {
    // A real campaign row, because redsim/services/ml_campaigns.py always sets
    // scanner to ml.campaign or ml.verify. A null here would have exercised a
    // fallback no live row ever reaches, and left the scanner id printing
    // under a header reading Model.
    const dehydratedState = await dehydratedRunsList({
      data: { runs: [run({ id: "run-7", scanner: "ml.campaign" })], count: 1 },
    });
    renderWithProviders(<RunsTable />, { dehydratedState });

    const headers = screen.getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual(["Run", "Model", "Attacks", "Status", "Created"]);

    // Read by column, since Model and Attacks now say the same thing.
    const cells = screen.getAllByRole("row")[1]?.querySelectorAll("td");
    expect(cells?.[1]?.textContent).toBe("not recorded");
    expect(cells?.[2]?.textContent).toBe("not recorded");
    // The scanner id is not a model, so it reaches no cell.
    expect(screen.queryByText("ml.campaign")).toBeNull();
  });

  it("formats Created in UTC, so the server and client markup agree", async () => {
    const dehydratedState = await dehydratedRunsList({
      data: { runs: [run({ created_at: "2026-01-02T03:04:05.000Z" })], count: 1 },
    });
    renderWithProviders(<RunsTable />, { dehydratedState });

    expect(screen.getByText(/UTC$/).textContent).toBe("Jan 02, 2026, 03:04 UTC");
  });

  it("carries the table caption and column scopes the a11y contract needs", async () => {
    const dehydratedState = await dehydratedRunsList({ data: { runs: [run()], count: 1 } });
    const { container } = renderWithProviders(<RunsTable />, { dehydratedState });

    expect(container.querySelector("caption")?.textContent).toBe("All runs");
    for (const header of container.querySelectorAll("th")) {
      expect(header.getAttribute("scope")).toBe("col");
    }
  });
});
