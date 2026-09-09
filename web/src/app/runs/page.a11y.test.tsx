// Accessibility of the /runs leaf. Renders the real design-system Table and
// RunStatusBadge (no primitive stubs) so axe sees the caption, the column
// scopes and the badge's aria-label.
import { cleanup } from "@testing-library/react";
import { dehydrate, type DehydratedState } from "@tanstack/react-query";
import { createTRPCClient, httpBatchLink } from "@trpc/client";
import { createTRPCOptionsProxy } from "@trpc/tanstack-react-query";
import { afterEach, describe, expect, it } from "vitest";
import { axe } from "vitest-axe";

import type { Run } from "@/lib/api";
import { makeQueryClient } from "@/lib/trpc/query-client";
import { renderWithProviders } from "@/test/render";
import { trpcUpstreamError } from "@/test/mock-upstream";
import type { AppRouter } from "@/server/trpc/root";

import { RunsTable } from "./runs-table";

async function dehydratedRuns(runs: Run[]): Promise<DehydratedState> {
  const queryClient = makeQueryClient();
  const client = createTRPCClient<AppRouter>({
    links: [
      httpBatchLink({
        url: "http://localhost:3000/api/trpc",
        fetch: (() => Promise.reject(new Error("unused"))) as unknown as typeof fetch,
      }),
    ],
  });
  const options = createTRPCOptionsProxy<AppRouter>({ client, queryClient }).runs.list.queryOptions({});
  await queryClient.prefetchQuery({
    ...options,
    retry: false,
    queryFn: () => Promise.resolve({ runs, count: runs.length }),
  });
  return dehydrate(queryClient);
}

const RUN: Run = {
  id: "run-7",
  project_id: "default",
  status: "running",
  scanner: "ml-campaign",
  mode: "campaign",
  created_at: "2026-01-02T03:04:05.000Z",
  created_by: null,
};

afterEach(cleanup);

describe("RunsTable a11y", () => {
  it("the populated table has no axe violations", async () => {
    const dehydratedState = await dehydratedRuns([RUN, { ...RUN, id: "run-8", status: "failed" }]);
    const { container } = renderWithProviders(<RunsTable />, { dehydratedState });
    expect((await axe(container)).violations).toEqual([]);
  });

  it("the empty state has no axe violations", async () => {
    const dehydratedState = await dehydratedRuns([]);
    const { container } = renderWithProviders(<RunsTable />, { dehydratedState });
    expect((await axe(container)).violations).toEqual([]);
  });

  it("the unavailable state has no axe violations", async () => {
    const { container, findByRole } = renderWithProviders(<RunsTable />, {
      respond: () => [trpcUpstreamError(503, { message: "database is unavailable" })],
    });
    await findByRole("alert");
    expect((await axe(container)).violations).toEqual([]);
  });
});
