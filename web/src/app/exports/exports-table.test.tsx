// The client leaf of /exports, mounted the way the browser mounts it.
//
// jsdom, no server module at runtime; the tRPC link is fed the wire envelope.
// The role hook is mocked so the gated actions can be exercised without a
// /v1/projects round trip.
import { act, cleanup, screen, waitFor } from "@testing-library/react";
import { QueryClient, dehydrate, type DehydratedState } from "@tanstack/react-query";
import { createTRPCClient, httpBatchLink } from "@trpc/client";
import { createTRPCOptionsProxy } from "@trpc/tanstack-react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ExportRow, ExportsList } from "@/lib/api";
import { makeQueryClient } from "@/lib/trpc/query-client";
import { renderWithProviders } from "@/test/render";
import { trpcResult, trpcUpstreamError } from "@/test/mock-upstream";
import type { AppRouter } from "@/server/trpc/root";

const rolesMock = vi.hoisted(() => ({ roles: {} as Record<string, string> }));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: rolesMock.roles, projects: [], isLoading: false, error: undefined }),
}));

import { EXPORTS_POLL_MS, ExportsTable } from "./exports-table";

function artifact(id: string, ext: string, source: "snapshot" | "artifact" = "snapshot") {
  return {
    artifact_id: id,
    kind: `report.${ext}`,
    sha256: "a".repeat(64),
    size_bytes: 1024,
    source,
    ...(source === "snapshot" ? { snapshot_version: 1 } : {}),
  };
}

function row(over: Partial<ExportRow> = {}): ExportRow {
  return {
    run_id: "run-1",
    project_id: "default",
    kind: "campaign",
    status: "succeeded",
    terminal: true,
    created_at: "2026-01-02T03:04:05+00:00",
    completed_at: "2026-01-02T03:10:05+00:00",
    model: { target_id: "tgt-1", name: "Vehicles CNN", value: "bundled:vehicles_cnn", modality: "image", fixture: false },
    reports: {
      run_id: "run-1",
      formats: {
        md: artifact("art-md", "md"),
        json: artifact("art-json", "json"),
        html: artifact("art-html", "html"),
        pdf: null,
      },
      available: ["md", "json", "html"],
      missing: ["pdf"],
      snapshot_count: 1,
      latest_snapshot: { id: "snap-1", version: 1, rendered_at: "2026-01-02T03:10:05+00:00", archived: false },
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
      blockers: [],
    },
    ...over,
  };
}

function list(rows: ExportRow[]): ExportsList {
  return { exports: rows, count: rows.length, report_formats: ["md", "json", "html", "pdf"], dataset_format: "croissant-parquet", limit: 50 };
}

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

async function dehydratedList(
  outcome: { data: ExportsList } | { error: unknown },
  input: { project?: string; limit?: number } = {},
): Promise<DehydratedState> {
  const queryClient = makeQueryClient();
  const options = keyProxy(queryClient).exports.list.queryOptions(input);
  await queryClient.prefetchQuery({
    ...options,
    retry: false,
    queryFn: () => ("data" in outcome ? Promise.resolve(outcome.data) : Promise.reject(outcome.error)),
  });
  return dehydrate(queryClient);
}

beforeEach(() => {
  rolesMock.roles = {};
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("ExportsTable hydration and polling", () => {
  it("renders hydrated rows synchronously and issues no fetch inside the stale window", async () => {
    const dehydratedState = await dehydratedList({ data: list([row({ run_id: "run-7" }), row({ run_id: "run-8" })]) });

    vi.useFakeTimers();
    const { trpcFetch } = renderWithProviders(<ExportsTable />, { dehydratedState });

    expect(screen.getByRole("link", { name: "run-7" }).getAttribute("href")).toBe("/runs/run-7");
    expect(screen.getByRole("link", { name: "run-8" }).getAttribute("href")).toBe("/runs/run-8");
    expect(trpcFetch).not.toHaveBeenCalled();

    await act(async () => {
      vi.advanceTimersByTime(EXPORTS_POLL_MS - 1);
    });
    expect(trpcFetch).not.toHaveBeenCalled();

    await act(async () => {
      vi.advanceTimersByTime(EXPORTS_POLL_MS + 1);
    });
    expect(trpcFetch).toHaveBeenCalledTimes(1);
  });

  it("keeps the rows and says they may be stale when a poll fails", async () => {
    const dehydratedState = await dehydratedList({ data: list([row({ run_id: "run-7" })]) });

    vi.useFakeTimers();
    const { trpcFetch } = renderWithProviders(<ExportsTable />, {
      dehydratedState,
      respond: () => [trpcUpstreamError(503, { message: "database is unavailable" })],
    });

    await act(async () => {
      vi.advanceTimersByTime(EXPORTS_POLL_MS + 1);
    });
    expect(trpcFetch).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });

    expect(screen.getByRole("link", { name: "run-7" })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("db_unavailable");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("blocks with the upstream code when nothing is in cache", async () => {
    renderWithProviders(<ExportsTable />, {
      respond: () => [trpcUpstreamError(503, { message: "database is unavailable" })],
    });
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Exports are unavailable");
    expect(alert.textContent).toContain("db_unavailable");
    expect(screen.queryByRole("table")).toBeNull();
  });
});

describe("ExportsTable rows", () => {
  it("renders the columns without a kind filter and the UTC timestamp", async () => {
    const dehydratedState = await dehydratedList({ data: list([row()]) }, { project: "proj-a" });
    renderWithProviders(<ExportsTable project="proj-a" />, { dehydratedState });

    const headers = screen.getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual(["Run", "Model", "Status", "Reports", "Dataset", "Created"]);

    expect(screen.queryByRole("navigation", { name: "Export kind" })).toBeNull();
    expect(screen.getByText(/UTC$/).textContent).toBe("Jan 02, 2026, 03:04 UTC");
    expect(screen.getByText("Vehicles CNN")).toBeTruthy();
  });

  it("links the rendered formats, strikes the missing one and names the snapshot", async () => {
    const dehydratedState = await dehydratedList({ data: list([row()]) });
    renderWithProviders(<ExportsTable />, { dehydratedState });

    for (const ext of ["md", "json", "html"]) {
      const link = screen.getByRole("link", { name: ext.toUpperCase() });
      expect(link.getAttribute("href")).toContain(`/v1/runs/run-1/report.${ext}`);
    }
    expect(screen.queryByRole("link", { name: "PDF" })).toBeNull();
    expect(screen.getByText("PDF").className).toContain("line-through");
    expect(screen.getByText("snapshot v1")).toBeTruthy();
  });

  it("shows an exported dataset with its manifest link, file count, bytes and digest", async () => {
    const exported = row({
      dataset: {
        format: "croissant-parquet",
        status: "exported",
        manifest_artifact_id: "art-manifest",
        manifest_sha256: "8a4a5dfa".padEnd(64, "0"),
        files: 3,
        bytes: 3 * 1024 * 1024,
        card: true,
        job_id: null,
        follow_up_run_id: null,
        error: null,
        blockers: [],
      },
    });
    const dehydratedState = await dehydratedList({ data: list([exported]) });
    renderWithProviders(<ExportsTable />, { dehydratedState });

    expect(screen.getByRole("link", { name: "Croissant manifest" }).getAttribute("href")).toContain("/v1/datasets/run-1");
    const detail = screen.getByText(/Parquet files/).textContent ?? "";
    expect(detail).toContain("3 Parquet files");
    expect(detail).toContain("3.0 MiB");
    expect(detail).toContain("8a4a5dfa0000…");
    expect(detail).toContain("card");
    expect(screen.queryByRole("button", { name: /Export dataset/ })).toBeNull();
  });

  it("spells out the blockers and offers no export button while one holds", async () => {
    rolesMock.roles = { default: "admin" };
    const blocked = row({
      status: "running",
      terminal: false,
      dataset: { ...row().dataset, blockers: ["not_terminal", "no_slices"] },
    });
    const dehydratedState = await dehydratedList({ data: list([blocked]) });
    renderWithProviders(<ExportsTable />, { dehydratedState });

    expect(screen.getByText("run not finished · no adversarial slices retained")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Export dataset" })).toBeNull();
    // A run that is not finished has nothing to re-render either.
    expect(screen.queryByRole("button", { name: "Render again" })).toBeNull();
  });

  it("shows a failed export with its error and a retry for a remediator", async () => {
    rolesMock.roles = { default: "remediator" };
    const failed = row({
      dataset: { ...row().dataset, status: "failed", error: "projection mismatch", job_id: "job-1", follow_up_run_id: "run-1-export" },
    });
    const dehydratedState = await dehydratedList({ data: list([failed]) });
    renderWithProviders(<ExportsTable />, { dehydratedState });

    expect(screen.getByText("export failed: projection mismatch")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Retry dataset export" })).toBeTruthy();
  });

  it("renders the empty state with the /models link", async () => {
    const dehydratedState = await dehydratedList({ data: list([]) });
    renderWithProviders(<ExportsTable />, { dehydratedState });
    expect(screen.getByText(/Nothing to export yet/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "/models" }).getAttribute("href")).toBe("/models");
    expect(screen.queryByRole("table")).toBeNull();
  });
});

describe("ExportsTable actions", () => {
  it("hides both actions from a viewer and shows only the render to a scanner", async () => {
    const dehydratedState = await dehydratedList({ data: list([row()]) });

    rolesMock.roles = { default: "viewer" };
    const first = renderWithProviders(<ExportsTable />, { dehydratedState });
    expect(screen.queryByRole("button", { name: "Render again" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Export dataset" })).toBeNull();
    first.unmount();

    rolesMock.roles = { default: "scanner" };
    renderWithProviders(<ExportsTable />, { dehydratedState });
    expect(screen.getByRole("button", { name: "Render again" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Export dataset" })).toBeNull();
  });

  it("starts a dataset export for a remediator and refetches the inventory", async () => {
    rolesMock.roles = { default: "remediator" };
    const dehydratedState = await dehydratedList({ data: list([row()]) });
    const calls: string[] = [];
    const { trpcFetch } = renderWithProviders(<ExportsTable />, {
      dehydratedState,
      respond: () => {
        calls.push("call");
        return calls.length === 1
          ? [trpcResult({ dataset_id: "run-1", status: "queued", type: "dataset.export", run_id: "run-1-export", job_id: "job-9" })]
          : [trpcResult(list([row({ dataset: { ...row().dataset, status: "queued", job_id: "job-9", follow_up_run_id: "run-1-export" } })]))];
      },
    });

    screen.getByRole("button", { name: "Export dataset" }).click();

    await waitFor(() => expect(trpcFetch).toHaveBeenCalledTimes(2));
    const mutation = String(trpcFetch.mock.calls[0]?.[0]);
    expect(mutation).toContain("exports.exportDataset");
    await waitFor(() => expect(screen.getByText(/export queued/)).toBeTruthy());
    expect(screen.getByRole("link", { name: "follow-up run" }).getAttribute("href")).toBe("/runs/run-1-export");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows the API refusal beside the row with its code", async () => {
    rolesMock.roles = { default: "remediator" };
    const dehydratedState = await dehydratedList({ data: list([row()]) });
    let first = true;
    renderWithProviders(<ExportsTable />, {
      dehydratedState,
      respond: () => {
        if (first) {
          first = false;
          return [trpcUpstreamError(409, { code: "export_unavailable", message: "the run retained no adversarial slices to export" })];
        }
        return [trpcResult(list([row()]))];
      },
    });

    screen.getByRole("button", { name: "Export dataset" }).click();

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("export_unavailable: the run retained no adversarial slices to export");
    // The row stays; the refusal is beside it, not in place of it.
    expect(screen.getByRole("link", { name: "run-1" })).toBeTruthy();
  });

  it("keeps each row's pending state while two actions are in flight at once", async () => {
    rolesMock.roles = { default: "remediator" };
    const rows = [row({ run_id: "run-a" }), row({ run_id: "run-b" })];
    const dehydratedState = await dehydratedList({ data: list(rows) });
    const { trpcFetch } = renderWithProviders(<ExportsTable />, { dehydratedState });

    // Hold every answer until both actions have been started, so both are in flight together.
    const release: Array<() => void> = [];
    trpcFetch.mockImplementation(
      () =>
        new Promise<Response>((resolve) => {
          release.push(() =>
            resolve(
              new Response(JSON.stringify([trpcResult(list(rows))]), {
                status: 200,
                headers: { "content-type": "application/json" },
              }),
            ),
          );
        }),
    );

    await act(async () => {
      screen.getAllByRole("button", { name: "Export dataset" })[0]!.click();
    });
    await act(async () => {
      screen.getAllByRole("button", { name: "Render again" })[1]!.click();
    });

    // Row A's export and row B's render are both pending; neither cleared the other.
    expect(screen.getByRole("button", { name: "Starting…" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Rendering…" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Export dataset" })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Render again" })).toHaveLength(1);

    await act(async () => {
      for (const done of release) done();
    });
    await waitFor(() => expect(screen.queryByRole("button", { name: "Starting…" })).toBeNull());
    expect(screen.queryByRole("button", { name: "Rendering…" })).toBeNull();
  });

  it("posts a render for a scanner and marks the render in flight from the refetched row", async () => {
    rolesMock.roles = { default: "scanner" };
    const dehydratedState = await dehydratedList({ data: list([row()]) });
    let first = true;
    const { trpcFetch } = renderWithProviders(<ExportsTable />, {
      dehydratedState,
      respond: () => {
        if (first) {
          first = false;
          return [trpcResult({ run_id: "run-1", job_id: "job-r", job_ids: ["job-r"], formats: ["md", "json", "html", "pdf"], status: "queued", type: "report.render" })];
        }
        return [trpcResult(list([row({ reports: { ...row().reports, render_in_flight: true } })]))];
      },
    });

    screen.getByRole("button", { name: "Render again" }).click();

    await waitFor(() => expect(trpcFetch).toHaveBeenCalledTimes(2));
    expect(String(trpcFetch.mock.calls[0]?.[0])).toContain("exports.renderReport");
    await waitFor(() => expect(screen.getByText(/render in flight/)).toBeTruthy());
    expect(screen.queryByRole("button", { name: "Render again" })).toBeNull();
  });
});
