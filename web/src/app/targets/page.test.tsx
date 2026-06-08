import { createElement as h } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// NOTE: this workspace's vitest v4 transforms via oxc, and web/tsconfig.json
// sets `jsx: "preserve"` (required by Next), so raw JSX syntax fails to parse
// in test files. We build elements with React.createElement (`h`) instead.

// SWR drives the targets list.
const useSWRMock = vi.hoisted(() => vi.fn());
const mutateMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const pushMock = vi.fn();
const replaceMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, replace: replaceMock }),
}));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: useRequireAuthMock,
}));

// targets calls api() DIRECTLY for create()/startScan() mutations -> mock it.
const apiMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({
  api: apiMock,
  apiBase: "http://api.test",
  apiWsBase: "ws://api.test",
}));

import TargetsPage from "./page";

function target(over: Record<string, unknown> = {}) {
  return {
    id: "t-1",
    kind: "url",
    value: "https://target.example",
    verified: false,
    project_id: "default",
    ...over,
  };
}

beforeEach(() => {
  useSWRMock.mockReset();
  apiMock.mockReset();
  mutateMock.mockReset();
  pushMock.mockReset();
  replaceMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
  // Default: authed, one target, no SWR error.
  useSWRMock.mockReturnValue({
    data: { targets: [target()] },
    error: undefined,
    mutate: mutateMock,
  });
});

afterEach(cleanup);

describe("TargetsPage", () => {
  it("shows the redirect placeholder when unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    render(h(TargetsPage));
    expect(screen.getByText("Redirecting to sign in…")).toBeTruthy();
    expect(screen.queryByText("Targets")).toBeNull();
  });

  it("shows the SWR load-failure message", () => {
    useSWRMock.mockReturnValue({
      data: undefined,
      error: new Error("nope"),
      mutate: mutateMock,
    });
    render(h(TargetsPage));
    expect(screen.getByText("Failed to load.")).toBeTruthy();
  });

  it("renders a row per target with id/kind/value/verified", () => {
    useSWRMock.mockReturnValue({
      data: {
        targets: [
          target({ id: "t-1", value: "https://a.example", verified: true }),
          target({ id: "t-2", value: "https://b.example", verified: false, kind: "domain" }),
        ],
      },
      error: undefined,
      mutate: mutateMock,
    });

    render(h(TargetsPage));

    expect(screen.getByText("t-1")).toBeTruthy();
    expect(screen.getByText("t-2")).toBeTruthy();
    expect(screen.getByText("https://a.example")).toBeTruthy();
    expect(screen.getByText("domain")).toBeTruthy();
    // verified booleans become yes/no.
    expect(screen.getByText("yes")).toBeTruthy();
    expect(screen.getByText("no")).toBeTruthy();
    // one Start scan button per row.
    expect(screen.getAllByRole("button", { name: "Start scan" })).toHaveLength(2);
  });

  it("create(): POSTs /v1/targets with the typed value then mutates and clears", async () => {
    apiMock.mockResolvedValue({});
    render(h(TargetsPage));

    const input = screen.getByPlaceholderText("https://target.example") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "https://new.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    await waitFor(() => expect(apiMock).toHaveBeenCalledTimes(1));
    expect(apiMock).toHaveBeenCalledWith("/v1/targets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind: "url", value: "https://new.example", project_id: "default" }),
    });
    await waitFor(() => expect(mutateMock).toHaveBeenCalledTimes(1));
    // Input is cleared after a successful create.
    await waitFor(() => expect(input.value).toBe(""));
  });

  it("create(): is a no-op when the input is empty", () => {
    render(h(TargetsPage));
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(apiMock).not.toHaveBeenCalled();
  });

  it("create(): surfaces the error panel and does not mutate on rejection", async () => {
    apiMock.mockRejectedValue(new Error("create-failed-422"));
    render(h(TargetsPage));

    fireEvent.change(screen.getByPlaceholderText("https://target.example"), {
      target: { value: "https://bad.example" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    const panel = await screen.findByText(/create-failed-422/);
    expect(panel.className).toContain("border-red-200");
    expect(mutateMock).not.toHaveBeenCalled();
  });

  it("startScan(): POSTs /v1/scans and routes to the new run on success", async () => {
    apiMock.mockResolvedValue({ run_id: "run-99" });
    useSWRMock.mockReturnValue({
      data: { targets: [target({ id: "t-9", value: "https://scan.example", project_id: "p7" })] },
      error: undefined,
      mutate: mutateMock,
    });

    render(h(TargetsPage));
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    await waitFor(() => expect(apiMock).toHaveBeenCalledTimes(1));
    expect(apiMock).toHaveBeenCalledWith("/v1/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: "https://scan.example", scanner: "trivy", project_id: "p7" }),
    });
    await waitFor(() => expect(pushMock).toHaveBeenCalledWith("/runs/run-99"));
  });

  it("startScan(): surfaces the error panel and does not navigate on rejection", async () => {
    apiMock.mockRejectedValue(new Error("scan-denied-403"));
    render(h(TargetsPage));

    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    const panel = await screen.findByText(/scan-denied-403/);
    expect(panel.className).toContain("border-red-200");
    expect(pushMock).not.toHaveBeenCalled();
  });
});
