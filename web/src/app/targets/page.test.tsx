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

// targets calls api() directly for create() and the typed startScan()/
// listAuthProfiles()/listScanners() helpers for scans, DAST auth profiles and
// the adapter roster -> mock all.
const apiMock = vi.hoisted(() => vi.fn());
const deleteTargetMock = vi.hoisted(() => vi.fn());
const startScanMock = vi.hoisted(() => vi.fn());
const listAuthProfilesMock = vi.hoisted(() => vi.fn());
const listScannersMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({
  api: apiMock,
  startScan: startScanMock,
  listAuthProfiles: listAuthProfilesMock,
  listScanners: listScannersMock,
  apiBase: "http://api.test",
  apiWsBase: "ws://api.test",
  deleteTarget: deleteTargetMock,
}));

const useRolesMock = vi.hoisted(() => vi.fn());
vi.mock("@/hooks/useRoles", () => ({ useRoles: useRolesMock }));

// Render RoleGated/AlertDialog transparently so gating + the confirm action
// stay observable in the DOM.
vi.mock("@redsim/design-system", () => ({
  RoleGated: ({ minRole, callerRole, children, fallback }: any) => {
    const rank: Record<string, number> = { scanner: 1, remediator: 2, approver: 3, admin: 4 };
    return (rank[callerRole] ?? 0) >= (rank[minRole] ?? 99)
      ? h("div", null, children)
      : h("div", null, fallback ?? null);
  },
  AlertDialog: ({ children }: any) => h("div", null, children),
  AlertDialogTrigger: ({ children }: any) => h("div", null, children),
  AlertDialogContent: ({ children }: any) => h("div", null, children),
  AlertDialogHeader: ({ children }: any) => h("div", null, children),
  AlertDialogFooter: ({ children }: any) => h("div", null, children),
  AlertDialogTitle: ({ children }: any) => h("div", null, children),
  AlertDialogDescription: ({ children }: any) => h("div", null, children),
  AlertDialogAction: ({ children, onClick }: any) => h("button", { onClick }, children),
  AlertDialogCancel: ({ children }: any) => h("button", null, children),
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

function profile(over: Record<string, unknown> = {}) {
  return {
    id: "ap-1",
    project_id: "default",
    name: "Staging login",
    kind: "form",
    config: { login_url: "https://target.example/login" },
    created_at: "2026-06-01T00:00:00Z",
    ...over,
  };
}

// The adapter roster the page reads from GET /v1/scanners. No literal
// adapter name is meaningful here: the pentest built-ins are gone and the
// real list is whatever registered (an ML attack adapter or a signed plugin).
const ROSTER = [
  { name: "fake-static", capabilities: ["sast"] },
  { name: "fake-dast", capabilities: ["dast"] },
];

// Key-aware SWR stub: the page issues three useSWR calls (targets list, the
// scanner roster, and auth profiles when a dast-capable adapter is selected).
// `scanners: null` models a roster that has not loaded yet (SWR data
// undefined); `undefined` would just select the ROSTER default.
function stubSWR({
  targets = [target()],
  profiles = [profile()],
  scanners = ROSTER,
  scannersError,
}: {
  targets?: unknown[];
  profiles?: unknown[];
  scanners?: unknown[] | null;
  scannersError?: Error;
} = {}) {
  useSWRMock.mockImplementation((key: string | null) => {
    if (key?.startsWith("/v1/auth-profiles")) {
      return { data: profiles, error: undefined, mutate: vi.fn() };
    }
    if (key === "/v1/scanners") {
      const data = scannersError || scanners === null ? undefined : scanners;
      return { data, error: scannersError, mutate: vi.fn() };
    }
    return { data: { targets }, error: undefined, mutate: mutateMock };
  });
}

beforeEach(() => {
  useSWRMock.mockReset();
  apiMock.mockReset();
  deleteTargetMock.mockReset();
  startScanMock.mockReset();
  listAuthProfilesMock.mockReset();
  listScannersMock.mockReset();
  mutateMock.mockReset();
  pushMock.mockReset();
  replaceMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
  // Default: admin on the default project so delete is shown.
  useRolesMock.mockReturnValue({ roles: { default: "admin" }, projects: [], isLoading: false, error: undefined });
  // Default: authed, one target, one auth profile, no SWR error.
  stubSWR();
});

afterEach(cleanup);

describe("TargetsPage", () => {
  it("shows the redirect placeholder when unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    render(h(TargetsPage));
    expect(screen.getByText("Signing in…")).toBeTruthy();
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
    // The value also appears in the per-row delete-confirm dialog body (the
    // transparent AlertDialog mock renders its description), so match all.
    expect(screen.getAllByText("https://a.example").length).toBeGreaterThanOrEqual(1);
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
    expect(panel.className).toContain("border-destructive");
    expect(mutateMock).not.toHaveBeenCalled();
  });

  it("startScan(): sends the first registered adapter without auth_profile_id and routes to the new run", async () => {
    startScanMock.mockResolvedValue({ run_id: "run-99" });
    stubSWR({
      targets: [target({ id: "t-9", value: "https://scan.example", project_id: "p7" })],
    });

    render(h(TargetsPage));
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    await waitFor(() => expect(startScanMock).toHaveBeenCalledTimes(1));
    expect(startScanMock).toHaveBeenCalledWith({
      target: "https://scan.example",
      scanner: "fake-static",
      project_id: "p7",
    });
    await waitFor(() => expect(pushMock).toHaveBeenCalledWith("/runs/run-99"));
  });

  it("scanner picker is populated from the roster, not a hardcoded list", () => {
    render(h(TargetsPage));
    const options = Array.from(
      (screen.getByLabelText("Scanner") as HTMLSelectElement).options,
    ).map((o) => o.value);
    expect(options).toEqual(["fake-static", "fake-dast"]);
    for (const removed of ["trivy", "zap", "nuclei", "strix"]) {
      expect(options).not.toContain(removed);
    }
  });

  it("empty roster: renders the no-adapter notice, disables Start scan and never calls startScan", () => {
    stubSWR({ scanners: [] });
    render(h(TargetsPage));

    expect(screen.getByRole("status").textContent).toMatch(/No attack adapter is registered/);
    expect(screen.getByRole("status").textContent).toMatch(/redsim\.ml\.attacks/);
    const start = screen.getByRole("button", { name: "Start scan" }) as HTMLButtonElement;
    expect(start.disabled).toBe(true);
    expect((screen.getByLabelText("Scanner") as HTMLSelectElement).disabled).toBe(true);
    fireEvent.click(start);
    expect(startScanMock).not.toHaveBeenCalled();
    expect(pushMock).not.toHaveBeenCalled();
  });

  it("roster load failure: shows the unavailable notice and disables Start scan", () => {
    stubSWR({ scannersError: new Error("roster-500") });
    render(h(TargetsPage));

    expect(screen.getByRole("status").textContent).toMatch(/Could not load the attack adapter roster/);
    const start = screen.getByRole("button", { name: "Start scan" }) as HTMLButtonElement;
    expect(start.disabled).toBe(true);
    fireEvent.click(start);
    expect(startScanMock).not.toHaveBeenCalled();
  });

  it("roster still loading: Start scan is disabled and nothing is sent", () => {
    stubSWR({ scanners: null });
    render(h(TargetsPage));

    expect(screen.getByRole("status").textContent).toMatch(/Loading attack adapters/);
    const start = screen.getByRole("button", { name: "Start scan" }) as HTMLButtonElement;
    expect(start.disabled).toBe(true);
    fireEvent.click(start);
    expect(startScanMock).not.toHaveBeenCalled();
  });

  it("startScan(): surfaces the error panel and does not navigate on rejection", async () => {
    startScanMock.mockRejectedValue(new Error("scan-denied-403"));
    render(h(TargetsPage));

    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    const panel = await screen.findByText(/scan-denied-403/);
    expect(panel.className).toContain("border-destructive");
    expect(pushMock).not.toHaveBeenCalled();
  });

  it("hides Delete for a non-admin caller", () => {
    useRolesMock.mockReturnValue({ roles: { default: "remediator" }, projects: [], isLoading: false, error: undefined });
    render(h(TargetsPage));
    expect(screen.queryByText("Delete target")).toBeNull();
  });

  it("delete: admin confirms then DELETEs the target and refetches", async () => {
    deleteTargetMock.mockResolvedValue(undefined);
    useSWRMock.mockReturnValue({
      data: { targets: [target({ id: "t-del", value: "https://gone.example" })] },
      error: undefined,
      mutate: mutateMock,
    });
    render(h(TargetsPage));

    // Trigger button + the confirm AlertDialogAction both read variants of
    // "Delete"; click the confirm action ("Delete target").
    fireEvent.click(screen.getByRole("button", { name: "Delete target" }));

    await waitFor(() => expect(deleteTargetMock).toHaveBeenCalledWith("t-del"));
    await waitFor(() => expect(mutateMock).toHaveBeenCalled());
  });

  it("delete: surfaces the error panel and does not refetch on rejection", async () => {
    deleteTargetMock.mockRejectedValue(new Error("delete-denied-403"));
    render(h(TargetsPage));

    fireEvent.click(screen.getByRole("button", { name: "Delete target" }));

    const panel = await screen.findByText(/delete-denied-403/);
    expect(panel.className).toContain("border-destructive");
    expect(mutateMock).not.toHaveBeenCalled();
  });

  it("hides the auth profile select for adapters without the dast capability", () => {
    render(h(TargetsPage));
    expect(screen.getByLabelText("Scanner")).toBeTruthy();
    expect(screen.queryByLabelText("Authentication profile (optional)")).toBeNull();
  });

  it("shows the auth profile select for a dast-capable adapter and includes auth_profile_id in the scan", async () => {
    startScanMock.mockResolvedValue({ run_id: "run-42" });
    stubSWR({
      targets: [target({ id: "t-9", value: "https://scan.example", project_id: "p7" })],
      profiles: [profile({ id: "ap-9", name: "Staging login", kind: "form" })],
    });

    render(h(TargetsPage));
    fireEvent.change(screen.getByLabelText("Scanner"), { target: { value: "fake-dast" } });

    const select = screen.getByLabelText("Authentication profile (optional)");
    expect(screen.getByText("Staging login (form)")).toBeTruthy();
    fireEvent.change(select, { target: { value: "ap-9" } });
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    await waitFor(() => expect(startScanMock).toHaveBeenCalledTimes(1));
    expect(startScanMock).toHaveBeenCalledWith({
      target: "https://scan.example",
      scanner: "fake-dast",
      project_id: "p7",
      auth_profile_id: "ap-9",
    });
    await waitFor(() => expect(pushMock).toHaveBeenCalledWith("/runs/run-42"));
  });

  it("omits auth_profile_id for a dast-capable adapter when no profile is chosen", async () => {
    startScanMock.mockResolvedValue({ run_id: "run-43" });
    render(h(TargetsPage));

    fireEvent.change(screen.getByLabelText("Scanner"), { target: { value: "fake-dast" } });
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));

    await waitFor(() => expect(startScanMock).toHaveBeenCalledTimes(1));
    expect(startScanMock).toHaveBeenCalledWith({
      target: "https://target.example",
      scanner: "fake-dast",
      project_id: "default",
    });
  });
});
