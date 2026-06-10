import { createElement as h } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: useRequireAuthMock }));

const useRolesMock = vi.hoisted(() => vi.fn());
vi.mock("@/hooks/useRoles", () => ({ useRoles: useRolesMock }));

const runKaliToolMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({ runKaliTool: runKaliToolMock }));

vi.mock("@aegis/design-system", () => ({
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

import ToolsPage from "./page";

function selectTool(name: string) {
  fireEvent.change(screen.getByLabelText("Tool"), { target: { value: name } });
}

beforeEach(() => {
  useRequireAuthMock.mockReturnValue(true);
  runKaliToolMock.mockReset();
  useRolesMock.mockReturnValue({ roles: { default: "approver" }, projects: [], isLoading: false, error: undefined });
});

afterEach(cleanup);

describe("ToolsPage", () => {
  it("redirects when unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    render(h(ToolsPage));
    expect(screen.getByText("Redirecting to sign in…")).toBeTruthy();
  });

  it("shows the authorized-targets safety banner", () => {
    render(h(ToolsPage));
    expect(screen.getByText(/authorized to test/)).toBeTruthy();
  });

  it("runs a read tool at remediator with execute=false and renders the outcome", async () => {
    runKaliToolMock.mockResolvedValue({
      tool: "nmap", success: true, return_code: 0, stdout: "PORT 80", stderr: "",
    });
    render(h(ToolsPage)); // nmap is the default (read) tool
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "host" } });
    fireEvent.click(screen.getByRole("button", { name: "Run tool" }));

    await waitFor(() => expect(runKaliToolMock).toHaveBeenCalledTimes(1));
    expect(runKaliToolMock).toHaveBeenCalledWith("nmap", {
      execute: false,
      params: { target: "host" },
    });
    expect(await screen.findByText("PORT 80")).toBeTruthy();
  });

  it("blocks submit on invalid JSON params", async () => {
    render(h(ToolsPage));
    fireEvent.change(screen.getByLabelText("Params"), { target: { value: "{not json" } });
    fireEvent.click(screen.getByRole("button", { name: "Run tool" }));
    expect(await screen.findByText("Params is not valid JSON.")).toBeTruthy();
    expect(runKaliToolMock).not.toHaveBeenCalled();
  });

  it("active tool with Execute on sends execute=true on confirm", async () => {
    runKaliToolMock.mockResolvedValue({
      tool: "sqlmap", success: true, return_code: 0, stdout: "ok", stderr: "",
    });
    render(h(ToolsPage));
    selectTool("sqlmap"); // active tool — exposes the Execute toggle
    fireEvent.click(screen.getByLabelText("Execute"));
    fireEvent.change(screen.getByLabelText("Params"), { target: { value: '{"url":"x"}' } });
    fireEvent.click(screen.getByRole("button", { name: "Execute" }));

    await waitFor(() => expect(runKaliToolMock).toHaveBeenCalledTimes(1));
    expect(runKaliToolMock).toHaveBeenCalledWith("sqlmap", {
      execute: true,
      params: { url: "x" },
    });
  });

  it("active tool without Execute submits execute=false (proposal)", async () => {
    runKaliToolMock.mockResolvedValue({
      tool: "sqlmap", status: "pending_approval", message: "resubmit with execute=true",
    });
    render(h(ToolsPage));
    selectTool("sqlmap");
    // Execute toggle left off.
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));

    await waitFor(() => expect(runKaliToolMock).toHaveBeenCalledTimes(1));
    expect(runKaliToolMock).toHaveBeenCalledWith("sqlmap", {
      execute: false,
      params: {},
    });
    expect(await screen.findByText(/resubmit with execute=true/)).toBeTruthy();
  });

  it("hides the active-tool control when the caller is below approver", () => {
    useRolesMock.mockReturnValue({ roles: { default: "remediator" }, projects: [], isLoading: false, error: undefined });
    render(h(ToolsPage));
    selectTool("sqlmap");
    expect(screen.queryByText("Execute tool")).toBeNull();
    expect(screen.getByText(/requires the approver role/)).toBeTruthy();
  });
});
