import { createElement as h } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: useRequireAuthMock }));

const useRolesMock = vi.hoisted(() => vi.fn());
vi.mock("@/hooks/useRoles", () => ({ useRoles: useRolesMock }));

// The agent picker now loads its roster from GET /v1/agents via SWR.
const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const runAgentMock = vi.hoisted(() => vi.fn());
const listAgentsMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({
  runAgent: runAgentMock,
  listAgents: listAgentsMock,
}));

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

import AgentsPage from "./page";

// A representative GET /v1/agents slice: one read agent, one active agent,
// plus an unwired agent that must be filtered out of the picker.
const AGENTS = [
  { name: "recon", domain: "recon", effect: "read", wired: true },
  { name: "red_teamer", domain: "offensive", effect: "active", wired: true },
  { name: "ghost", domain: "audit", effect: "read", wired: false },
];

function withAgents(over: { data?: unknown; error?: unknown } = {}) {
  useSWRMock.mockReturnValue({ data: AGENTS, error: undefined, ...over });
}

function selectAgent(name: string) {
  fireEvent.change(screen.getByLabelText("Agent"), { target: { value: name } });
}

beforeEach(() => {
  useRequireAuthMock.mockReturnValue(true);
  runAgentMock.mockReset();
  listAgentsMock.mockReset();
  useSWRMock.mockReset();
  withAgents();
  // approver on the default project (first in the projects list).
  useRolesMock.mockReturnValue({
    roles: { "proj-1": "approver" },
    projects: [{ id: "proj-1", slug: "p1", name: "P1", org_id: "o", daily_llm_budget_cents: null, role: "approver" }],
    isLoading: false,
    error: undefined,
  });
});

afterEach(cleanup);

describe("AgentsPage", () => {
  it("redirects when unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    render(h(AgentsPage));
    expect(screen.getByText("Redirecting to sign in…")).toBeTruthy();
  });

  it("passes the agents key only once authed (null while not)", () => {
    useRequireAuthMock.mockReturnValue(false);
    render(h(AgentsPage));
    expect(useSWRMock).toHaveBeenLastCalledWith(null, listAgentsMock);

    cleanup();
    useRequireAuthMock.mockReturnValue(true);
    render(h(AgentsPage));
    expect(useSWRMock).toHaveBeenLastCalledWith("/v1/agents", listAgentsMock);
  });

  it("shows the safety banner", () => {
    render(h(AgentsPage));
    expect(screen.getByText(/may run active operations/)).toBeTruthy();
  });

  it("offers only wired agents in the picker", () => {
    render(h(AgentsPage));
    const select = screen.getByLabelText("Agent") as HTMLSelectElement;
    const values = Array.from(select.options).map((o) => o.value);
    expect(values).toEqual(["recon", "red_teamer"]);
    expect(values).not.toContain("ghost");
  });

  it("runs a read agent at remediator with execute=false", async () => {
    runAgentMock.mockResolvedValue({ run_id: "r1", job_id: "j1", status: "queued" });
    render(h(AgentsPage));
    selectAgent("recon"); // recon is a read agent
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "enumerate" } });
    fireEvent.click(screen.getByRole("button", { name: "Run agent" }));

    await waitFor(() => expect(runAgentMock).toHaveBeenCalledTimes(1));
    expect(runAgentMock).toHaveBeenCalledWith("recon", {
      prompt: "enumerate",
      project_id: "proj-1",
      execute: false,
      target: undefined,
    });
    expect(await screen.findByText("r1")).toBeTruthy();
  });

  it("gates an active agent behind approval + sends execute=true on confirm", async () => {
    runAgentMock.mockResolvedValue({ run_id: "r2", job_id: "j2", status: "queued" });
    render(h(AgentsPage));
    selectAgent("red_teamer"); // offensive/active
    fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "exploit" } });

    // The confirm action ("Invoke agent") is rendered transparently.
    fireEvent.click(screen.getByRole("button", { name: "Invoke agent" }));

    await waitFor(() => expect(runAgentMock).toHaveBeenCalledTimes(1));
    expect(runAgentMock).toHaveBeenCalledWith("red_teamer", {
      prompt: "exploit",
      project_id: "proj-1",
      execute: true,
      target: undefined,
    });
  });

  it("hides the active-agent control when the caller is below approver", () => {
    useRolesMock.mockReturnValue({
      roles: { "proj-1": "remediator" },
      projects: [{ id: "proj-1", slug: "p1", name: "P1", org_id: "o", daily_llm_budget_cents: null, role: "remediator" }],
      isLoading: false,
      error: undefined,
    });
    render(h(AgentsPage));
    selectAgent("red_teamer");
    expect(screen.queryByText("Invoke agent")).toBeNull();
    expect(screen.getByText(/requires the approver role/)).toBeTruthy();
  });

  it("requires a prompt before submitting", async () => {
    render(h(AgentsPage));
    selectAgent("recon");
    fireEvent.click(screen.getByRole("button", { name: "Run agent" }));
    expect(await screen.findByText("A prompt is required.")).toBeTruthy();
    expect(runAgentMock).not.toHaveBeenCalled();
  });

  it("shows a failed-load placeholder option when the roster errors", () => {
    withAgents({ data: undefined, error: new Error("boom") });
    render(h(AgentsPage));
    expect(screen.getByText("Failed to load agents")).toBeTruthy();
  });
});
