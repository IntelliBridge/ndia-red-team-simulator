import React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true as boolean));
vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: useRequireAuthMock,
}));

const useRolesMock = vi.hoisted(() =>
  vi.fn(() => ({
    projects: [] as Array<{
      id: string;
      slug: string;
      name: string;
      role: string;
      org_id: string;
      daily_llm_budget_cents: number | null;
    }>,
    roles: {} as Record<string, string>,
    isLoading: false,
    error: undefined as unknown,
  }))
);
vi.mock("@/hooks/useRoles", () => ({ useRoles: useRolesMock }));

import ProjectsPage from "./page";

afterEach(cleanup);
beforeEach(() => {
  useRequireAuthMock.mockReturnValue(true);
  useRolesMock.mockReturnValue({
    projects: [],
    roles: {},
    isLoading: false,
    error: undefined,
  });
});

describe("ProjectsPage", () => {
  it("renders the 'Loading…' paragraph while fetching", () => {
    useRolesMock.mockReturnValue({
      projects: [],
      roles: {},
      isLoading: true,
      error: undefined,
    });
    render(React.createElement(ProjectsPage));
    const el = screen.getByText("Loading…");
    expect(el.tagName.toLowerCase()).toBe("p");
  });

  it("renders a red error paragraph containing the error message", () => {
    useRolesMock.mockReturnValue({
      projects: [],
      roles: {},
      isLoading: false,
      error: new Error("forbidden"),
    });
    render(React.createElement(ProjectsPage));
    const el = screen.getByText(/Failed to load projects/);
    expect(el.textContent).toContain("forbidden");
  });

  it("renders 'Signing in…' when not authed", () => {
    useRequireAuthMock.mockReturnValue(false);
    render(React.createElement(ProjectsPage));
    const el = screen.getByText("Signing in…");
    expect(el.tagName.toLowerCase()).toBe("p");
  });

  it("renders the empty-state message when there are no projects", () => {
    render(React.createElement(ProjectsPage));
    const el = screen.getByText(/You don't belong to any projects yet/);
    expect(el.tagName.toLowerCase()).toBe("p");
  });

  it("renders an H1 'Projects' heading", () => {
    render(React.createElement(ProjectsPage));
    const h1 = screen.getByText("Projects");
    expect(h1.tagName.toLowerCase()).toBe("h1");
  });

  it("renders a table row with slug link, name, role, and formatted budget", () => {
    useRolesMock.mockReturnValue({
      projects: [
        {
          id: "p1",
          slug: "alpha",
          name: "Alpha Project",
          role: "admin",
          org_id: "org1",
          daily_llm_budget_cents: 500,
        },
      ],
      roles: { p1: "admin", alpha: "admin" },
      isLoading: false,
      error: undefined,
    });
    render(React.createElement(ProjectsPage));
    expect(screen.getByText("alpha").textContent).toBe("alpha");
    expect(screen.getByText("Alpha Project").textContent).toBe("Alpha Project");
    expect(screen.getByText("admin").textContent).toBe("admin");
    // 500 cents → "$5.00"
    expect(screen.getByText("$5.00").textContent).toBe("$5.00");
  });

  it("renders '—' for a null daily_llm_budget_cents", () => {
    useRolesMock.mockReturnValue({
      projects: [
        {
          id: "p2",
          slug: "beta",
          name: "Beta Project",
          role: "viewer",
          org_id: "org1",
          daily_llm_budget_cents: null,
        },
      ],
      roles: { p2: "viewer" },
      isLoading: false,
      error: undefined,
    });
    render(React.createElement(ProjectsPage));
    expect(screen.getByText("—").textContent).toBe("—");
  });

  it("renders a settings link for each project slug with correct href", () => {
    useRolesMock.mockReturnValue({
      projects: [
        {
          id: "p3",
          slug: "gamma",
          name: "Gamma Project",
          role: "editor",
          org_id: "org1",
          daily_llm_budget_cents: null,
        },
      ],
      roles: { p3: "editor" },
      isLoading: false,
      error: undefined,
    });
    render(React.createElement(ProjectsPage));
    const link = screen.getByRole("link", { name: "gamma" });
    expect(link.getAttribute("href")).toBe("/projects/gamma/settings");
  });

  it("renders table column headers Slug, Name, Role, and Daily budget", () => {
    useRolesMock.mockReturnValue({
      projects: [
        {
          id: "p4",
          slug: "delta",
          name: "Delta Project",
          role: "viewer",
          org_id: "org1",
          daily_llm_budget_cents: null,
        },
      ],
      roles: {},
      isLoading: false,
      error: undefined,
    });
    render(React.createElement(ProjectsPage));
    for (const header of ["Slug", "Name", "Role", "Daily budget"]) {
      expect(screen.getByText(header).textContent).toBe(header);
    }
  });
});
