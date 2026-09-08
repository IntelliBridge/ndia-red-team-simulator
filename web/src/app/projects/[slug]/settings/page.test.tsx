import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true as boolean));
vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: useRequireAuthMock,
}));

const useRolesMock = vi.hoisted(() =>
  vi.fn(() => ({
    roles: {} as Record<string, string>,
    projects: [] as unknown[],
    isLoading: false,
    error: undefined as unknown,
  }))
);
vi.mock("@/hooks/useRoles", () => ({ useRoles: useRolesMock }));

// Stub RoleGated — pass through children so admin-only sections render in tests
vi.mock("@redsim/design-system", () => ({
  RoleGated: ({ children }: { children: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

// Mock api — ProjectSettingsPage calls api() directly for the PUT mutation
const apiMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({
  api: apiMock,
  apiBase: "http://api.test",
  apiWsBase: "ws://api.test",
}));

import ProjectSettingsPage from "./page";

const membershipData = {
  project: {
    id: "proj-demo",
    slug: "demo",
    name: "Demo Project",
    daily_llm_budget_cents: 1000,
  },
  members: [
    { sub: "sub-1", email: "alice@redsim.local", display_name: "Alice", role: "admin" },
    { sub: "sub-2", email: "bob@redsim.local", display_name: "Bob", role: "viewer" },
  ],
};

afterEach(cleanup);

beforeEach(() => {
  useRequireAuthMock.mockReturnValue(true);
  useRolesMock.mockReturnValue({
    roles: { "proj-demo": "admin" },
    projects: [],
    isLoading: false,
    error: undefined,
  });
  apiMock.mockResolvedValue({});
  useSWRMock.mockReturnValue({
    data: membershipData,
    error: undefined,
    isLoading: false,
    mutate: vi.fn().mockResolvedValue(undefined),
  });
});

describe("ProjectSettingsPage", () => {
  it("renders the 'Loading…' paragraph while SWR is fetching", () => {
    useSWRMock.mockReturnValue({
      data: undefined,
      error: undefined,
      isLoading: true,
      mutate: vi.fn(),
    });
    render(React.createElement(ProjectSettingsPage, { params: { slug: "demo" } }));
    const el = screen.getByText("Loading…");
    expect(el.tagName.toLowerCase()).toBe("p");
  });

  it("renders a red error paragraph when SWR fails", () => {
    useSWRMock.mockReturnValue({
      data: undefined,
      error: new Error("not found"),
      isLoading: false,
      mutate: vi.fn(),
    });
    render(React.createElement(ProjectSettingsPage, { params: { slug: "demo" } }));
    const el = screen.getByText(/Failed to load/);
    expect(el.textContent).toContain("not found");
  });

  it("renders 'Redirecting to sign in…' when not authed", () => {
    useRequireAuthMock.mockReturnValue(false);
    render(React.createElement(ProjectSettingsPage, { params: { slug: "demo" } }));
    const el = screen.getByText("Redirecting to sign in…");
    expect(el.tagName.toLowerCase()).toBe("p");
  });

  it("renders the project name as H1 heading and slug as monospace subtext", () => {
    render(React.createElement(ProjectSettingsPage, { params: { slug: "demo" } }));
    expect(screen.getByText("Demo Project").tagName.toLowerCase()).toBe("h1");
    expect(screen.getByText("demo").textContent).toBe("demo");
  });

  it("renders the members table rows with email and role", () => {
    render(React.createElement(ProjectSettingsPage, { params: { slug: "demo" } }));
    expect(screen.getByText("alice@redsim.local").textContent).toBe("alice@redsim.local");
    expect(screen.getByText("bob@redsim.local").textContent).toBe("bob@redsim.local");
    expect(screen.getByText("admin").textContent).toBe("admin");
    expect(screen.getByText("viewer").textContent).toBe("viewer");
  });

  it("pre-populates the budget input with daily_llm_budget_cents from SWR data", async () => {
    render(React.createElement(ProjectSettingsPage, { params: { slug: "demo" } }));
    const input = await screen.findByRole("spinbutton") as HTMLInputElement;
    expect(input.value).toBe("1000");
  });

  it("calls api() PUT /v1/projects/{slug}/settings with the updated budget", async () => {
    render(React.createElement(ProjectSettingsPage, { params: { slug: "demo" } }));
    const input = await screen.findByRole("spinbutton");
    fireEvent.change(input, { target: { value: "2500" } });

    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      expect(apiMock).toHaveBeenCalledWith(
        "/v1/projects/demo/settings",
        expect.objectContaining({
          method: "PUT",
          body: JSON.stringify({ daily_llm_budget_cents: 2500 }),
        })
      );
    });
  });

  it("sends null budget when the input is cleared before saving", async () => {
    render(React.createElement(ProjectSettingsPage, { params: { slug: "demo" } }));
    const input = await screen.findByRole("spinbutton");
    fireEvent.change(input, { target: { value: "" } });

    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      expect(apiMock).toHaveBeenCalledWith(
        "/v1/projects/demo/settings",
        expect.objectContaining({
          method: "PUT",
          body: JSON.stringify({ daily_llm_budget_cents: null }),
        })
      );
    });
  });

  it("renders a red error paragraph when the PUT api call rejects", async () => {
    apiMock.mockRejectedValue(new Error("budget update failed"));
    render(React.createElement(ProjectSettingsPage, { params: { slug: "demo" } }));

    fireEvent.click(await screen.findByRole("button", { name: "Save" }));

    // Wait for the error to appear; findByText throws if not found within timeout
    const errEl = await screen.findByText(/budget update failed/);
    expect(errEl.textContent).toContain("budget update failed");
  });

  it("calls mutate() once after a successful save to revalidate data", async () => {
    const mutateSpy = vi.fn().mockResolvedValue(undefined);
    useSWRMock.mockReturnValue({
      data: membershipData,
      error: undefined,
      isLoading: false,
      mutate: mutateSpy,
    });
    render(React.createElement(ProjectSettingsPage, { params: { slug: "demo" } }));

    fireEvent.click(await screen.findByRole("button", { name: "Save" }));

    await waitFor(() => expect(mutateSpy).toHaveBeenCalledTimes(1));
  });

  it("passes the slug from params to build the SWR membership URL", () => {
    render(React.createElement(ProjectSettingsPage, { params: { slug: "my-proj" } }));
    expect(useSWRMock).toHaveBeenCalledWith(
      "/v1/projects/my-proj/membership",
      expect.any(Function)
    );
  });
});
