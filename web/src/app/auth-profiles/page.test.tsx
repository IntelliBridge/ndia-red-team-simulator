import { createElement as h, Fragment, type ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// NOTE: elements are built with React.createElement (`h`) — see
// targets/page.test.tsx for why raw JSX can't be used in test files.

const useSWRMock = vi.hoisted(() => vi.fn());
const mutateMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: useRequireAuthMock,
}));

const useRolesMock = vi.hoisted(() =>
  vi.fn(() => ({
    roles: { default: "admin" } as Record<string, string>,
    projects: [] as unknown[],
    isLoading: false,
    error: undefined as unknown,
  }))
);
vi.mock("@/hooks/useRoles", () => ({ useRoles: useRolesMock }));

// Stub RoleGated — pass through children so admin-only sections render.
vi.mock("@redsim/design-system", () => ({
  RoleGated: ({ children }: { children: ReactNode }) =>
    h(Fragment, null, children),
}));

const listAuthProfilesMock = vi.hoisted(() => vi.fn());
const createAuthProfileMock = vi.hoisted(() => vi.fn());
const deleteAuthProfileMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({
  listAuthProfiles: listAuthProfilesMock,
  createAuthProfile: createAuthProfileMock,
  deleteAuthProfile: deleteAuthProfileMock,
  apiBase: "http://api.test",
  apiWsBase: "ws://api.test",
}));

import AuthProfilesPage from "./page";

function profile(over: Record<string, unknown> = {}) {
  return {
    id: "ap-1",
    project_id: "default",
    name: "Staging login",
    kind: "form",
    config: { login_url: "https://target.example/login", username: "scanner" },
    created_at: "2026-06-01T00:00:00Z",
    ...over,
  };
}

function stubList(profiles: unknown[]) {
  useSWRMock.mockReturnValue({
    data: profiles,
    error: undefined,
    isLoading: false,
    mutate: mutateMock,
  });
}

beforeEach(() => {
  useSWRMock.mockReset();
  mutateMock.mockReset();
  listAuthProfilesMock.mockReset();
  createAuthProfileMock.mockReset();
  deleteAuthProfileMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
  useRolesMock.mockReturnValue({
    roles: { default: "admin" },
    projects: [],
    isLoading: false,
    error: undefined,
  });
  stubList([profile()]);
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("AuthProfilesPage", () => {
  it("shows the redirect placeholder when unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    render(h(AuthProfilesPage));
    expect(screen.getByText("Redirecting to sign in…")).toBeTruthy();
    expect(screen.queryByText("Auth Profiles")).toBeNull();
  });

  it("shows the loading state while SWR is fetching", () => {
    useSWRMock.mockReturnValue({
      data: undefined,
      error: undefined,
      isLoading: true,
      mutate: mutateMock,
    });
    render(h(AuthProfilesPage));
    expect(screen.getByText("Loading…")).toBeTruthy();
  });

  it("shows the SWR load-failure message", () => {
    useSWRMock.mockReturnValue({
      data: undefined,
      error: new Error("nope"),
      isLoading: false,
      mutate: mutateMock,
    });
    render(h(AuthProfilesPage));
    expect(screen.getByText("Failed to load.")).toBeTruthy();
  });

  it("renders a row per profile with name, kind, and non-secret config", () => {
    stubList([
      profile({ id: "ap-1", name: "Staging login", kind: "form" }),
      profile({ id: "ap-2", name: "API key", kind: "header", config: { header_name: "X-Api-Key" } }),
    ]);
    render(h(AuthProfilesPage));

    expect(screen.getByText("Staging login")).toBeTruthy();
    expect(screen.getByText("API key")).toBeTruthy();
    expect(screen.getByText("header_name=X-Api-Key")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Delete" })).toHaveLength(2);
  });

  it("shows the empty state when there are no profiles", () => {
    stubList([]);
    render(h(AuthProfilesPage));
    expect(screen.getByText("No authentication profiles yet.")).toBeTruthy();
  });

  it("create(): POSTs the kind-specific config + secret then mutates and clears", async () => {
    createAuthProfileMock.mockResolvedValue(profile());
    render(h(AuthProfilesPage));

    fireEvent.change(screen.getByLabelText("Kind"), { target: { value: "header" } });
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "API key" } });
    fireEvent.change(screen.getByLabelText("Header name"), { target: { value: "X-Api-Key" } });
    const secretInput = screen.getByLabelText("Header value") as HTMLInputElement;
    expect(secretInput.type).toBe("password");
    fireEvent.change(secretInput, { target: { value: "sekrit-key-9" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(createAuthProfileMock).toHaveBeenCalledTimes(1));
    expect(createAuthProfileMock).toHaveBeenCalledWith({
      project_id: "default",
      name: "API key",
      kind: "header",
      config: { header_name: "X-Api-Key" },
      secret: "sekrit-key-9",
    });
    await waitFor(() => expect(mutateMock).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(secretInput.value).toBe(""));
  });

  it("create(): form kind posts login_url/username_field/password_field/username", async () => {
    createAuthProfileMock.mockResolvedValue(profile());
    render(h(AuthProfilesPage));

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Staging" } });
    fireEvent.change(screen.getByLabelText("Login URL"), {
      target: { value: "https://t.example/login" },
    });
    fireEvent.change(screen.getByLabelText("Username field"), { target: { value: "email" } });
    fireEvent.change(screen.getByLabelText("Password field"), { target: { value: "pass" } });
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "bot@x.io" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "hunter2" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(createAuthProfileMock).toHaveBeenCalledTimes(1));
    expect(createAuthProfileMock).toHaveBeenCalledWith({
      project_id: "default",
      name: "Staging",
      kind: "form",
      config: {
        login_url: "https://t.example/login",
        username_field: "email",
        password_field: "pass",
        username: "bot@x.io",
      },
      secret: "hunter2",
    });
  });

  it("create(): is a no-op when name or secret is missing", () => {
    render(h(AuthProfilesPage));
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    expect(createAuthProfileMock).not.toHaveBeenCalled();
  });

  it("create(): surfaces the error panel on rejection", async () => {
    createAuthProfileMock.mockRejectedValue(new Error("create-denied-403"));
    render(h(AuthProfilesPage));

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "y" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    const panel = await screen.findByText(/create-denied-403/);
    expect(panel.className).toContain("border-destructive");
    expect(mutateMock).not.toHaveBeenCalled();
  });

  it("never echoes the secret into the page outside the password input", async () => {
    createAuthProfileMock.mockResolvedValue(profile());
    render(h(AuthProfilesPage));

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Staging" } });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "s3cr3t-never-shown" },
    });
    // Secret is not visible text before, during, or after the create.
    expect(document.body.textContent).not.toContain("s3cr3t-never-shown");
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(createAuthProfileMock).toHaveBeenCalledTimes(1));
    expect(document.body.textContent).not.toContain("s3cr3t-never-shown");
    // And the list rows only ever render the non-secret config.
    expect(screen.getByText(/login_url=/).textContent).not.toContain("s3cr3t-never-shown");
  });

  it("delete(): confirms, DELETEs the profile, and mutates", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    deleteAuthProfileMock.mockResolvedValue(undefined);
    render(h(AuthProfilesPage));

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(deleteAuthProfileMock).toHaveBeenCalledWith("ap-1"));
    await waitFor(() => expect(mutateMock).toHaveBeenCalledTimes(1));
    expect(window.confirm).toHaveBeenCalledWith('Delete auth profile "Staging login"?');
  });

  it("delete(): is a no-op when the confirm dialog is dismissed", () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    render(h(AuthProfilesPage));

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    expect(deleteAuthProfileMock).not.toHaveBeenCalled();
    expect(mutateMock).not.toHaveBeenCalled();
  });
});
