import { createElement as h, Fragment } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// NOTE: this workspace's vitest v4 transforms via oxc, and web/tsconfig.json
// sets `jsx: "preserve"` (required by Next), so raw JSX syntax fails to parse
// in test files. We build elements with React.createElement (`h`) instead —
// behaviour and assertions are unchanged.

// SWR drives the single-finding fetch.
const useSWRMock = vi.hoisted(() => vi.fn());
const mutateMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({
  useRequireAuth: useRequireAuthMock,
}));

// useRoles supplies the project_id -> role map consumed for RBAC.
const useRolesMock = vi.hoisted(() => vi.fn(() => ({ roles: {} as Record<string, string> })));
vi.mock("@/hooks/useRoles", () => ({ useRoles: useRolesMock }));

// The page calls api() directly for fix/verify mutations.
const apiMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api", () => ({ api: apiMock }));

// Stub design-system. FindingCard surfaces its props so we can assert them.
// RoleGated honors a real low->high hierarchy so gating is meaningfully tested.
const ROLE_ORDER = ["viewer", "remediator", "approver", "admin"];
vi.mock("@aegis/design-system", () => ({
  FindingCard: (props: Record<string, any>) =>
    h(
      "section",
      { "data-testid": "finding-card" },
      h("span", { "data-testid": "fc-id" }, props.id),
      h("span", { "data-testid": "fc-title" }, props.title),
      h("span", { "data-testid": "fc-severity" }, props.severity),
      h("span", { "data-testid": "fc-status" }, props.status),
      h("span", { "data-testid": "fc-validation" }, props.validationState),
      h("span", { "data-testid": "fc-target" }, props.target),
      h("div", { "data-testid": "fc-body" }, props.children),
      h("div", { "data-testid": "fc-actions" }, props.actions),
    ),
  RoleGated: ({
    minRole,
    callerRole,
    children,
  }: {
    minRole: string;
    callerRole?: string;
    children: any;
  }) => {
    const need = ROLE_ORDER.indexOf(minRole);
    const have = callerRole ? ROLE_ORDER.indexOf(callerRole) : -1;
    return have >= need ? h(Fragment, null, children) : null;
  },
}));

import FindingPage from "./page";

function finding(over: Record<string, unknown> = {}) {
  return {
    id: "f-1",
    run_id: "run-1",
    project_id: "proj-alpha",
    severity: "high",
    status: "open",
    source_tool: "trivy",
    validation_state: "poc_passed",
    dedup_key: null,
    schema_blob: {
      title: "SQL injection in /login",
      description: "User input flows unsanitised into a query.",
      target: "https://target.example/login",
    },
    ...over,
  };
}

function renderPage(id = "f-1") {
  return render(h(FindingPage, { params: { id } }));
}

beforeEach(() => {
  useSWRMock.mockReset();
  apiMock.mockReset();
  mutateMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
  useRolesMock.mockReturnValue({ roles: {} });
});

afterEach(cleanup);

describe("FindingPage", () => {
  it("shows the redirect placeholder when unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false, mutate: mutateMock });
    renderPage();
    expect(screen.getByText("Redirecting to sign in…")).toBeTruthy();
    expect(screen.queryByTestId("finding-card")).toBeNull();
  });

  it("keys SWR by the route param once authed", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true, mutate: mutateMock });
    renderPage("f-42");
    expect(useSWRMock).toHaveBeenLastCalledWith("/v1/findings/f-42", expect.any(Function));
  });

  it("renders the loading state", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true, mutate: mutateMock });
    renderPage();
    expect(screen.getByText("Loading…")).toBeTruthy();
  });

  it("renders the failure panel on error", () => {
    useSWRMock.mockReturnValue({
      data: undefined,
      error: new Error("boom"),
      isLoading: false,
      mutate: mutateMock,
    });
    renderPage();
    const panel = screen.getByText("Failed to load.");
    expect(panel.className).toContain("border-red-200");
  });

  it("renders the failure panel when data is missing (no error)", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false, mutate: mutateMock });
    renderPage();
    expect(screen.getByText("Failed to load.")).toBeTruthy();
  });

  it("renders the finding's severity, status, validation, title and body", () => {
    useSWRMock.mockReturnValue({ data: finding(), error: undefined, isLoading: false, mutate: mutateMock });
    renderPage();

    expect(screen.getByTestId("fc-id").textContent).toContain("f-1");
    expect(screen.getByTestId("fc-title").textContent).toContain("SQL injection in /login");
    expect(screen.getByTestId("fc-severity").textContent).toContain("high");
    expect(screen.getByTestId("fc-status").textContent).toContain("open");
    expect(screen.getByTestId("fc-validation").textContent).toContain("poc_passed");
    expect(screen.getByTestId("fc-target").textContent).toContain("https://target.example/login");
    expect(screen.getByTestId("fc-body").textContent).toContain("User input flows unsanitised into a query.");
  });

  it("falls back to the finding id as the title when the blob omits one", () => {
    useSWRMock.mockReturnValue({
      data: finding({ id: "f-xyz", schema_blob: { description: "d" } }),
      error: undefined,
      isLoading: false,
      mutate: mutateMock,
    });
    renderPage("f-xyz");
    expect(screen.getByTestId("fc-title").textContent).toContain("f-xyz");
  });

  it("hides both RBAC actions for a viewer", () => {
    useRolesMock.mockReturnValue({ roles: { "proj-alpha": "viewer" } });
    useSWRMock.mockReturnValue({ data: finding(), error: undefined, isLoading: false, mutate: mutateMock });
    renderPage();
    expect(screen.queryByRole("button", { name: "Verify" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Apply patch + open PR" })).toBeNull();
  });

  it("shows Verify (remediator) but hides Apply for a remediator", () => {
    useRolesMock.mockReturnValue({ roles: { "proj-alpha": "remediator" } });
    useSWRMock.mockReturnValue({ data: finding(), error: undefined, isLoading: false, mutate: mutateMock });
    renderPage();
    expect(screen.getByRole("button", { name: "Verify" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Apply patch + open PR" })).toBeNull();
  });

  it("shows both actions for an approver", () => {
    useRolesMock.mockReturnValue({ roles: { "proj-alpha": "approver" } });
    useSWRMock.mockReturnValue({ data: finding(), error: undefined, isLoading: false, mutate: mutateMock });
    renderPage();
    expect(screen.getByRole("button", { name: "Verify" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Apply patch + open PR" })).toBeTruthy();
  });

  it("triggerVerify(): POSTs the verify endpoint then revalidates", async () => {
    useRolesMock.mockReturnValue({ roles: { "proj-alpha": "approver" } });
    apiMock.mockResolvedValue({});
    useSWRMock.mockReturnValue({ data: finding({ id: "f-7" }), error: undefined, isLoading: false, mutate: mutateMock });

    renderPage("f-7");
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(apiMock).toHaveBeenCalledWith("/v1/findings/f-7/verify", { method: "POST" }));
    await waitFor(() => expect(mutateMock).toHaveBeenCalledTimes(1));
  });

  it("applyFix(): POSTs the fix payload then revalidates", async () => {
    useRolesMock.mockReturnValue({ roles: { "proj-alpha": "approver" } });
    apiMock.mockResolvedValue({});
    useSWRMock.mockReturnValue({ data: finding({ id: "f-9" }), error: undefined, isLoading: false, mutate: mutateMock });

    renderPage("f-9");
    fireEvent.click(screen.getByRole("button", { name: "Apply patch + open PR" }));

    await waitFor(() =>
      expect(apiMock).toHaveBeenCalledWith("/v1/findings/f-9/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ strategy: "patch", apply: true, open_pr: true }),
      }),
    );
    await waitFor(() => expect(mutateMock).toHaveBeenCalledTimes(1));
  });

  it("surfaces the error panel when a mutation rejects", async () => {
    useRolesMock.mockReturnValue({ roles: { "proj-alpha": "approver" } });
    apiMock.mockRejectedValue(new Error("verify-failed-409"));
    useSWRMock.mockReturnValue({ data: finding(), error: undefined, isLoading: false, mutate: mutateMock });

    renderPage();
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    const panel = await screen.findByText(/verify-failed-409/);
    expect(panel.className).toContain("border-red-200");
    expect(mutateMock).not.toHaveBeenCalled();
  });
});
