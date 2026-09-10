// The Palantir Foundry panel of /exports, mounted the way the browser mounts it.
//
// jsdom, the tRPC link fed the wire envelope. The role hook is mocked so the
// admin gate and the project selector can be exercised without a /v1/projects
// round trip. The settings query arrives hydrated, as the page prefetches it.
import { act, cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { QueryClient, dehydrate, type DehydratedState } from "@tanstack/react-query";
import { createTRPCClient, httpBatchLink } from "@trpc/client";
import { createTRPCOptionsProxy } from "@trpc/tanstack-react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AuthProfile, FoundryProjectSettings, ProjectMembership } from "@/lib/api";
import { makeQueryClient } from "@/lib/trpc/query-client";
import { renderWithProviders } from "@/test/render";
import { trpcResult, trpcUpstreamError } from "@/test/mock-upstream";
import type { AppRouter } from "@/server/trpc/root";

const rolesMock = vi.hoisted(() => ({
  roles: {} as Record<string, string>,
  projects: [] as ProjectMembership[],
}));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: rolesMock.roles, projects: rolesMock.projects, isLoading: false, error: undefined }),
}));

import { FoundryPanel } from "./foundry-panel";

const RID = "ri.foundry.main.dataset.9bc42537-e3d6-4c3d-8591-f560e9a34c16";
const HOST = "ndia-hackathon-2026.palantirsec.com";

function membership(over: Partial<ProjectMembership> = {}): ProjectMembership {
  return { id: "proj-1", slug: "default", name: "Default", org_id: "org-1", daily_llm_budget_cents: null, role: "admin", ...over };
}

function settings(over: {
  deployment?: Partial<FoundryProjectSettings["deployment"]>;
  settings?: Partial<FoundryProjectSettings["settings"]>;
  effective?: Partial<FoundryProjectSettings["effective"]>;
} = {}): FoundryProjectSettings {
  return {
    project_id: "proj-1",
    project: "default",
    deployment: { status: "configured", host: HOST, reason: null, attested: true, default_dataset_rid: null, ...over.deployment },
    settings: {
      dataset_rid: RID,
      auth_profile_id: "authprof-1",
      auth_profile_name: "foundry",
      auto_push: true,
      updated_at: "2026-09-10T03:00:00+00:00",
      updated_by: "user:demo-admin",
      ...over.settings,
    },
    effective: { dataset_rid: RID, ready: true, blockers: [], ...over.effective },
  };
}

const PROFILES: AuthProfile[] = [
  { id: "authprof-1", project_id: "proj-1", name: "foundry", kind: "bearer", config: { platform: "foundry" }, created_at: "2026-09-10T02:00:00+00:00" },
  { id: "authprof-2", project_id: "proj-1", name: "endpoint-form", kind: "form", config: {}, created_at: "2026-09-10T02:00:00+00:00" },
  { id: "authprof-3", project_id: "proj-1", name: "foundry-2", kind: "bearer", config: {}, created_at: "2026-09-10T02:00:00+00:00" },
];

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

async function dehydratedSettings(data: FoundryProjectSettings, project = "default"): Promise<DehydratedState> {
  const queryClient = makeQueryClient();
  const options = keyProxy(queryClient).exports.foundrySettings.queryOptions({ project });
  await queryClient.prefetchQuery({ ...options, retry: false, queryFn: () => Promise.resolve(data) });
  return dehydrate(queryClient);
}

/** The JSON body of the n-th tRPC request the link issued. */
function requestBody(trpcFetch: ReturnType<typeof vi.fn>, index: number): unknown {
  const init = trpcFetch.mock.calls[index]?.[1] as RequestInit | undefined;
  return init?.body ? JSON.parse(String(init.body)) : undefined;
}

beforeEach(() => {
  rolesMock.roles = { "proj-1": "admin" };
  rolesMock.projects = [membership()];
});

afterEach(() => {
  cleanup();
});

describe("FoundryPanel states", () => {
  it("renders the configured deployment, the saved settings and the ready line for an admin", async () => {
    const dehydratedState = await dehydratedSettings(settings());
    renderWithProviders(<FoundryPanel project="default" />, {
      dehydratedState,
      respond: () => [trpcResult(PROFILES)],
    });

    expect(screen.getByRole("heading", { name: "Palantir Foundry" })).toBeTruthy();
    expect(screen.getByText(HOST)).toBeTruthy();
    expect(screen.getByText("configured")).toBeTruthy();
    expect((screen.getByRole("textbox") as HTMLInputElement).value).toBe(RID);
    const toggle = screen.getByRole("checkbox", { name: /Auto-push finished campaigns/ }) as HTMLInputElement;
    expect(toggle.checked).toBe(true);
    expect(toggle.disabled).toBe(false);
    expect(screen.getByText(/^Ready · pushes write to/).textContent).toContain(RID);
    expect(screen.getByText(/auto-push on/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Save" })).toBeTruthy();

    // Only bearer profiles are offered, plus the "none" row.
    await waitFor(() => expect(screen.getByRole("option", { name: "foundry-2" })).toBeTruthy());
    expect(screen.queryByRole("option", { name: "endpoint-form" })).toBeNull();
    expect((screen.getByRole("combobox", { name: /Bearer auth profile/ }) as HTMLSelectElement).value).toBe("authprof-1");
    expect(screen.getByRole("link", { name: "Manage auth profiles" }).getAttribute("href")).toBe("/auth-profiles");
  });

  it("renders the disabled deployment with the operator hint and every blocker as a sentence", async () => {
    const dehydratedState = await dehydratedSettings(
      settings({
        deployment: { status: "disabled", host: null, reason: "REDSIM_INTEGRATION_FOUNDRY_URL is unset", attested: false },
        settings: { dataset_rid: null, auth_profile_id: null, auth_profile_name: null, auto_push: false, updated_at: null, updated_by: null },
        effective: { dataset_rid: null, ready: false, blockers: ["integration_disabled", "auth_profile_missing", "dataset_rid_missing"] },
      }),
    );
    renderWithProviders(<FoundryPanel project="default" />, { dehydratedState, respond: () => [trpcResult([])] });

    expect(screen.getByText("disabled")).toBeTruthy();
    expect(screen.getByText(/REDSIM_INTEGRATION_FOUNDRY_URL is unset/)).toBeTruthy();
    expect(screen.getByText(/An operator sets REDSIM_INTEGRATION_FOUNDRY_URL/)).toBeTruthy();
    expect(screen.getByText("Foundry is not configured on this deployment.")).toBeTruthy();
    expect(screen.getByText("No bearer auth profile is selected for the token.")).toBeTruthy();
    expect(screen.getByText("No Foundry dataset rid is set and the deployment has no default.")).toBeTruthy();
    expect(screen.getByText(/Not ready/)).toBeTruthy();
    expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false);
  });

  it("shows the values read-only and no Save to a viewer", async () => {
    rolesMock.roles = { "proj-1": "viewer" };
    rolesMock.projects = [membership({ role: "viewer" })];
    const dehydratedState = await dehydratedSettings(settings());
    renderWithProviders(<FoundryPanel project="default" />, { dehydratedState, respond: () => [trpcResult(PROFILES)] });

    expect(screen.queryByRole("button", { name: "Save" })).toBeNull();
    expect(screen.getByText("Admins of this project can change these.")).toBeTruthy();
    expect((screen.getByRole("textbox") as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole("checkbox") as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole("combobox", { name: /Bearer auth profile/ }) as HTMLSelectElement).disabled).toBe(true);
  });

  it("blocks with the upstream code when the settings cannot be read", async () => {
    renderWithProviders(<FoundryPanel project="default" />, {
      respond: () => [trpcUpstreamError(503, { message: "database is unavailable" })],
    });
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Foundry settings are unavailable");
    expect(alert.textContent).toContain("db_unavailable");
  });

  it("offers a project selector without ?project= and defaults to the caller's admin project", async () => {
    rolesMock.roles = { "proj-1": "viewer", "proj-2": "admin" };
    rolesMock.projects = [membership({ role: "viewer" }), membership({ id: "proj-2", slug: "alpha", name: "Alpha", role: "admin" })];
    const dehydratedState = await dehydratedSettings({ ...settings(), project_id: "proj-2", project: "alpha" }, "alpha");
    renderWithProviders(<FoundryPanel />, { dehydratedState, respond: () => [trpcResult(PROFILES)] });

    const selector = screen.getByRole("combobox", { name: "Project" }) as HTMLSelectElement;
    expect(selector.value).toBe("alpha");
    expect(screen.getByText(HOST)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Save" })).toBeTruthy();
  });
});

describe("FoundryPanel save", () => {
  it("sends the edited rid, profile and toggle as the PUT body, then refetches and says Saved", async () => {
    const dehydratedState = await dehydratedSettings(settings({ settings: { auto_push: false } }));
    let call = 0;
    const { trpcFetch } = renderWithProviders(<FoundryPanel project="default" />, {
      dehydratedState,
      respond: () => {
        call += 1;
        if (call === 1) return [trpcResult(PROFILES)];
        if (call === 2) return [trpcResult(settings({ settings: { auth_profile_id: "authprof-3", auth_profile_name: "foundry-2", auto_push: true } }))];
        return [trpcResult(settings({ settings: { auth_profile_id: "authprof-3", auth_profile_name: "foundry-2", auto_push: true } }))];
      },
    });
    await waitFor(() => expect(screen.getByRole("option", { name: "foundry-2" })).toBeTruthy());

    fireEvent.change(screen.getByRole("textbox"), { target: { value: ` ${RID} ` } });
    fireEvent.change(screen.getByRole("combobox", { name: /Bearer auth profile/ }), { target: { value: "authprof-3" } });
    fireEvent.click(screen.getByRole("checkbox"));
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
    });

    await waitFor(() => expect(trpcFetch).toHaveBeenCalledTimes(3));
    expect(String(trpcFetch.mock.calls[1]?.[0])).toContain("exports.updateFoundrySettings");
    const body = requestBody(trpcFetch, 1) as { 0: Record<string, unknown> };
    expect(body[0]).toEqual({ project: "default", dataset_rid: RID, auth_profile_id: "authprof-3", auto_push: true });
    expect(String(trpcFetch.mock.calls[2]?.[0])).toContain("exports.foundrySettings");
    await waitFor(() => expect(screen.getByRole("status").textContent).toBe("Saved"));
    expect(screen.getByText(/auto-push on/)).toBeTruthy();
  });

  it("sends null for an emptied rid and profile", async () => {
    const dehydratedState = await dehydratedSettings(settings());
    let call = 0;
    const { trpcFetch } = renderWithProviders(<FoundryPanel project="default" />, {
      dehydratedState,
      respond: () => {
        call += 1;
        return call === 1 ? [trpcResult(PROFILES)] : [trpcResult(settings())];
      },
    });
    await waitFor(() => expect(screen.getByRole("option", { name: "foundry-2" })).toBeTruthy());

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "" } });
    fireEvent.change(screen.getByRole("combobox", { name: /Bearer auth profile/ }), { target: { value: "" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
    });

    await waitFor(() => expect(trpcFetch.mock.calls.length).toBeGreaterThanOrEqual(2));
    const body = requestBody(trpcFetch, 1) as { 0: Record<string, unknown> };
    expect(body[0]).toEqual({ project: "default", dataset_rid: null, auth_profile_id: null, auto_push: true });
  });

  it("shows the API refusal by code beside the form and keeps the edited values", async () => {
    const dehydratedState = await dehydratedSettings(settings());
    let call = 0;
    renderWithProviders(<FoundryPanel project="default" />, {
      dehydratedState,
      respond: () => {
        call += 1;
        if (call === 1) return [trpcResult(PROFILES)];
        return [trpcUpstreamError(422, { code: "params_out_of_range", message: "target_ref must be a Foundry resource identifier", field: "dataset_rid" })];
      },
    });
    await waitFor(() => expect(screen.getByRole("option", { name: "foundry-2" })).toBeTruthy());

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "https://foundry.invalid/x" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Save" }));
    });

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("params_out_of_range: target_ref must be a Foundry resource identifier");
    expect((screen.getByRole("textbox") as HTMLInputElement).value).toBe("https://foundry.invalid/x");
    expect(screen.queryByRole("status")).toBeNull();
  });
});
