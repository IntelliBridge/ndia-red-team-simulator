import { renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ProjectMembership } from "@/lib/api";

const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

import { useRoles } from "./useRoles";

function project(over: Partial<ProjectMembership>): ProjectMembership {
  return {
    id: "p",
    slug: "p",
    name: "P",
    org_id: "o",
    daily_llm_budget_cents: null,
    role: "viewer",
    ...over,
  };
}

afterEach(() => {
  useSWRMock.mockReset();
});

describe("useRoles", () => {
  it("derives a project_id -> role map and adds slug aliases", () => {
    useSWRMock.mockReturnValue({
      data: {
        projects: [
          project({ id: "p1", slug: "alpha", role: "admin" }),
          project({ id: "p2", slug: "p2", role: "viewer" }),
        ],
      },
      error: undefined,
      isLoading: false,
    });

    const { result } = renderHook(() => useRoles());

    expect(result.current.roles).toEqual({
      p1: "admin",
      alpha: "admin",
      p2: "viewer",
    });
    expect(result.current.projects).toHaveLength(2);
    expect(result.current.isLoading).toBe(false);
  });

  it("returns an empty role map while loading with no data", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    const { result } = renderHook(() => useRoles());
    expect(result.current.roles).toEqual({});
    expect(result.current.projects).toEqual([]);
    expect(result.current.isLoading).toBe(true);
  });

  it("passes SWR errors straight through", () => {
    const boom = new Error("nope");
    useSWRMock.mockReturnValue({ data: undefined, error: boom, isLoading: false });
    const { result } = renderHook(() => useRoles());
    expect(result.current.error).toBe(boom);
  });
});
