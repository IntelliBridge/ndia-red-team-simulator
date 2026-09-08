import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// --- hoisted mocks ---
const requireAuthMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/auth", () => ({ requireAuth: requireAuthMock }));

const routerStub = { push: vi.fn(), replace: vi.fn() };
vi.mock("next/navigation", () => ({ useRouter: () => routerStub }));

import { useRequireAuth } from "./useRequireAuth";

beforeEach(() => {
  requireAuthMock.mockReset();
});

describe("useRequireAuth", () => {
  it("returns true once requireAuth(router) authorizes, passing the router", async () => {
    requireAuthMock.mockReturnValue(true);

    const { result } = renderHook(() => useRequireAuth());

    await waitFor(() => expect(result.current).toBe(true));
    expect(requireAuthMock).toHaveBeenCalledWith(routerStub);
  });

  it("stays false when requireAuth(router) denies (redirect path)", async () => {
    requireAuthMock.mockReturnValue(false);

    const { result } = renderHook(() => useRequireAuth());

    // The effect runs but never flips authed to true.
    await waitFor(() => expect(requireAuthMock).toHaveBeenCalled());
    expect(result.current).toBe(false);
  });
});
