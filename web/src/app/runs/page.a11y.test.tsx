import { createElement as h } from "react";
import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { axe } from "vitest-axe";

// Accessibility check for the runs list page. Renders the real design-system
// Table + RunStatusBadge (no primitive stubs) so axe verifies the caption +
// scope + the badge's aria-label.

const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: useRequireAuthMock }));

vi.mock("@/lib/api", () => ({ api: vi.fn() }));

import RunsPage from "./page";

beforeEach(() => {
  useSWRMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
});

afterEach(cleanup);

describe("RunsPage a11y", () => {
  it("the populated runs table has no axe violations", async () => {
    useSWRMock.mockReturnValue({
      data: {
        runs: [
          { id: "run-7", project_id: "p", status: "running", scanner: "trivy", mode: "live", created_at: "2026-01-02T03:04:05.000Z", created_by: null },
          { id: "run-8", project_id: "p", status: "failed", scanner: null, mode: "live", created_at: "2026-01-02T03:04:05.000Z", created_by: null },
        ],
        count: 2,
      },
      error: undefined,
      isLoading: false,
    });

    const { container } = render(h(RunsPage));
    const results = await axe(container);
    expect(results.violations).toEqual([]);
  });

  it("the empty state has no axe violations", async () => {
    useSWRMock.mockReturnValue({
      data: { runs: [], count: 0 },
      error: undefined,
      isLoading: false,
    });
    const { container } = render(h(RunsPage));
    const results = await axe(container);
    expect(results.violations).toEqual([]);
  });
});
