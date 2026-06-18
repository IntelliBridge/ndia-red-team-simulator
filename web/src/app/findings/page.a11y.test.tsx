import { createElement as h } from "react";
import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { axe } from "vitest-axe";

// Accessibility check for the findings list page. Unlike page.test.tsx we do
// NOT stub the design-system primitives — axe must see the real Table markup
// (caption + scope) to verify it. Only the data sources are mocked.

const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: useRequireAuthMock }));

vi.mock("@/lib/api", () => ({ api: vi.fn() }));

import FindingsPage from "./page";

beforeEach(() => {
  useSWRMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
});

afterEach(cleanup);

describe("FindingsPage a11y", () => {
  it("the populated findings table has no axe violations", async () => {
    useSWRMock.mockReturnValue({
      data: {
        findings: [
          {
            id: "f-1",
            run_id: "run-1",
            project_id: "p",
            severity: "critical",
            status: "open",
            source_tool: "trivy",
            validation_state: "unvalidated",
            dedup_key: null,
            schema_blob: { title: "RCE in handler" },
          },
          {
            id: "f-2",
            run_id: "run-1",
            project_id: "p",
            severity: "low",
            status: "triaged",
            source_tool: null,
            validation_state: "unvalidated",
            dedup_key: null,
            schema_blob: {},
          },
        ],
        count: 2,
      },
      error: undefined,
      isLoading: false,
    });

    const { container } = render(h(FindingsPage));
    const results = await axe(container);
    expect(results.violations).toEqual([]);
  });

  it("the empty state has no axe violations", async () => {
    useSWRMock.mockReturnValue({
      data: { findings: [], count: 0 },
      error: undefined,
      isLoading: false,
    });
    const { container } = render(h(FindingsPage));
    const results = await axe(container);
    expect(results.violations).toEqual([]);
  });
});
