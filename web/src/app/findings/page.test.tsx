import { createElement as h } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// SWR drives the findings list; hoisted so per-test mockReturnValue selects
// the loading/error/empty/data branch.
const useSWRMock = vi.hoisted(() => vi.fn());
vi.mock("swr", () => ({ default: useSWRMock }));

const useRequireAuthMock = vi.hoisted(() => vi.fn(() => true));
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: useRequireAuthMock }));

vi.mock("@/lib/api", () => ({ api: vi.fn() }));

// Stub the design-system table/severity primitives down to plain elements so
// the test asserts page behaviour, not primitive styling.
vi.mock("@redsim/design-system", () => ({
  PanelSection: ({ title, children }: any) => h("section", null, h("h2", null, title), children),
  SeverityChip: ({ level }: { level: string }) =>
    h("span", { "data-testid": "sev" }, level),
  Table: ({ children }: any) => h("table", null, children),
  TableHeader: ({ children }: any) => h("thead", null, children),
  TableBody: ({ children }: any) => h("tbody", null, children),
  TableRow: ({ children }: any) => h("tr", null, children),
  TableHead: ({ children }: any) => h("th", null, children),
  TableCell: ({ children }: any) => h("td", null, children),
  TableCaption: ({ children }: any) => h("caption", null, children),
}));

import FindingsPage from "./page";

function finding(over: Record<string, unknown> = {}) {
  return {
    id: "f-1",
    run_id: "run-1",
    project_id: "proj-1",
    severity: "high",
    status: "open",
    source_tool: "trivy",
    dedup_key: null,
    schema_blob: { title: "SQLi" },
    ...over,
  };
}

beforeEach(() => {
  localStorage.clear();
  useSWRMock.mockReset();
  useRequireAuthMock.mockReturnValue(true);
});

afterEach(cleanup);

describe("FindingsPage", () => {
  it("shows the redirect placeholder when unauthenticated", () => {
    useRequireAuthMock.mockReturnValue(false);
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: false });
    render(h(FindingsPage));
    expect(screen.getByText("Signing in…")).toBeTruthy();
    expect(screen.queryByText("Findings")).toBeNull();
  });

  it("requests the unfiltered findings key when authed and no filter", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(h(FindingsPage));
    expect(useSWRMock).toHaveBeenLastCalledWith("/v1/findings", expect.any(Function));
  });

  it("renders the loading state", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: undefined, isLoading: true });
    render(h(FindingsPage));
    expect(screen.getByText("Loading…")).toBeTruthy();
  });

  it("renders the error panel", () => {
    useSWRMock.mockReturnValue({ data: undefined, error: new Error("boom-503"), isLoading: false });
    render(h(FindingsPage));
    const panel = screen.getByText(/Failed to load findings:/);
    expect(panel.textContent).toContain("boom-503");
    expect(panel.className).toContain("border-destructive");
  });

  it("renders the empty state", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    render(h(FindingsPage));
    expect(screen.getByText(/No findings/)).toBeTruthy();
  });

  it("renders a row per finding with a link, severity chip and source", () => {
    useSWRMock.mockReturnValue({
      data: {
        findings: [
          finding({ id: "f-7", severity: "critical", schema_blob: { title: "RCE" } }),
          finding({ id: "f-8", severity: "low", source_tool: null, schema_blob: {} }),
        ],
        count: 2,
      },
      error: undefined,
      isLoading: false,
    });
    render(h(FindingsPage));

    const link7 = screen.getByRole("link", { name: "f-7" });
    expect(link7.getAttribute("href")).toBe("/findings/f-7");
    expect(screen.getByRole("link", { name: "f-8" }).getAttribute("href")).toBe("/findings/f-8");

    const chips = screen.getAllByTestId("sev");
    expect(chips.map((c) => c.textContent)).toEqual(["critical", "low"]);

    expect(screen.getByText("RCE")).toBeTruthy();
    // Missing title and null source both fall back to the em dash.
    expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(2);
  });

  it("re-keys the SWR query when a severity filter is chosen", () => {
    useSWRMock.mockReturnValue({ data: { findings: [], count: 0 }, error: undefined, isLoading: false });
    render(h(FindingsPage));

    fireEvent.change(screen.getByLabelText("Filter by severity"), {
      target: { value: "critical" },
    });
    expect(useSWRMock).toHaveBeenLastCalledWith(
      "/v1/findings?severity=critical",
      expect.any(Function),
    );
  });

  const catalog = () =>
    useSWRMock.mockReturnValue({
      data: {
        findings: [
          finding({ id: "f-1", severity: "medium", status: "open", source_tool: "ml-campaign",
            schema_blob: { title: "PGD flips vehicles", target: "bundled:vehicles_cnn", affected_component: "vehicles_cnn-1",
              ml: { attack_id: "pgd", asr_at_reference: 0.62, first_success_eps: 0.03 } } }),
          finding({ id: "f-2", severity: "critical", status: "open", source_tool: "ml-campaign",
            schema_blob: { title: "FGSM flips URL trees", target: "bundled:url_trees",
              ml: { attack_id: "fgsm", asr_at_reference: 0.91, first_success_eps: 0.01 } } }),
          finding({ id: "f-3", severity: "low", status: "false_positive", source_tool: "ml-llm-probe",
            schema_blob: { title: "DAN jailbreak", target: "openai/gpt-4o", llm: { probe_id: "dan.Dan_11_0", n_hits: 2, n_evaluated: 20 } } }),
        ],
        count: 3,
      },
      error: undefined,
      isLoading: false,
    });
  const titles = () => screen.getAllByRole("listitem").map((li) => li.querySelector("a")!.textContent);

  it("orders by severity by default and filters by status, model, attack and text", () => {
    catalog();
    render(h(FindingsPage));
    expect(titles()).toEqual(["FGSM flips URL trees", "PGD flips vehicles", "DAN jailbreak"]);
    expect(screen.getByTestId("findings-count").textContent).toBe("3 findings");
    fireEvent.change(screen.getByLabelText("status"), { target: { value: "false_positive" } });
    expect(titles()).toEqual(["DAN jailbreak"]);
    expect(screen.getByTestId("findings-count").textContent).toBe("1 of 3 findings");
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    fireEvent.change(screen.getByLabelText("model"), { target: { value: "url_trees" } });
    expect(titles()).toEqual(["FGSM flips URL trees"]);
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    fireEvent.change(screen.getByLabelText("attack or probe"), { target: { value: "dan.Dan_11_0" } });
    expect(titles()).toEqual(["DAN jailbreak"]);
    fireEvent.change(screen.getByLabelText("search"), { target: { value: "vehicles" } });
    expect(screen.queryAllByRole("listitem")).toHaveLength(0);
    expect(screen.getByText("No findings match")).toBeTruthy();
    // The server-side severity filter still re-keys the query.
    expect(useSWRMock).toHaveBeenLastCalledWith("/v1/findings", expect.any(Function));
  });

  it("sorts by attack success rate, remembers the order and notes missing values", () => {
    catalog();
    render(h(FindingsPage));
    fireEvent.change(screen.getByLabelText("sort"), { target: { value: "asr:asc" } });
    // The LLM hit rate 2/20 = 0.1 is the lowest; every row has a value, so no note.
    expect(titles()).toEqual(["DAN jailbreak", "PGD flips vehicles", "FGSM flips URL trees"]);
    expect(localStorage.getItem("redsim_findings_sort")).toBe("asr:asc");
    expect(screen.queryByTestId("sort-coverage")).toBeNull();
    fireEvent.change(screen.getByLabelText("sort"), { target: { value: "first_eps:asc" } });
    expect(titles()).toEqual(["FGSM flips URL trees", "PGD flips vehicles", "DAN jailbreak"]);
    expect(screen.getByTestId("sort-coverage").textContent).toBe(
      "The first successful eps is known for 2 of 3 findings. Rows without one follow in severity order. An attack campaign records it when an attack succeeds on the grid.",
    );
  });
});
