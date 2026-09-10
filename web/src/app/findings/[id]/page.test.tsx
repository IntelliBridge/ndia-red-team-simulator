import { createElement } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "@/__fixtures__/finding.json";

const explain = vi.hoisted(() => vi.fn());
const harden = vi.hoisted(() => vi.fn());
const useFinding = vi.hoisted(() => vi.fn());
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: () => true }));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: { default: "approver" } }),
}));
vi.mock("@/hooks/useFinding", () => ({
  useFinding,
}));
vi.mock("@/lib/chat", async () => ({
  ...(await vi.importActual("@/lib/chat")),
  fetchChatStatus: vi.fn(async () => ({ configured: true, model: "anthropic/claude-opus-5" })),
  streamFindingChat: vi.fn(),
}));
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual("@/lib/api")),
  explainFinding: explain,
  hardenFinding: harden,
  artifactUrl: (id: string) => `/v1/artifacts/${id}`,
}));
import FindingPage from "./page";

describe("/findings/[id]", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useFinding.mockReturnValue({
      data: structuredClone(fixture),
      mutate: vi.fn(),
    });
  });
  afterEach(() => cleanup());
  it("renders recorded image, explanation, candidate, curve, audit, and campaign", () => {
    render(createElement(FindingPage, { params: { id: "fixture-finding" } }));
    expect(screen.getByAltText("original evidence for sample 4")).toBeTruthy();
    expect(
      screen.getByText(
        "Attribution describes model sensitivity; it is not causal proof.",
      ),
    ).toBeTruthy();
    expect(screen.getByText("candidate")).toBeTruthy();
    expect(screen.queryByText(/not evaluated/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Verify" })).toBeNull();
    expect(screen.getByRole("link", { name: "fixture-run-001" })).toBeTruthy();
    expect(screen.getByText(/per-sample explanation shift 0.37/)).toBeTruthy();
    expect(
      screen.getByText(/aggregate explanation shift at reference ε not recorded/),
    ).toBeTruthy();
  });
  it("renders tabular evidence as a recorded diff", () => {
    const data = structuredClone(fixture) as any;
    const observation = data.schema_blob.ml.observations[0];
    observation.modality = "tabular";
    observation.feature_values_clean = { url_length: 42 };
    observation.feature_values_adv = { url_length: 67 };
    useFinding.mockReturnValue({ data, mutate: vi.fn() });
    render(createElement(FindingPage, { params: { id: "fixture-finding" } }));
    expect(screen.getByLabelText("Tabular evidence difference")).toBeTruthy();
    expect(screen.getByText(/url_length: 42/)).toBeTruthy();
    expect(screen.getByText(/url_length: 67/)).toBeTruthy();
  });
  it("offers scanner explanation only when SHAP evidence is absent", () => {
    const data = structuredClone(fixture) as any;
    const artifacts = data.schema_blob.ml.observations[0].artifacts;
    delete artifacts.shap_clean;
    delete artifacts.shap_adv;
    useFinding.mockReturnValue({ data, mutate: vi.fn() });
    render(createElement(FindingPage, { params: { id: "fixture-finding" } }));
    expect(screen.getByText(/Explanation absent/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Explain" }));
    expect(explain).toHaveBeenCalledWith("fixture-finding");
  });
  it("queues rule-layer hardening without claiming evaluation", () => {
    render(createElement(FindingPage, { params: { id: "fixture-finding" } }));
    fireEvent.click(screen.getByRole("button", { name: "Harden" }));
    expect(harden).toHaveBeenCalledWith("fixture-finding", {
      llm_narrative: false,
    });
    expect(screen.getByText("candidate")).toBeTruthy();
  });
  it("opens the finding chat drawer from the Chat button", async () => {
    render(createElement(FindingPage, { params: { id: "fixture-finding" } }));
    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Chat" }));
    const dialog = await screen.findByRole("dialog", { name: "Chat with this finding" });
    expect(dialog.textContent).toContain("fixture-finding");
    expect(screen.getByRole("button", { name: /Explain this finding in plain language/ })).toBeTruthy();
  });
});
