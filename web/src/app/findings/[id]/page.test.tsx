import { createElement } from "react";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "@/__fixtures__/finding.json";

const explain = vi.hoisted(() => vi.fn());
const harden = vi.hoisted(() => vi.fn());
const verify = vi.hoisted(() => vi.fn());
const useFinding = vi.hoisted(() => vi.fn());
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: () => true }));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: { default: "approver" } }),
}));
vi.mock("@/hooks/useFinding", () => ({
  useFinding,
}));
vi.mock("@/hooks/useMlCatalog", () => ({
  useDefenses: () => ({ data: [{ id: "jpeg", name: "JPEG preprocessing" }] }),
}));
vi.mock("@/lib/api", async () => ({
  ...(await vi.importActual("@/lib/api")),
  explainFinding: explain,
  hardenFinding: harden,
  verifyFinding: verify,
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
  it("renders recorded image, explanation, unmeasured candidate, curve, audit, and campaign", () => {
    render(createElement(FindingPage, { params: { id: "fixture-finding" } }));
    expect(screen.getByAltText("original evidence for sample 4")).toBeTruthy();
    expect(
      screen.getByText(
        "Attribution describes model sensitivity; it is not causal proof.",
      ),
    ).toBeTruthy();
    expect(screen.getByText(/candidate · not evaluated/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "fixture-run-001" })).toBeTruthy();
  });
  it("submits selected defense and editable params", async () => {
    render(createElement(FindingPage, { params: { id: "fixture-finding" } }));
    fireEvent.change(screen.getByLabelText("Defense"), {
      target: { value: "jpeg" },
    });
    fireEvent.change(screen.getByLabelText("Defense parameters"), {
      target: { value: '{"quality":72}' },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() =>
      expect(verify).toHaveBeenCalledWith("fixture-finding", "jpeg", {
        quality: 72,
      }),
    );
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
  it("renders a schema-valid completed verification delta", () => {
    const data = structuredClone(fixture) as any;
    data.schema_blob.ml.verify = {
      run_id: "verify-run-1",
      defense: { name: "feature_squeezing", params: { bit_depth: 5 } },
      outcome: "verified",
      delta: {
        baseline_run_id: "fixture-run-001",
        mri_before: 58,
        mri_after: 66,
        delta: 8,
        delta_subscores: {
          S_acc: 0,
          S_asr: 12.5,
          S_eps: 6,
          S_conf: 3.1,
          S_expl: null,
        },
        delta_acc_clean: {
          before: { n: 50, n_correct: 41, accuracy: 0.82 },
          after: { n: 50, n_correct: 40, accuracy: 0.8 },
          delta: -0.02,
        },
        delta_families: [
          {
            measurement_id: "m.evasion.fgsm.eps0.03",
            before: { n: 50, n_correct: 24, accuracy: 0.48 },
            after: { n: 50, n_correct: 31, accuracy: 0.62 },
            delta: 0.14,
          },
          {
            measurement_id: "m.control.noise.eps0.03",
            before: { n: 0, n_correct: 0, accuracy: null },
            after: { n: 0, n_correct: 0, accuracy: null },
            delta: null,
          },
        ],
      },
    };
    useFinding.mockReturnValue({ data, mutate: vi.fn() });
    render(createElement(FindingPage, { params: { id: "fixture-finding" } }));
    expect(screen.getByText(/ΔMRI 8 · 58 → 66 · baseline fixture-run-001/)).toBeTruthy();
    expect(screen.getByText("S_asr: 12.5")).toBeTruthy();
    expect(screen.getByText("S_expl: not recorded")).toBeTruthy();
    expect(
      screen.getByText(/clean accuracy 0.82 \(n=50\) → 0.8 \(n=50\) · Δ -0.02/),
    ).toBeTruthy();
    expect(
      screen.getByText(
        /m\.evasion\.fgsm\.eps0\.03: 0.48 \(n=50\) → 0.62 \(n=50\) · Δ 0.14/,
      ),
    ).toBeTruthy();
    expect(
      screen.getByText(
        /m\.control\.noise\.eps0\.03: no evidence recorded → no evidence recorded · Δ not recorded/,
      ),
    ).toBeTruthy();
  });
  it("queues rule-layer hardening without claiming evaluation", () => {
    render(createElement(FindingPage, { params: { id: "fixture-finding" } }));
    fireEvent.click(screen.getByRole("button", { name: "Harden" }));
    expect(harden).toHaveBeenCalledWith("fixture-finding", {
      llm_narrative: false,
    });
    expect(screen.getByText(/candidate · not evaluated/)).toBeTruthy();
  });
});
