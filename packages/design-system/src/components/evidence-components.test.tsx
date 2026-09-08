import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MeasurementTable } from "./measurement-table";
import { MriScorecard } from "./mri-scorecard";
import { ObservationCard } from "./observation-card";
import { RobustnessCurve } from "./robustness-curve";

describe("P5 evidence components", () => {
  it("refuses to render an incomplete MRI", () => {
    render(
      <MriScorecard
        score={{ mri: 71, grade: "B" }}
        unavailableReason="family table missing"
      />,
    );
    expect(
      screen.getByText("Score unavailable: family table missing"),
    ).toBeTruthy();
  });
  it("uses exact zero-evidence wording and exposes details", () => {
    render(
      <MeasurementTable
        measurements={[
          {
            family: "control",
            n: 0,
            n_correct: 0,
            accuracy: 0,
            notes: ["not sampled"],
          },
        ]}
      />,
    );
    expect(screen.getByText("no evidence recorded")).toBeTruthy();
    fireEvent.click(screen.getByText("Details"));
    expect(screen.getByText("not sampled")).toBeTruthy();
  });
  it("does not synthesize curve points", () => {
    render(<RobustnessCurve points={[]} />);
    expect(
      screen.getByText("Curve unavailable: no evidence recorded"),
    ).toBeTruthy();
  });
  it("neither plots missing evidence as zero accuracy nor bridges across it", () => {
    const fgsm = { family: "evasion", attack_id: "fgsm" };
    const { container } = render(
      <RobustnessCurve
        points={[
          { ...fgsm, eps: 0.01, accuracy: 0.9, n: 50, n_correct: 45 },
          { ...fgsm, eps: 0.03, accuracy: 0.7, n: 50, n_correct: 35 },
          { ...fgsm, eps: 0.05, accuracy: 0, n: 0, n_correct: 0 },
          { ...fgsm, eps: 0.1, accuracy: 0.5, n: 50, n_correct: 25 },
        ]}
      />,
    );
    const missing = screen.getByLabelText(
      "fgsm, epsilon 0.05, no evidence recorded",
    );
    expect(missing.tagName.toLowerCase()).toBe("line");
    expect(missing.getAttribute("cy")).toBeNull();
    const circles = Array.from(container.querySelectorAll("circle"));
    expect(circles).toHaveLength(3);
    expect(circles.every((c) => c.getAttribute("cy") !== "96")).toBe(true);
    const strokes = Array.from(
      container.querySelectorAll('path[stroke-width="2"]'),
    );
    expect(strokes).toHaveLength(1);
    // Only the two measured neighbours left of the gap are joined; the
    // point at ε 0.1 stands alone rather than being connected across ε 0.05.
    expect(strokes[0].getAttribute("d")?.match(/[ML]/g)).toHaveLength(2);
    expect(strokes[0].getAttribute("d")).not.toContain(" 100 ");
    expect(
      screen.getByText("dashed marker: no evidence recorded at that ε"),
    ).toBeTruthy();
  });
  it("resolves canonical observation artifacts and handles image failure", () => {
    render(
      <ObservationCard
        artifactUrl={(id) => `/v1/artifacts/${id}`}
        observation={{
          id: "o1",
          sample_index: 4,
          true_label: "car",
          pred_clean: "car",
          pred_adv: "truck",
          confidence_clean: 0.82,
          confidence_adv: 0.61,
          artifacts: { original: "a1" },
          metric_note: "illustrative heuristic",
        }}
      />,
    );
    const image = screen.getByAltText(
      "original recorded evidence for sample 4",
    );
    fireEvent.error(image);
    expect(screen.getByLabelText(/image unavailable/)).toBeTruthy();
  });
});
