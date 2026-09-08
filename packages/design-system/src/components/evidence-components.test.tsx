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
  it("splits measured curve segments around missing evidence", () => {
    const { container } = render(
      <RobustnessCurve
        points={[
          { family: "evasion", eps: 0.01, accuracy: 0.8, n: 10, n_correct: 8 },
          { family: "evasion", eps: 0.03, accuracy: 0, n: 0, n_correct: 0 },
          { family: "evasion", eps: 0.1, accuracy: 0.4, n: 10, n_correct: 4 },
        ]}
      />,
    );
    expect(
      screen.getByLabelText("evasion, epsilon 0.03, no evidence recorded"),
    ).toBeTruthy();
    expect(container.querySelectorAll("circle")).toHaveLength(2);
    expect(container.querySelectorAll("path")).toHaveLength(3);
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
