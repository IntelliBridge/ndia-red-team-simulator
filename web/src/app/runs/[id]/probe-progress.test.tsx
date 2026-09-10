import { createElement } from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import {
  ProbeProgress,
  ageSeconds,
  readProgressBlock,
  type ProgressBlock,
} from "./probe-progress";

// Three seconds after the block's stamp.
const NOW = Date.parse("2026-09-10T12:00:03.000Z");

function block(overrides: Partial<ProgressBlock> = {}): ProgressBlock {
  return {
    unit: "prompts",
    done: 37,
    total: 64,
    percent: 57,
    probe: "Dan_11_0",
    probes_done: 0,
    n_probes: 2,
    updated_at: "2026-09-10T12:00:00.000+00:00",
    ...overrides,
  };
}

function renderBar(
  value: ProgressBlock | null,
  runStatus: string | null = "running",
) {
  return render(
    createElement(ProbeProgress, { block: value, runStatus, now: NOW }),
  );
}

afterEach(() => cleanup());

describe("readProgressBlock", () => {
  it("returns null without the key or with a malformed block", () => {
    expect(readProgressBlock(undefined)).toBeNull();
    expect(readProgressBlock({})).toBeNull();
    expect(readProgressBlock({ progress: null })).toBeNull();
    expect(readProgressBlock({ progress: "37 of 64" })).toBeNull();
    expect(
      readProgressBlock({ progress: { ...block(), done: "37" } }),
    ).toBeNull();
    expect(
      readProgressBlock({ progress: { ...block(), updated_at: 12 } }),
    ).toBeNull();
  });

  it("reads a well-formed block as is and clamps the percent to 0..100", () => {
    expect(readProgressBlock({ progress: block() })).toEqual(block());
    expect(readProgressBlock({ progress: block({ probe: null }) })?.probe).toBe(
      null,
    );
    expect(
      readProgressBlock({ progress: block({ percent: 140 }) })?.percent,
    ).toBe(100);
  });
});

describe("ageSeconds", () => {
  it("counts whole seconds since the stamp, clamped at zero", () => {
    expect(ageSeconds("2026-09-10T12:00:00.000+00:00", NOW)).toBe(3);
    expect(ageSeconds("2026-09-10T12:00:10.000+00:00", NOW)).toBe(0);
    expect(ageSeconds("not a stamp", NOW)).toBeNull();
  });
});

describe("ProbeProgress", () => {
  it("renders the bar at the persisted count with the probe and the age", () => {
    renderBar(block());
    const bar = screen.getByRole("progressbar", { name: "prompts sent" });
    expect(bar.getAttribute("aria-valuenow")).toBe("57");
    expect(bar.getAttribute("aria-valuemin")).toBe("0");
    expect(bar.getAttribute("aria-valuemax")).toBe("100");
    expect(
      screen.getByText("prompts sent 37 of 64 · probe Dan_11_0 · updated 3 s ago"),
    ).toBeTruthy();
  });

  it("shows 100 on a succeeded run's final block", () => {
    renderBar(
      block({ done: 64, total: 64, percent: 100, probe: null, probes_done: 2 }),
      "succeeded",
    );
    const bar = screen.getByRole("progressbar", { name: "prompts sent" });
    expect(bar.getAttribute("aria-valuenow")).toBe("100");
    expect(
      screen.getByText("prompts sent 64 of 64 · updated 3 s ago"),
    ).toBeTruthy();
  });

  it("freezes the last count on a failed run and adds no wording of its own", () => {
    const { container } = renderBar(
      block({ done: 12, total: 64, percent: 18 }),
      "failed",
    );
    expect(
      screen
        .getByRole("progressbar", { name: "prompts sent" })
        .getAttribute("aria-valuenow"),
    ).toBe("18");
    expect(screen.getByText(/prompts sent 12 of 64/)).toBeTruthy();
    expect(container.textContent).not.toMatch(/fail|cancel|timed/i);
  });

  it("omits the probe segment when the block names no probe", () => {
    renderBar(block({ probe: null }));
    expect(
      screen.getByText("prompts sent 37 of 64 · updated 3 s ago"),
    ).toBeTruthy();
  });

  it("clamps a stamp from the future to zero seconds", () => {
    renderBar(block({ updated_at: "2026-09-10T12:00:30.000+00:00" }));
    expect(screen.getByText(/updated 0 s ago$/)).toBeTruthy();
  });

  it("renders nothing without a block", () => {
    const { container } = renderBar(null);
    expect(container.firstChild).toBeNull();
    expect(screen.queryByRole("progressbar")).toBeNull();
  });

  it("is labelled as an operational count, never as a score or a pass rate", () => {
    const { container } = renderBar(block());
    expect(container.textContent).toContain("prompts sent");
    expect(container.textContent).not.toMatch(/\b(score|pass|rate)\b/i);
  });
});
