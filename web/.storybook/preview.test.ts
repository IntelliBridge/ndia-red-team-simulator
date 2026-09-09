// @vitest-environment node
import { describe, expect, it, vi } from "vitest";

// preview.ts imports globals.css; that import is irrelevant to the config
// shape and will fail under vitest (no CSS loader). Stub it.
vi.mock("../src/styles/globals.css", () => ({}));

// @storybook/react is a type-only import in preview.ts so no runtime mock needed.

import preview from "./preview";

describe("storybook preview config", () => {
  it("exports a default preview object", () => {
    expect(preview).not.toBeNull();
    expect(typeof preview).toBe("object");
  });

  it("parameters is truthy", () => {
    expect(preview.parameters).toBeTruthy();
  });

  it("parameters.controls.matchers.color is /(background|color)$/i", () => {
    const { controls } = preview.parameters as Record<string, Record<string, Record<string, unknown>>>;
    expect(controls.matchers.color.toString()).toBe("/(background|color)$/i");
  });

  it("parameters.controls.matchers.date is /Date$/", () => {
    const { controls } = preview.parameters as Record<string, Record<string, Record<string, unknown>>>;
    expect(controls.matchers.date.toString()).toBe("/Date$/");
  });

  it("parameters.a11y.config.rules is an empty array", () => {
    const { a11y } = preview.parameters as Record<string, Record<string, unknown>>;
    expect(a11y.config).toEqual({ rules: [] });
  });

  it("parameters.backgrounds.default is 'redsim-navy'", () => {
    const { backgrounds } = preview.parameters as Record<string, Record<string, unknown>>;
    expect(backgrounds.default).toBe("redsim-navy");
  });

  it("parameters.backgrounds.values contains the redsim-navy page ground", () => {
    const { backgrounds } = preview.parameters as Record<string, Record<string, unknown>>;
    expect(backgrounds.values).toEqual(
      expect.arrayContaining([{ name: "redsim-navy", value: "#04060f" }]),
    );
  });

  it("parameters.backgrounds.values contains the redsim-surface card ground", () => {
    const { backgrounds } = preview.parameters as Record<string, Record<string, unknown>>;
    expect(backgrounds.values).toEqual(
      expect.arrayContaining([{ name: "redsim-surface", value: "#0f1f36" }]),
    );
  });

  it("parameters.backgrounds.values has exactly 2 entries", () => {
    const { backgrounds } = preview.parameters as Record<string, Record<string, unknown>>;
    expect((backgrounds.values as unknown[]).length).toBe(2);
  });
});
