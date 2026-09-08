// @vitest-environment node
import { describe, expect, it, vi } from "vitest";

// @storybook/nextjs runs webpack resolution that can fail under vitest; stub
// the module so the config object itself still loads cleanly.
vi.mock("@storybook/nextjs", () => ({}));

// path is used inside webpackFinal — mock it so __dirname resolution doesn't
// fail in the vitest module graph.
vi.mock("node:path", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:path")>();
  return actual;
});

import config from "./main";

describe("storybook main config", () => {
  it("exports a default config object", () => {
    expect(config).not.toBeNull();
    expect(typeof config).toBe("object");
  });

  it("framework is @storybook/nextjs with an options object", () => {
    expect(config.framework).toEqual({ name: "@storybook/nextjs", options: {} });
  });

  it("stories includes design-system glob", () => {
    expect(config.stories).toContain(
      "../../project_repos/design-system/src/**/*.stories.@(ts|tsx)",
    );
  });

  it("stories includes local src glob", () => {
    expect(config.stories).toContain("../src/**/*.stories.@(ts|tsx)");
  });

  it("stories has exactly 2 entries", () => {
    expect(config.stories).toHaveLength(2);
  });

  it("addons contains @storybook/addon-essentials", () => {
    expect(config.addons).toEqual(
      expect.arrayContaining(["@storybook/addon-essentials"]),
    );
  });

  it("addons contains @storybook/addon-a11y", () => {
    expect(config.addons).toEqual(
      expect.arrayContaining(["@storybook/addon-a11y"]),
    );
  });

  it("typescript.check is false", () => {
    expect(config.typescript?.check).toBe(false);
  });

  it("typescript.reactDocgen is react-docgen-typescript", () => {
    expect(config.typescript?.reactDocgen).toBe("react-docgen-typescript");
  });

  it("docs.autodocs is 'tag'", () => {
    expect(config.docs?.autodocs).toBe("tag");
  });

  it("webpackFinal is a function", () => {
    expect(typeof config.webpackFinal).toBe("function");
  });
});
