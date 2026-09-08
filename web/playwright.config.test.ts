// @vitest-environment node
import { describe, expect, it, vi } from "vitest";

// @playwright/test is not installed in this workspace; mock it so playwright.config.ts
// can be imported and its real authored values can be asserted.
vi.mock("@playwright/test", () => ({
  defineConfig: (c: unknown) => c,
  devices: new Proxy({}, { get: () => ({}) }),
}));

import config from "./playwright.config";

describe("playwright config", () => {
  it("exports a default config object", () => {
    expect(config).not.toBeNull();
    expect(typeof config).toBe("object");
  });

  it("testDir is './tests'", () => {
    expect((config as Record<string, unknown>).testDir).toBe("./tests");
  });

  it("timeout is 120000", () => {
    expect((config as Record<string, unknown>).timeout).toBe(120000);
  });

  it("retries is 0", () => {
    expect((config as Record<string, unknown>).retries).toBe(0);
  });

  it("use.headless is true", () => {
    const use = (config as Record<string, Record<string, unknown>>).use;
    expect(use.headless).toBe(true);
  });

  it("use.baseURL falls back to http://localhost:3000 when env var unset", () => {
    const use = (config as Record<string, Record<string, unknown>>).use;
    // process.env.REDSIM_WEB_URL is not set in this test environment
    expect(use.baseURL).toBe("http://localhost:3000");
  });

  it("use.trace is 'retain-on-failure'", () => {
    const use = (config as Record<string, Record<string, unknown>>).use;
    expect(use.trace).toBe("retain-on-failure");
  });
});
