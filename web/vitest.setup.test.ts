import { describe, expect, it } from "vitest";

// vitest.setup.ts is auto-applied via setupFiles in vitest.config.ts.
// DO NOT import it here — that would double-register its beforeEach.
// The tests below exercise the global `localStorage` stub it installs,
// relying on the per-test beforeEach reset to start each test with a
// clean MemoryStorage instance.

describe("localStorage stub (installed by vitest.setup.ts)", () => {
  it("setItem / getItem roundtrip", () => {
    localStorage.setItem("redsim_token", "abc");
    expect(localStorage.getItem("redsim_token")).toBe("abc");
  });

  it("length reflects the number of stored keys", () => {
    localStorage.setItem("redsim_token", "abc");
    expect(localStorage.length).toBe(1);
  });

  it("key(0) returns the first stored key", () => {
    localStorage.setItem("redsim_token", "abc");
    expect(localStorage.key(0)).toBe("redsim_token");
  });

  it("removeItem deletes the key", () => {
    localStorage.setItem("redsim_token", "abc");
    localStorage.removeItem("redsim_token");
    expect(localStorage.getItem("redsim_token")).toBeNull();
    expect(localStorage.length).toBe(0);
  });

  it("getItem returns null for a key that was never set", () => {
    expect(localStorage.getItem("nope")).toBeNull();
  });

  it("clear empties the store when multiple keys are present", () => {
    localStorage.setItem("k1", "v1");
    localStorage.setItem("k2", "v2");
    expect(localStorage.length).toBe(2);
    localStorage.clear();
    expect(localStorage.length).toBe(0);
  });

  it("data written in this test is visible within the same test", () => {
    localStorage.setItem("leak", "1");
    expect(localStorage.getItem("leak")).toBe("1");
  });

  it("beforeEach installs a fresh store — previous test's 'leak' key is gone", () => {
    // The prior `it` set localStorage["leak"] = "1". The setup's beforeEach
    // must have replaced the store with a new MemoryStorage, so it is absent here.
    expect(localStorage.getItem("leak")).toBeNull();
    expect(localStorage.length).toBe(0);
  });
});
