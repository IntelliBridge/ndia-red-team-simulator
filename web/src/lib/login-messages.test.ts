import { describe, expect, it } from "vitest";

import { loginMessage, reasonMessage, safeNextPath } from "./login-messages";

describe("loginMessage", () => {
  it("has a sentence for every code and a generic one for anything else", () => {
    for (const code of [
      "invalid_request",
      "invalid_credentials",
      "account_disabled",
      "account_locked",
      "not_configured",
      "unavailable",
    ]) {
      expect(loginMessage(code)).not.toBe(loginMessage("unknown"));
    }
    expect(loginMessage("something_new")).toBe(loginMessage("unknown"));
  });

  it("never names the identity provider", () => {
    for (const code of ["invalid_credentials", "account_locked", "not_configured", "unavailable", "unknown"]) {
      expect(loginMessage(code).toLowerCase()).not.toMatch(/keycloak|oidc|oauth|realm/);
    }
  });
});

describe("reasonMessage", () => {
  it("explains a rejected session and says nothing for an unknown reason", () => {
    expect(reasonMessage("rejected")).toMatch(/session ended/i);
    expect(reasonMessage("signed_out")).toMatch(/signed out/i);
    expect(reasonMessage("anything")).toBeUndefined();
    expect(reasonMessage(null)).toBeUndefined();
  });
});

describe("safeNextPath", () => {
  it("honours a same-origin path and nothing else", () => {
    expect(safeNextPath("/runs/abc?tab=x")).toBe("/runs/abc?tab=x");
    expect(safeNextPath(undefined)).toBe("/dashboard");
    expect(safeNextPath(null)).toBe("/dashboard");
    expect(safeNextPath("")).toBe("/dashboard");
    expect(safeNextPath("/")).toBe("/dashboard");
    expect(safeNextPath("/login")).toBe("/dashboard");
    expect(safeNextPath("/login?next=%2Fruns")).toBe("/dashboard");
    expect(safeNextPath("https://evil.test/")).toBe("/dashboard");
    expect(safeNextPath("//evil.test/")).toBe("/dashboard");
    expect(safeNextPath("/\\evil.test")).toBe("/dashboard");
    expect(safeNextPath("runs")).toBe("/dashboard");
  });
});
