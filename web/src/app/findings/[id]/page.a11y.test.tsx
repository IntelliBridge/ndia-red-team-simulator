import { createElement } from "react";
import { render } from "@testing-library/react";
import { axe } from "vitest-axe";
import { expect, it, vi } from "vitest";
import fixture from "@/__fixtures__/finding.json";
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: () => true }));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: { default: "viewer" } }),
}));
vi.mock("@/hooks/useFinding", () => ({
  useFinding: () => ({ data: fixture, mutate: vi.fn() }),
}));
import FindingPage from "./page";
it("has no obvious accessibility violations", async () => {
  const view = render(
    createElement(FindingPage, { params: { id: "fixture-finding" } }),
  );
  expect((await axe(view.container)).violations).toHaveLength(0);
});
