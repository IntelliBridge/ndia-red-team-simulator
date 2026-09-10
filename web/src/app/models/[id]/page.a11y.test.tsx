import { createElement } from "react";
import { render } from "@testing-library/react";
import { axe } from "vitest-axe";
import { expect, it, vi } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: () => true }));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: { p1: "viewer" } }),
}));
vi.mock("@/hooks/useModel", () => ({ useModel: () => ({ data: undefined }) }));
vi.mock("@/hooks/useMlCatalog", () => ({
  useAttacks: () => ({ data: [] }),
  useDatasets: () => ({ data: [] }),
  useCapabilities: () => ({ data: {} }),
}));
import ModelPage from "./page";
it("has no obvious accessibility violations", async () => {
  expect(
    (
      await axe(
        render(createElement(ModelPage, { params: { id: "m1" } })).container,
      )
    ).violations,
  ).toHaveLength(0);
});
