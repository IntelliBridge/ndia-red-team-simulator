import { createElement } from "react";
import { render } from "@testing-library/react";
import { axe } from "vitest-axe";
import { expect, it, vi } from "vitest";
vi.mock("@/hooks/useRequireAuth", () => ({ useRequireAuth: () => true }));
vi.mock("@/hooks/useRoles", () => ({
  useRoles: () => ({ roles: { default: "viewer" } }),
}));
vi.mock("@/hooks/useModels", () => ({
  useModels: () => ({ data: [], isLoading: false }),
}));
vi.mock("@/hooks/useMlCatalog", () => ({
  useCapabilities: () => ({ data: {} }),
  useDatasets: () => ({ data: [] }),
}));
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));
import ModelsPage from "./page";
it("has no obvious accessibility violations", async () => {
  expect(
    (await axe(render(createElement(ModelsPage)).container)).violations,
  ).toHaveLength(0);
});
