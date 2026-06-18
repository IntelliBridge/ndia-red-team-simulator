import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";

// CommandPalette (mounted in the layout) calls useRouter(); stub it so the
// shell renders outside a Next app-router context.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}));

import RootLayout from "./layout";

afterEach(cleanup);

function renderLayout() {
  return render(
    React.createElement(
      RootLayout,
      null,
      React.createElement("h1", null, "Page heading"),
    ),
  );
}

describe("RootLayout a11y", () => {
  it("renders a skip link that targets the main landmark", () => {
    renderLayout();
    const skip = screen.getByText("Skip to content", { selector: "a" });
    expect(skip.getAttribute("href")).toBe("#main-content");

    const main = document.querySelector("main");
    expect(main?.getAttribute("id")).toBe("main-content");
  });

  it("the app shell has no axe violations", async () => {
    const { container } = renderLayout();
    const results = await axe(container);
    expect(results.violations).toEqual([]);
  });
});
